from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

import httpx
from dotenv import load_dotenv

from playbooks.audit import log_event

load_dotenv()
logger = logging.getLogger(__name__)
TELEGRAM_TIMEOUT_SECONDS = 5.0


def _log_telegram_event(result: dict[str, Any]) -> None:
    try:
        log_event("telegram_notification", result)
    except (sqlite3.Error, OSError):
        logger.exception("Could not persist Telegram notification event")


def _telegram_message(
    alert_id: str,
    alert_type: str,
    risk: float,
    label: str,
    top_features: Sequence[dict[str, Any]],
    selected_playbooks: Sequence[str],
    approval_required: bool,
) -> str:
    feature_text = ", ".join(
        str(item.get("feature", "unknown")) for item in top_features[:3]
    ) or "none available"
    playbook_text = ", ".join(selected_playbooks) or "none"
    return (
        f"SOAR alert: {alert_id}\n"
        f"Type: {alert_type}\n"
        f"Risk: {risk:.2f}/100\n"
        f"ML label: {label}\n"
        f"Top SHAP features: {feature_text}\n"
        f"Selected playbooks: {playbook_text}\n"
        f"Approval required: {'Yes' if approval_required else 'No'}"
    )


def block_ip(alert_id: str, ip: str | None) -> dict[str, Any]:
    result = {
        "action": "block_ip",
        "status": "simulated",
        "alert_id": alert_id,
        "ip": ip,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    log_event("simulated_action", result)
    return result


def create_ticket(alert_id: str, alert_type: str, risk: float, label: str) -> dict[str, Any]:
    ticket = {
        "ticket_id": f"TICKET-{alert_id}",
        "alert_id": alert_id,
        "alert_type": alert_type,
        "risk": risk,
        "label": label,
        "status": "open",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    tickets_dir = Path(__file__).resolve().parents[1] / "data" / "tickets"
    tickets_dir.mkdir(parents=True, exist_ok=True)
    (tickets_dir / f"{ticket['ticket_id']}.json").write_text(
        json.dumps(ticket, indent=2),
        encoding="utf-8",
    )
    log_event("ticket_created", ticket)
    return ticket


async def notify_telegram(
    alert_id: str,
    risk: float,
    label: str,
    alert_type: str = "unknown",
    top_features: Sequence[dict[str, Any]] = (),
    selected_playbooks: Sequence[str] = (),
    approval_required: bool = False,
) -> dict[str, Any]:
    simulation_mode = os.getenv("SIMULATION_MODE", "true").strip().lower() != "false"
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    text = _telegram_message(
        alert_id,
        alert_type,
        risk,
        label,
        top_features,
        selected_playbooks,
        approval_required,
    )
    if simulation_mode or not token or not chat_id:
        result = {
            "action": "notify_telegram",
            "status": "simulated",
            "alert_id": alert_id,
            "message": text,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        _log_telegram_event(result)
        return result

    try:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if approval_required:
            payload["reply_markup"] = {
                "inline_keyboard": [[
                    {"text": "Approve", "callback_data": f"approve:{alert_id}"},
                    {"text": "Reject", "callback_data": f"reject:{alert_id}"},
                ]]
            }
        async with httpx.AsyncClient(timeout=TELEGRAM_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json=payload,
            )
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or body.get("ok") is not True:
                raise ValueError("Telegram API did not confirm message delivery")
        result = {
            "action": "notify_telegram",
            "status": "sent",
            "alert_id": alert_id,
            "message": text,
        }
    except Exception:
        logger.exception("Telegram notification failed for alert %s", alert_id)
        result = {
            "action": "notify_telegram",
            "status": "fallback_simulated",
            "alert_id": alert_id,
            "message": text,
        }
    _log_telegram_event(result)
    return result
