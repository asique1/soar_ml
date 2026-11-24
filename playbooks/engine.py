from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import yaml

from playbooks.actions import block_ip, create_ticket, notify_telegram
from playbooks.audit import log_event, store_pending_alert


PLAYBOOK_DIR = Path(__file__).resolve().parent


def load_playbooks(directory: Path | None = None) -> list[dict[str, Any]]:
    root = directory or PLAYBOOK_DIR
    playbooks: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as stream:
            playbook = yaml.safe_load(stream)
        if isinstance(playbook, dict):
            playbooks.append(playbook)
    return playbooks


def matches(playbook: Mapping[str, Any], alert_type: str, label: str, risk: float) -> bool:
    triggers = playbook.get("triggers", {})
    alert_types = [str(value).strip().lower() for value in triggers.get("alert_types", [])]
    labels = [str(value).strip().lower() for value in triggers.get("labels", [])]
    minimum_risk = float(triggers.get("minimum_risk", 0))
    return (
        alert_type.lower() in alert_types
        and label.lower() in labels
        and risk >= minimum_risk
    )


async def execute_playbooks(
    alert_id: str,
    alert_type: str,
    label: str,
    risk: float,
    source_ip: str | None,
    top_features: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    applicable = [
        playbook
        for playbook in load_playbooks()
        if matches(playbook, alert_type, label, risk)
    ]
    selected = [str(playbook["name"]) for playbook in applicable]
    approval_required = risk >= 70 and any(
        playbook.get("action", {}).get("type") == "block_ip"
        for playbook in applicable
    )
    actions: list[dict[str, Any]] = []

    for playbook in applicable:
        action_type = playbook["action"]["type"]
        if action_type == "block_ip":
            if risk >= 70:
                store_pending_alert(alert_id, alert_type, source_ip, risk, label)
                action = {
                    "action": "block_ip",
                    "status": "pending_approval",
                    "alert_id": alert_id,
                    "ip": source_ip,
                }
            else:
                action = block_ip(alert_id, source_ip)
        elif action_type == "create_ticket":
            action = create_ticket(alert_id, alert_type, risk, label)
        elif action_type == "notify_telegram":
            action = await notify_telegram(
                alert_id=alert_id,
                risk=risk,
                label=label,
                alert_type=alert_type,
                top_features=top_features or [],
                selected_playbooks=selected,
                approval_required=approval_required,
            )
        else:
            action = {"action": action_type, "status": "unsupported"}
        actions.append(action)

    record = {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "label": label,
        "risk": risk,
        "selected_playbooks": selected,
        "actions": actions,
    }
    log_event("playbook_execution", record)
    return record
