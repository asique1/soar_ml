from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx
from dotenv import load_dotenv

from playbooks.approval import process_decision


load_dotenv()
logger = logging.getLogger(__name__)
TELEGRAM_TIMEOUT_SECONDS = 30.0


def process_callback(update: dict[str, Any], authorized_chat_id: str) -> dict[str, Any]:
    query = update.get("callback_query", {})
    message = query.get("message", {})
    chat_id = str(message.get("chat", {}).get("id", ""))
    if not authorized_chat_id or chat_id != str(authorized_chat_id):
        return {
            "authorized": False,
            "callback_query_id": query.get("id"),
            "text": "Unauthorized chat",
        }

    callback_data = str(query.get("data", ""))
    decision, separator, alert_id = callback_data.partition(":")
    if not separator or decision not in {"approve", "reject"} or not alert_id:
        return {
            "authorized": True,
            "callback_query_id": query.get("id"),
            "text": "Invalid decision request",
        }

    result = process_decision(
        alert_id=alert_id,
        decision=decision,
        analyst="telegram-analyst",
        comment="Decision submitted from Telegram",
    )
    return {
        "authorized": True,
        "callback_query_id": query.get("id"),
        "text": f"{decision.title()} recorded for {alert_id}",
        "result": result,
        "chat_id": chat_id,
    }


async def run_bot() -> None:
    if os.getenv("SIMULATION_MODE", "true").strip().lower() != "false":
        raise RuntimeError("Telegram approval bot requires SIMULATION_MODE=false")
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required")

    base_url = f"https://api.telegram.org/bot{token}"
    offset: int | None = None
    async with httpx.AsyncClient(timeout=TELEGRAM_TIMEOUT_SECONDS) as client:
        while True:
            try:
                response = await client.get(
                    f"{base_url}/getUpdates",
                    params={"timeout": 20, "offset": offset},
                )
                response.raise_for_status()
                updates = response.json().get("result", [])
                for update in updates:
                    offset = int(update["update_id"]) + 1
                    if "callback_query" not in update:
                        continue
                    result = process_callback(update, chat_id)
                    callback_id = result.get("callback_query_id")
                    if callback_id:
                        await client.post(
                            f"{base_url}/answerCallbackQuery",
                            json={"callback_query_id": callback_id, "text": result["text"]},
                        )
                    if result.get("authorized") and result.get("chat_id"):
                        await client.post(
                            f"{base_url}/sendMessage",
                            json={"chat_id": result["chat_id"], "text": result["text"]},
                        )
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                logger.warning("Telegram polling failed: %s", exc)
                await asyncio.sleep(2)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_bot())
