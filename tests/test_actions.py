from __future__ import annotations

import asyncio
import json

from playbooks.actions import block_ip, create_ticket, notify_telegram


def test_block_ip_is_simulated(monkeypatch) -> None:
    monkeypatch.setattr("playbooks.actions.log_event", lambda *args, **kwargs: None)
    result = block_ip("action-block-1", "198.51.100.10")
    assert result["status"] == "simulated"
    assert result["ip"] == "198.51.100.10"


def test_ticket_action_writes_local_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "playbooks.actions.__file__",
        str(tmp_path / "playbooks" / "actions.py"),
    )
    monkeypatch.setattr("playbooks.actions.log_event", lambda *args, **kwargs: None)
    ticket = create_ticket("action-ticket-1", "ssh brute force", 88.0, "malicious")
    path = tmp_path / "data" / "tickets" / "TICKET-action-ticket-1.json"
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "open"
    assert ticket["status"] == "open"


def test_telegram_action_simulates_by_default(monkeypatch) -> None:
    monkeypatch.setenv("SIMULATION_MODE", "true")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")

    result = asyncio.run(notify_telegram("action-telegram-1", 52.0, "malicious"))
    assert result["status"] == "simulated"
    assert "Approval required: No" in result["message"]
