from __future__ import annotations

import asyncio

import httpx

from bot.telegram_bot import process_callback
from playbooks.actions import notify_telegram


class MockTelegramResponse:
    def __init__(self, body: dict[str, object] | None = None) -> None:
        self.body = body or {"ok": True, "result": {"message_id": 1}}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self.body


def test_telegram_send_success(monkeypatch) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("playbooks.actions.log_event", lambda *args, **kwargs: None)

    class MockClient:
        def __init__(self, timeout: float) -> None:
            assert timeout == 5.0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url: str, json: dict[str, object]):
            calls.append(json)
            return MockTelegramResponse()

    monkeypatch.setenv("SIMULATION_MODE", "false")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")
    monkeypatch.setattr("playbooks.actions.httpx.AsyncClient", MockClient)

    result = asyncio.run(notify_telegram(
        "alert-1", 91.2, "malicious", "ssh brute force",
        [{"feature": "Flow_Duration"}, {"feature": "SYN_Flag_Count"}],
        ["block_ip", "notify_telegram"], True,
    ))

    assert result["status"] == "sent"
    assert calls[0]["chat_id"] == "123"
    assert "Approval required: Yes" in str(calls[0]["text"])
    assert "Top SHAP features: Flow_Duration, SYN_Flag_Count" in str(calls[0]["text"])
    assert "inline_keyboard" in calls[0]["reply_markup"]


def test_telegram_timeout_falls_back_without_raising(monkeypatch) -> None:
    monkeypatch.setattr("playbooks.actions.log_event", lambda *args, **kwargs: None)
    class TimeoutClient:
        def __init__(self, timeout: float) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            raise httpx.TimeoutException("timed out")

    monkeypatch.setenv("SIMULATION_MODE", "false")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")
    monkeypatch.setattr("playbooks.actions.httpx.AsyncClient", TimeoutClient)

    result = asyncio.run(notify_telegram("alert-2", 75, "malicious"))
    assert result["status"] == "fallback_simulated"


def test_simulation_mode_does_not_call_telegram(monkeypatch) -> None:
    monkeypatch.setattr("playbooks.actions.log_event", lambda *args, **kwargs: None)
    def unexpected_client(*args, **kwargs):
        raise AssertionError("Telegram HTTP client must not be constructed")

    monkeypatch.setenv("SIMULATION_MODE", "true")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")
    monkeypatch.setattr("playbooks.actions.httpx.AsyncClient", unexpected_client)

    result = asyncio.run(notify_telegram("alert-3", 60, "benign"))
    assert result["status"] == "simulated"


def test_unauthorized_chat_cannot_submit_approval(monkeypatch) -> None:
    def unexpected_decision(**kwargs):
        raise AssertionError("Unauthorized callback must not reach approval logic")

    monkeypatch.setattr("bot.telegram_bot.process_decision", unexpected_decision)
    update = {
        "callback_query": {
            "id": "callback-1",
            "data": "approve:alert-4",
            "message": {"chat": {"id": 999}},
        }
    }

    result = process_callback(update, authorized_chat_id="123")
    assert result["authorized"] is False
    assert result["text"] == "Unauthorized chat"
