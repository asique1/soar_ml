from __future__ import annotations

import asyncio

import httpx

from enrichment.providers import enrich_hash, enrich_ip


class TimeoutClient:
    def __init__(self, timeout: float) -> None:
        assert timeout == 5.0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, *args, **kwargs):
        raise httpx.TimeoutException("provider timed out")


def test_abuseipdb_timeout_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr("enrichment.providers.httpx.AsyncClient", TimeoutClient)

    result = asyncio.run(enrich_ip("198.51.100.10"))
    assert result["abuseipdb"]["status"] == "error"
    assert result["abuseipdb"]["source"] == "fallback"


def test_virustotal_timeout_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr("enrichment.providers.httpx.AsyncClient", TimeoutClient)

    result = asyncio.run(enrich_hash("a" * 64))
    assert result["status"] == "error"
    assert result["source"] == "fallback"
