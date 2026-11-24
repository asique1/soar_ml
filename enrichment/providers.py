from __future__ import annotations

import os
from ipaddress import ip_address
from typing import Any

import httpx


HTTP_TIMEOUT_SECONDS = 5.0


def mock_geoip(ip: str) -> dict[str, Any]:
    try:
        ip_address(ip)
    except ValueError:
        return {"source": "mock", "status": "invalid_ip", "country": "Unknown"}
    return {"source": "mock", "country": "Unknown", "city": "Unknown", "asn": "Unknown"}


async def enrich_ip(ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"status": "skipped", "reason": "No source IP supplied"}

    try:
        ip_address(ip)
    except ValueError:
        return {"status": "invalid", "reason": "Invalid source IP"}

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not abuse_key:
        abuse = {"source": "mock", "abuse_confidence": 0, "status": "mock"}
    else:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                response.raise_for_status()
                data = response.json().get("data", {})
                abuse = {
                    "source": "abuseipdb",
                    "abuse_confidence": data.get("abuseConfidenceScore"),
                    "status": "enriched",
                }
        except (httpx.HTTPError, ValueError):
            abuse = {"source": "fallback", "abuse_confidence": 0, "status": "error"}

    return {
        "ip": ip,
        "abuseipdb": abuse,
        "geoip": mock_geoip(ip),
    }


async def enrich_hash(file_hash: str | None) -> dict[str, Any]:
    if not file_hash:
        return {"status": "skipped", "reason": "No file hash supplied"}

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not vt_key:
        return {
            "status": "mock",
            "source": "mock",
            "malicious": False,
            "suspicious": False,
        }

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": vt_key},
            )
            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "enriched",
                "source": "virustotal",
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
            }
    except (httpx.HTTPError, ValueError):
        return {
            "status": "error",
            "source": "fallback",
            "malicious": 0,
            "suspicious": 0,
        }


async def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    source = alert.get("source")
    ip = source.get("ip") if isinstance(source, dict) else None
    return {
        "ip": await enrich_ip(ip),
        "file_hash": await enrich_hash(alert.get("file_hash")),
    }
