from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def mttr_seconds(connection: sqlite3.Connection, alert_id: str) -> float | None:
    """Calculate received-to-approved time for one alert in seconds."""
    rows = connection.execute(
        """
        SELECT timestamp, event_type, payload
        FROM pipeline_events
        WHERE payload LIKE ?
        ORDER BY id
        """,
        (f'%"{alert_id}"%',),
    ).fetchall()
    if not rows:
        return None
    timestamps: dict[str, datetime] = {}
    for timestamp, event_type, _payload in rows:
        timestamps[event_type] = datetime.fromisoformat(timestamp)
    received = timestamps.get("playbook_execution")
    resolved = timestamps.get("analyst_decision")
    if received is None or resolved is None:
        return None
    return max(0.0, (resolved - received).total_seconds())


def database_path() -> Path:
    url = os.getenv("DATABASE_URL", "sqlite:///./data/soar.db")
    if not url.startswith("sqlite:///"):
        return Path(__file__).resolve().parents[1] / "data" / "soar.db"
    raw_path = url.removeprefix("sqlite:///")
    if raw_path.startswith("/"):
        return Path(raw_path)
    return Path(__file__).resolve().parents[1] / raw_path


def log_event(event_type: str, payload: dict[str, Any]) -> None:
    import json

    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pipeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO pipeline_events (timestamp, event_type, payload) VALUES (?, ?, ?)",
            (datetime.now(UTC).isoformat(), event_type, json.dumps(payload, default=str)),
        )


def store_pending_alert(
    alert_id: str,
    alert_type: str,
    source_ip: str | None,
    risk: float,
    label: str,
) -> None:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_alerts (
                alert_id TEXT PRIMARY KEY,
                alert_type TEXT NOT NULL,
                source_ip TEXT,
                risk REAL NOT NULL,
                label TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO pending_alerts
            (alert_id, alert_type, source_ip, risk, label, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """,
            (alert_id, alert_type, source_ip, risk, label, datetime.now(UTC).isoformat()),
        )


def get_pending_alert(alert_id: str) -> dict[str, Any] | None:
    path = database_path()
    if not path.exists():
        return None
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM pending_alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None
