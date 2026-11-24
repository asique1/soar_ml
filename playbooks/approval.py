from __future__ import annotations

import csv
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from playbooks.actions import block_ip
from playbooks.audit import database_path, get_pending_alert, log_event


def save_feedback(
    alert_id: str,
    decision: str,
    analyst: str,
    comment: str,
    alert_context: dict[str, Any],
) -> dict[str, Any]:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    feedback = {
        "alert_id": alert_id,
        "decision": decision,
        "analyst": analyst,
        "comment": comment,
        "alert_type": alert_context["alert_type"],
        "risk": alert_context["risk"],
        "ml_label": alert_context["label"],
        "timestamp": datetime.now(UTC).isoformat(),
    }

    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                analyst TEXT NOT NULL,
                comment TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                risk REAL NOT NULL,
                ml_label TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO feedback
            (alert_id, decision, analyst, comment, alert_type, risk, ml_label, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                decision,
                analyst,
                comment,
                alert_context["alert_type"],
                alert_context["risk"],
                alert_context["label"],
                feedback["timestamp"],
            ),
        )
        connection.execute(
            "UPDATE pending_alerts SET status = ? WHERE alert_id = ?",
            ("approved" if decision == "approve" else "rejected", alert_id),
        )

    log_event("analyst_decision", feedback)
    return feedback


def process_decision(
    alert_id: str,
    decision: str,
    analyst: str,
    comment: str,
) -> dict[str, Any]:
    context = get_pending_alert(alert_id)
    if context is None:
        raise LookupError(f"Alert {alert_id} has no pending high-risk action")

    feedback = save_feedback(alert_id, decision, analyst, comment, context)
    action: dict[str, Any]
    if decision == "approve":
        action = block_ip(alert_id, context["source_ip"])
        action["status"] = "simulated_approved"
    else:
        action = {
            "action": "block_ip",
            "status": "rejected",
            "alert_id": alert_id,
        }
    log_event("approval_action", {"feedback": feedback, "action": action})
    return {"feedback": feedback, "action": action}


def export_feedback_csv(output: Path | None = None) -> Path:
    target = output or database_path().parent / "processed" / "feedback.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    path = database_path()
    if not path.exists():
        raise FileNotFoundError("No feedback database exists")

    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM feedback").fetchall()

    with target.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "id", "alert_id", "decision", "analyst", "comment",
                "alert_type", "risk", "ml_label", "timestamp",
            ],
        )
        writer.writeheader()
        writer.writerows(dict(row) for row in rows)
    return target
