from __future__ import annotations

import sqlite3

from playbooks.approval import export_feedback_csv, process_decision
from playbooks.audit import database_path, store_pending_alert
from playbooks.audit import mttr_seconds


def test_approval_and_rejection_store_feedback(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'approval.db'}")
    store_pending_alert("alert-1", "ssh brute force", "198.51.100.10", 91.0, "malicious")

    approved = process_decision("alert-1", "approve", "analyst1", "Confirmed")
    assert approved["feedback"]["decision"] == "approve"
    assert approved["action"]["status"] == "simulated_approved"

    store_pending_alert("alert-2", "rdp brute force", "198.51.100.20", 82.0, "malicious")
    rejected = process_decision("alert-2", "reject", "analyst1", "False positive")
    assert rejected["feedback"]["decision"] == "reject"
    assert rejected["action"]["status"] == "rejected"

    with sqlite3.connect(database_path()) as connection:
        count = connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
    assert count == 2

    exported = export_feedback_csv(tmp_path / "feedback.csv")
    assert exported.exists()


def test_mttr_requires_received_and_resolution_events(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'mttr.db'}")
    from playbooks.audit import log_event
    import sqlite3

    log_event("playbook_execution", {"alert_id": "mttr-1"})
    log_event("analyst_decision", {"alert_id": "mttr-1"})
    with sqlite3.connect(database_path()) as connection:
        value = mttr_seconds(connection, "mttr-1")
    assert value is not None
    assert value >= 0
