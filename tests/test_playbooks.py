from __future__ import annotations

from playbooks.engine import load_playbooks, matches


def test_load_all_playbooks() -> None:
    playbooks = load_playbooks()
    names = {playbook["name"] for playbook in playbooks}
    assert names == {"block_ip", "create_ticket", "notify_telegram"}


def test_malicious_ssh_alert_matches_block_and_ticket_playbooks() -> None:
    playbooks = load_playbooks()
    selected = [
        playbook["name"]
        for playbook in playbooks
        if matches(playbook, "ssh brute force", "malicious", 80)
    ]
    assert selected == ["block_ip", "create_ticket", "notify_telegram"]


def test_low_risk_alert_does_not_match_malicious_playbooks() -> None:
    playbooks = load_playbooks()
    selected = [
        playbook["name"]
        for playbook in playbooks
        if matches(playbook, "suspicious ip", "malicious", 20)
    ]
    assert selected == []
