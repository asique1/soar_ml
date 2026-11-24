from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_alert_endpoint_mock_enrichment(monkeypatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("SIMULATION_MODE", "true")

    response = client.post(
        "/alerts",
        json={
            "alert_type": "suspicious IP",
            "source": {"ip": "198.51.100.10"},
            "destination_port": 3389,
            "features": {"Duration": 2.0, "Destination Port": 3389},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["alert_type"] == "suspicious ip"
    assert 0 <= body["risk"] <= 100
    assert body["enrichment"]["ip"]["geoip"]["source"] == "mock"
    assert body["enrichment"]["file_hash"]["status"] == "skipped"
    assert "selected_playbooks" in body["playbooks"]


def test_alert_missing_model_returns_service_unavailable(monkeypatch) -> None:
    async def fake_enrich(alert):
        return {"ip": {"status": "skipped"}, "file_hash": {"status": "skipped"}}

    def missing_model(alert):
        raise FileNotFoundError("model missing")

    monkeypatch.setattr("api.main.enrich_alert", fake_enrich)
    monkeypatch.setattr("api.main.score", missing_model)
    response = client.post("/alerts", json={"alert_type": "suspicious ip"})

    assert response.status_code == 503
    assert response.json()["detail"] == "model missing"


def test_alert_scoring_value_error_returns_unprocessable(monkeypatch) -> None:
    async def fake_enrich(alert):
        return {"ip": {"status": "skipped"}, "file_hash": {"status": "skipped"}}

    def invalid_alert(alert):
        raise ValueError("invalid feature values")

    monkeypatch.setattr("api.main.enrich_alert", fake_enrich)
    monkeypatch.setattr("api.main.score", invalid_alert)
    response = client.post("/alerts", json={"alert_type": "suspicious ip"})

    assert response.status_code == 422
    assert "invalid feature values" in response.json()["detail"]
