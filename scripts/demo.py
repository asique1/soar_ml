from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sklearn.model_selection import train_test_split

from api.main import app
from ml.data_loader import load_dataset
from ml.score import load_bundle


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"


def choose_scenarios() -> list[dict[str, Any]]:
    features, labels = load_dataset()
    sample_size = min(50_000, len(features))
    sample_x, _, sample_y, _ = train_test_split(
        features,
        labels,
        train_size=sample_size,
        random_state=2026,
        stratify=labels,
    )
    model = load_bundle()["model"]
    probabilities = model.predict_proba(sample_x)[:, 1]

    positive = [index for index, value in enumerate(sample_y.to_numpy()) if value == 1]
    benign = [index for index, value in enumerate(sample_y.to_numpy()) if value == 0]
    incident_index = max(positive, key=lambda index: probabilities[index])
    false_positive_index = min(benign, key=lambda index: probabilities[index])
    borderline_index = min(
        range(len(probabilities)),
        key=lambda index: abs(float(probabilities[index]) - 0.5),
    )

    choices = [
        ("true_incident", "ssh brute force", incident_index),
        ("false_positive", "suspicious ip", false_positive_index),
        ("borderline", "rdp brute force", borderline_index),
    ]
    scenarios: list[dict[str, Any]] = []
    for scenario_name, alert_type, index in choices:
        row = sample_x.iloc[index]
        fields = {
            str(name): float(value)
            for name, value in row.items()
        }
        scenarios.append({
            "scenario": scenario_name,
            "ground_truth": "malicious" if int(sample_y.iloc[index]) == 1 else "benign",
            "alert": {
                "alert_id": f"DEMO-{scenario_name.upper()}",
                "alert_type": alert_type,
                "source": {"ip": "198.51.100.10"},
                "destination_port": int(fields.get("Destination_Port", 22)),
                "features": fields,
            },
        })
    return scenarios


def run_demo() -> str:
    previous_simulation_mode = os.environ.get("SIMULATION_MODE")
    os.environ["SIMULATION_MODE"] = "true"
    client = TestClient(app)
    output: list[str] = [
        "SOAR ML end-to-end demo",
        f"Generated at: {datetime.now(UTC).isoformat()}",
        "Source: CIC-IDS2017 cleaned data; scenarios selected from a deterministic stratified sample.",
        "Telegram forced to simulation mode for this demo; IP blocking remains simulated.",
        "",
    ]

    try:
        for scenario in choose_scenarios():
            alert = scenario["alert"]
            started = datetime.now(UTC)
            response = client.post("/alerts", json=alert)
            finished = datetime.now(UTC)
            if response.status_code != 200:
                raise RuntimeError(
                    f"Demo scenario {scenario['scenario']} failed: "
                    f"{response.status_code} {response.text}"
                )
            decision = response.json()
            actions = decision["playbooks"].get("actions", [])
            approval_required = any(
                action.get("status") == "pending_approval" for action in actions
            )

            scenario_output = {
                "scenario": scenario["scenario"],
                "ground_truth": scenario["ground_truth"],
                "processing_started_at": started.isoformat(),
                "processing_completed_at": finished.isoformat(),
                "processing_seconds": (finished - started).total_seconds(),
                "enrichment": decision["enrichment"],
                "ml_decision": {
                    "label": decision["label"],
                    "risk": decision["risk"],
                    "probability": decision["probability"],
                    "top_features": decision["top_features"],
                    "model": decision["model"],
                },
                "selected_playbooks": decision["playbooks"]["selected_playbooks"],
                "actions": actions,
                "approval_required": approval_required,
            }
            output.append(json.dumps(scenario_output, indent=2))
            output.append("")

        transcript = "\n".join(output)
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        output_path = RESULTS_DIR / "demo_output.txt"
        output_path.write_text(transcript, encoding="utf-8")
        return transcript
    finally:
        if previous_simulation_mode is None:
            os.environ.pop("SIMULATION_MODE", None)
        else:
            os.environ["SIMULATION_MODE"] = previous_simulation_mode


if __name__ == "__main__":
    print(run_demo())
