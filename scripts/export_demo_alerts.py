"""Save the three demo alerts as JSON files so the live demo needs no data loading.

Run once (takes about a minute, it reads the CIC-IDS2017 CSVs):

    python -m scripts.export_demo_alerts

The files are written to results/demo_alerts/ and are sent to a running API
by scripts/send_demo_alerts.py.
"""
from __future__ import annotations

import json
from pathlib import Path

from scripts.demo import choose_scenarios

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "demo_alerts"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for scenario in choose_scenarios():
        path = OUTPUT_DIR / f"{scenario['scenario']}.json"
        path.write_text(json.dumps(scenario["alert"], indent=2), encoding="utf-8")
        print(f"{path.name}: ground truth = {scenario['ground_truth']}")
    print(f"Saved to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
