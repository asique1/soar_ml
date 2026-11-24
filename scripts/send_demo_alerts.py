"""Send the saved demo alerts to a running API and print a short summary.

Start the API in another terminal first:

    uvicorn api.main:app

Then run:

    python -m scripts.send_demo_alerts
    python -m scripts.send_demo_alerts --approve    # also approve pending blocks
    python -m scripts.send_demo_alerts --unique     # new alert ids for repeated runs

Uses only the standard library. IP blocking stays simulated; Telegram follows
SIMULATION_MODE in the API's .env.
"""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ALERTS_DIR = ROOT / "results" / "demo_alerts"
ORDER = ("true_incident", "false_positive", "borderline")


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def action_name(action: dict[str, Any]) -> str:
    if "action" in action:
        return str(action["action"])
    return "create_ticket" if "ticket_id" in action else "unknown"


def print_summary(name: str, decision: dict[str, Any]) -> list[dict[str, Any]]:
    playbooks = decision.get("playbooks", {})
    actions = playbooks.get("actions", [])
    features = ", ".join(item["feature"] for item in decision.get("top_features", [])[:3])
    print(f"\n=== {name} ===")
    print(f"label: {decision['label']}   risk: {decision['risk']}   model: {decision.get('model')}")
    print(f"top features: {features}")
    print(f"playbooks: {', '.join(playbooks.get('selected_playbooks', [])) or 'none'}")
    for action in actions:
        print(f"  - {action_name(action)}: {action.get('status')}")
    return actions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument("--approve", action="store_true", help="approve pending blocks")
    parser.add_argument("--unique", action="store_true", help="append a time suffix to alert ids")
    args = parser.parse_args()

    missing = [name for name in ORDER if not (ALERTS_DIR / f"{name}.json").exists()]
    if missing:
        raise SystemExit(
            f"Missing alert files in {ALERTS_DIR}: {missing}. "
            "Run `python -m scripts.export_demo_alerts` first."
        )

    suffix = datetime.now().strftime("-%H%M%S") if args.unique else ""
    for name in ORDER:
        alert = json.loads((ALERTS_DIR / f"{name}.json").read_text(encoding="utf-8"))
        alert["alert_id"] = f"{alert['alert_id']}{suffix}"
        try:
            decision = post_json(f"{args.url}/alerts", alert)
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"Cannot reach the API at {args.url} ({exc}). "
                "Start it with: uvicorn api.main:app"
            ) from exc
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"{name}: API returned {exc.code}: {exc.read().decode('utf-8')}") from exc

        actions = print_summary(name, decision)
        pending = any(action.get("status") == "pending_approval" for action in actions)
        if pending and args.approve:
            reply = post_json(
                f"{args.url}/alerts/{alert['alert_id']}/approval",
                {"decision": "approve", "analyst": "demo-analyst", "comment": "Confirmed in demo"},
            )
            print(f"  analyst decision stored: {json.dumps(reply)[:200]}")


if __name__ == "__main__":
    main()
