from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status

from api.schemas import Alert, AlertDecision
from enrichment.providers import enrich_alert
from ml.score import score
from playbooks.engine import execute_playbooks
from playbooks.approval import process_decision
from api.schemas import ApprovalDecision


load_dotenv()

app = FastAPI(
    title="SOAR ML MVP",
    version="0.1.0",
    description="SIEM alert ingestion, enrichment, and ML risk scoring.",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/alerts", response_model=AlertDecision, status_code=status.HTTP_200_OK)
async def ingest_alert(alert: Alert) -> AlertDecision:
    alert_dict = alert.model_dump()
    try:
        enrichment = await enrich_alert(alert_dict)
        ml_result = score(
            {
                **alert_dict,
                "enrichment": enrichment,
            }
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Alert could not be scored: {exc}",
        ) from exc

    alert_id = alert.alert_id or str(uuid4())
    received_at = datetime.now(UTC).isoformat()
    source_ip = alert.source.ip if alert.source else None
    playbook_result = await execute_playbooks(
        alert_id=alert_id,
        alert_type=alert.alert_type,
        label=ml_result["label"],
        risk=ml_result["risk"],
        source_ip=source_ip,
        top_features=ml_result["top_features"],
    )
    return AlertDecision(
        alert_id=alert_id,
        received_at=received_at,
        alert_type=alert.alert_type,
        enrichment=enrichment,
        risk=ml_result["risk"],
        label=ml_result["label"],
        probability=ml_result["probability"],
        top_features=ml_result["top_features"],
        model=ml_result["model"],
        playbooks=playbook_result,
    )


@app.post("/alerts/{alert_id}/approval")
async def approve_alert(alert_id: str, decision: ApprovalDecision) -> dict[str, Any]:
    try:
        return process_decision(
            alert_id=alert_id,
            decision=decision.decision,
            analyst=decision.analyst,
            comment=decision.comment,
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
