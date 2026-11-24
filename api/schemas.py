from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class AlertSource(BaseModel):
    ip: str | None = Field(default=None, description="Source IP address")
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)


class Alert(BaseModel):
    alert_id: str | None = None
    alert_type: str = Field(
        description="SSH brute force, RDP brute force, suspicious IP, or malicious file hash"
    )
    severity: str = "medium"
    timestamp: str | None = None
    source: AlertSource | None = None
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    file_hash: str | None = None
    features: dict[str, Any] = Field(default_factory=dict)

    @field_validator("alert_type")
    @classmethod
    def normalize_alert_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("alert_type cannot be empty")
        return normalized


class AlertDecision(BaseModel):
    alert_id: str
    received_at: str
    alert_type: str
    enrichment: dict[str, Any]
    risk: float = Field(ge=0, le=100)
    label: str
    probability: float = Field(ge=0, le=1)
    top_features: list[dict[str, Any]]
    model: str
    playbooks: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    decision: str = Field(description="approve or reject")
    analyst: str = Field(min_length=1, max_length=100)
    comment: str = Field(default="", max_length=2000)

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"approve", "reject"}:
            raise ValueError("decision must be approve or reject")
        return normalized
