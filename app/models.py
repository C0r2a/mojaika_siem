from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EventIn(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    event_type: str = "unknown"
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    asset_id: str | None = None
    severity: Severity = Severity.info
    message: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    vendor: str
    event_type: str
    src_ip: str | None
    dst_ip: str | None
    username: str | None
    asset_id: str | None
    severity: Severity
    message: str | None
    raw: dict[str, Any]
    normalized_fields: dict[str, Any] = Field(default_factory=dict)


class UniversalSystemEvent(BaseModel):
    """Domain-neutral input contract for any monitored system."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    system_id: str
    system_type: str = "generic"
    event_type: str
    severity: Severity = Severity.info
    actor: str | None = None
    object_id: str | None = None
    source_address: str | None = None
    target_address: str | None = None
    message: str | None = None
    metrics: dict[str, float] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class Enrichment(BaseModel):
    geoip: dict[str, Any] = Field(default_factory=dict)
    whois: dict[str, Any] = Field(default_factory=dict)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    asset_context: dict[str, Any] = Field(default_factory=dict)


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Prediction(BaseModel):
    prediction_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    probability: float = Field(ge=0, le=1)
    risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    threat_class: str
    confidence: float = Field(ge=0, le=1)
    explanations: list[str]
    recommendations: list[str]
    normalized_event: NormalizedEvent
    enrichment: Enrichment


class WebhookPayload(BaseModel):
    events: list[EventIn] | None = None
    event: EventIn | None = None
