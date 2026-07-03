from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.models import NormalizedEvent, Prediction, Severity
from app.pipeline import process_normalized_event


class RuSIEMContext(BaseModel):
    tenant_id: str | None = None
    node_id: str | None = None
    correlation_rule_id: str | None = None
    symptom_ids: list[str] = Field(default_factory=list)
    asset: dict[str, Any] = Field(default_factory=dict)
    user: dict[str, Any] = Field(default_factory=dict)
    dictionaries: dict[str, Any] = Field(default_factory=dict)


class RuSIEMNormalizedEvent(BaseModel):
    event_id: str
    event_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    severity: Severity = Severity.info
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    asset_id: str | None = None
    message: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    context: RuSIEMContext = Field(default_factory=RuSIEMContext)


class RuSIEMPredictionResult(BaseModel):
    event_id: str
    tenant_id: str | None
    node_id: str | None
    risk_score: float
    probability: float
    risk_level: str
    threat_class: str
    confidence: float
    explanation: list[str]
    recommendations: list[str]
    rusiem_fields: dict[str, Any]


class RuSIEMInternalAdapter:
    """Boundary between RuSIEM internals and the prediction engine.

    In production this adapter should be backed by RuSIEM services: normalized
    event stream, assets, users, dictionaries, symptoms and incident APIs.
    """

    def to_normalized_event(self, event: RuSIEMNormalizedEvent) -> NormalizedEvent:
        normalized_fields = {
            "tenant.id": event.context.tenant_id,
            "node.id": event.context.node_id,
            "rusiem.symptom_ids": event.context.symptom_ids,
            "rusiem.correlation_rule_id": event.context.correlation_rule_id,
            **event.fields,
        }

        return NormalizedEvent(
            event_id=event.event_id,
            timestamp=event.event_time,
            vendor="rusiem",
            event_type=event.event_type,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            username=event.username,
            asset_id=event.asset_id,
            severity=event.severity,
            message=event.message,
            raw={
                "fields": event.fields,
                "context": event.context.model_dump(mode="json"),
            },
            normalized_fields=normalized_fields,
        )

    def to_rusiem_result(
        self,
        prediction: Prediction,
        source_event: RuSIEMNormalizedEvent,
    ) -> RuSIEMPredictionResult:
        return RuSIEMPredictionResult(
            event_id=source_event.event_id,
            tenant_id=source_event.context.tenant_id,
            node_id=source_event.context.node_id,
            risk_score=prediction.risk_score,
            probability=prediction.probability,
            risk_level=prediction.risk_level.value,
            threat_class=prediction.threat_class,
            confidence=prediction.confidence,
            explanation=prediction.explanations,
            recommendations=prediction.recommendations,
            rusiem_fields={
                "prediction.id": prediction.prediction_id,
                "prediction.risk_score": prediction.risk_score,
                "prediction.probability": prediction.probability,
                "prediction.risk_level": prediction.risk_level.value,
                "prediction.threat_class": prediction.threat_class,
                "prediction.confidence": prediction.confidence,
                "prediction.explanations": prediction.explanations,
                "prediction.recommendations": prediction.recommendations,
                "source.event_id": source_event.event_id,
                "tenant.id": source_event.context.tenant_id,
                "node.id": source_event.context.node_id,
            },
        )

    def process_internal_event(self, event: RuSIEMNormalizedEvent) -> RuSIEMPredictionResult:
        normalized = self.to_normalized_event(event)
        prediction = process_normalized_event(normalized)
        return self.to_rusiem_result(prediction, event)


rusiem_internal_adapter = RuSIEMInternalAdapter()

