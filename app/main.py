from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI

from app.adapters import adapter_registry
from app.models import EventIn, NormalizedEvent, Prediction, UniversalSystemEvent, WebhookPayload
from app.pipeline import process_event, process_normalized_event, process_system_event
from app.rusiem_internal import RuSIEMNormalizedEvent, RuSIEMPredictionResult, rusiem_internal_adapter
from app.store import prediction_store
from app.syslog_server import start_syslog_server

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Incident Prediction Module",
    version="0.1.0",
    description="Prototype module for predictive incident scoring and RuSIEM integration.",
)

_syslog_transport: asyncio.DatagramTransport | None = None


@app.on_event("startup")
async def startup() -> None:
    global _syslog_transport
    _syslog_transport = await start_syslog_server()


@app.on_event("shutdown")
async def shutdown() -> None:
    if _syslog_transport:
        _syslog_transport.close()


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/events", response_model=Prediction)
def ingest_event(event: EventIn) -> Prediction:
    prediction = process_event(event)
    prediction_store.add(prediction)
    return prediction


@app.post("/api/v1/events/normalized", response_model=Prediction)
def ingest_normalized_event(event: NormalizedEvent) -> Prediction:
    prediction = process_normalized_event(event)
    prediction_store.add(prediction)
    return prediction


@app.post("/api/v1/systems/events", response_model=Prediction)
def ingest_system_event(event: UniversalSystemEvent) -> Prediction:
    prediction = process_system_event(event)
    prediction_store.add(prediction)
    return prediction


@app.get("/api/v1/systems/adapters", response_model=list[str])
def system_adapters() -> list[str]:
    return adapter_registry.registered_types()


@app.post("/api/v1/rusiem/internal/events", response_model=RuSIEMPredictionResult)
def ingest_rusiem_internal_event(event: RuSIEMNormalizedEvent) -> RuSIEMPredictionResult:
    return rusiem_internal_adapter.process_internal_event(event)


@app.post("/api/v1/webhook/rusiem", response_model=list[Prediction])
def ingest_webhook(payload: WebhookPayload) -> list[Prediction]:
    events = payload.events or ([payload.event] if payload.event else [])
    predictions = [process_event(event) for event in events]
    for prediction in predictions:
        prediction_store.add(prediction)
    return predictions


@app.get("/api/v1/predictions/recent", response_model=list[Prediction])
def recent_predictions(limit: int = 50) -> list[Prediction]:
    return prediction_store.recent(limit)
