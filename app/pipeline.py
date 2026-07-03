from app.adapters import adapter_registry
from app.enrichment import enrich_event
from app.models import EventIn, NormalizedEvent, Prediction, UniversalSystemEvent
from app.normalizer import normalize_event
from app.scoring import score_event
from app.sequence import sequence_analyzer


def process_event(event: EventIn) -> Prediction:
    normalized = normalize_event(event)
    return process_normalized_event(normalized)


def process_normalized_event(normalized: NormalizedEvent) -> Prediction:
    enrichment = enrich_event(normalized)
    sequence_features = sequence_analyzer.add_and_analyze(normalized)
    return score_event(normalized, enrichment, sequence_features)


def process_system_event(event: UniversalSystemEvent) -> Prediction:
    adapter = adapter_registry.get(event.system_type)
    normalized = adapter.to_normalized_event(event)
    return process_normalized_event(normalized)
