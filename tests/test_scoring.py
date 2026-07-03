from datetime import datetime, timezone

from app.models import EventIn, NormalizedEvent, Severity, UniversalSystemEvent
from app.pipeline import process_event, process_normalized_event, process_system_event
from app.rusiem_internal import RuSIEMContext, RuSIEMNormalizedEvent, rusiem_internal_adapter


def test_known_bad_critical_asset_has_high_risk() -> None:
    prediction = process_event(
        EventIn(
            source="rusiem",
            event_type="auth_failed",
            src_ip="203.0.113.10",
            asset_id="srv-ad-01",
            severity=Severity.high,
            raw={"event.id": "4625"},
        )
    )

    assert prediction.risk_score >= 75
    assert prediction.threat_class == "bruteforce_or_password_spraying"
    assert prediction.explanations


def test_success_after_failed_logins_increases_risk() -> None:
    for _ in range(5):
        process_event(
            EventIn(
                source="rusiem",
                event_type="auth_failed",
                src_ip="10.0.0.10",
                username="ivanov",
                severity=Severity.medium,
            )
        )

    prediction = process_event(
        EventIn(
            source="rusiem",
            event_type="auth_success",
            src_ip="10.0.0.10",
            username="ivanov",
            severity=Severity.low,
        )
    )

    assert prediction.threat_class == "account_compromise"
    assert prediction.risk_score >= 45


def test_normalized_event_skips_raw_normalization() -> None:
    prediction = process_normalized_event(
        NormalizedEvent(
            event_id="normalized-1",
            timestamp=datetime.now(timezone.utc),
            vendor="rusiem",
            event_type="web_attack",
            src_ip="198.51.100.23",
            dst_ip="10.0.0.20",
            username=None,
            asset_id="srv-web-01",
            severity=Severity.high,
            message="WAF detected SQL injection",
            raw={"rusiem.normalized": True},
            normalized_fields={"event.category": "network", "event.action": "deny"},
        )
    )

    assert prediction.normalized_event.event_type == "web_attack"
    assert prediction.risk_score >= 60
    assert prediction.enrichment.threat_intel["known_bad_ip"] is True


def test_rusiem_internal_adapter_returns_rusiem_fields() -> None:
    result = rusiem_internal_adapter.process_internal_event(
        RuSIEMNormalizedEvent(
            event_id="rusiem-internal-1",
            event_type="auth_failed",
            src_ip="203.0.113.10",
            dst_ip="10.0.0.5",
            username="petrov",
            asset_id="srv-dc-01",
            severity=Severity.high,
            fields={"event.category": "authentication", "event.outcome": "failure"},
            context=RuSIEMContext(
                tenant_id="tenant-1",
                node_id="node-main",
                symptom_ids=["symptom-auth-failed"],
                asset={"criticality": "high"},
            ),
        )
    )

    assert result.tenant_id == "tenant-1"
    assert result.rusiem_fields["prediction.risk_score"] >= 75
    assert result.rusiem_fields["tenant.id"] == "tenant-1"


def test_universal_security_adapter_reuses_prediction_core() -> None:
    prediction = process_system_event(
        UniversalSystemEvent(
            system_id="custom-iam",
            system_type="security",
            event_type="login_failed",
            actor="sidorov",
            object_id="vpn-gateway-01",
            source_address="203.0.113.10",
            severity=Severity.high,
            attributes={"tenant.id": "tenant-2"},
        )
    )

    assert prediction.normalized_event.vendor == "custom-iam"
    assert prediction.normalized_event.event_type == "auth_failed"
    assert prediction.threat_class == "bruteforce_or_password_spraying"
    assert prediction.risk_score >= 75


def test_universal_ops_adapter_maps_to_operational_risk() -> None:
    prediction = process_system_event(
        UniversalSystemEvent(
            system_id="k8s-prod",
            system_type="ops",
            event_type="cpu_spike",
            object_id="api-node-01",
            severity=Severity.medium,
            metrics={"cpu_percent": 97.5},
        )
    )

    assert prediction.normalized_event.event_type == "resource_anomaly"
    assert prediction.threat_class == "operational_risk"
    assert prediction.normalized_event.normalized_fields["domain"] == "operations"
