from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.models import NormalizedEvent, UniversalSystemEvent


class SystemAdapter(ABC):
    """Converts a source-specific event to the shared prediction schema."""

    name = "generic"

    @abstractmethod
    def to_normalized_event(self, event: UniversalSystemEvent) -> NormalizedEvent:
        raise NotImplementedError


class GenericSystemAdapter(SystemAdapter):
    name = "generic"

    def to_normalized_event(self, event: UniversalSystemEvent) -> NormalizedEvent:
        normalized_fields: dict[str, Any] = {
            "system.id": event.system_id,
            "system.type": event.system_type,
            "source.adapter": self.name,
            "actor": event.actor,
            "object.id": event.object_id,
            "metrics": event.metrics,
            **event.attributes,
        }

        raw = {
            **event.raw,
            "metrics": event.metrics,
            "attributes": event.attributes,
        }

        return NormalizedEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            vendor=event.system_id,
            event_type=event.event_type,
            src_ip=event.source_address,
            dst_ip=event.target_address,
            username=event.actor,
            asset_id=event.object_id or event.system_id,
            severity=event.severity,
            message=event.message,
            raw=raw,
            normalized_fields=normalized_fields,
        )


class SecuritySystemAdapter(GenericSystemAdapter):
    name = "security"

    EVENT_ALIASES = {
        "login_failed": "auth_failed",
        "login_success": "auth_success",
        "blocked_http_attack": "web_attack_blocked",
        "http_attack": "web_attack",
        "privilege_change": "privilege_escalation",
    }

    def to_normalized_event(self, event: UniversalSystemEvent) -> NormalizedEvent:
        normalized = super().to_normalized_event(event)
        normalized.event_type = self.EVENT_ALIASES.get(event.event_type, event.event_type)
        normalized.normalized_fields["source.adapter"] = self.name
        normalized.normalized_fields["domain"] = "security"
        return normalized


class OpsSystemAdapter(GenericSystemAdapter):
    name = "ops"

    EVENT_ALIASES = {
        "cpu_spike": "resource_anomaly",
        "memory_spike": "resource_anomaly",
        "service_restart": "service_instability",
        "deployment_failed": "change_failure",
    }

    def to_normalized_event(self, event: UniversalSystemEvent) -> NormalizedEvent:
        normalized = super().to_normalized_event(event)
        normalized.event_type = self.EVENT_ALIASES.get(event.event_type, event.event_type)
        normalized.normalized_fields["source.adapter"] = self.name
        normalized.normalized_fields["domain"] = "operations"
        return normalized


class AdapterRegistry:
    def __init__(self) -> None:
        self._fallback = GenericSystemAdapter()
        self._adapters: dict[str, SystemAdapter] = {
            self._fallback.name: self._fallback,
            SecuritySystemAdapter.name: SecuritySystemAdapter(),
            OpsSystemAdapter.name: OpsSystemAdapter(),
        }

    def get(self, system_type: str) -> SystemAdapter:
        return self._adapters.get(system_type.lower(), self._fallback)

    def registered_types(self) -> list[str]:
        return sorted(self._adapters)


adapter_registry = AdapterRegistry()
