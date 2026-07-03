from app.models import EventIn, NormalizedEvent


EVENT_ALIASES = {
    "4625": "auth_failed",
    "4624": "auth_success",
    "4688": "process_started",
    "syslog.auth.failed": "auth_failed",
    "syslog.ssh.failed": "auth_failed",
    "waf.attack": "web_attack",
    "waf.block": "web_attack_blocked",
}


def normalize_event(event: EventIn) -> NormalizedEvent:
    raw_event_id = str(event.raw.get("event.id") or event.raw.get("event_id") or "")
    event_type = EVENT_ALIASES.get(raw_event_id, EVENT_ALIASES.get(event.event_type, event.event_type))

    normalized_fields = {
        "source_product": event.raw.get("product") or event.source,
        "original_event_type": event.event_type,
        "raw_event_id": raw_event_id or None,
    }

    return NormalizedEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        vendor=event.source,
        event_type=event_type,
        src_ip=event.src_ip or event.raw.get("src_ip") or event.raw.get("source.ip"),
        dst_ip=event.dst_ip or event.raw.get("dst_ip") or event.raw.get("destination.ip"),
        username=event.username or event.raw.get("user.name") or event.raw.get("username"),
        asset_id=event.asset_id or event.raw.get("asset.id") or event.raw.get("host.name"),
        severity=event.severity,
        message=event.message,
        raw=event.raw,
        normalized_fields=normalized_fields,
    )

