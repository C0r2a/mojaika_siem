from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.models import NormalizedEvent


class SequenceAnalyzer:
    def __init__(self) -> None:
        self._events_by_key: dict[str, deque[NormalizedEvent]] = defaultdict(deque)

    def add_and_analyze(self, event: NormalizedEvent) -> dict[str, int | bool]:
        key = event.username or event.src_ip or event.asset_id or "global"
        bucket = self._events_by_key[key]
        bucket.append(event)
        self._evict_old(bucket, event.timestamp)

        failed_auth = sum(1 for item in bucket if item.event_type == "auth_failed")
        success_after_fail = event.event_type == "auth_success" and failed_auth >= 3
        web_attacks = sum(1 for item in bucket if item.event_type in {"web_attack", "web_attack_blocked"})
        privilege_events = sum(1 for item in bucket if item.event_type in {"privilege_escalation", "admin_action"})

        return {
            "events_in_window": len(bucket),
            "failed_auth_in_window": failed_auth,
            "success_after_fail": success_after_fail,
            "web_attacks_in_window": web_attacks,
            "privilege_events_in_window": privilege_events,
        }

    def _evict_old(self, bucket: deque[NormalizedEvent], now: datetime) -> None:
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        min_time = now - timedelta(seconds=settings.sequence_window_seconds)
        while bucket and bucket[0].timestamp < min_time:
            bucket.popleft()


sequence_analyzer = SequenceAnalyzer()

