from __future__ import annotations

import asyncio
import logging

from app.config import settings
from app.models import EventIn, Severity
from app.pipeline import process_event
from app.store import prediction_store

logger = logging.getLogger(__name__)


class SyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        message = data.decode("utf-8", errors="replace").strip()
        event = EventIn(
            source="syslog",
            event_type=_guess_event_type(message),
            src_ip=addr[0],
            severity=_guess_severity(message),
            message=message,
            raw={"syslog": message, "transport": "udp", "sender": f"{addr[0]}:{addr[1]}"},
        )
        prediction = process_event(event)
        prediction_store.add(prediction)
        logger.info("Processed syslog event %s risk=%s", event.event_id, prediction.risk_score)


async def start_syslog_server() -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        SyslogProtocol,
        local_addr=(settings.syslog_host, settings.syslog_port),
    )
    logger.info("Syslog UDP listener started on %s:%s", settings.syslog_host, settings.syslog_port)
    return transport


def _guess_event_type(message: str) -> str:
    lowered = message.lower()
    if "failed password" in lowered or "authentication failure" in lowered:
        return "auth_failed"
    if "accepted password" in lowered or "session opened" in lowered:
        return "auth_success"
    if "sql injection" in lowered or "xss" in lowered or "waf" in lowered:
        return "web_attack"
    return "unknown"


def _guess_severity(message: str) -> Severity:
    lowered = message.lower()
    if "critical" in lowered or "attack" in lowered:
        return Severity.high
    if "failed" in lowered or "warning" in lowered:
        return Severity.medium
    return Severity.info

