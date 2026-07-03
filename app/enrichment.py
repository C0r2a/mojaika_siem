from ipaddress import ip_address

from app.models import Enrichment, NormalizedEvent


HIGH_RISK_NETS = ("203.0.113.", "198.51.100.")
KNOWN_TOR_OR_PROXY = {"203.0.113.10", "198.51.100.23"}


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def enrich_event(event: NormalizedEvent) -> Enrichment:
    src_ip = event.src_ip or ""
    public_ip = bool(src_ip and not _is_private(src_ip))
    high_risk_network = any(src_ip.startswith(prefix) for prefix in HIGH_RISK_NETS)
    known_bad = src_ip in KNOWN_TOR_OR_PROXY

    return Enrichment(
        geoip={
            "src_ip_public": public_ip,
            "country": "unknown" if public_ip else "private",
            "asn": "unknown" if public_ip else "internal",
        },
        whois={
            "registrar": "unknown",
            "is_recent_domain": False,
        },
        threat_intel={
            "known_bad_ip": known_bad,
            "tor_or_proxy": src_ip in KNOWN_TOR_OR_PROXY,
            "high_risk_network": high_risk_network,
            "matched_feeds": ["prototype-feed"] if known_bad else [],
        },
        asset_context={
            "asset_id": event.asset_id,
            "critical_asset": bool(event.asset_id and any(x in event.asset_id.lower() for x in ("ad", "dc", "vpn", "fw"))),
        },
    )

