from app.config import settings
from app.models import Enrichment, NormalizedEvent, Prediction, RiskLevel, Severity


SEVERITY_POINTS = {
    Severity.info: 3,
    Severity.low: 8,
    Severity.medium: 18,
    Severity.high: 35,
    Severity.critical: 50,
}


def score_event(
    event: NormalizedEvent,
    enrichment: Enrichment,
    sequence_features: dict[str, int | bool],
) -> Prediction:
    score = float(SEVERITY_POINTS[event.severity])
    explanations: list[str] = [f"Базовый вклад по критичности события: {event.severity.value}."]
    recommendations: list[str] = []

    if enrichment.threat_intel.get("known_bad_ip"):
        score += 25
        explanations.append("IP-адрес найден во внешнем источнике Threat Intelligence.")
        recommendations.append("Проверить все события от источника и временно ограничить сетевое взаимодействие.")

    if enrichment.threat_intel.get("tor_or_proxy"):
        score += 12
        explanations.append("Источник похож на TOR/proxy-инфраструктуру.")

    if enrichment.asset_context.get("critical_asset"):
        score += 15
        explanations.append("Целевой актив относится к критичным системам.")
        recommendations.append("Приоритизировать проверку владельцем критичного актива.")

    failed_auth = int(sequence_features.get("failed_auth_in_window", 0))
    if failed_auth >= 5:
        score += 18
        explanations.append(f"За окно анализа обнаружено {failed_auth} неуспешных попыток аутентификации.")
        recommendations.append("Проверить brute-force/password spraying и заблокировать учетную запись при подтверждении.")

    if sequence_features.get("success_after_fail"):
        score += 22
        explanations.append("Успешный вход произошел после серии неуспешных попыток.")
        recommendations.append("Проверить легитимность входа, MFA и географию источника.")

    web_attacks = int(sequence_features.get("web_attacks_in_window", 0))
    if web_attacks >= 3:
        score += 15
        explanations.append(f"Обнаружена серия web/WAF-событий: {web_attacks} за окно анализа.")
        recommendations.append("Проверить сработавшие WAF-правила и целевой URI.")

    if event.event_type in {"resource_anomaly", "service_instability", "change_failure"}:
        score += 10
        explanations.append("Detected operational instability signal from a non-security system adapter.")
        recommendations.append("Check recent changes, service health and related infrastructure metrics.")

    score = min(score, 100.0)
    probability = round(score / 100.0, 3)
    risk_level = _risk_level(score)
    threat_class = _classify_threat(event, sequence_features)
    confidence = _confidence(enrichment, sequence_features)

    if not recommendations:
        recommendations.append("Продолжить мониторинг и сопоставить событие с соседними активностями пользователя/актива.")

    return Prediction(
        event_id=event.event_id,
        probability=probability,
        risk_score=round(score, 2),
        risk_level=risk_level,
        threat_class=threat_class,
        confidence=confidence,
        explanations=explanations,
        recommendations=recommendations,
        normalized_event=event,
        enrichment=enrichment,
    )


def _risk_level(score: float) -> RiskLevel:
    if score >= 90:
        return RiskLevel.critical
    if score >= settings.high_risk_threshold:
        return RiskLevel.high
    if score >= settings.medium_risk_threshold:
        return RiskLevel.medium
    return RiskLevel.low


def _classify_threat(event: NormalizedEvent, sequence_features: dict[str, int | bool]) -> str:
    if sequence_features.get("success_after_fail"):
        return "account_compromise"
    if event.event_type in {"web_attack", "web_attack_blocked"}:
        return "web_attack"
    if event.event_type == "auth_failed":
        return "bruteforce_or_password_spraying"
    if event.event_type in {"privilege_escalation", "admin_action"}:
        return "privilege_misuse"
    if event.event_type in {"resource_anomaly", "service_instability", "change_failure"}:
        return "operational_risk"
    return "suspicious_activity"


def _confidence(enrichment: Enrichment, sequence_features: dict[str, int | bool]) -> float:
    confidence = 0.45
    if enrichment.threat_intel.get("known_bad_ip"):
        confidence += 0.2
    if int(sequence_features.get("events_in_window", 0)) >= 3:
        confidence += 0.15
    if enrichment.asset_context.get("asset_id"):
        confidence += 0.1
    return round(min(confidence, 0.95), 2)
