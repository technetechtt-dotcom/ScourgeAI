"""Auditable, deterministic risk rules. Not an ML crime classifier."""
from __future__ import annotations

SOS_EVENTS = {
    "sos.manual",
    "sos.volume",
    "sos.safeword",
    "sos.duress",
    "sos.wearable",
    "sos.vehicle",
    "panic.activated",
}
TAMPER_EVENTS = {
    "device.power_cut",
    "device.tamper",
    "vehicle.unauthorized_movement",
    "device.primary_signal_lost",
    "device.backup_activated",
    "vehicle.position_divergence",
    "device.interference_suspected",
    "device.gnss_integrity",
}
INCOMPLETE_CONTEXT = "Telemetry and user context may be incomplete; do not infer intent or a criminal act."


def _observed(events):
    return [
        {"event_id": event.id, "signal": event.event_type, "occurred_at": event.occurred_at.isoformat()}
        for event in events
    ]


def assess(events):
    kinds = {event.event_type for event in events}
    observed = _observed(events)
    unknowns = [INCOMPLETE_CONTEXT]
    if kinds & SOS_EVENTS:
        return {
            "risk_level": "EMERGENCY",
            "confidence": "CONFIRMED_TRIGGER",
            "observed": observed,
            "inferred": ["Explicit distress trigger received. This does not establish the nature of the danger."],
            "unknowns": unknowns,
            "recommendation": "Follow emergency escalation policy and contact authorised responders.",
        }
    indicators = kinds & TAMPER_EVENTS
    if len(indicators) >= 2:
        return {
            "risk_level": "HIGH_RISK",
            "confidence": "RULE_MATCH_MULTIPLE_SIGNALS",
            "observed": observed,
            "inferred": ["Multiple different device or movement anomalies warrant investigation; theft is not confirmed."],
            "unknowns": unknowns,
            "recommendation": "Operator should verify independent device evidence and determine escalation.",
        }
    if indicators:
        return {
            "risk_level": "CONCERN",
            "confidence": "RULE_MATCH_SINGLE_SIGNAL",
            "observed": observed,
            "inferred": ["Anomaly merits review; connectivity or hardware failure remains possible."],
            "unknowns": unknowns,
            "recommendation": "Inspect device health and seek corroborating evidence.",
        }
    return {
        "risk_level": "NORMAL",
        "confidence": "INSUFFICIENT_RISK_EVIDENCE",
        "observed": observed,
        "inferred": ["No configured risk rule matched these events."],
        "unknowns": unknowns,
        "recommendation": None,
    }


def sos_fallback(events, reason: str):
    """Used when the rules engine fails. An explicit SOS is still an emergency."""
    return {
        "risk_level": "EMERGENCY",
        "confidence": "CONFIRMED_TRIGGER",
        "observed": _observed(events),
        "inferred": [
            "Explicit distress trigger received. Assessment rules were unavailable and were not allowed to suppress the SOS."
        ],
        "unknowns": [reason, INCOMPLETE_CONTEXT],
        "recommendation": "Follow emergency escalation policy and contact authorised responders.",
    }


def degraded_fallback(events, reason: str):
    return {
        "risk_level": "NORMAL",
        "confidence": "ASSESSMENT_UNAVAILABLE",
        "observed": _observed(events),
        "inferred": ["Risk rules were unavailable. No elevated risk was invented from the outage."],
        "unknowns": [reason, INCOMPLETE_CONTEXT],
        "recommendation": None,
    }
