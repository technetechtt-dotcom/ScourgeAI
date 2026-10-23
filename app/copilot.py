"""Deterministic, evidence-grounded incident brief. No external language model."""
from __future__ import annotations

LLM_STATUS = "disabled_until_grounding_permissions_evaluation_and_audit_are_verified"
REFUSAL_TOKENS = (
    "immobil",
    "dispatch",
    "suppress",
    "ignore previous",
    "ignore all",
    "delete evidence",
    "modify evidence",
)


def _ordered(events):
    return sorted(events, key=lambda event: (event.occurred_at, event.id))


def build_brief(incident, events, assessment, recommendations):
    ordered = _ordered(events)
    latest = ordered[-1] if ordered else None
    emergency = incident.incident_type == "EXPLICIT_SOS"
    facts = [] if not assessment else list(assessment.observed)
    predictions = [] if not assessment else list(assessment.inferred)
    uncertainties = [] if not assessment else list(assessment.unknowns)
    explanations = [
        {
            "statement": f"{item.get('signal')} recorded",
            "source_event_ids": [item.get("event_id")],
        }
        for item in facts
        if isinstance(item, dict)
    ]
    timeline = [
        {
            "event_id": event.id,
            "type": event.event_type,
            "occurred_at": event.occurred_at.isoformat(),
            "payload_sha256": event.raw_sha256,
        }
        for event in ordered
    ]
    return {
        "incident_id": incident.id,
        "product": incident.product,
        "subject_id": incident.subject_id,
        "generated_by": "grounded-template-v0.3",
        "ai_generated": False,
        "llm_enabled": False,
        "llm_status": LLM_STATUS,
        "headline": "Explicit emergency trigger received" if emergency else "Security telemetry requires review",
        "current_status": incident.status,
        "risk_level": incident.severity,
        "summary": (
            f"{len(ordered)} event(s) received for this {incident.product} subject. "
            + (
                "An explicit SOS was recorded; the reason for distress has not been established."
                if emergency
                else "Available device signals have been assessed; malicious activity has not been established."
            )
        ),
        "last_observed_event": None
        if latest is None
        else {"event_id": latest.id, "type": latest.event_type, "at": latest.occurred_at.isoformat()},
        "key_observations": facts,
        "known_facts": facts,
        "inferences": predictions,
        "predictions": predictions,
        "uncertainties": uncertainties,
        "explanations": explanations,
        "timeline": timeline,
        "evidence_references": [{"event_id": event.id, "sha256": event.raw_sha256} for event in ordered],
        "recommended_actions": [
            {"id": row.id, "action": row.action, "status": row.status}
            for row in recommendations
            if row.status == "PENDING"
        ],
        "source_event_ids": [event.id for event in ordered],
        "human_review_required": True,
        "not_performed": [
            "No responder dispatched",
            "No vehicle commands issued",
            "No inference of criminal guilt",
            "No language model was called",
        ],
    }


def handover_report(incident, events, assessment, recommendations):
    brief = build_brief(incident, events, assessment, recommendations)
    return {
        "report_type": "incident_handover",
        "generated_by": "grounded-template-v0.3",
        "ai_generated": False,
        "llm_enabled": False,
        "incident_id": incident.id,
        "status": incident.status,
        "summary": brief["summary"],
        "known_facts": brief["known_facts"],
        "predictions": brief["predictions"],
        "uncertainties": brief["uncertainties"],
        "timeline": brief["timeline"],
        "evidence_references": brief["evidence_references"],
        "pending_recommendations": brief["recommended_actions"],
        "human_review_required": True,
        "not_performed": brief["not_performed"],
    }


def answer_question(incident, events, assessment, question: str) -> dict:
    text = (question or "").strip()
    base = {
        "llm_enabled": False,
        "llm_status": LLM_STATUS,
        "question": text,
        "human_review_required": True,
        "incident_id": incident.id,
    }
    lowered = text.lower()
    if any(token in lowered for token in REFUSAL_TOKENS):
        return {
            **base,
            "grounded": False,
            "answer": "This assistant cannot dispatch responders, suppress an SOS, immobilise a vehicle, or change evidence.",
            "sources": [],
        }
    if len(text) < 3:
        return {
            **base,
            "grounded": False,
            "answer": "Ask about recorded events, severity, or evidence on this incident.",
            "sources": [],
        }
    ordered = _ordered(events)
    if any(word in lowered for word in ("how many", "count", "number of events")):
        return {
            **base,
            "grounded": True,
            "answer": f"{len(ordered)} event(s) are stored on this incident.",
            "sources": [event.id for event in ordered],
        }
    if any(word in lowered for word in ("what happened", "timeline", "which events", "event types")):
        kinds = ", ".join(event.event_type for event in ordered) or "none"
        return {
            **base,
            "grounded": True,
            "answer": f"Recorded event types: {kinds}.",
            "sources": [event.id for event in ordered],
        }
    if "sos" in lowered or "emergency" in lowered or "distress" in lowered:
        matches = [
            event
            for event in ordered
            if event.event_type.startswith("sos.") or event.event_type == "panic.activated"
        ]
        if matches:
            return {
                **base,
                "grounded": True,
                "answer": "An explicit SOS or panic event is in this incident record. The cause is not established.",
                "sources": [event.id for event in matches],
            }
        return {
            **base,
            "grounded": True,
            "answer": "No explicit SOS event is stored on this incident.",
            "sources": [],
        }
    if "risk" in lowered or "severity" in lowered:
        return {
            **base,
            "grounded": True,
            "answer": f"Stored severity is {incident.severity}. This is a rules label, not a finding of guilt.",
            "sources": [event.id for event in ordered],
        }
    if assessment and "unknown" in lowered:
        unknowns = list(assessment.unknowns)
        return {
            **base,
            "grounded": True,
            "answer": " ".join(unknowns) if unknowns else "No uncertainty notes are stored.",
            "sources": [event.id for event in ordered],
        }
    return {
        **base,
        "grounded": False,
        "answer": "The stored record does not contain a sourced answer to that question.",
        "sources": [],
    }
