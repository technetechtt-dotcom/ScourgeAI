"""Deterministic specialist agents. None of them call a language model."""
from __future__ import annotations

from types import SimpleNamespace

from app import engine as rules
from app.adapters import UNVERIFIED_PLATFORM_FEATURES
from app.agents.base import SAFE_RECOMMENDATIONS, AgentResult, AgentSpec
from app.copilot import build_brief
from app.correlation import correlate_guardian
from app.vehicle import summarise


def _spec(name: str, responsibilities: list[str], tools: list[str]) -> AgentSpec:
    return AgentSpec(
        name=name,
        responsibilities=responsibilities,
        input_schema={"type": "object"},
        output_schema={"type": "object", "required": ["confidence"]},
        allowed_tools=tools,
    )


class ThreatIntelligenceAgent:
    spec = _spec(
        "threat_intelligence",
        ["Apply deterministic risk rules to stored events.", "Do not invent a criminal verdict."],
        ["read_events", "rules_assess"],
    )

    def run(self, ctx: dict) -> AgentResult:
        try:
            outcome = rules.assess(ctx["events"])
        except Exception as exc:
            return AgentResult(self.spec.name, "error", "UNAVAILABLE", ["Rules engine unavailable."], {}, str(exc))
        return AgentResult(
            self.spec.name,
            "completed",
            outcome["confidence"],
            list(outcome["unknowns"]),
            {
                "risk_level": outcome["risk_level"],
                "inferred": outcome["inferred"],
                "recommendation": outcome["recommendation"],
            },
        )


class IncidentCopilotAgent:
    spec = _spec(
        "incident_copilot",
        ["Produce a source-linked brief from stored rows.", "Do not call a language model."],
        ["read_incident", "read_events", "read_assessment"],
    )

    def run(self, ctx: dict) -> AgentResult:
        assessment = ctx.get("assessment")
        if assessment is None and ctx.get("outcome"):
            outcome = ctx["outcome"]
            assessment = SimpleNamespace(
                observed=outcome["observed"],
                inferred=outcome["inferred"],
                unknowns=outcome["unknowns"],
            )
        brief = build_brief(ctx["incident"], ctx["events"], assessment, ctx.get("recommendations") or [])
        return AgentResult(
            self.spec.name,
            "completed",
            "TEMPLATE",
            list(brief["uncertainties"]),
            {"summary": brief["summary"], "llm_enabled": False, "source_event_ids": brief["source_event_ids"]},
        )


class GuardianSafetyAgent:
    spec = _spec(
        "guardian_safety",
        [
            "Record Guardian SOS, journey, device, acknowledgement, and responder-status events.",
            "Never suppress or delay an explicit SOS because another signal is ambiguous.",
        ],
        ["read_events"],
    )

    def run(self, ctx: dict) -> AgentResult:
        summary = correlate_guardian(ctx["events"])
        uncertainty = ["Operating-system SOS features are not assumed: " + ", ".join(UNVERIFIED_PLATFORM_FEATURES)]
        status = "completed"
        if summary["explicit_sos"] and ctx.get("outcome", {}).get("risk_level") not in (None, "EMERGENCY"):
            status = "blocked"
            uncertainty.append("A non-emergency label was refused because an explicit SOS is present.")
        return AgentResult(
            self.spec.name,
            status,
            "CONFIRMED_TRIGGER" if summary["explicit_sos"] else "INSUFFICIENT",
            uncertainty,
            {**summary, "suppressed": False},
        )


class ArxVigilVehicleTrustAgent:
    spec = _spec(
        "arxvigil_vehicle_trust",
        [
            "Classify JamShield telemetry as missing, contradictory, or a client/hardware claim.",
            "Observe backup-tracker reports. Do not activate hardware or immobilise a vehicle.",
        ],
        ["read_events", "vehicle_trust"],
    )

    def run(self, ctx: dict) -> AgentResult:
        summary = summarise(ctx["events"])
        if summary["backup_policy"]["activated_by_backend"] is not False:
            return AgentResult(
                self.spec.name,
                "blocked",
                "UNAVAILABLE",
                ["Backend activation flag was refused."],
                {"immobilisation": "not_available"},
                "activated_by_backend must stay false",
            )
        return AgentResult(
            self.spec.name,
            "completed",
            "RULE_MATCH" if summary["data_quality"] != "missing" else "INSUFFICIENT",
            ["Hardware state is only as complete as the events received."],
            summary,
        )


class EvidenceIntelligenceAgent:
    spec = _spec(
        "evidence_intelligence",
        ["List evidence hashes linked to the incident.", "Refuse any request to modify evidence."],
        ["read_evidence"],
    )

    def run(self, ctx: dict) -> AgentResult:
        if ctx.get("requested_action") == "modify_evidence":
            return AgentResult(
                self.spec.name,
                "blocked",
                "UNAVAILABLE",
                ["Evidence mutation is forbidden."],
                {"modified": False},
                "modify_evidence blocked",
            )
        refs = ctx.get("evidence") or []
        return AgentResult(
            self.spec.name,
            "completed",
            "HASH_LINKED" if refs else "INSUFFICIENT",
            ["A hash shows the stored payload bytes. It does not prove a physical event."],
            {"evidence": refs, "modified": False},
        )


class SearchLocationAgent:
    spec = _spec(
        "search_location",
        ["Match a query against event ids, types, and subject ids already loaded for one tenant."],
        ["read_events"],
    )

    def run(self, ctx: dict) -> AgentResult:
        query = (ctx.get("query") or "").lower()
        matches = []
        for event in ctx.get("events") or []:
            haystack = f"{event.id} {event.event_type} {event.subject_id}".lower()
            if query and query in haystack:
                matches.append({"event_id": event.id, "event_type": event.event_type, "subject_id": event.subject_id})
        return AgentResult(
            self.spec.name,
            "completed",
            "MATCHED" if matches else "INSUFFICIENT",
            ["Search does not leave this tenant or invent locations."],
            {"matches": matches, "query": ctx.get("query")},
        )


class OperationsIntelligenceAgent:
    spec = _spec(
        "operations_intelligence",
        ["Report counts that were computed from stored rows for one tenant and product."],
        ["read_counts"],
    )

    def run(self, ctx: dict) -> AgentResult:
        counts = ctx.get("counts") or {}
        return AgentResult(
            self.spec.name,
            "completed",
            "COUNTED",
            ["Counts are of stored records, not of a live field deployment."],
            {"counts": counts, "simulated": False},
        )


class AIGovernanceAgent:
    spec = _spec(
        "ai_governance",
        [
            "Allow only known human-review recommendations.",
            "Block dispatch, SOS suppression, immobilisation, evidence modification, and other irreversible safety actions.",
        ],
        ["read_recommendation"],
    )

    def run(self, ctx: dict) -> AgentResult:
        action = ctx.get("proposed_action")
        if action is None:
            return AgentResult(self.spec.name, "completed", "NOT_APPLICABLE", [], {"allowed": True, "action": None})
        lowered = action.lower()
        blocked_word = any(
            token in lowered
            for token in ("immobil", "suppress sos", "modify evidence", "delete evidence", "dispatch responder")
        )
        if action in SAFE_RECOMMENDATIONS and not blocked_word:
            return AgentResult(
                self.spec.name,
                "completed",
                "ALLOWLIST",
                ["The text is a suggestion for a person. It does not execute an action."],
                {"allowed": True, "action": action, "executed": False},
            )
        return AgentResult(
            self.spec.name,
            "blocked",
            "BLOCKED",
            ["The proposed action is not on the allowlist."],
            {"allowed": False, "action": action, "executed": False},
            "blocked by governance",
        )


AGENTS = {
    agent.spec.name: agent
    for agent in (
        ThreatIntelligenceAgent(),
        IncidentCopilotAgent(),
        GuardianSafetyAgent(),
        ArxVigilVehicleTrustAgent(),
        EvidenceIntelligenceAgent(),
        SearchLocationAgent(),
        OperationsIntelligenceAgent(),
        AIGovernanceAgent(),
    )
}
