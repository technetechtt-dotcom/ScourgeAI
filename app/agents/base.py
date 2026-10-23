"""Shared agent types. Agents return data. They do not receive a database session."""
from __future__ import annotations

from dataclasses import dataclass, field


FORBIDDEN_AUTONOMOUS_ACTIONS = (
    "dispatch_responders",
    "suppress_sos",
    "activate_immobilisation",
    "modify_evidence",
    "irreversible_safety_decision",
)

SAFE_RECOMMENDATIONS = {
    "Follow emergency escalation policy and contact authorised responders.",
    "Operator should verify independent device evidence and determine escalation.",
    "Inspect device health and seek corroborating evidence.",
}


@dataclass
class AgentSpec:
    name: str
    responsibilities: list[str]
    input_schema: dict
    output_schema: dict
    allowed_tools: list[str]
    forbidden_actions: tuple[str, ...] = field(default_factory=lambda: FORBIDDEN_AUTONOMOUS_ACTIONS)


@dataclass
class AgentResult:
    agent_name: str
    status: str
    confidence: str
    uncertainty: list[str]
    output: dict
    error: str | None = None
