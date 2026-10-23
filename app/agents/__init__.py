"""Run agents and store an execution row. Agents do not write domain data."""
from __future__ import annotations

import hashlib
import json
import uuid

from sqlalchemy.orm import Session

from app.agents.base import AgentResult
from app.agents.specialists import AGENTS
from app.models import AgentExecution


def catalogue() -> list[dict]:
    items = []
    for agent in AGENTS.values():
        spec = agent.spec
        items.append(
            {
                "name": spec.name,
                "responsibilities": spec.responsibilities,
                "input_schema": spec.input_schema,
                "output_schema": spec.output_schema,
                "allowed_tools": spec.allowed_tools,
                "forbidden_actions": list(spec.forbidden_actions),
            }
        )
    return items


def execute(
    db: Session,
    agent_name: str,
    ctx: dict,
    *,
    tenant_id: str,
    product: str | None,
    incident_id: str | None,
) -> AgentResult:
    agent = AGENTS[agent_name]
    identity = {
        "agent": agent_name,
        "incident_id": incident_id,
        "event_ids": [getattr(event, "id", None) for event in ctx.get("events") or []],
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()
    try:
        result = agent.run(ctx)
    except Exception as exc:
        result = AgentResult(agent_name, "error", "UNAVAILABLE", ["Agent crashed."], {}, str(exc))
    db.add(
        AgentExecution(
            id=uuid.uuid4().hex,
            tenant_id=tenant_id,
            product=product,
            incident_id=incident_id,
            agent_name=result.agent_name,
            status=result.status,
            confidence=result.confidence,
            uncertainty=result.uncertainty,
            input_hash=digest,
            output=result.output,
            error=result.error,
        )
    )
    return result


def run_for_ingest(db: Session, ctx: dict, tenant_id: str, product: str, incident_id: str) -> list[AgentResult]:
    names = ["threat_intelligence", "incident_copilot", "evidence_intelligence", "ai_governance"]
    if product == "guardian":
        names.append("guardian_safety")
    if product == "arxvigil":
        names.append("arxvigil_vehicle_trust")
    results = []
    for name in names:
        try:
            results.append(
                execute(db, name, ctx, tenant_id=tenant_id, product=product, incident_id=incident_id)
            )
        except Exception as exc:
            results.append(AgentResult(name, "error", "UNAVAILABLE", ["Runner failed."], {}, str(exc)))
    return results
