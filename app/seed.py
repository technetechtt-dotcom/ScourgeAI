"""Reference rows for the model registry and local demo accounts. Idempotent."""
from __future__ import annotations

import os
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .accounts import create_user, ensure_organisation
from .models import ModelVersion

CATALOGUE = (
    ("rules", "v0.1", "rules", "Deterministic SOS and device-anomaly rules.", False),
    ("grounded-template", "v0.3", "template", "Source-linked incident brief. Language model disabled.", False),
    ("threat-intelligence-agent", "v0.3", "agent", "Reads events and applies the rules engine.", False),
    ("incident-copilot-agent", "v0.3", "agent", "Builds the deterministic brief. No external model.", False),
    ("guardian-safety-agent", "v0.3", "agent", "Classifies Guardian signals and refuses to suppress SOS.", False),
    ("arxvigil-vehicle-trust-agent", "v0.3", "agent", "Classifies JamShield telemetry. Does not immobilise.", False),
    ("evidence-intelligence-agent", "v0.3", "agent", "Lists evidence hashes. Cannot modify evidence.", False),
    ("search-location-agent", "v0.3", "agent", "Filters stored events inside one tenant.", False),
    ("operations-intelligence-agent", "v0.3", "agent", "Counts stored incidents. Does not invent statistics.", False),
    ("ai-governance-agent", "v0.3", "agent", "Blocks autonomous safety actions.", False),
)


DEMO_PASSWORD = "correct-horse-battery"
DEMO_ACCOUNTS = (
    ("demo", "ScourgeAI Demo", "operator@example.com", "operator"),
    ("demo", "ScourgeAI Demo", "supervisor@example.com", "supervisor"),
    ("demo", "ScourgeAI Demo", "admin@example.com", "administrator"),
    ("demo", "ScourgeAI Demo", "developer@example.com", "developer"),
    ("field", "Field Operations", "field.operator@example.com", "operator"),
)


def seed_demo_accounts(db: Session) -> int:
    """Create local sign-in accounts. Production does not receive these passwords."""
    if os.environ.get("TIC_ENV", "development") == "production":
        return 0
    created = 0
    for organisation_id, name, email, role in DEMO_ACCOUNTS:
        organisation = ensure_organisation(db, organisation_id, name)
        if organisation.name in ("", organisation_id):
            organisation.name = name
        try:
            create_user(db, organisation_id, email, DEMO_PASSWORD, role)
        except ValueError:
            continue
        created += 1
    return created


def register_model(
    db: Session,
    name: str,
    version: str,
    kind: str,
    status: str,
    description: str,
) -> tuple[ModelVersion, bool]:
    """Insert or update a registry row. Language-model calls stay disabled on every row."""
    existing = db.scalar(select(ModelVersion).where(ModelVersion.name == name, ModelVersion.version == version))
    if existing:
        existing.kind = kind
        existing.status = status
        existing.description = description
        existing.llm = False
        return existing, False
    row = ModelVersion(
        id=uuid.uuid4().hex,
        name=name,
        version=version,
        kind=kind,
        status=status,
        description=description,
        llm=False,
    )
    db.add(row)
    db.flush()
    return row, True


def seed_reference_data(db: Session) -> int:
    created = 0
    for name, version, kind, description, llm in CATALOGUE:
        existing = db.scalar(
            select(ModelVersion).where(ModelVersion.name == name, ModelVersion.version == version)
        )
        if existing:
            continue
        db.add(
            ModelVersion(
                id=uuid.uuid4().hex,
                name=name,
                version=version,
                kind=kind,
                status="active",
                description=description,
                llm=llm,
            )
        )
        created += 1
    return created
