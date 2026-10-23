"""Cross-domain comparison. Products stay isolated unless a grant row exists."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CrossDomainGrant, Event


def _coords(event: Event):
    observation = (event.payload or {}).get("observation") or {}
    lat = observation.get("lat")
    lon = observation.get("lon")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        return float(lat), float(lon)
    return None


def compare_positions(left, right) -> str:
    if left is None or right is None:
        return "missing"
    if abs(left[0] - right[0]) > 0.01 or abs(left[1] - right[1]) > 0.01:
        return "contradictory"
    return "consistent"


def cross_domain_divergence(db: Session, tenant_id: str, subject_id: str) -> dict:
    grant = db.scalar(select(CrossDomainGrant).where(CrossDomainGrant.tenant_id == tenant_id))
    if grant is None:
        return {
            "status": "not_authorised",
            "compared": False,
            "event_ids": [],
            "theft_confirmed": False,
            "reason": "No explicit cross-domain grant. Guardian and ArxVigil records were not linked.",
        }
    rows = list(
        db.scalars(
            select(Event).where(Event.tenant_id == tenant_id, Event.subject_id == subject_id)
        )
    )
    guardian = [row for row in rows if row.product == "guardian"]
    arx = [row for row in rows if row.product == "arxvigil"]
    left = next((_coords(row) for row in guardian if _coords(row)), None)
    right = next((_coords(row) for row in arx if _coords(row)), None)
    quality = compare_positions(left, right)
    return {
        "status": "compared",
        "compared": True,
        "data_quality": quality,
        "event_ids": [row.id for row in rows],
        "theft_confirmed": False,
        "reason": "Position comparison is not confirmation of theft or of a criminal act.",
        "grant_purpose": grant.purpose,
    }
