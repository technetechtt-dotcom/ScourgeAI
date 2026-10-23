"""Queries that always include the tenant id."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Incident


class TenantScope:
    def __init__(self, db: Session, tenant_id: str, product: str | None = None):
        if not tenant_id:
            raise ValueError("tenant_id is required")
        self.db = db
        self.tenant_id = tenant_id
        self.product = product

    def incidents(self, limit: int = 100):
        query = select(Incident).where(Incident.tenant_id == self.tenant_id)
        if self.product:
            query = query.where(Incident.product == self.product)
        return list(self.db.scalars(query.order_by(Incident.created_at.desc()).limit(limit)))

    def incident(self, incident_id: str) -> Incident | None:
        row = self.db.get(Incident, incident_id)
        if row is None or row.tenant_id != self.tenant_id:
            return None
        if self.product and row.product != self.product:
            return None
        return row
