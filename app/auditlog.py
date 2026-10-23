"""Append-only audit helper. Callers commit the surrounding transaction."""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from .models import Audit


def record(
    db: Session,
    *,
    tenant_id: str,
    actor: str,
    action: str,
    subject: str,
    data: dict[str, Any],
    product: str | None = None,
) -> Audit:
    row = Audit(
        id=uuid.uuid4().hex,
        tenant_id=tenant_id,
        product=product,
        actor=actor,
        action=action,
        subject=subject,
        data=data,
    )
    db.add(row)
    return row
