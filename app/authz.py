"""Backend authorisation. Client secrets stay product-scoped. User tokens stay tenant-scoped."""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .accounts import user_for_token
from .metrics import increment
from .models import ROLES
from .oidc import verify_token
from .security import client_secrets, safe_compare


@dataclass
class Principal:
    tenant_id: str
    product: str
    actor: str
    role: str
    method: str
    user_id: str | None = None


def resolve_principal(
    db: Session,
    tenant_id: str,
    product: str,
    authorization: str | None,
    client_secret: str | None,
) -> Principal:
    if authorization:
        if not authorization.lower().startswith("bearer "):
            increment("scourgeai_auth_failures_total")
            raise HTTPException(401, "Unauthorized")
        raw = authorization.split(" ", 1)[1].strip()
        user = user_for_token(db, raw, scope="full")
        if user is None and raw.count(".") == 2:
            claims = verify_token(raw)
            organisation = str(claims.get("organisation_id") or "") if claims else ""
            role = str(claims.get("role") or "") if claims else ""
            actor = str(claims.get("email") or claims.get("sub") or "") if claims else ""
            if claims and role in ROLES and actor and organisation == tenant_id:
                return Principal(
                    tenant_id=tenant_id,
                    product=product,
                    actor=actor,
                    role=role,
                    method="oidc",
                    user_id=None,
                )
            if claims and organisation and organisation != tenant_id:
                increment("scourgeai_auth_failures_total")
                raise HTTPException(403, "Forbidden")
        if user is None:
            increment("scourgeai_auth_failures_total")
            raise HTTPException(401, "Unauthorized")
        if user.organisation_id != tenant_id:
            increment("scourgeai_auth_failures_total")
            raise HTTPException(403, "Forbidden")
        return Principal(
            tenant_id=tenant_id,
            product=product,
            actor=user.email,
            role=user.role,
            method="bearer",
            user_id=user.id,
        )
    expected = client_secrets().get(f"{tenant_id}:{product}")
    if not expected or not client_secret or not safe_compare(expected, client_secret):
        increment("scourgeai_auth_failures_total")
        raise HTTPException(401, "Unauthorized")
    return Principal(
        tenant_id=tenant_id,
        product=product,
        actor=f"client:{product}",
        role="service",
        method="client_secret",
    )


def require(principal: Principal, *roles: str) -> None:
    if principal.role not in roles:
        raise HTTPException(403, "Forbidden")


# Developer is the platform role: every human action, plus maintenance.
ACCOUNT_ROLES = ("administrator", "developer")
REVIEW_ROLES = ("service", "supervisor", "administrator", "developer")
STATUS_ROLES = ("supervisor", "administrator", "developer")
MAINTAINER_ROLES = ("developer",)
PERMISSIONS = {
    "records.read": ("administrator", "supervisor", "operator", "developer", "service"),
    "users.manage": ACCOUNT_ROLES,
    "incidents.update": STATUS_ROLES,
    "recommendations.review": REVIEW_ROLES,
    "platform.maintain": MAINTAINER_ROLES,
    "security.monitor": ("supervisor", "administrator", "developer"),
}


def require_permission(principal: Principal, permission: str) -> None:
    require(principal, *PERMISSIONS[permission])
