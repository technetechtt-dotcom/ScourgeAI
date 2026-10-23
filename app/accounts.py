"""Organisations, users, and server-side sessions."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import ROLES, Organisation, SessionToken, User, now
from .passwords import hash_password, verify_password


def aware(value):
    if value is None:
        return None
    if value.tzinfo is None:
        from datetime import timezone

        return value.replace(tzinfo=timezone.utc)
    return value


def ensure_organisation(db: Session, organisation_id: str, name: str | None = None) -> Organisation:
    row = db.get(Organisation, organisation_id)
    if row:
        return row
    row = Organisation(id=organisation_id, name=name or organisation_id)
    db.add(row)
    db.flush()
    return row


def create_user(db: Session, organisation_id: str, email: str, password: str, role: str) -> User:
    if role not in ROLES:
        raise ValueError("Unknown role")
    ensure_organisation(db, organisation_id)
    normalised = email.strip().lower()
    existing = db.scalar(
        select(User).where(User.organisation_id == organisation_id, User.email == normalised)
    )
    if existing:
        raise ValueError("User already exists")
    user = User(
        id=uuid.uuid4().hex,
        organisation_id=organisation_id,
        email=normalised,
        password_hash=hash_password(password),
        role=role,
        mfa_enabled=False,
        disabled=False,
    )
    db.add(user)
    db.flush()
    return user


def update_user(
    db: Session,
    organisation_id: str,
    user_id: str,
    *,
    role: str | None = None,
    disabled: bool | None = None,
) -> User | None:
    user = db.get(User, user_id)
    if user is None or user.organisation_id != organisation_id:
        return None
    if role is not None:
        if role not in ROLES:
            raise ValueError("Unknown role")
        user.role = role
    if disabled is True:
        user.disabled = True
        moment = now()
        sessions = list(
            db.scalars(
                select(SessionToken).where(
                    SessionToken.user_id == user.id,
                    SessionToken.revoked_at.is_(None),
                )
            )
        )
        for session in sessions:
            session.revoked_at = moment
    elif disabled is False:
        user.disabled = False
    db.flush()
    return user


def issue_session(db: Session, user: User, scope: str = "full", hours: int = 12) -> str:
    raw = secrets.token_urlsafe(32)
    db.add(
        SessionToken(
            id=uuid.uuid4().hex,
            user_id=user.id,
            token_hash=hashlib.sha256(raw.encode()).hexdigest(),
            scope=scope,
            expires_at=now() + timedelta(hours=hours),
        )
    )
    db.flush()
    return raw


def user_for_token(db: Session, raw_token: str, scope: str = "full") -> User | None:
    if not raw_token:
        return None
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    session = db.scalar(select(SessionToken).where(SessionToken.token_hash == digest))
    if session is None or session.revoked_at is not None or session.scope != scope:
        return None
    if aware(session.expires_at) <= now():
        return None
    user = db.get(User, session.user_id)
    if user is None or user.disabled:
        return None
    return user


def revoke_token(db: Session, raw_token: str) -> bool:
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    session = db.scalar(select(SessionToken).where(SessionToken.token_hash == digest))
    if session is None or session.revoked_at is not None:
        return False
    session.revoked_at = now()
    db.flush()
    return True


def authenticate_password(db: Session, organisation_id: str, email: str, password: str) -> User | None:
    email_key = email.strip().lower()
    org_key = organisation_id.strip()
    organisation_ids = [org_key]
    for organisation in db.scalars(select(Organisation.id).where(func.lower(Organisation.name) == org_key.lower())):
        if organisation not in organisation_ids:
            organisation_ids.append(organisation)
    for candidate in organisation_ids:
        user = db.scalar(select(User).where(User.organisation_id == candidate, User.email == email_key))
        if user is None or user.disabled or user.role == "service":
            continue
        if verify_password(password.strip(), user.password_hash):
            return user
    return None
