"""Organisations, users, and server-side sessions."""
from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import ROLES, Organisation, PasswordReset, SessionToken, User, now

LOCK_AFTER_FAILURES = 5
LOCK_MINUTES = 15
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


def issue_session(
    db: Session,
    user: User,
    scope: str = "full",
    hours: int = 12,
    client_host: str | None = None,
) -> str:
    raw = secrets.token_urlsafe(32)
    db.add(
        SessionToken(
            id=uuid.uuid4().hex,
            user_id=user.id,
            token_hash=hashlib.sha256(raw.encode()).hexdigest(),
            scope=scope,
            expires_at=now() + timedelta(hours=hours),
            client_host=client_host,
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


def list_sessions(db: Session, user_id: str, current_raw: str | None) -> list[dict]:
    digest = hashlib.sha256(current_raw.encode()).hexdigest() if current_raw else ""
    rows = list(
        db.scalars(
            select(SessionToken).where(SessionToken.user_id == user_id).order_by(SessionToken.created_at.desc())
        )
    )
    return [
        {
            "id": row.id,
            "scope": row.scope,
            "client_host": row.client_host,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "revoked": row.revoked_at is not None,
            "current": row.token_hash == digest,
        }
        for row in rows
    ]


def revoke_session_id(db: Session, session_id: str, user_id: str) -> bool:
    row = db.get(SessionToken, session_id)
    if row is None or row.user_id != user_id or row.revoked_at is not None:
        return False
    row.revoked_at = now()
    db.flush()
    return True


def revoke_token(db: Session, raw_token: str) -> bool:
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    session = db.scalar(select(SessionToken).where(SessionToken.token_hash == digest))
    if session is None or session.revoked_at is not None:
        return False
    session.revoked_at = now()
    db.flush()
    return True


def lookup_user(db: Session, organisation_id: str, email: str) -> User | None:
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
        return user
    return None


def account_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    return aware(user.locked_until) > now()


def register_login_failure(user: User) -> None:
    user.failed_attempts = int(user.failed_attempts or 0) + 1
    if user.failed_attempts >= LOCK_AFTER_FAILURES:
        user.locked_until = now() + timedelta(minutes=LOCK_MINUTES)


def clear_login_failures(user: User) -> None:
    user.failed_attempts = 0
    user.locked_until = None


def issue_recovery_codes(user: User, count: int = 8) -> list[str]:
    codes = [secrets.token_hex(4) for _ in range(count)]
    user.recovery_hashes = json.dumps([hashlib.sha256(code.encode()).hexdigest() for code in codes])
    return codes


def consume_recovery_code(user: User, code: str | None) -> bool:
    if not code or not user.recovery_hashes:
        return False
    try:
        hashes = json.loads(user.recovery_hashes)
    except json.JSONDecodeError:
        return False
    if not isinstance(hashes, list):
        return False
    digest = hashlib.sha256(code.strip().encode()).hexdigest()
    if digest not in hashes:
        return False
    hashes.remove(digest)
    user.recovery_hashes = json.dumps(hashes)
    return True


def revoke_user_sessions(db: Session, user_id: str, keep_hash: str | None = None) -> int:
    rows = list(
        db.scalars(
            select(SessionToken).where(SessionToken.user_id == user_id, SessionToken.revoked_at.is_(None))
        )
    )
    moment = now()
    revoked = 0
    for row in rows:
        if keep_hash and row.token_hash == keep_hash:
            continue
        row.revoked_at = moment
        revoked += 1
    return revoked


def issue_password_reset(db: Session, user: User, hours: int = 1) -> str:
    raw = secrets.token_urlsafe(32)
    db.add(
        PasswordReset(
            id=uuid.uuid4().hex,
            user_id=user.id,
            token_hash=hashlib.sha256(raw.encode()).hexdigest(),
            expires_at=now() + timedelta(hours=hours),
        )
    )
    db.flush()
    return raw


def consume_password_reset(db: Session, token: str, password: str) -> User | None:
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = db.scalar(select(PasswordReset).where(PasswordReset.token_hash == digest))
    if row is None or row.used_at is not None or aware(row.expires_at) <= now():
        return None
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    user.password_hash = hash_password(password)
    clear_login_failures(user)
    row.used_at = now()
    revoke_user_sessions(db, user.id)
    db.flush()
    return user


def authenticate_password(db: Session, organisation_id: str, email: str, password: str) -> User | None:
    user = lookup_user(db, organisation_id, email)
    if user is None or account_locked(user):
        return None
    if verify_password(password.strip(), user.password_hash):
        return user
    return None
