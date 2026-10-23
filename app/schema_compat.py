"""Add tables and nullable-or-defaulted columns without dropping existing rows."""
from __future__ import annotations

from sqlalchemy import inspect, text

from .models import Base


def ensure_schema(engine) -> None:
    Base.metadata.create_all(engine)
    alters = [
        ("audit_log", "product", "product VARCHAR(32)"),
        ("security_events", "device_signature_verified", _bool_ddl(engine, "device_signature_verified")),
        ("security_events", "delayed", _bool_ddl(engine, "delayed")),
        ("outbox", "claimed_by", "claimed_by VARCHAR(80)"),
        ("outbox", "claimed_at", "claimed_at TIMESTAMP"),
    ]
    inspector = inspect(engine)
    names = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, column, ddl in alters:
            if table not in names:
                continue
            present = {col["name"] for col in inspector.get_columns(table)}
            if column not in present:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))
        for statement in _index_statements():
            conn.execute(text(statement))
    _widen_user_role_check(engine)


def _bool_ddl(engine, name: str) -> str:
    if engine.dialect.name == "sqlite":
        return f"{name} BOOLEAN NOT NULL DEFAULT 0"
    return f"{name} BOOLEAN NOT NULL DEFAULT false"


def _index_statements() -> list[str]:
    return [
        "CREATE INDEX IF NOT EXISTS ix_incidents_scope ON incidents (tenant_id, product, subject_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_events_incident ON security_events (incident_id)",
        "CREATE INDEX IF NOT EXISTS ix_events_tenant_product_time ON security_events (tenant_id, product, occurred_at)",
        "CREATE INDEX IF NOT EXISTS ix_audit_tenant_created ON audit_log (tenant_id, created_at)",
    ]


_ROLE_CHECK = "role in ('operator','supervisor','administrator','service','developer')"


def _widen_user_role_check(engine) -> None:
    """Existing databases keep the original role check until this widens it."""
    if engine.dialect.name == "sqlite":
        _widen_sqlite_role_check(engine)
    elif engine.dialect.name == "postgresql":
        _widen_postgres_role_check(engine)


def _widen_sqlite_role_check(engine) -> None:
    with engine.connect() as conn:
        defined = conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")).scalar()
    if not defined or "developer" in defined:
        return
    raw = engine.raw_connection()
    try:
        cursor = raw.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("BEGIN")
        cursor.execute(
            f"""
            CREATE TABLE users_role_rebuild (
                id VARCHAR(60) NOT NULL PRIMARY KEY,
                organisation_id VARCHAR(120) NOT NULL,
                email VARCHAR(254) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(32) NOT NULL,
                mfa_secret TEXT,
                mfa_enabled BOOLEAN NOT NULL,
                disabled BOOLEAN NOT NULL,
                created_at DATETIME NOT NULL,
                CONSTRAINT uq_user_org_email UNIQUE (organisation_id, email),
                CONSTRAINT ck_user_role CHECK ({_ROLE_CHECK})
            )
            """
        )
        cursor.execute(
            """
            INSERT INTO users_role_rebuild (
                id, organisation_id, email, password_hash, role, mfa_secret, mfa_enabled, disabled, created_at
            )
            SELECT id, organisation_id, email, password_hash, role, mfa_secret, mfa_enabled, disabled, created_at
            FROM users
            """
        )
        cursor.execute("DROP TABLE users")
        cursor.execute("ALTER TABLE users_role_rebuild RENAME TO users")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_users_organisation_id ON users (organisation_id)")
        raw.commit()
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        raw.close()


def _widen_postgres_role_check(engine) -> None:
    with engine.begin() as conn:
        defined = conn.execute(text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_user_role'")).scalar()
        if defined and "developer" in defined:
            return
        if defined:
            conn.execute(text("ALTER TABLE users DROP CONSTRAINT ck_user_role"))
        conn.execute(text(f"ALTER TABLE users ADD CONSTRAINT ck_user_role CHECK ({_ROLE_CHECK})"))
