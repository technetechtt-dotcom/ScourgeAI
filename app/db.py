"""Database engine. SQLite remains the default for local runs and tests.

PostgreSQL uses a QueuePool. The URL is read when the process starts so tests
can point DATABASE_URL at a disposable file before importing the app.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

DEFAULT_URL = "sqlite:///./techne.db"


def database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_URL)


def build_engine(url: str | None = None):
    url = url or database_url()
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False}, pool_pre_ping=True)
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=int(os.environ.get("DB_POOL_SIZE", "5")),
        max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "10")),
        pool_timeout=int(os.environ.get("DB_POOL_TIMEOUT", "30")),
    )


engine = build_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def db_session():
    with SessionLocal() as session:
        yield session
