"""Live PostgreSQL check. Skipped unless TIC_POSTGRES_URL is set."""
import os

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.skipif(not os.environ.get("TIC_POSTGRES_URL"), reason="TIC_POSTGRES_URL is not set")


def test_postgres_accepts_a_transaction():
    from app.db import build_engine
    from app.models import Base, Organisation
    from sqlalchemy.orm import Session

    url = os.environ["TIC_POSTGRES_URL"]
    database = build_engine(url)
    Base.metadata.create_all(database)
    try:
        assert database.dialect.name == "postgresql"
        assert database.pool.size() == int(os.environ.get("DB_POOL_SIZE", "5"))
        with database.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar() == 1
        with Session(database) as session:
            session.merge(Organisation(id="pg-live-probe", name="PostgreSQL probe"))
            session.commit()
            row = session.get(Organisation, "pg-live-probe")
            assert row is not None
            assert row.name == "PostgreSQL probe"
            session.delete(row)
            session.commit()
    finally:
        database.dispose()
