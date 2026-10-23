"""Create the first administrator. There is no public registration endpoint."""
from __future__ import annotations

import argparse

from .accounts import create_user
from .db import SessionLocal, engine
from .schema_compat import ensure_schema


def create_admin(organisation_id: str, name: str, email: str, password: str) -> None:
    ensure_schema(engine)
    with SessionLocal() as db:
        user = create_user(db, organisation_id, email, password, "administrator")
        org = db.get(user.__class__, user.id)
        from .models import Organisation

        organisation = db.get(Organisation, organisation_id)
        if organisation and name:
            organisation.name = name
        db.commit()
        print(f"administrator created for organisation {organisation_id}: {user.email}")
        if org is None:
            raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="ScourgeAI administration")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin")
    create.add_argument("--org", required=True)
    create.add_argument("--name", default="")
    create.add_argument("--email", required=True)
    create.add_argument("--password", required=True)
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.org, args.name or args.org, args.email, args.password)


if __name__ == "__main__":
    main()
