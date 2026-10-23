"""Operator console. Every figure comes from the API. Nothing here dispatches help or commands a vehicle."""
from __future__ import annotations

import argparse
import os
import shutil

from app.backup import backup_sqlite, postgres_backup_command, postgres_restore_command, restore_sqlite, sqlite_path
from app.db import database_url


def main() -> None:
    parser = argparse.ArgumentParser(description="Backup or restore the ScourgeAI database")
    parser.add_argument("action", choices=("backup", "restore"))
    parser.add_argument("path")
    parser.add_argument("--execute-postgres", action="store_true")
    args = parser.parse_args()
    url = database_url()
    if url.startswith("sqlite"):
        source = sqlite_path(url)
        if args.action == "backup":
            backup_sqlite(source, args.path)
        else:
            restore_sqlite(args.path, source)
        print(args.action + " complete for sqlite")
        return
    command = postgres_backup_command(url, args.path) if args.action == "backup" else postgres_restore_command(url, args.path)
    print(" ".join(command))
    print("Set PGPASSWORD in the environment. The password is not placed in this command.")
    if not args.execute_postgres:
        print("Not executed. Pass --execute-postgres to run it if the client tool is installed.")
        return
    tool = command[0]
    if shutil.which(tool) is None:
        raise SystemExit(f"{tool} is not installed")
    env = os.environ.copy()
    raise SystemExit(__import__("subprocess").call(command, env=env))


if __name__ == "__main__":
    main()
