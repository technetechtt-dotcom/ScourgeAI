"""SQLite backup API and PostgreSQL dump command construction.

PostgreSQL commands are returned for an operator to run. This module does not
invent a successful restore.
"""
from __future__ import annotations

import sqlite3
from urllib.parse import urlparse


def sqlite_path(url: str) -> str:
    if not url.startswith("sqlite:///"):
        raise ValueError("Not a SQLite URL")
    return url[len("sqlite:///") :]


def backup_sqlite(source_path: str, destination_path: str) -> None:
    source = sqlite3.connect(source_path)
    destination = sqlite3.connect(destination_path)
    try:
        with destination:
            source.backup(destination)
    finally:
        source.close()
        destination.close()


def restore_sqlite(backup_path: str, destination_path: str) -> None:
    backup_sqlite(backup_path, destination_path)


def postgres_backup_command(database_url: str, output_path: str) -> list[str]:
    parsed = urlparse(database_url.replace("postgresql+psycopg", "postgresql", 1))
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ValueError("Not a PostgreSQL URL")
    database = (parsed.path or "/techne").lstrip("/")
    command = ["pg_dump", "--format=custom", "--file", output_path, database]
    if parsed.hostname:
        command[1:1] = ["--host", parsed.hostname]
    if parsed.port:
        command[1:1] = ["--port", str(parsed.port)]
    if parsed.username:
        command[1:1] = ["--username", parsed.username]
    return command


def postgres_restore_command(database_url: str, input_path: str) -> list[str]:
    parsed = urlparse(database_url.replace("postgresql+psycopg", "postgresql", 1))
    database = (parsed.path or "/techne").lstrip("/")
    command = ["pg_restore", "--clean", "--if-exists", "--dbname", database, input_path]
    if parsed.hostname:
        command[1:1] = ["--host", parsed.hostname]
    if parsed.port:
        command[1:1] = ["--port", str(parsed.port)]
    if parsed.username:
        command[1:1] = ["--username", parsed.username]
    return command
