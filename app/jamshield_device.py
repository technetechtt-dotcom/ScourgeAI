"""JamShield backup decision for device firmware.

The API does not import this module. A lost primary tracker is handled on the
device after 10 seconds. The cloud only records what the device reports.
"""
from __future__ import annotations

BACKUP_AFTER_SECONDS = 10


def local_backup_tracker_decision(primary_lost: bool, elapsed_seconds: float | None) -> str:
    if not primary_lost:
        return "idle"
    if elapsed_seconds is None or elapsed_seconds < BACKUP_AFTER_SECONDS:
        return "wait"
    return "activate_secondary_tracker_locally"
