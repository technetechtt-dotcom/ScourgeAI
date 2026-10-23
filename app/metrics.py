"""Prometheus text exposition. Counters live in this process only."""
from __future__ import annotations

import threading

_LOCK = threading.Lock()
_COUNTERS = {
    "scourgeai_events_ingested_total": 0,
    "scourgeai_events_duplicate_total": 0,
    "scourgeai_auth_failures_total": 0,
    "scourgeai_assessment_failures_total": 0,
}


def increment(name: str, amount: int = 1) -> None:
    with _LOCK:
        _COUNTERS[name] = _COUNTERS.get(name, 0) + amount


def render() -> str:
    lines = [
        "# HELP scourgeai_events_ingested_total Accepted events",
        "# TYPE scourgeai_events_ingested_total counter",
        f"scourgeai_events_ingested_total {_COUNTERS['scourgeai_events_ingested_total']}",
        "# HELP scourgeai_events_duplicate_total Duplicate event deliveries",
        "# TYPE scourgeai_events_duplicate_total counter",
        f"scourgeai_events_duplicate_total {_COUNTERS['scourgeai_events_duplicate_total']}",
        "# HELP scourgeai_auth_failures_total Rejected authentications",
        "# TYPE scourgeai_auth_failures_total counter",
        f"scourgeai_auth_failures_total {_COUNTERS['scourgeai_auth_failures_total']}",
        "# HELP scourgeai_assessment_failures_total Rules engine failures",
        "# TYPE scourgeai_assessment_failures_total counter",
        f"scourgeai_assessment_failures_total {_COUNTERS['scourgeai_assessment_failures_total']}",
        "# HELP scourgeai_live_dispatch_enabled Live responder dispatch flag",
        "# TYPE scourgeai_live_dispatch_enabled gauge",
        "scourgeai_live_dispatch_enabled 0",
        "# HELP scourgeai_llm_enabled Language model invocation flag",
        "# TYPE scourgeai_llm_enabled gauge",
        "scourgeai_llm_enabled 0",
    ]
    return "\n".join(lines) + "\n"
