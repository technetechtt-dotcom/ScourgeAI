"""Guardian correlation notes. Explicit SOS is never downgraded here."""
from __future__ import annotations

from .engine import SOS_EVENTS


def correlate_guardian(events) -> dict:
    kinds = {event.event_type for event in events}
    notes: list[str] = []
    explicit = bool(kinds & SOS_EVENTS)
    if explicit:
        notes.append("Explicit SOS is present. Correlation must not delay or suppress it.")
    if "journey.route_deviation" in kinds and "journey.checkin_missed" in kinds:
        notes.append("Route deviation and a missed check-in are both in this incident. Cause is not established.")
    if "device.network_lost" in kinds:
        notes.append("Connectivity loss is recorded. It is not treated as distress by itself.")
    if "guardian.acknowledged" in kinds:
        notes.append("A trusted-contact acknowledgement event is recorded. It does not close the incident.")
    if "responder.status_updated" in kinds:
        notes.append("A responder status update was ingested. This service did not dispatch a responder.")
    return {
        "explicit_sos": explicit,
        "event_types": sorted(kinds),
        "notes": notes,
        "platform_features_assumed": [],
    }
