"""Validate domain-specific event vocabularies. Acceptance is not a physical action."""
from __future__ import annotations

GUARDIAN_EVENTS = {
    "sos.manual",
    "sos.volume",
    "sos.safeword",
    "sos.duress",
    "sos.wearable",
    "sos.vehicle",
    "panic.activated",
    "journey.route_deviation",
    "journey.checkin_missed",
    "device.network_lost",
    "device.location_updated",
    "guardian.acknowledged",
    "device.heartbeat",
    "responder.status_updated",
}
ARXVIGIL_EVENTS = {
    "panic.activated",
    "device.power_cut",
    "device.tamper",
    "vehicle.unauthorized_movement",
    "device.primary_signal_lost",
    "device.backup_activated",
    "vehicle.position_divergence",
    "device.heartbeat",
    "device.network_lost",
    "vehicle.location_updated",
    "device.battery_low",
    "device.jscore.telemetry",
    "device.jsghost.status",
    "device.jseed.witness",
    "device.interference_suspected",
    "device.gnss_integrity",
}
ALLOWED = {"guardian": GUARDIAN_EVENTS, "arxvigil": ARXVIGIL_EVENTS}

# Operating-system features this service does not claim.
UNVERIFIED_PLATFORM_FEATURES = (
    "background microphone access",
    "hardware-button interception",
    "silent OS-level SOS capture",
)


def validate_adapter(event) -> bool:
    return event.event_type in ALLOWED[event.source_product]
