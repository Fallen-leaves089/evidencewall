from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import canonical_json, sha256_hex, sign_payload, verify_payload
from .domain import SCHEMA_VERSION, Event, ValidationError, new_id, parse_iso8601, utc_now

MAX_BATCH_EVENTS = 500
BATCH_FIELDS = {
    "schema_version",
    "batch_id",
    "sensor_id",
    "matrix_id",
    "sequence_start",
    "sequence_end",
    "created_at",
    "events",
    "events_sha256",
    "sensor_signature",
}


def build_batch(
    events: list[Event],
    private_key: Ed25519PrivateKey,
    sensor_id: str,
    matrix_id: str,
) -> dict[str, Any]:
    if not events:
        raise ValidationError("cannot build an empty batch")
    if len(events) > MAX_BATCH_EVENTS:
        raise ValidationError(f"batch exceeds {MAX_BATCH_EVENTS} events")
    for event in events:
        event.validate()
        if not event.sensor_signature:
            raise ValidationError("event is missing its sensor signature")
        if event.sensor_id != sensor_id or event.matrix_id != matrix_id:
            raise ValidationError("event belongs to a different sensor or matrix")

    event_dicts = [event.to_dict() for event in events]
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "batch_id": new_id("batch"),
        "sensor_id": sensor_id,
        "matrix_id": matrix_id,
        "sequence_start": events[0].sequence,
        "sequence_end": events[-1].sequence,
        "created_at": utc_now(),
        "events": event_dicts,
        "events_sha256": sha256_hex(canonical_json(event_dicts)),
    }
    payload["sensor_signature"] = sign_payload(private_key, payload)
    return payload


def verify_batch(public_key: Ed25519PublicKey, payload: dict[str, Any]) -> list[Event]:
    if not isinstance(payload, dict):
        raise ValidationError("batch must be a JSON object")
    unknown = set(payload) - BATCH_FIELDS
    if unknown:
        raise ValidationError(f"unknown batch fields: {sorted(unknown)}")
    for field_name in BATCH_FIELDS:
        if field_name not in payload:
            raise ValidationError(f"batch missing required field: {field_name}")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ValidationError("unsupported batch schema_version")
    if not isinstance(payload["batch_id"], str) or not payload["batch_id"]:
        raise ValidationError("batch_id must be a non-empty string")
    if not isinstance(payload["sensor_id"], str) or not payload["sensor_id"]:
        raise ValidationError("sensor_id must be a non-empty string")
    if not isinstance(payload["matrix_id"], str) or not payload["matrix_id"]:
        raise ValidationError("matrix_id must be a non-empty string")
    if isinstance(payload["sequence_start"], bool) or not isinstance(payload["sequence_start"], int):
        raise ValidationError("sequence_start must be an integer")
    if isinstance(payload["sequence_end"], bool) or not isinstance(payload["sequence_end"], int):
        raise ValidationError("sequence_end must be an integer")
    if payload["sequence_start"] < 1 or payload["sequence_end"] < payload["sequence_start"]:
        raise ValidationError("invalid batch sequence range")
    parse_iso8601(payload["created_at"], "created_at")
    if not isinstance(payload["events"], list) or not payload["events"]:
        raise ValidationError("batch events must be a non-empty list")
    if len(payload["events"]) > MAX_BATCH_EVENTS:
        raise ValidationError(f"batch exceeds {MAX_BATCH_EVENTS} events")
    if not isinstance(payload["events_sha256"], str) or payload["events_sha256"] != sha256_hex(canonical_json(payload["events"])):
        raise ValidationError("batch events hash mismatch")
    if not isinstance(payload["sensor_signature"], str) or not payload["sensor_signature"]:
        raise ValidationError("batch is missing sensor_signature")

    signed_payload = {key: value for key, value in payload.items() if key != "sensor_signature"}
    if not verify_payload(public_key, signed_payload, payload["sensor_signature"]):
        raise ValidationError("batch signature verification failed")

    events: list[Event] = []
    previous_sequence = 0
    for raw_event in payload["events"]:
        event = Event.from_dict(raw_event)
        if event.sensor_id != payload["sensor_id"] or event.matrix_id != payload["matrix_id"]:
            raise ValidationError("event sensor/matrix does not match batch")
        if event.sequence <= previous_sequence:
            raise ValidationError("event sequences must be strictly increasing")
        if event.sequence < payload["sequence_start"] or event.sequence > payload["sequence_end"]:
            raise ValidationError("event sequence is outside batch range")
        if not event.sensor_signature:
            raise ValidationError("event is missing sensor_signature")
        if not verify_payload(public_key, event.to_signing_dict(), event.sensor_signature):
            raise ValidationError(f"event signature verification failed: {event.event_id}")
        previous_sequence = event.sequence
        events.append(event)
    if events[0].sequence != payload["sequence_start"] or events[-1].sequence != payload["sequence_end"]:
        raise ValidationError("batch sequence range does not match its events")
    return events

