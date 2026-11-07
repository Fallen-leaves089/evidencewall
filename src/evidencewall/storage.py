from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .analysis import (
    ASSOCIATION_WINDOW_SECONDS,
    analyze_events,
    event_sha256,
)
from .crypto import (
    CryptoError,
    Ed25519PrivateKey,
    canonical_json,
    load_public_key_text,
    sha256_hex,
    sign_payload,
)
from .domain import (
    CASE_STATUSES,
    CanaryDeployment,
    Case,
    Endpoint,
    EndpointMatrix,
    Event,
    ValidationError,
    format_utc,
    new_id,
    parse_iso8601,
    utc_now,
)


class StorageError(RuntimeError):
    pass


class StorageConflict(StorageError):
    pass


class SequenceError(StorageError):
    pass


_HIGHWALL_EXTERNAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$")
_HIGHWALL_EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_HIGHWALL_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_HIGHWALL_TRANSPORTS = frozenset({"tcp", "udp", "tls", "http", "https", "other"})
_HIGHWALL_FIELDS = frozenset(
    {
        "external_id",
        "event_type",
        "observed_at",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "transport",
        "method",
        "host",
        "path",
        "action",
        "rule_id",
        "severity",
        "request_sha256",
    }
)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def _json_object(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    parsed = json.loads(value)
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: str | None) -> list[Any]:
    if not value:
        return []
    parsed = json.loads(value)
    return parsed if isinstance(parsed, list) else []


def _bounded_text(value: Any, field_name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValidationError(f"{field_name} must be a non-empty string without NUL bytes")
    if len(value) > maximum:
        raise ValidationError(f"{field_name} is too long")
    return value


def _optional_text(value: Any, field_name: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, field_name, maximum)


def _optional_port(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise ValidationError(f"{field_name} must be an integer between 0 and 65535")
    return value


def _normalize_highwall_item(source: str, raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError("Highwall event must be an object")
    unknown = set(raw) - _HIGHWALL_FIELDS
    if unknown:
        raise ValidationError(f"unknown Highwall fields: {sorted(unknown)}")
    external_id = _bounded_text(raw.get("external_id"), "external_id", 128)
    if not _HIGHWALL_EXTERNAL_ID_RE.fullmatch(external_id):
        raise ValidationError("external_id contains unsupported characters")
    event_type = _bounded_text(raw.get("event_type"), "event_type", 64)
    if not _HIGHWALL_EVENT_TYPE_RE.fullmatch(event_type):
        raise ValidationError("event_type contains unsupported characters")
    observed_at = _bounded_text(raw.get("observed_at"), "observed_at", 64)
    observed_at = format_utc(parse_iso8601(observed_at, "observed_at"))

    normalized: dict[str, Any] = {
        "external_id": external_id,
        "event_type": event_type,
        "observed_at": observed_at,
    }
    source_ip = raw.get("source_ip")
    if source_ip is not None:
        _bounded_text(source_ip, "source_ip", 64)
        try:
            normalized["source_ip"] = str(ipaddress.ip_address(source_ip))
        except ValueError as exc:
            raise ValidationError("source_ip is not a valid IP address") from exc
    source_port = _optional_port(raw.get("source_port"), "source_port")
    if source_port is not None:
        normalized["source_port"] = source_port
    destination_ip = raw.get("destination_ip")
    if destination_ip is not None:
        _bounded_text(destination_ip, "destination_ip", 64)
        try:
            normalized["destination_ip"] = str(ipaddress.ip_address(destination_ip))
        except ValueError as exc:
            raise ValidationError("destination_ip is not a valid IP address") from exc
    destination_port = _optional_port(raw.get("destination_port"), "destination_port")
    if destination_port is not None:
        normalized["destination_port"] = destination_port

    transport = raw.get("transport")
    if transport is not None:
        transport = _bounded_text(transport, "transport", 16).lower()
        if transport not in _HIGHWALL_TRANSPORTS:
            raise ValidationError(f"transport must be one of {sorted(_HIGHWALL_TRANSPORTS)}")
        normalized["transport"] = transport
    method = raw.get("method")
    if method is not None:
        method = _bounded_text(method, "method", 32).upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9-]{0,31}", method):
            raise ValidationError("method contains unsupported characters")
        normalized["method"] = method
    host = raw.get("host")
    if host is not None:
        host = _bounded_text(host, "host", 255).rsplit("@", 1)[-1]
        host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if not host or any(character.isspace() for character in host):
            raise ValidationError("host is invalid")
        normalized["host"] = host
    path = raw.get("path")
    if path is not None:
        path = _bounded_text(path, "path", 1024).split("?", 1)[0].split("#", 1)[0]
        if path:
            normalized["path"] = path
    action = raw.get("action")
    if action is not None:
        action = _bounded_text(action, "action", 64)
        if not _HIGHWALL_EVENT_TYPE_RE.fullmatch(action):
            raise ValidationError("action contains unsupported characters")
        normalized["action"] = action
    rule_id = raw.get("rule_id")
    if rule_id is not None:
        normalized["rule_id"] = _bounded_text(rule_id, "rule_id", 128)
    severity = raw.get("severity")
    if severity is not None:
        severity = _bounded_text(severity, "severity", 16).lower()
        if severity not in _HIGHWALL_SEVERITIES:
            raise ValidationError(f"severity must be one of {sorted(_HIGHWALL_SEVERITIES)}")
        normalized["severity"] = severity
    request_sha256 = raw.get("request_sha256")
    if request_sha256 is not None:
        request_sha256 = _bounded_text(request_sha256, "request_sha256", 64)
        if not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
            raise ValidationError("request_sha256 must be lowercase SHA-256 hex")
        normalized["request_sha256"] = request_sha256

    normalized["source"] = source
    return normalized


def _merge_time_intervals(
    intervals: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        previous_start, previous_end = merged[-1]
        if start <= previous_end:
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return merged


class SensorStore:
    def __init__(self, path: Path, sensor_id: str, matrix_id: str, private_key: Ed25519PrivateKey):
        self.path = path
        self.sensor_id = sensor_id
        self.matrix_id = matrix_id
        self.private_key = private_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        connection = _connect(self.path)
        try:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        event_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        batch_id TEXT,
                        sent_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_events_unsent
                        ON events(sent_at, sequence);
                    CREATE TABLE IF NOT EXISTS pending_batches (
                        batch_id TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        event_sequences TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    """
                )
        finally:
            connection.close()

    def append_event(self, event: Event) -> Event:
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT seq FROM sqlite_sequence WHERE name = 'events'").fetchone()
            sequence = (int(row[0]) if row else 0) + 1
            event = replace(
                event,
                sequence=sequence,
                sensor_id=self.sensor_id,
                matrix_id=self.matrix_id,
            )
            event.validate()
            event = event.with_signature(sign_payload(self.private_key, event.to_signing_dict()))
            payload = canonical_json(event.to_dict()).decode("utf-8")
            connection.execute(
                "INSERT INTO events(sequence, event_id, event_json, created_at, sent_at) VALUES (?, ?, ?, ?, NULL)",
                (event.sequence, event.event_id, payload, utc_now()),
            )
            connection.commit()
            return event
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StorageConflict("event_id already exists in the local buffer") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_unsent_events(self, limit: int) -> list[Event]:
        if limit < 1 or limit > 500:
            raise ValidationError("limit must be between 1 and 500")
        connection = _connect(self.path)
        try:
            rows = connection.execute(
                "SELECT event_json FROM events WHERE sent_at IS NULL ORDER BY sequence LIMIT ?",
                (limit,),
            ).fetchall()
            return [Event.from_dict(json.loads(row["event_json"])) for row in rows]
        finally:
            connection.close()

    def get_pending_batch(self) -> dict[str, Any] | None:
        connection = _connect(self.path)
        try:
            row = connection.execute(
                "SELECT payload_json FROM pending_batches ORDER BY created_at LIMIT 1"
            ).fetchone()
            return json.loads(row["payload_json"]) if row else None
        finally:
            connection.close()

    def create_pending_batch(self, payload: dict[str, Any], event_sequences: list[int]) -> dict[str, Any]:
        if not event_sequences:
            raise ValidationError("pending batch must contain at least one event")
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload_json FROM pending_batches ORDER BY created_at LIMIT 1"
            ).fetchone()
            if existing:
                connection.rollback()
                return json.loads(existing["payload_json"])
            placeholders = ",".join("?" for _ in event_sequences)
            found = connection.execute(
                f"SELECT COUNT(*) AS count FROM events WHERE sent_at IS NULL AND sequence IN ({placeholders})",
                tuple(event_sequences),
            ).fetchone()
            if int(found["count"]) != len(event_sequences):
                connection.rollback()
                raise StorageError("pending batch references missing or already sent events")
            connection.execute(
                "INSERT INTO pending_batches(batch_id, payload_json, event_sequences, created_at) VALUES (?, ?, ?, ?)",
                (
                    payload["batch_id"],
                    canonical_json(payload).decode("utf-8"),
                    json.dumps(event_sequences, separators=(",", ":")),
                    utc_now(),
                ),
            )
            connection.execute(
                f"UPDATE events SET batch_id = ? WHERE sent_at IS NULL AND sequence IN ({placeholders})",
                tuple([payload["batch_id"], *event_sequences]),
            )
            connection.commit()
            return payload
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def mark_batch_sent(self, batch_id: str) -> bool:
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT event_sequences FROM pending_batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if not row:
                connection.rollback()
                return False
            event_sequences = json.loads(row["event_sequences"])
            if not isinstance(event_sequences, list) or not event_sequences:
                connection.rollback()
                raise StorageError("pending batch has invalid event_sequences")
            placeholders = ",".join("?" for _ in event_sequences)
            sent_at = utc_now()
            connection.execute(
                f"UPDATE events SET sent_at = ? WHERE batch_id = ? AND sent_at IS NULL AND sequence IN ({placeholders})",
                tuple([sent_at, batch_id, *event_sequences]),
            )
            connection.execute("DELETE FROM pending_batches WHERE batch_id = ?", (batch_id,))
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def stats(self) -> dict[str, Any]:
        connection = _connect(self.path)
        try:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN sent_at IS NULL THEN 1 ELSE 0 END) AS unsent,
                    SUM(CASE WHEN sent_at IS NOT NULL THEN 1 ELSE 0 END) AS sent,
                    MAX(sequence) AS last_sequence
                FROM events
                """
            ).fetchone()
            pending = connection.execute("SELECT COUNT(*) AS count FROM pending_batches").fetchone()
            return {
                "total_events": int(row["total"] or 0),
                "unsent_events": int(row["unsent"] or 0),
                "sent_events": int(row["sent"] or 0),
                "last_sequence": int(row["last_sequence"] or 0),
                "pending_batches": int(pending["count"] or 0),
            }
        finally:
            connection.close()


class CollectorStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        connection = _connect(self.path)
        try:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS enrollment_tokens (
                        token_hash TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        used_at TEXT,
                        used_by TEXT,
                        revoked_at TEXT
                    );
                    CREATE TABLE IF NOT EXISTS sensors (
                        sensor_id TEXT PRIMARY KEY,
                        matrix_id TEXT NOT NULL,
                        public_key TEXT NOT NULL,
                        registered_at TEXT NOT NULL,
                        last_seen TEXT,
                        last_sequence INTEGER NOT NULL DEFAULT 0,
                        status TEXT NOT NULL DEFAULT 'active',
                        metadata_json TEXT
                    );
                    CREATE TABLE IF NOT EXISTS endpoints (
                        endpoint_id TEXT PRIMARY KEY,
                        sensor_id TEXT NOT NULL,
                        matrix_id TEXT NOT NULL,
                        listen_ip TEXT NOT NULL,
                        listen_port INTEGER NOT NULL,
                        advertised_ip TEXT NOT NULL,
                        advertised_port INTEGER NOT NULL,
                        transport TEXT NOT NULL,
                        profile_id TEXT NOT NULL,
                        exposure TEXT NOT NULL,
                        source_quality TEXT NOT NULL,
                        enabled INTEGER NOT NULL,
                        config_version INTEGER NOT NULL,
                        FOREIGN KEY(sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_endpoints_sensor
                        ON endpoints(sensor_id);
                    CREATE TABLE IF NOT EXISTS batches (
                        batch_id TEXT PRIMARY KEY,
                        sensor_id TEXT NOT NULL,
                        sequence_start INTEGER NOT NULL,
                        sequence_end INTEGER NOT NULL,
                        received_at TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        FOREIGN KEY(sensor_id) REFERENCES sensors(sensor_id)
                    );
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        sensor_id TEXT NOT NULL,
                        matrix_id TEXT NOT NULL,
                        endpoint_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        observed_at TEXT NOT NULL,
                        received_at TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        transport TEXT NOT NULL,
                        event_json TEXT NOT NULL,
                        batch_id TEXT NOT NULL,
                        UNIQUE(sensor_id, sequence),
                        FOREIGN KEY(sensor_id) REFERENCES sensors(sensor_id),
                        FOREIGN KEY(batch_id) REFERENCES batches(batch_id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_events_sensor_time
                        ON events(sensor_id, observed_at);
                    CREATE INDEX IF NOT EXISTS idx_events_source_time
                        ON events(source_ip, observed_at);
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        at TEXT NOT NULL,
                        action TEXT NOT NULL,
                        actor TEXT,
                        detail_json TEXT
                    );
                    CREATE TABLE IF NOT EXISTS canary_deployments (
                        sensor_id TEXT NOT NULL,
                        group_id TEXT NOT NULL,
                        token_hash TEXT NOT NULL,
                        token_type TEXT NOT NULL,
                        endpoint_ids_json TEXT NOT NULL,
                        active INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        retired_at TEXT,
                        replaced_by TEXT,
                        PRIMARY KEY(sensor_id, group_id),
                        FOREIGN KEY(sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_canary_deployments_hash
                        ON canary_deployments(token_hash);
                    CREATE TABLE IF NOT EXISTS cases (
                        case_id TEXT PRIMARY KEY,
                        case_key TEXT NOT NULL UNIQUE,
                        title TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        status TEXT NOT NULL,
                        confidence TEXT NOT NULL,
                        event_count INTEGER NOT NULL,
                        sensor_ids_json TEXT NOT NULL,
                        endpoint_ids_json TEXT NOT NULL,
                        source_ips_json TEXT NOT NULL,
                        source_quality TEXT NOT NULL,
                        asns_json TEXT NOT NULL,
                        canary_hashes_json TEXT NOT NULL,
                        fingerprints_json TEXT NOT NULL,
                        scan_shape_json TEXT NOT NULL,
                        confidence_signals_json TEXT NOT NULL,
                        recommended_actions_json TEXT NOT NULL,
                        not_checked_json TEXT NOT NULL,
                        evidence_hashes_json TEXT NOT NULL,
                        evidence_package_id TEXT,
                        legal_hold_id TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_cases_last_seen
                        ON cases(last_seen DESC);
                    CREATE TABLE IF NOT EXISTS case_events (
                        case_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        linked_at TEXT NOT NULL,
                        PRIMARY KEY(case_id, event_id),
                        FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
                        FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_case_events_event
                        ON case_events(event_id);
                    CREATE TABLE IF NOT EXISTS case_aliases (
                        case_key TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_case_aliases_case
                        ON case_aliases(case_id);
                    CREATE TABLE IF NOT EXISTS case_reviews (
                        review_id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        note TEXT,
                        actor TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_case_reviews_case
                        ON case_reviews(case_id, created_at);
                    CREATE TABLE IF NOT EXISTS legal_holds (
                        hold_id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        actor TEXT,
                        started_at TEXT NOT NULL,
                        expected_until TEXT,
                        released_at TEXT,
                        release_reason TEXT,
                        release_actor TEXT,
                        FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_legal_holds_case
                        ON legal_holds(case_id, status);
                    CREATE TABLE IF NOT EXISTS highwall_events (
                        highwall_event_id TEXT PRIMARY KEY,
                        source TEXT NOT NULL,
                        external_id TEXT,
                        event_type TEXT NOT NULL,
                        source_ip TEXT,
                        observed_at TEXT NOT NULL,
                        received_at TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_highwall_source_time
                        ON highwall_events(source_ip, observed_at);
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_highwall_source_external
                        ON highwall_events(source, external_id)
                        WHERE external_id IS NOT NULL;
                    CREATE TABLE IF NOT EXISTS case_highwall_events (
                        case_id TEXT NOT NULL,
                        highwall_event_id TEXT NOT NULL,
                        linked_at TEXT NOT NULL,
                        PRIMARY KEY(case_id, highwall_event_id),
                        FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
                        FOREIGN KEY(highwall_event_id) REFERENCES highwall_events(highwall_event_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_case_highwall_event
                        ON case_highwall_events(highwall_event_id);
                    CREATE TABLE IF NOT EXISTS evidence_packages (
                        package_id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        directory_path TEXT NOT NULL,
                        archive_path TEXT,
                        manifest_sha256 TEXT NOT NULL,
                        package_sha256 TEXT,
                        status TEXT NOT NULL,
                        actor TEXT,
                        FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_evidence_packages_case
                        ON evidence_packages(case_id, created_at DESC);
                    CREATE TABLE IF NOT EXISTS canary_sync_state (
                        sensor_id TEXT PRIMARY KEY,
                        snapshot_sha256 TEXT NOT NULL,
                        generated_at TEXT NOT NULL,
                        synced_at TEXT NOT NULL,
                        FOREIGN KEY(sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE
                    );
                    """
                )
        finally:
            connection.close()

    def _audit(
        self,
        connection: sqlite3.Connection,
        action: str,
        actor: str | None,
        detail: dict[str, Any] | None,
    ) -> None:
        connection.execute(
            "INSERT INTO audit_log(at, action, actor, detail_json) VALUES (?, ?, ?, ?)",
            (
                utc_now(),
                action,
                actor,
                canonical_json(detail or {}).decode("utf-8"),
            ),
        )

    def audit(self, action: str, actor: str | None = None, detail: dict[str, Any] | None = None) -> None:
        connection = _connect(self.path)
        try:
            with connection:
                self._audit(connection, action, actor, detail)
        finally:
            connection.close()

    def create_enrollment_token(self, token_hash: str) -> None:
        connection = _connect(self.path)
        try:
            with connection:
                connection.execute(
                    "INSERT INTO enrollment_tokens(token_hash, created_at) VALUES (?, ?)",
                    (token_hash, utc_now()),
                )
                self._audit(connection, "enrollment_token_created", "collector", {})
        finally:
            connection.close()

    def rotate_enrollment_token(self, token_hash: str) -> None:
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            now = utc_now()
            connection.execute(
                "UPDATE enrollment_tokens SET revoked_at = ? WHERE used_at IS NULL AND revoked_at IS NULL",
                (now,),
            )
            connection.execute(
                "INSERT INTO enrollment_tokens(token_hash, created_at) VALUES (?, ?)",
                (token_hash, now),
            )
            self._audit(connection, "enrollment_token_rotated", "collector", {})
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def enroll_sensor(
        self,
        *,
        token_hash: str,
        sensor_id: str,
        matrix_id: str,
        public_key: str,
        endpoints: list[Endpoint],
        canaries: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            load_public_key_text(public_key)
        except CryptoError as exc:
            raise ValidationError("public_key is not a valid Ed25519 public key") from exc
        matrix = EndpointMatrix(matrix_id=matrix_id, sensor_id=sensor_id, endpoints=list(endpoints))
        matrix.validate()
        endpoints = matrix.endpoints
        deployments = [CanaryDeployment.from_dict(item) for item in (canaries or [])]
        if len(deployments) > 256:
            raise ValidationError("canary deployment list exceeds 256 groups")
        endpoint_ids = {endpoint.endpoint_id for endpoint in endpoints}
        seen_group_ids: set[str] = set()
        seen_hashes: set[str] = set()
        for deployment in deployments:
            if deployment.group_id in seen_group_ids:
                raise ValidationError(f"duplicate canary group_id: {deployment.group_id}")
            if deployment.token_hash in seen_hashes:
                raise ValidationError("duplicate canary token hash in enrollment")
            if not set(deployment.endpoint_ids).issubset(endpoint_ids):
                raise ValidationError(
                    f"canary group {deployment.group_id} references an unregistered endpoint"
                )
            seen_group_ids.add(deployment.group_id)
            seen_hashes.add(deployment.token_hash)
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            token = connection.execute(
                "SELECT token_hash FROM enrollment_tokens WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL",
                (token_hash,),
            ).fetchone()
            if not token:
                connection.rollback()
                raise StorageConflict("invalid, used, or revoked enrollment token")
            existing = connection.execute(
                "SELECT sensor_id FROM sensors WHERE sensor_id = ?",
                (sensor_id,),
            ).fetchone()
            if existing:
                connection.rollback()
                raise StorageConflict("sensor_id is already registered")
            now = utc_now()
            connection.execute(
                """
                INSERT INTO sensors(sensor_id, matrix_id, public_key, registered_at, last_seen, last_sequence, status, metadata_json)
                VALUES (?, ?, ?, ?, NULL, 0, 'active', ?)
                """,
                (
                    sensor_id,
                    matrix_id,
                    public_key,
                    now,
                    canonical_json(metadata or {}).decode("utf-8"),
                ),
            )
            for endpoint in endpoints:
                if endpoint.sensor_id != sensor_id or endpoint.matrix_id != matrix_id:
                    raise ValidationError("endpoint belongs to a different sensor or matrix")
                endpoint.validate()
                connection.execute(
                    """
                    INSERT INTO endpoints(
                        endpoint_id, sensor_id, matrix_id, listen_ip, listen_port,
                        advertised_ip, advertised_port, transport, profile_id,
                        exposure, source_quality, enabled, config_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        endpoint.endpoint_id,
                        endpoint.sensor_id,
                        endpoint.matrix_id,
                        endpoint.listen_ip,
                        endpoint.listen_port,
                        endpoint.advertised_ip,
                        endpoint.advertised_port,
                        endpoint.transport,
                        endpoint.profile_id,
                        endpoint.exposure,
                        endpoint.source_quality,
                        1 if endpoint.enabled else 0,
                        endpoint.config_version,
                    ),
                )
            for deployment in deployments:
                connection.execute(
                    """
                    INSERT INTO canary_deployments(
                        sensor_id, group_id, token_hash, token_type, endpoint_ids_json,
                        active, created_at, retired_at, replaced_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sensor_id,
                        deployment.group_id,
                        deployment.token_hash,
                        deployment.token_type,
                        canonical_json(deployment.endpoint_ids).decode("utf-8"),
                        1 if deployment.active else 0,
                        deployment.created_at,
                        deployment.retired_at,
                        deployment.replaced_by,
                    ),
                )
            connection.execute(
                "UPDATE enrollment_tokens SET used_at = ?, used_by = ? WHERE token_hash = ?",
                (now, sensor_id, token_hash),
            )
            self._audit(
                connection,
                "sensor_enrolled",
                sensor_id,
                {
                    "matrix_id": matrix_id,
                    "endpoint_count": len(endpoints),
                    "canary_group_count": len(deployments),
                },
            )
            connection.commit()
            return {
                "sensor_id": sensor_id,
                "matrix_id": matrix_id,
                "registered_at": now,
                "endpoint_count": len(endpoints),
                "canary_group_count": len(deployments),
            }
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StorageConflict("endpoint or sensor conflicts with existing registration") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_sensor(self, sensor_id: str, *, include_public_key: bool = False) -> dict[str, Any] | None:
        connection = _connect(self.path)
        try:
            row = connection.execute("SELECT * FROM sensors WHERE sensor_id = ?", (sensor_id,)).fetchone()
            if not row:
                return None
            result = {
                "sensor_id": row["sensor_id"],
                "matrix_id": row["matrix_id"],
                "registered_at": row["registered_at"],
                "last_seen": row["last_seen"],
                "last_sequence": row["last_sequence"],
                "status": row["status"],
                "metadata": _json_object(row["metadata_json"]),
            }
            if include_public_key:
                result["public_key"] = row["public_key"]
            return result
        finally:
            connection.close()

    def list_sensors(self) -> list[dict[str, Any]]:
        connection = _connect(self.path)
        try:
            rows = connection.execute(
                "SELECT sensor_id, matrix_id, registered_at, last_seen, last_sequence, status, metadata_json FROM sensors ORDER BY registered_at"
            ).fetchall()
            return [
                {
                    "sensor_id": row["sensor_id"],
                    "matrix_id": row["matrix_id"],
                    "registered_at": row["registered_at"],
                    "last_seen": row["last_seen"],
                    "last_sequence": row["last_sequence"],
                    "status": row["status"],
                    "metadata": _json_object(row["metadata_json"]),
                }
                for row in rows
            ]
        finally:
            connection.close()

    def list_endpoints(self, sensor_id: str | None = None) -> list[dict[str, Any]]:
        connection = _connect(self.path)
        try:
            if sensor_id:
                rows = connection.execute(
                    "SELECT * FROM endpoints WHERE sensor_id = ? ORDER BY listen_ip, listen_port",
                    (sensor_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM endpoints ORDER BY sensor_id, listen_ip, listen_port"
                ).fetchall()
            return [
                {
                    "endpoint_id": row["endpoint_id"],
                    "sensor_id": row["sensor_id"],
                    "matrix_id": row["matrix_id"],
                    "listen_ip": row["listen_ip"],
                    "listen_port": row["listen_port"],
                    "advertised_ip": row["advertised_ip"],
                    "advertised_port": row["advertised_port"],
                    "transport": row["transport"],
                    "profile_id": row["profile_id"],
                    "exposure": row["exposure"],
                    "source_quality": row["source_quality"],
                    "enabled": bool(row["enabled"]),
                    "config_version": row["config_version"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def _canary_case_candidates(
        self, connection: sqlite3.Connection, event: Event
    ) -> list[sqlite3.Row]:
        if not event.canary_hashes:
            return []
        wanted = set(event.canary_hashes)
        event_time = parse_iso8601(event.observed_at, "observed_at")
        window = timedelta(seconds=ASSOCIATION_WINDOW_SECONDS)
        rows = connection.execute(
            "SELECT * FROM cases WHERE source_quality = ? ORDER BY created_at, case_id",
            (event.source_quality,),
        ).fetchall()
        candidates: list[sqlite3.Row] = []
        for row in rows:
            if not wanted.intersection(set(_json_list(row["canary_hashes_json"]))):
                continue
            first_seen = parse_iso8601(row["first_seen"], "first_seen")
            last_seen = parse_iso8601(row["last_seen"], "last_seen")
            if first_seen - window <= event_time <= last_seen + window:
                candidates.append(row)
        return candidates

    @staticmethod
    def _sync_case_legal_hold(connection: sqlite3.Connection, case_id: str) -> None:
        active = connection.execute(
            """
            SELECT hold_id FROM legal_holds
            WHERE case_id = ? AND status = 'active'
            ORDER BY started_at, hold_id
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
        connection.execute(
            "UPDATE cases SET legal_hold_id = ? WHERE case_id = ?",
            (active["hold_id"] if active else None, case_id),
        )

    @staticmethod
    def _invalidate_evidence_packages(connection: sqlite3.Connection, case_id: str) -> None:
        connection.execute(
            "UPDATE evidence_packages SET status = 'superseded' WHERE case_id = ? AND status = 'valid'",
            (case_id,),
        )
        connection.execute(
            "UPDATE cases SET evidence_package_id = NULL WHERE case_id = ?",
            (case_id,),
        )

    def _merge_case(
        self,
        connection: sqlite3.Connection,
        *,
        target_id: str,
        source_id: str,
    ) -> None:
        if target_id == source_id:
            return
        target = connection.execute("SELECT * FROM cases WHERE case_id = ?", (target_id,)).fetchone()
        source = connection.execute("SELECT * FROM cases WHERE case_id = ?", (source_id,)).fetchone()
        if target is None or source is None:
            return
        now = utc_now()
        connection.execute(
            """
            INSERT INTO case_aliases(case_key, case_id, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(case_key) DO UPDATE SET case_id = excluded.case_id
            """,
            (source["case_key"], target_id, now),
        )
        connection.execute("UPDATE case_aliases SET case_id = ? WHERE case_id = ?", (target_id, source_id))
        connection.execute("UPDATE case_reviews SET case_id = ? WHERE case_id = ?", (target_id, source_id))
        connection.execute("UPDATE legal_holds SET case_id = ? WHERE case_id = ?", (target_id, source_id))
        connection.execute("UPDATE evidence_packages SET case_id = ? WHERE case_id = ?", (target_id, source_id))
        self._sync_case_legal_hold(connection, target_id)
        connection.execute(
            """
            INSERT OR IGNORE INTO case_events(case_id, event_id, linked_at)
            SELECT ?, event_id, linked_at FROM case_events WHERE case_id = ?
            """,
            (target_id, source_id),
        )
        connection.execute("DELETE FROM case_events WHERE case_id = ?", (source_id,))
        connection.execute(
            """
            INSERT OR IGNORE INTO case_highwall_events(case_id, highwall_event_id, linked_at)
            SELECT ?, highwall_event_id, linked_at FROM case_highwall_events WHERE case_id = ?
            """,
            (target_id, source_id),
        )
        connection.execute("DELETE FROM case_highwall_events WHERE case_id = ?", (source_id,))
        self._invalidate_evidence_packages(connection, target_id)
        connection.execute("DELETE FROM cases WHERE case_id = ?", (source_id,))

    def _find_or_create_case(
        self,
        connection: sqlite3.Connection,
        event: Event,
        received_at: str,
    ) -> str:
        base_key = f"{event.source_quality}|{event.source_ip}"
        base_row = connection.execute("SELECT * FROM cases WHERE case_key = ?", (base_key,)).fetchone()
        alias_row = connection.execute(
            "SELECT case_id FROM case_aliases WHERE case_key = ?", (base_key,)
        ).fetchone()
        alias_case = None
        if alias_row:
            alias_case = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?", (alias_row["case_id"],)
            ).fetchone()
            if alias_case is None:
                connection.execute("DELETE FROM case_aliases WHERE case_key = ?", (base_key,))

        candidates = self._canary_case_candidates(connection, event)
        target = candidates[0] if candidates else None
        if target is None and alias_case is not None:
            target = alias_case
        if target is None:
            target = base_row

        if target is None:
            case_id = new_id("case")
            empty = "[]"
            connection.execute(
                """
                INSERT INTO cases(
                    case_id, case_key, title, first_seen, last_seen, status, confidence,
                    event_count, sensor_ids_json, endpoint_ids_json, source_ips_json,
                    source_quality, asns_json, canary_hashes_json, fingerprints_json,
                    scan_shape_json, confidence_signals_json, recommended_actions_json,
                    not_checked_json, evidence_hashes_json, evidence_package_id,
                    legal_hold_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'new', 'low', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    case_id,
                    base_key,
                    f"Activity from {event.source_ip}",
                    event.observed_at,
                    event.observed_at,
                    empty,
                    empty,
                    canonical_json([event.source_ip]).decode("utf-8"),
                    event.source_quality,
                    empty,
                    empty,
                    empty,
                    empty,
                    empty,
                    empty,
                    empty,
                    empty,
                    received_at,
                    received_at,
                ),
            )
            return case_id

        target_id = str(target["case_id"])
        for candidate in candidates:
            if str(candidate["case_id"]) != target_id:
                self._merge_case(
                    connection,
                    target_id=target_id,
                    source_id=str(candidate["case_id"]),
                )
        if base_row is not None and str(base_row["case_id"]) != target_id:
            self._merge_case(
                connection,
                target_id=target_id,
                source_id=str(base_row["case_id"]),
            )
        if alias_case is not None and str(alias_case["case_id"]) != target_id:
            self._merge_case(
                connection,
                target_id=target_id,
                source_id=str(alias_case["case_id"]),
            )
        target = connection.execute("SELECT * FROM cases WHERE case_id = ?", (target_id,)).fetchone()
        if target is None:
            raise StorageError("case disappeared during association")
        if target["case_key"] != base_key:
            connection.execute(
                """
                INSERT INTO case_aliases(case_key, case_id, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(case_key) DO UPDATE SET case_id = excluded.case_id
                """,
                (base_key, target_id, received_at),
            )
        return target_id

    def _link_highwall_for_case(
        self,
        connection: sqlite3.Connection,
        case_id: str,
        events: list[Event],
    ) -> None:
        if not events:
            return
        source_ips = sorted({event.source_ip for event in events})
        if not source_ips:
            return
        window = timedelta(seconds=ASSOCIATION_WINDOW_SECONDS)
        intervals_by_source: dict[str, list[tuple[datetime, datetime]]] = {}
        for event in events:
            observed = parse_iso8601(event.observed_at, "observed_at")
            intervals_by_source.setdefault(event.source_ip, []).append(
                (observed - window, observed + window)
            )
        rows: list[sqlite3.Row] = []
        for source_ip, intervals in intervals_by_source.items():
            for lower, upper in _merge_time_intervals(intervals):
                rows.extend(
                    connection.execute(
                        """
                        SELECT highwall_event_id FROM highwall_events
                        WHERE source_ip = ? AND observed_at >= ? AND observed_at <= ?
                        ORDER BY observed_at
                        """,
                        (source_ip, format_utc(lower), format_utc(upper)),
                    ).fetchall()
                )
        linked_at = utc_now()
        seen: set[str] = set()
        for row in rows:
            highwall_event_id = row["highwall_event_id"]
            if highwall_event_id in seen:
                continue
            seen.add(highwall_event_id)
            connection.execute(
                """
                INSERT OR IGNORE INTO case_highwall_events(case_id, highwall_event_id, linked_at)
                VALUES (?, ?, ?)
                """,
                (case_id, highwall_event_id, linked_at),
            )

    @staticmethod
    def _case_highwall_events(
        connection: sqlite3.Connection, case_id: str
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT h.* FROM case_highwall_events ch
            JOIN highwall_events h ON h.highwall_event_id = ch.highwall_event_id
            WHERE ch.case_id = ?
            ORDER BY h.observed_at, h.highwall_event_id
            """,
            (case_id,),
        ).fetchall()
        return [
            {
                "highwall_event_id": row["highwall_event_id"],
                "source": row["source"],
                "external_id": row["external_id"],
                "event_type": row["event_type"],
                "source_ip": row["source_ip"],
                "observed_at": row["observed_at"],
                "received_at": row["received_at"],
                "payload_sha256": row["payload_sha256"],
                "payload": _json_object(row["payload_json"]),
            }
            for row in rows
        ]

    def _refresh_case(self, connection: sqlite3.Connection, case_id: str, received_at: str) -> None:
        row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise StorageError(f"case not found during refresh: {case_id}")
        event_rows = connection.execute(
            """
            SELECT e.event_json FROM case_events ce
            JOIN events e ON e.event_id = ce.event_id
            WHERE ce.case_id = ?
            ORDER BY e.observed_at, e.sequence
            """,
            (case_id,),
        ).fetchall()
        events = [Event.from_dict(json.loads(event_row["event_json"])) for event_row in event_rows]
        if not events:
            raise StorageError(f"case has no events: {case_id}")
        self._invalidate_evidence_packages(connection, case_id)
        self._link_highwall_for_case(connection, case_id, events)
        highwall_events = self._case_highwall_events(connection, case_id)
        analysis = analyze_events(events, highwall_events=highwall_events)
        source_ips = list(analysis["source_ips"])
        source_summary = ", ".join(source_ips[:2])
        if len(source_ips) > 2:
            source_summary += f" and {len(source_ips) - 2} more"
        case = Case(
            case_id=case_id,
            title=f"Activity from {source_summary}",
            first_seen=analysis["first_seen"],
            last_seen=analysis["last_seen"],
            status=row["status"],
            confidence=analysis["confidence"],
            event_count=analysis["event_count"],
            sensor_ids=analysis["sensor_ids"],
            endpoint_ids=analysis["endpoint_ids"],
            source_ips=source_ips,
            source_quality=analysis["source_quality"],
            asns=analysis["asns"],
            canary_hashes=analysis["canary_hashes"],
            fingerprints=analysis["fingerprints"],
            scan_shape=analysis["scan_shape"],
            confidence_signals=analysis["confidence_signals"],
            recommended_actions=analysis["recommended_actions"],
            not_checked=analysis["not_checked"],
            evidence_hashes=analysis["evidence_hashes"],
            evidence_package_id=None,
            legal_hold_id=row["legal_hold_id"],
            created_at=row["created_at"],
            updated_at=received_at,
        )
        case.validate()
        connection.execute(
            """
            UPDATE cases SET title = ?, first_seen = ?, last_seen = ?, status = ?, confidence = ?,
                event_count = ?, sensor_ids_json = ?, endpoint_ids_json = ?, source_ips_json = ?,
                source_quality = ?, asns_json = ?, canary_hashes_json = ?, fingerprints_json = ?,
                scan_shape_json = ?, confidence_signals_json = ?, recommended_actions_json = ?,
                not_checked_json = ?, evidence_hashes_json = ?, evidence_package_id = ?,
                legal_hold_id = ?, updated_at = ?
            WHERE case_id = ?
            """,
            (
                case.title,
                case.first_seen,
                case.last_seen,
                case.status,
                case.confidence,
                case.event_count,
                canonical_json(case.sensor_ids).decode("utf-8"),
                canonical_json(case.endpoint_ids).decode("utf-8"),
                canonical_json(case.source_ips).decode("utf-8"),
                case.source_quality,
                canonical_json(case.asns).decode("utf-8"),
                canonical_json(case.canary_hashes).decode("utf-8"),
                canonical_json(case.fingerprints).decode("utf-8"),
                canonical_json(case.scan_shape).decode("utf-8"),
                canonical_json(case.confidence_signals).decode("utf-8"),
                canonical_json(case.recommended_actions).decode("utf-8"),
                canonical_json(case.not_checked).decode("utf-8"),
                canonical_json(case.evidence_hashes).decode("utf-8"),
                case.evidence_package_id,
                case.legal_hold_id,
                case.updated_at,
                case.case_id,
            ),
        )

    def _associate_event(
        self, connection: sqlite3.Connection, event: Event, received_at: str
    ) -> str:
        case_id = self._find_or_create_case(connection, event, received_at)
        connection.execute(
            "INSERT OR IGNORE INTO case_events(case_id, event_id, linked_at) VALUES (?, ?, ?)",
            (case_id, event.event_id, received_at),
        )
        return case_id

    @staticmethod
    def _case_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "case_id": row["case_id"],
            "title": row["title"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "status": row["status"],
            "confidence": row["confidence"],
            "event_count": int(row["event_count"]),
            "sensor_ids": _json_list(row["sensor_ids_json"]),
            "endpoint_ids": _json_list(row["endpoint_ids_json"]),
            "source_ips": _json_list(row["source_ips_json"]),
            "source_quality": row["source_quality"],
            "asns": _json_list(row["asns_json"]),
            "canary_hashes": _json_list(row["canary_hashes_json"]),
            "fingerprints": _json_list(row["fingerprints_json"]),
            "scan_shape": _json_list(row["scan_shape_json"]),
            "confidence_signals": _json_list(row["confidence_signals_json"]),
            "recommended_actions": _json_list(row["recommended_actions_json"]),
            "not_checked": _json_list(row["not_checked_json"]),
            "evidence_hashes": _json_list(row["evidence_hashes_json"]),
            "evidence_package_id": row["evidence_package_id"],
            "legal_hold_id": row["legal_hold_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_cases(self, *, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValidationError("limit must be between 1 and 500")
        if status is not None and status not in CASE_STATUSES:
            raise ValidationError(f"status must be one of {sorted(CASE_STATUSES)}")
        connection = _connect(self.path)
        try:
            if status is None:
                rows = connection.execute(
                    "SELECT * FROM cases ORDER BY last_seen DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM cases WHERE status = ? ORDER BY last_seen DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            return [self._case_dict(row) for row in rows]
        finally:
            connection.close()

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        connection = _connect(self.path)
        try:
            row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
            case = self._case_dict(row)
            event_rows = connection.execute(
                """
                SELECT e.event_json, e.received_at AS collector_received_at, e.batch_id
                FROM case_events ce
                JOIN events e ON e.event_id = ce.event_id
                WHERE ce.case_id = ?
                ORDER BY e.observed_at, e.sequence
                """,
                (case_id,),
            ).fetchall()
            timeline: list[dict[str, Any]] = []
            for event_row in event_rows:
                stored = json.loads(event_row["event_json"])
                event = Event.from_dict(stored)
                timeline.append(
                    {
                        "event_sha256": sha256_hex(canonical_json(event.to_signing_dict())),
                        **stored,
                        "received_at": event_row["collector_received_at"],
                        "batch_id": event_row["batch_id"],
                    }
                )
            case["timeline"] = timeline
            review_rows = connection.execute(
                "SELECT * FROM case_reviews WHERE case_id = ? ORDER BY created_at, review_id",
                (case_id,),
            ).fetchall()
            case["reviews"] = [
                {
                    "review_id": row["review_id"],
                    "status": row["status"],
                    "note": row["note"],
                    "actor": row["actor"],
                    "created_at": row["created_at"],
                }
                for row in review_rows
            ]
            hold_rows = connection.execute(
                "SELECT * FROM legal_holds WHERE case_id = ? ORDER BY started_at, hold_id",
                (case_id,),
            ).fetchall()
            case["legal_holds"] = [
                {
                    "hold_id": row["hold_id"],
                    "status": row["status"],
                    "reason": row["reason"],
                    "actor": row["actor"],
                    "started_at": row["started_at"],
                    "expected_until": row["expected_until"],
                    "released_at": row["released_at"],
                    "release_reason": row["release_reason"],
                    "release_actor": row["release_actor"],
                }
                for row in hold_rows
            ]
            package_rows = connection.execute(
                "SELECT * FROM evidence_packages WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
            case["evidence_packages"] = [
                {
                    "package_id": row["package_id"],
                    "created_at": row["created_at"],
                    "directory_path": row["directory_path"],
                    "archive_path": row["archive_path"],
                    "manifest_sha256": row["manifest_sha256"],
                    "package_sha256": row["package_sha256"],
                    "status": row["status"],
                    "actor": row["actor"],
                }
                for row in package_rows
            ]
            case["highwall_events"] = self._case_highwall_events(connection, case_id)
            return case
        finally:
            connection.close()

    def review_case(
        self,
        case_id: str,
        *,
        status: str,
        note: str | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        if status not in CASE_STATUSES:
            raise ValidationError(f"status must be one of {sorted(CASE_STATUSES)}")
        note = _optional_text(note, "note", 4096)
        actor = _bounded_text(actor or "local-operator", "actor", 128)
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone() is None:
                connection.rollback()
                raise StorageError(f"case not found: {case_id}")
            created_at = utc_now()
            review_id = new_id("review")
            connection.execute(
                """
                INSERT INTO case_reviews(review_id, case_id, status, note, actor, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (review_id, case_id, status, note, actor, created_at),
            )
            connection.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                (status, created_at, case_id),
            )
            self._audit(
                connection,
                "case_reviewed",
                actor,
                {"case_id": case_id, "status": status, "note": note, "review_id": review_id},
            )
            connection.commit()
            return {
                "review_id": review_id,
                "case_id": case_id,
                "status": status,
                "note": note,
                "actor": actor,
                "created_at": created_at,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_case_reviews(self, case_id: str) -> list[dict[str, Any]]:
        connection = _connect(self.path)
        try:
            rows = connection.execute(
                "SELECT * FROM case_reviews WHERE case_id = ? ORDER BY created_at, review_id",
                (case_id,),
            ).fetchall()
            return [
                {
                    "review_id": row["review_id"],
                    "status": row["status"],
                    "note": row["note"],
                    "actor": row["actor"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def set_legal_hold(
        self,
        case_id: str,
        *,
        reason: str,
        actor: str | None = None,
        expected_until: str | None = None,
    ) -> dict[str, Any]:
        reason = _bounded_text(reason, "reason", 2048)
        actor = _bounded_text(actor or "local-operator", "actor", 128)
        if expected_until is not None:
            parse_iso8601(expected_until, "expected_until")
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone() is None:
                connection.rollback()
                raise StorageError(f"case not found: {case_id}")
            active = connection.execute(
                "SELECT hold_id FROM legal_holds WHERE case_id = ? AND status = 'active'",
                (case_id,),
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise StorageConflict(f"case already has an active legal hold: {active['hold_id']}")
            hold_id = new_id("hold")
            started_at = utc_now()
            connection.execute(
                """
                INSERT INTO legal_holds(
                    hold_id, case_id, status, reason, actor, started_at, expected_until
                ) VALUES (?, ?, 'active', ?, ?, ?, ?)
                """,
                (hold_id, case_id, reason, actor, started_at, expected_until),
            )
            connection.execute(
                "UPDATE cases SET legal_hold_id = ?, updated_at = ? WHERE case_id = ?",
                (hold_id, started_at, case_id),
            )
            self._audit(
                connection,
                "legal_hold_started",
                actor,
                {
                    "case_id": case_id,
                    "hold_id": hold_id,
                    "reason": reason,
                    "expected_until": expected_until,
                },
            )
            connection.commit()
            return {
                "hold_id": hold_id,
                "case_id": case_id,
                "status": "active",
                "reason": reason,
                "actor": actor,
                "started_at": started_at,
                "expected_until": expected_until,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def release_legal_hold(
        self,
        case_id: str,
        *,
        reason: str,
        actor: str | None = None,
        confirm: bool = False,
        hold_id: str | None = None,
    ) -> dict[str, Any]:
        if confirm is not True:
            raise ValidationError("releasing a legal hold requires explicit confirmation")
        reason = _bounded_text(reason, "reason", 2048)
        actor = _bounded_text(actor or "local-operator", "actor", 128)
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone() is None:
                connection.rollback()
                raise StorageError(f"case not found: {case_id}")
            if hold_id is None:
                active = connection.execute(
                    "SELECT hold_id FROM legal_holds WHERE case_id = ? AND status = 'active' ORDER BY started_at, hold_id",
                    (case_id,),
                ).fetchall()
                if not active:
                    connection.rollback()
                    raise StorageConflict("case has no active legal hold")
                if len(active) > 1:
                    connection.rollback()
                    raise ValidationError("case has multiple active legal holds; specify hold_id")
                hold_id = active[0]["hold_id"]
            else:
                active = connection.execute(
                    "SELECT hold_id FROM legal_holds WHERE case_id = ? AND hold_id = ? AND status = 'active'",
                    (case_id, hold_id),
                ).fetchone()
                if active is None:
                    connection.rollback()
                    raise StorageConflict("active legal hold not found for this case")
            released_at = utc_now()
            connection.execute(
                """
                UPDATE legal_holds SET status = 'released', released_at = ?,
                    release_reason = ?, release_actor = ?
                WHERE hold_id = ?
                """,
                (released_at, reason, actor, hold_id),
            )
            self._sync_case_legal_hold(connection, case_id)
            self._audit(
                connection,
                "legal_hold_released",
                actor,
                {"case_id": case_id, "hold_id": hold_id, "reason": reason},
            )
            connection.commit()
            return {
                "hold_id": hold_id,
                "case_id": case_id,
                "status": "released",
                "released_at": released_at,
                "release_reason": reason,
                "release_actor": actor,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_legal_holds(self, case_id: str) -> list[dict[str, Any]]:
        connection = _connect(self.path)
        try:
            rows = connection.execute(
                "SELECT * FROM legal_holds WHERE case_id = ? ORDER BY started_at, hold_id",
                (case_id,),
            ).fetchall()
            return [
                {
                    "hold_id": row["hold_id"],
                    "status": row["status"],
                    "reason": row["reason"],
                    "actor": row["actor"],
                    "started_at": row["started_at"],
                    "expected_until": row["expected_until"],
                    "released_at": row["released_at"],
                    "release_reason": row["release_reason"],
                    "release_actor": row["release_actor"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def evidence_snapshot(self, case_id: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        if case is None:
            raise StorageError(f"case not found: {case_id}")
        connection = _connect(self.path)
        try:
            event_rows = connection.execute(
                """
                SELECT e.event_json, e.received_at AS collector_received_at, e.batch_id
                FROM case_events ce
                JOIN events e ON e.event_id = ce.event_id
                WHERE ce.case_id = ?
                ORDER BY e.observed_at, e.sensor_id, e.sequence
                """,
                (case_id,),
            ).fetchall()
            events = [
                {
                    "event": json.loads(row["event_json"]),
                    "event_sha256": event_sha256(Event.from_dict(json.loads(row["event_json"]))),
                    "batch_id": row["batch_id"],
                    "collector_received_at": row["collector_received_at"],
                }
                for row in event_rows
            ]
            batch_ids = sorted({item["batch_id"] for item in events})
            batches: list[dict[str, Any]] = []
            if batch_ids:
                placeholders = ",".join("?" for _ in batch_ids)
                batch_rows = connection.execute(
                    f"SELECT payload_json FROM batches WHERE batch_id IN ({placeholders}) ORDER BY received_at, batch_id",
                    tuple(batch_ids),
                ).fetchall()
                batches = [json.loads(row["payload_json"]) for row in batch_rows]
            sensor_ids = sorted({str(item["event"]["sensor_id"]) for item in events})
            sensors: list[dict[str, Any]] = []
            if sensor_ids:
                placeholders = ",".join("?" for _ in sensor_ids)
                sensor_rows = connection.execute(
                    f"""
                    SELECT sensor_id, matrix_id, public_key, registered_at, metadata_json
                    FROM sensors WHERE sensor_id IN ({placeholders})
                    ORDER BY sensor_id
                    """,
                    tuple(sensor_ids),
                ).fetchall()
                sensors = [
                    {
                        "sensor_id": row["sensor_id"],
                        "matrix_id": row["matrix_id"],
                        "public_key": row["public_key"],
                        "registered_at": row["registered_at"],
                        "metadata": _json_object(row["metadata_json"]),
                    }
                    for row in sensor_rows
                ]
            reviews = self.list_case_reviews(case_id)
            holds = self.list_legal_holds(case_id)
            review_ids = {item["review_id"] for item in reviews}
            hold_ids = {item["hold_id"] for item in holds}
            linked_highwall_ids = {
                item["highwall_event_id"] for item in case.get("highwall_events", [])
            }
            audit_rows = connection.execute(
                "SELECT id, at, action, actor, detail_json FROM audit_log ORDER BY id"
            ).fetchall()
            custody: list[dict[str, Any]] = []
            for row in audit_rows:
                detail = _json_object(row["detail_json"])
                include = detail.get("case_id") == case_id
                include = include or detail.get("batch_id") in batch_ids
                include = include or detail.get("review_id") in review_ids
                include = include or detail.get("hold_id") in hold_ids
                include = include or bool(linked_highwall_ids.intersection(detail.get("highwall_event_ids", [])))
                include = include or (row["action"] == "sensor_enrolled" and row["actor"] in sensor_ids)
                if include:
                    custody.append(
                        {
                            "id": row["id"],
                            "at": row["at"],
                            "action": row["action"],
                            "actor": row["actor"],
                            "detail": detail,
                        }
                    )
            return {
                "case": case,
                "events": events,
                "batches": batches,
                "sensors": sensors,
                "reviews": reviews,
                "legal_holds": holds,
                "highwall_events": case.get("highwall_events", []),
                "custody": custody,
            }
        finally:
            connection.close()

    def record_evidence_package(
        self,
        *,
        package_id: str,
        case_id: str,
        created_at: str,
        directory_path: str,
        archive_path: str | None,
        manifest_sha256: str,
        package_sha256: str | None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        parse_iso8601(created_at, "created_at")
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
            raise ValidationError("manifest_sha256 must be lowercase SHA-256 hex")
        if package_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", package_sha256):
            raise ValidationError("package_sha256 must be lowercase SHA-256 hex")
        actor = _bounded_text(actor or "local-operator", "actor", 128)
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone() is None:
                connection.rollback()
                raise StorageError(f"case not found: {case_id}")
            connection.execute(
                """
                INSERT INTO evidence_packages(
                    package_id, case_id, created_at, directory_path, archive_path,
                    manifest_sha256, package_sha256, status, actor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'valid', ?)
                """,
                (
                    package_id,
                    case_id,
                    created_at,
                    directory_path,
                    archive_path,
                    manifest_sha256,
                    package_sha256,
                    actor,
                ),
            )
            connection.execute(
                "UPDATE cases SET evidence_package_id = ?, updated_at = ? WHERE case_id = ?",
                (package_id, created_at, case_id),
            )
            self._audit(
                connection,
                "evidence_exported",
                actor,
                {
                    "case_id": case_id,
                    "package_id": package_id,
                    "directory_path": directory_path,
                    "archive_path": archive_path,
                    "manifest_sha256": manifest_sha256,
                },
            )
            connection.commit()
            return {
                "package_id": package_id,
                "case_id": case_id,
                "created_at": created_at,
                "directory_path": directory_path,
                "archive_path": archive_path,
                "manifest_sha256": manifest_sha256,
                "package_sha256": package_sha256,
                "status": "valid",
                "actor": actor,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_evidence_packages(self, case_id: str | None = None) -> list[dict[str, Any]]:
        connection = _connect(self.path)
        try:
            if case_id is None:
                rows = connection.execute(
                    "SELECT * FROM evidence_packages ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM evidence_packages WHERE case_id = ? ORDER BY created_at DESC",
                    (case_id,),
                ).fetchall()
            return [
                {
                    "package_id": row["package_id"],
                    "case_id": row["case_id"],
                    "created_at": row["created_at"],
                    "directory_path": row["directory_path"],
                    "archive_path": row["archive_path"],
                    "manifest_sha256": row["manifest_sha256"],
                    "package_sha256": row["package_sha256"],
                    "status": row["status"],
                    "actor": row["actor"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def list_canary_deployments(self, sensor_id: str | None = None) -> list[dict[str, Any]]:
        connection = _connect(self.path)
        try:
            if sensor_id is None:
                rows = connection.execute(
                    "SELECT * FROM canary_deployments ORDER BY sensor_id, created_at"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM canary_deployments WHERE sensor_id = ? ORDER BY created_at",
                    (sensor_id,),
                ).fetchall()
            return [
                {
                    "sensor_id": row["sensor_id"],
                    "group_id": row["group_id"],
                    "token_hash": row["token_hash"],
                    "token_type": row["token_type"],
                    "endpoint_ids": _json_list(row["endpoint_ids_json"]),
                    "active": bool(row["active"]),
                    "created_at": row["created_at"],
                    "retired_at": row["retired_at"],
                    "replaced_by": row["replaced_by"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def import_highwall_events(
        self,
        *,
        source: str,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        source = _bounded_text(source, "source", 64)
        if not _HIGHWALL_EVENT_TYPE_RE.fullmatch(source):
            raise ValidationError("source contains unsupported characters")
        if not isinstance(events, list) or not 1 <= len(events) <= 500:
            raise ValidationError("Highwall events must be a list of 1 to 500 entries")
        normalized = [_normalize_highwall_item(source, item) for item in events]
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            inserted_ids: list[str] = []
            duplicate_count = 0
            case_ids_to_refresh: set[str] = set()
            for item in normalized:
                external_id = item["external_id"]
                payload_json = canonical_json(item).decode("utf-8")
                payload_hash = sha256_hex(canonical_json(item))
                existing = connection.execute(
                    "SELECT highwall_event_id, payload_sha256 FROM highwall_events WHERE source = ? AND external_id = ?",
                    (source, external_id),
                ).fetchone()
                if existing is not None:
                    if existing["payload_sha256"] != payload_hash:
                        connection.rollback()
                        raise StorageConflict(
                            f"Highwall event {source}/{external_id} already exists with different content"
                        )
                    duplicate_count += 1
                    continue
                highwall_event_id = "hwe_" + sha256_hex(
                    canonical_json({"source": source, "external_id": external_id})
                )
                observed = parse_iso8601(item["observed_at"], "observed_at")
                window = timedelta(seconds=ASSOCIATION_WINDOW_SECONDS)
                connection.execute(
                    """
                    INSERT INTO highwall_events(
                        highwall_event_id, source, external_id, event_type, source_ip,
                        observed_at, received_at, payload_json, payload_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        highwall_event_id,
                        source,
                        external_id,
                        item["event_type"],
                        item.get("source_ip"),
                        item["observed_at"],
                        utc_now(),
                        payload_json,
                        payload_hash,
                    ),
                )
                inserted_ids.append(highwall_event_id)

                if item.get("source_ip"):
                    case_rows = connection.execute(
                        """
                        SELECT DISTINCT ce.case_id FROM case_events ce
                        JOIN events e ON e.event_id = ce.event_id
                        WHERE e.source_ip = ? AND e.observed_at >= ? AND e.observed_at <= ?
                        ORDER BY ce.case_id
                        """,
                        (
                            item["source_ip"],
                            format_utc(observed - window),
                            format_utc(observed + window),
                        ),
                    ).fetchall()
                    for case_row in case_rows:
                        case_ids_to_refresh.add(case_row["case_id"])

            refresh_time = utc_now()
            for case_id in sorted(case_ids_to_refresh):
                self._refresh_case(connection, case_id, refresh_time)

            self._audit(
                connection,
                "highwall_events_imported",
                source,
                {
                    "source": source,
                    "accepted": len(inserted_ids),
                    "duplicates": duplicate_count,
                    "highwall_event_ids": inserted_ids,
                },
            )
            connection.commit()
            return {
                "status": "accepted" if inserted_ids else "duplicate",
                "source": source,
                "accepted": len(inserted_ids),
                "duplicates": duplicate_count,
                "highwall_event_ids": inserted_ids,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_highwall_events(
        self,
        *,
        source: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValidationError("limit must be between 1 and 500")
        connection = _connect(self.path)
        try:
            if source is None:
                rows = connection.execute(
                    "SELECT * FROM highwall_events ORDER BY observed_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM highwall_events WHERE source = ? ORDER BY observed_at DESC LIMIT ?",
                    (source, limit),
                ).fetchall()
            return [
                {
                    "highwall_event_id": row["highwall_event_id"],
                    "source": row["source"],
                    "external_id": row["external_id"],
                    "event_type": row["event_type"],
                    "source_ip": row["source_ip"],
                    "observed_at": row["observed_at"],
                    "received_at": row["received_at"],
                    "payload_sha256": row["payload_sha256"],
                    "payload": _json_object(row["payload_json"]),
                }
                for row in rows
            ]
        finally:
            connection.close()

    def sync_canary_deployments(
        self,
        *,
        sensor_id: str,
        matrix_id: str,
        generated_at: str,
        snapshot_sha256: str,
        deployments: list[CanaryDeployment],
    ) -> dict[str, Any]:
        parse_iso8601(generated_at, "generated_at")
        if not re.fullmatch(r"[0-9a-f]{64}", snapshot_sha256):
            raise ValidationError("snapshot_sha256 must be lowercase SHA-256 hex")
        if len(deployments) > 256:
            raise ValidationError("canary deployment list exceeds 256 groups")
        seen_group_ids: set[str] = set()
        seen_hashes: set[str] = set()
        by_group: dict[str, CanaryDeployment] = {}
        for deployment in deployments:
            deployment.validate()
            if deployment.group_id in seen_group_ids:
                raise ValidationError(f"duplicate canary group_id: {deployment.group_id}")
            if deployment.token_hash in seen_hashes:
                raise ValidationError("duplicate canary token hash in snapshot")
            seen_group_ids.add(deployment.group_id)
            seen_hashes.add(deployment.token_hash)
            by_group[deployment.group_id] = deployment

        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            sensor = connection.execute(
                "SELECT matrix_id FROM sensors WHERE sensor_id = ?",
                (sensor_id,),
            ).fetchone()
            if sensor is None:
                connection.rollback()
                raise StorageError("unknown sensor")
            if sensor["matrix_id"] != matrix_id:
                connection.rollback()
                raise StorageConflict("canary snapshot matrix_id does not match registered sensor")
            endpoint_rows = connection.execute(
                "SELECT endpoint_id FROM endpoints WHERE sensor_id = ?",
                (sensor_id,),
            ).fetchall()
            known_endpoints = {row["endpoint_id"] for row in endpoint_rows}
            for deployment in deployments:
                missing = set(deployment.endpoint_ids) - known_endpoints
                if missing:
                    connection.rollback()
                    raise ValidationError(
                        f"canary group {deployment.group_id} references unregistered endpoints: {sorted(missing)}"
                    )

            state = connection.execute(
                "SELECT * FROM canary_sync_state WHERE sensor_id = ?",
                (sensor_id,),
            ).fetchone()
            if state is not None:
                if state["snapshot_sha256"] == snapshot_sha256:
                    connection.rollback()
                    return {
                        "status": "duplicate",
                        "sensor_id": sensor_id,
                        "snapshot_sha256": snapshot_sha256,
                    }
                if parse_iso8601(generated_at, "generated_at") < parse_iso8601(
                    state["generated_at"], "generated_at"
                ):
                    connection.rollback()
                    raise StorageConflict("stale canary snapshot: generated_at is older than the last accepted sync")

            existing_rows = connection.execute(
                "SELECT * FROM canary_deployments WHERE sensor_id = ?",
                (sensor_id,),
            ).fetchall()
            existing = {row["group_id"]: row for row in existing_rows}
            accepted = 0
            updated = 0
            retired = 0
            for group_id, deployment in by_group.items():
                row = existing.get(group_id)
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO canary_deployments(
                            sensor_id, group_id, token_hash, token_type, endpoint_ids_json,
                            active, created_at, retired_at, replaced_by
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sensor_id,
                            group_id,
                            deployment.token_hash,
                            deployment.token_type,
                            canonical_json(deployment.endpoint_ids).decode("utf-8"),
                            1 if deployment.active else 0,
                            deployment.created_at,
                            deployment.retired_at,
                            deployment.replaced_by,
                        ),
                    )
                    accepted += 1
                    continue

                if row["token_hash"] != deployment.token_hash:
                    connection.rollback()
                    raise StorageConflict(f"canary group {group_id} changed token_hash")
                if row["token_type"] != deployment.token_type:
                    connection.rollback()
                    raise StorageConflict(f"canary group {group_id} changed token_type")
                if row["created_at"] != deployment.created_at:
                    connection.rollback()
                    raise StorageConflict(f"canary group {group_id} changed created_at")
                was_active = bool(row["active"])
                if not was_active and deployment.active:
                    connection.rollback()
                    raise StorageConflict(f"retired canary group {group_id} cannot become active again")
                endpoint_ids = _json_list(row["endpoint_ids_json"])
                if not was_active and list(deployment.endpoint_ids) != endpoint_ids:
                    connection.rollback()
                    raise StorageConflict(f"retired canary group {group_id} changed endpoint_ids")
                if (
                    not deployment.active
                    and row["retired_at"] is not None
                    and row["retired_at"] != deployment.retired_at
                ):
                    connection.rollback()
                    raise StorageConflict(f"canary group {group_id} changed retired_at")
                if (
                    not deployment.active
                    and row["replaced_by"] is not None
                    and row["replaced_by"] != deployment.replaced_by
                ):
                    connection.rollback()
                    raise StorageConflict(f"canary group {group_id} changed replaced_by")

                changed = (
                    endpoint_ids != list(deployment.endpoint_ids)
                    or was_active != deployment.active
                    or row["retired_at"] != deployment.retired_at
                    or row["replaced_by"] != deployment.replaced_by
                )
                connection.execute(
                    """
                    UPDATE canary_deployments SET
                        endpoint_ids_json = ?, active = ?, retired_at = ?, replaced_by = ?
                    WHERE sensor_id = ? AND group_id = ?
                    """,
                    (
                        canonical_json(deployment.endpoint_ids).decode("utf-8"),
                        1 if deployment.active else 0,
                        deployment.retired_at,
                        deployment.replaced_by,
                        sensor_id,
                        group_id,
                    ),
                )
                if changed:
                    updated += 1
                if was_active and not deployment.active:
                    retired += 1

            for group_id, row in existing.items():
                if group_id in by_group or not bool(row["active"]):
                    continue
                connection.execute(
                    """
                    UPDATE canary_deployments SET active = 0, retired_at = ?, replaced_by = NULL
                    WHERE sensor_id = ? AND group_id = ?
                    """,
                    (generated_at, sensor_id, group_id),
                )
                retired += 1

            synced_at = utc_now()
            connection.execute(
                """
                INSERT INTO canary_sync_state(sensor_id, snapshot_sha256, generated_at, synced_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sensor_id) DO UPDATE SET
                    snapshot_sha256 = excluded.snapshot_sha256,
                    generated_at = excluded.generated_at,
                    synced_at = excluded.synced_at
                """,
                (sensor_id, snapshot_sha256, generated_at, synced_at),
            )
            self._audit(
                connection,
                "canary_snapshot_synced",
                sensor_id,
                {
                    "snapshot_sha256": snapshot_sha256,
                    "generated_at": generated_at,
                    "groups": len(deployments),
                    "accepted": accepted,
                    "updated": updated,
                    "retired": retired,
                },
            )
            connection.commit()
            return {
                "status": "accepted",
                "sensor_id": sensor_id,
                "snapshot_sha256": snapshot_sha256,
                "accepted": accepted,
                "updated": updated,
                "retired": retired,
                "total": len(deployments),
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def ingest_batch(self, payload: dict[str, Any], events: list[Event]) -> dict[str, Any]:
        connection = _connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            payload_hash = sha256_hex(canonical_json(payload))
            existing_batch = connection.execute(
                "SELECT payload_sha256 FROM batches WHERE batch_id = ?",
                (payload["batch_id"],),
            ).fetchone()
            if existing_batch:
                connection.rollback()
                if existing_batch["payload_sha256"] != payload_hash:
                    raise StorageConflict("batch_id already exists with a different payload")
                return {
                    "status": "duplicate",
                    "batch_id": payload["batch_id"],
                    "accepted_events": 0,
                }
            sensor = connection.execute(
                "SELECT last_sequence FROM sensors WHERE sensor_id = ?",
                (payload["sensor_id"],),
            ).fetchone()
            if not sensor:
                connection.rollback()
                raise StorageError("unknown sensor")
            last_sequence = int(sensor["last_sequence"])
            if int(payload["sequence_end"]) <= last_sequence:
                connection.rollback()
                raise SequenceError(
                    f"sequence rollback: batch ends at {payload['sequence_end']}, sensor is at {last_sequence}"
                )
            sequence_gap = int(payload["sequence_start"]) > last_sequence + 1
            received_at = utc_now()
            connection.execute(
                """
                INSERT INTO batches(batch_id, sensor_id, sequence_start, sequence_end, received_at, payload_sha256, payload_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'accepted')
                """,
                (
                    payload["batch_id"],
                    payload["sensor_id"],
                    payload["sequence_start"],
                    payload["sequence_end"],
                    received_at,
                    payload_hash,
                    canonical_json(payload).decode("utf-8"),
                ),
            )
            accepted_events = 0
            duplicate_events = 0
            accepted_event_ids: list[str] = []
            for event in events:
                if event.sensor_id != payload["sensor_id"] or event.matrix_id != payload["matrix_id"]:
                    connection.rollback()
                    raise StorageError("event belongs to a different sensor or matrix")
                if event.sequence < int(payload["sequence_start"]) or event.sequence > int(payload["sequence_end"]):
                    connection.rollback()
                    raise StorageError("event sequence is outside the batch range")
                existing_event = connection.execute(
                    "SELECT event_id, sequence, event_json FROM events WHERE event_id = ? OR (sensor_id = ? AND sequence = ?)",
                    (event.event_id, event.sensor_id, event.sequence),
                ).fetchall()
                if existing_event:
                    identical = len(existing_event) == 1 and all(
                        row["event_id"] == event.event_id and int(row["sequence"]) == event.sequence
                        for row in existing_event
                    )
                    if identical:
                        stored_event = Event.from_dict(json.loads(existing_event[0]["event_json"]))
                        identical = canonical_json(stored_event.to_signing_dict()) == canonical_json(
                            event.to_signing_dict()
                        )
                    if identical:
                        duplicate_events += 1
                        continue
                    connection.rollback()
                    raise StorageConflict("event_id or sequence conflicts with different evidence content")
                stored = event.to_dict()
                stored["received_at"] = received_at
                connection.execute(
                    """
                    INSERT INTO events(event_id, sensor_id, matrix_id, endpoint_id, sequence, observed_at, received_at, source_ip, transport, event_json, batch_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.sensor_id,
                        event.matrix_id,
                        event.endpoint_id,
                        event.sequence,
                        event.observed_at,
                        received_at,
                        event.source_ip,
                        event.transport,
                        canonical_json(stored).decode("utf-8"),
                        payload["batch_id"],
                    ),
                )
                self._associate_event(connection, event, received_at)
                accepted_event_ids.append(event.event_id)
                accepted_events += 1
            if accepted_event_ids:
                placeholders = ",".join("?" for _ in accepted_event_ids)
                case_rows = connection.execute(
                    f"SELECT DISTINCT case_id FROM case_events WHERE event_id IN ({placeholders})",
                    tuple(accepted_event_ids),
                ).fetchall()
                for case_row in case_rows:
                    self._refresh_case(connection, case_row["case_id"], received_at)
            connection.execute(
                "UPDATE sensors SET last_seen = ?, last_sequence = ? WHERE sensor_id = ?",
                (received_at, max(last_sequence, int(payload["sequence_end"])), payload["sensor_id"]),
            )
            if sequence_gap:
                self._audit(
                    connection,
                    "sequence_gap",
                    payload["sensor_id"],
                    {
                        "batch_id": payload["batch_id"],
                        "expected_start": last_sequence + 1,
                        "actual_start": payload["sequence_start"],
                    },
                )
            self._audit(
                connection,
                "batch_accepted",
                payload["sensor_id"],
                {
                    "batch_id": payload["batch_id"],
                    "accepted_events": accepted_events,
                    "duplicate_events": duplicate_events,
                    "sequence_gap": sequence_gap,
                },
            )
            connection.commit()
            return {
                "status": "accepted",
                "batch_id": payload["batch_id"],
                "accepted_events": accepted_events,
                "duplicate_events": duplicate_events,
                "sequence_gap": sequence_gap,
            }
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StorageConflict("event or batch conflicts with existing evidence") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def stats(self) -> dict[str, Any]:
        connection = _connect(self.path)
        try:
            sensors = connection.execute("SELECT COUNT(*) AS count FROM sensors").fetchone()
            endpoints = connection.execute("SELECT COUNT(*) AS count FROM endpoints").fetchone()
            batches = connection.execute("SELECT COUNT(*) AS count FROM batches").fetchone()
            events = connection.execute("SELECT COUNT(*) AS count FROM events").fetchone()
            audit = connection.execute("SELECT COUNT(*) AS count FROM audit_log").fetchone()
            cases = connection.execute("SELECT COUNT(*) AS count FROM cases").fetchone()
            canaries = connection.execute("SELECT COUNT(*) AS count FROM canary_deployments").fetchone()
            active_holds = connection.execute(
                "SELECT COUNT(*) AS count FROM legal_holds WHERE status = 'active'"
            ).fetchone()
            highwall = connection.execute("SELECT COUNT(*) AS count FROM highwall_events").fetchone()
            packages = connection.execute(
                "SELECT COUNT(*) AS count FROM evidence_packages WHERE status = 'valid'"
            ).fetchone()
            return {
                "sensors": int(sensors["count"] or 0),
                "endpoints": int(endpoints["count"] or 0),
                "batches": int(batches["count"] or 0),
                "events": int(events["count"] or 0),
                "audit_rows": int(audit["count"] or 0),
                "cases": int(cases["count"] or 0),
                "canary_deployments": int(canaries["count"] or 0),
                "active_legal_holds": int(active_holds["count"] or 0),
                "highwall_events": int(highwall["count"] or 0),
                "valid_evidence_packages": int(packages["count"] or 0),
            }
        finally:
            connection.close()

