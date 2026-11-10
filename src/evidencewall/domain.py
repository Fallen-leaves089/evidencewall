from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 1
MAX_ENDPOINTS = 256
TRANSPORTS = frozenset({"http1", "tcp"})
EXPOSURES = frozenset({"direct", "nat", "proxy", "edge"})
SOURCE_QUALITIES = frozenset({"direct", "nat", "edge-provided"})
CANARY_TYPES = frozenset(
    {
        "api-key",
        "download-url",
        "webhook-url",
        "cookie",
        "admin-token",
        "object-url",
    }
)
CASE_STATUSES = frozenset({"new", "reviewing", "confirmed", "dismissed"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})
DEFAULT_SOURCE_QUALITY = {
    "direct": "direct",
    "nat": "nat",
    "proxy": "edge-provided",
    "edge": "edge-provided",
}

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso8601(value: str, field_name: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty ISO-8601 string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"{field_name} is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _check_id(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"{field_name} must match {_ID_RE.pattern}")


def _check_text(value: Any, field_name: str, *, max_length: int = 4096, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValidationError(f"{field_name} must be a non-empty string without NUL bytes")
    if len(value) > max_length:
        raise ValidationError(f"{field_name} is too long")


def _check_int(
    value: Any,
    field_name: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    optional: bool = False,
) -> None:
    if value is None and optional:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValidationError(f"{field_name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{field_name} must be <= {maximum}")


def _check_ip(value: Any, field_name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be an IP address string")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"{field_name} is not a valid IP address") from exc


def _check_network(value: Any, field_name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a CIDR string")
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(f"{field_name} is not a valid network") from exc


def _check_sha256(value: Any, field_name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValidationError(f"{field_name} must be a lowercase SHA-256 hex digest")


def _check_id_list(value: Any, field_name: str, *, minimum: int = 0, maximum: int = 256) -> None:
    if not isinstance(value, list) or len(value) < minimum or len(value) > maximum:
        raise ValidationError(f"{field_name} must be a list with {minimum}..{maximum} entries")
    seen: set[str] = set()
    for item in value:
        _check_id(item, field_name)
        if item in seen:
            raise ValidationError(f"{field_name} contains duplicate id: {item}")
        seen.add(item)


def _check_sha256_list(value: Any, field_name: str, *, maximum: int = 256) -> None:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValidationError(f"{field_name} must be a list of at most {maximum} hashes")
    seen: set[str] = set()
    for item in value:
        _check_sha256(item, field_name)
        if item in seen:
            raise ValidationError(f"{field_name} contains a duplicate hash")
        seen.add(item)


@dataclass
class Endpoint:
    endpoint_id: str
    sensor_id: str
    matrix_id: str
    listen_ip: str
    listen_port: int
    advertised_ip: str
    advertised_port: int
    transport: str
    profile_id: str
    exposure: str = "direct"
    source_quality: str = "direct"
    enabled: bool = True
    config_version: int = 1

    def validate(self) -> None:
        _check_id(self.endpoint_id, "endpoint_id")
        _check_id(self.sensor_id, "sensor_id")
        _check_id(self.matrix_id, "matrix_id")
        _check_ip(self.listen_ip, "listen_ip")
        _check_int(self.listen_port, "listen_port", minimum=1, maximum=65535)
        _check_ip(self.advertised_ip, "advertised_ip")
        if ipaddress.ip_address(self.advertised_ip).is_unspecified:
            raise ValidationError("advertised_ip must not be unspecified")
        _check_int(self.advertised_port, "advertised_port", minimum=1, maximum=65535)
        if self.transport not in TRANSPORTS:
            raise ValidationError(f"transport must be one of {sorted(TRANSPORTS)}")
        _check_text(self.profile_id, "profile_id", max_length=128)
        if self.exposure not in EXPOSURES:
            raise ValidationError(f"exposure must be one of {sorted(EXPOSURES)}")
        if self.source_quality not in SOURCE_QUALITIES:
            raise ValidationError(f"source_quality must be one of {sorted(SOURCE_QUALITIES)}")
        if not isinstance(self.enabled, bool):
            raise ValidationError("enabled must be a boolean")
        _check_int(self.config_version, "config_version", minimum=1)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Endpoint":
        if not isinstance(data, dict):
            raise ValidationError("endpoint must be an object")
        allowed = {
            "endpoint_id",
            "sensor_id",
            "matrix_id",
            "listen_ip",
            "listen_port",
            "advertised_ip",
            "advertised_port",
            "transport",
            "profile_id",
            "exposure",
            "source_quality",
            "enabled",
            "config_version",
        }
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown endpoint fields: {sorted(unknown)}")
        for required in ("endpoint_id", "sensor_id", "matrix_id", "listen_ip", "listen_port", "transport", "profile_id"):
            if required not in data:
                raise ValidationError(f"endpoint missing required field: {required}")
        exposure = data.get("exposure", "direct")
        endpoint = cls(
            endpoint_id=data["endpoint_id"],
            sensor_id=data["sensor_id"],
            matrix_id=data["matrix_id"],
            listen_ip=data["listen_ip"],
            listen_port=data["listen_port"],
            advertised_ip=data.get("advertised_ip", data["listen_ip"]),
            advertised_port=data.get("advertised_port", data["listen_port"]),
            transport=data["transport"],
            profile_id=data["profile_id"],
            exposure=exposure,
            source_quality=data.get("source_quality") or DEFAULT_SOURCE_QUALITY.get(exposure, "direct"),
            enabled=data.get("enabled", True),
            config_version=data.get("config_version", 1),
        )
        endpoint.validate()
        return endpoint

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def listen_key(self) -> tuple[str, int]:
        return self.listen_ip, self.listen_port

    @property
    def advertised_key(self) -> tuple[str, int]:
        return self.advertised_ip, self.advertised_port


@dataclass
class EndpointMatrix:
    matrix_id: str
    sensor_id: str
    endpoints: list[Endpoint] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> None:
        _check_id(self.matrix_id, "matrix_id")
        _check_id(self.sensor_id, "sensor_id")
        if self.schema_version != SCHEMA_VERSION:
            raise ValidationError(f"unsupported matrix schema_version: {self.schema_version}")
        if len(self.endpoints) > MAX_ENDPOINTS:
            raise ValidationError(f"matrix has more than {MAX_ENDPOINTS} endpoints")
        ids: set[str] = set()
        listen_keys: set[tuple[str, int]] = set()
        advertised_keys: set[tuple[str, int]] = set()
        for endpoint in self.endpoints:
            endpoint.validate()
            if endpoint.sensor_id != self.sensor_id:
                raise ValidationError(f"endpoint {endpoint.endpoint_id} has a different sensor_id")
            if endpoint.matrix_id != self.matrix_id:
                raise ValidationError(f"endpoint {endpoint.endpoint_id} has a different matrix_id")
            if endpoint.endpoint_id in ids:
                raise ValidationError(f"duplicate endpoint_id: {endpoint.endpoint_id}")
            if endpoint.listen_key in listen_keys:
                raise ValidationError(f"duplicate listen endpoint: {endpoint.listen_ip}:{endpoint.listen_port}")
            if endpoint.advertised_key in advertised_keys:
                raise ValidationError(f"duplicate advertised endpoint: {endpoint.advertised_ip}:{endpoint.advertised_port}")
            ids.add(endpoint.endpoint_id)
            listen_keys.add(endpoint.listen_key)
            advertised_keys.add(endpoint.advertised_key)

    def add_endpoint(self, endpoint: Endpoint) -> Endpoint:
        if len(self.endpoints) >= MAX_ENDPOINTS:
            raise ValidationError(f"matrix has reached the {MAX_ENDPOINTS} endpoint limit")
        if endpoint.sensor_id and endpoint.sensor_id != self.sensor_id:
            raise ValidationError("endpoint sensor_id does not match matrix")
        if endpoint.matrix_id and endpoint.matrix_id != self.matrix_id:
            raise ValidationError("endpoint matrix_id does not match matrix")
        endpoint = replace(endpoint, sensor_id=self.sensor_id, matrix_id=self.matrix_id)
        endpoint.validate()
        self.validate_candidate(endpoint)
        self.endpoints.append(endpoint)
        return endpoint

    def validate_candidate(self, endpoint: Endpoint) -> None:
        if any(existing.endpoint_id == endpoint.endpoint_id for existing in self.endpoints):
            raise ValidationError(f"duplicate endpoint_id: {endpoint.endpoint_id}")
        if any(existing.listen_key == endpoint.listen_key for existing in self.endpoints):
            raise ValidationError(f"duplicate listen endpoint: {endpoint.listen_ip}:{endpoint.listen_port}")
        if any(existing.advertised_key == endpoint.advertised_key for existing in self.endpoints):
            raise ValidationError(f"duplicate advertised endpoint: {endpoint.advertised_ip}:{endpoint.advertised_port}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointMatrix":
        if not isinstance(data, dict):
            raise ValidationError("matrix must be an object")
        allowed = {"schema_version", "matrix_id", "sensor_id", "endpoints"}
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown matrix fields: {sorted(unknown)}")
        for required in ("matrix_id", "sensor_id", "endpoints"):
            if required not in data:
                raise ValidationError(f"matrix missing required field: {required}")
        if not isinstance(data["endpoints"], list):
            raise ValidationError("matrix endpoints must be a list")
        endpoints: list[Endpoint] = []
        for raw in data["endpoints"]:
            if not isinstance(raw, dict):
                raise ValidationError("matrix endpoint must be an object")
            item = dict(raw)
            item.setdefault("sensor_id", data["sensor_id"])
            item.setdefault("matrix_id", data["matrix_id"])
            endpoints.append(Endpoint.from_dict(item))
        matrix = cls(
            matrix_id=data["matrix_id"],
            sensor_id=data["sensor_id"],
            endpoints=endpoints,
            schema_version=data.get("schema_version", SCHEMA_VERSION),
        )
        matrix.validate()
        return matrix

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "matrix_id": self.matrix_id,
            "sensor_id": self.sensor_id,
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
        }


@dataclass
class CanaryGroup:
    group_id: str
    token_type: str
    token: str
    token_hash: str
    endpoint_ids: list[str]
    created_at: str
    active: bool = True
    retired_at: str | None = None
    replaced_by: str | None = None

    def validate(self) -> None:
        _check_id(self.group_id, "group_id")
        if self.token_type not in CANARY_TYPES:
            raise ValidationError(f"token_type must be one of {sorted(CANARY_TYPES)}")
        _check_text(self.token, "token", max_length=4096)
        if len(self.token) < 32:
            raise ValidationError("canary token must contain at least 128 bits of encoded randomness")
        _check_sha256(self.token_hash, "token_hash")
        _check_id_list(self.endpoint_ids, "endpoint_ids", minimum=1)
        parse_iso8601(self.created_at, "created_at")
        if not isinstance(self.active, bool):
            raise ValidationError("active must be a boolean")
        if self.retired_at is not None:
            parse_iso8601(self.retired_at, "retired_at")
        if self.replaced_by is not None:
            _check_id(self.replaced_by, "replaced_by")
        if self.active and self.retired_at is not None:
            raise ValidationError("active canary group must not have retired_at")
        if self.active and self.replaced_by is not None:
            raise ValidationError("active canary group must not have replaced_by")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CanaryGroup":
        if not isinstance(data, dict):
            raise ValidationError("canary group must be an object")
        allowed = set(cls.__dataclass_fields__.keys())
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown canary group fields: {sorted(unknown)}")
        for required in (
            "group_id",
            "token_type",
            "token",
            "token_hash",
            "endpoint_ids",
            "created_at",
        ):
            if required not in data:
                raise ValidationError(f"canary group missing required field: {required}")
        group = cls(
            group_id=data["group_id"],
            token_type=data["token_type"],
            token=data["token"],
            token_hash=data["token_hash"],
            endpoint_ids=list(data["endpoint_ids"]),
            created_at=data["created_at"],
            active=data.get("active", True),
            retired_at=data.get("retired_at"),
            replaced_by=data.get("replaced_by"),
        )
        group.validate()
        return group

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_public_dict(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("token", None)
        return payload


@dataclass
class CanaryDeployment:
    group_id: str
    token_type: str
    token_hash: str
    endpoint_ids: list[str]
    created_at: str
    active: bool = True
    retired_at: str | None = None
    replaced_by: str | None = None

    def validate(self) -> None:
        _check_id(self.group_id, "group_id")
        if self.token_type not in CANARY_TYPES:
            raise ValidationError(f"token_type must be one of {sorted(CANARY_TYPES)}")
        _check_sha256(self.token_hash, "token_hash")
        _check_id_list(self.endpoint_ids, "endpoint_ids", minimum=1)
        parse_iso8601(self.created_at, "created_at")
        if not isinstance(self.active, bool):
            raise ValidationError("active must be a boolean")
        if self.retired_at is not None:
            parse_iso8601(self.retired_at, "retired_at")
        if self.replaced_by is not None:
            _check_id(self.replaced_by, "replaced_by")
        if self.active and self.retired_at is not None:
            raise ValidationError("active canary deployment must not have retired_at")
        if self.active and self.replaced_by is not None:
            raise ValidationError("active canary deployment must not have replaced_by")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CanaryDeployment":
        if not isinstance(data, dict):
            raise ValidationError("canary deployment must be an object")
        allowed = set(cls.__dataclass_fields__.keys())
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown canary deployment fields: {sorted(unknown)}")
        for required in ("group_id", "token_type", "token_hash", "endpoint_ids", "created_at"):
            if required not in data:
                raise ValidationError(f"canary deployment missing required field: {required}")
        deployment = cls(
            group_id=data["group_id"],
            token_type=data["token_type"],
            token_hash=data["token_hash"],
            endpoint_ids=list(data["endpoint_ids"]),
            created_at=data["created_at"],
            active=data.get("active", True),
            retired_at=data.get("retired_at"),
            replaced_by=data.get("replaced_by"),
        )
        deployment.validate()
        return deployment

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Event:
    event_id: str
    sensor_id: str
    matrix_id: str
    endpoint_id: str
    sequence: int
    observed_at: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    advertised_ip: str
    advertised_port: int
    transport: str
    profile_id: str
    source_quality: str
    received_at: str | None = None
    source_asn: int | None = None
    source_prefix: str | None = None
    method: str | None = None
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    headers_fingerprint: str | None = None
    tls_fingerprint: str | None = None
    body_size: int | None = None
    body_sha256: str | None = None
    first_payload_size: int | None = None
    first_payload_sha256: str | None = None
    canary_hashes: list[str] = field(default_factory=list)
    response_status: int | None = None
    tarpit_ms: int = 0
    highwall_event_id: str | None = None
    sensor_signature: str | None = None

    def validate(self, *, allow_unsequenced: bool = False) -> None:
        _check_id(self.event_id, "event_id")
        _check_id(self.sensor_id, "sensor_id")
        _check_id(self.matrix_id, "matrix_id")
        _check_id(self.endpoint_id, "endpoint_id")
        if allow_unsequenced and self.sequence == 0:
            pass
        else:
            _check_int(self.sequence, "sequence", minimum=1)
        parse_iso8601(self.observed_at, "observed_at")
        if self.received_at is not None:
            parse_iso8601(self.received_at, "received_at")
        _check_ip(self.source_ip, "source_ip")
        _check_int(self.source_port, "source_port", minimum=0, maximum=65535)
        _check_ip(self.destination_ip, "destination_ip")
        _check_int(self.destination_port, "destination_port", minimum=1, maximum=65535)
        _check_ip(self.advertised_ip, "advertised_ip")
        _check_int(self.advertised_port, "advertised_port", minimum=1, maximum=65535)
        if self.transport not in TRANSPORTS:
            raise ValidationError(f"transport must be one of {sorted(TRANSPORTS)}")
        _check_text(self.profile_id, "profile_id", max_length=128)
        if self.source_quality not in SOURCE_QUALITIES:
            raise ValidationError(f"source_quality must be one of {sorted(SOURCE_QUALITIES)}")
        _check_int(self.source_asn, "source_asn", minimum=0, maximum=4294967295, optional=True)
        _check_network(self.source_prefix, "source_prefix", optional=True)
        _check_text(self.method, "method", max_length=32, optional=True)
        _check_text(self.scheme, "scheme", max_length=16, optional=True)
        _check_text(self.host, "host", max_length=255, optional=True)
        _check_text(self.path, "path", max_length=4096, optional=True)
        _check_text(self.headers_fingerprint, "headers_fingerprint", max_length=256, optional=True)
        _check_text(self.tls_fingerprint, "tls_fingerprint", max_length=256, optional=True)
        _check_int(self.body_size, "body_size", minimum=0, maximum=1_000_000_000, optional=True)
        _check_sha256(self.body_sha256, "body_sha256", optional=True)
        _check_int(self.first_payload_size, "first_payload_size", minimum=0, maximum=1_000_000_000, optional=True)
        _check_sha256(self.first_payload_sha256, "first_payload_sha256", optional=True)
        if not isinstance(self.canary_hashes, list) or len(self.canary_hashes) > 32:
            raise ValidationError("canary_hashes must be a list of at most 32 hashes")
        for canary_hash in self.canary_hashes:
            _check_sha256(canary_hash, "canary_hash")
        _check_int(self.response_status, "response_status", minimum=100, maximum=599, optional=True)
        _check_int(self.tarpit_ms, "tarpit_ms", minimum=0, maximum=86_400_000)
        _check_text(self.highwall_event_id, "highwall_event_id", max_length=256, optional=True)
        _check_text(self.sensor_signature, "sensor_signature", max_length=512, optional=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        if not isinstance(data, dict):
            raise ValidationError("event must be an object")
        allowed = set(cls.__dataclass_fields__.keys())
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown event fields: {sorted(unknown)}")
        required = (
            "event_id",
            "sensor_id",
            "matrix_id",
            "endpoint_id",
            "sequence",
            "observed_at",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "advertised_ip",
            "advertised_port",
            "transport",
            "profile_id",
            "source_quality",
        )
        for field_name in required:
            if field_name not in data:
                raise ValidationError(f"event missing required field: {field_name}")
        event = cls(
            event_id=data["event_id"],
            sensor_id=data["sensor_id"],
            matrix_id=data["matrix_id"],
            endpoint_id=data["endpoint_id"],
            sequence=data["sequence"],
            observed_at=data["observed_at"],
            source_ip=data["source_ip"],
            source_port=data["source_port"],
            destination_ip=data["destination_ip"],
            destination_port=data["destination_port"],
            advertised_ip=data["advertised_ip"],
            advertised_port=data["advertised_port"],
            transport=data["transport"],
            profile_id=data["profile_id"],
            source_quality=data["source_quality"],
            received_at=data.get("received_at"),
            source_asn=data.get("source_asn"),
            source_prefix=data.get("source_prefix"),
            method=data.get("method"),
            scheme=data.get("scheme"),
            host=data.get("host"),
            path=data.get("path"),
            headers_fingerprint=data.get("headers_fingerprint"),
            tls_fingerprint=data.get("tls_fingerprint"),
            body_size=data.get("body_size"),
            body_sha256=data.get("body_sha256"),
            first_payload_size=data.get("first_payload_size"),
            first_payload_sha256=data.get("first_payload_sha256"),
            canary_hashes=list(data.get("canary_hashes") or []),
            response_status=data.get("response_status"),
            tarpit_ms=data.get("tarpit_ms", 0),
            highwall_event_id=data.get("highwall_event_id"),
            sensor_signature=data.get("sensor_signature"),
        )
        event.validate()
        return event

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_signing_dict(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("received_at", None)
        payload.pop("sensor_signature", None)
        return payload

    def with_sequence(self, sequence: int) -> "Event":
        return replace(self, sequence=sequence)

    def with_signature(self, signature: str) -> "Event":
        return replace(self, sensor_signature=signature)


@dataclass
class Case:
    case_id: str
    title: str
    first_seen: str
    last_seen: str
    status: str
    confidence: str
    event_count: int
    sensor_ids: list[str]
    endpoint_ids: list[str]
    source_ips: list[str]
    source_quality: str
    asns: list[int] = field(default_factory=list)
    canary_hashes: list[str] = field(default_factory=list)
    fingerprints: list[str] = field(default_factory=list)
    scan_shape: list[dict[str, Any]] = field(default_factory=list)
    confidence_signals: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)
    evidence_hashes: list[str] = field(default_factory=list)
    evidence_package_id: str | None = None
    legal_hold_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        _check_id(self.case_id, "case_id")
        _check_text(self.title, "title", max_length=512)
        parse_iso8601(self.first_seen, "first_seen")
        parse_iso8601(self.last_seen, "last_seen")
        if parse_iso8601(self.last_seen, "last_seen") < parse_iso8601(self.first_seen, "first_seen"):
            raise ValidationError("last_seen must not be earlier than first_seen")
        if self.status not in CASE_STATUSES:
            raise ValidationError(f"status must be one of {sorted(CASE_STATUSES)}")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise ValidationError(f"confidence must be one of {sorted(CONFIDENCE_LEVELS)}")
        _check_int(self.event_count, "event_count", minimum=0)
        _check_id_list(self.sensor_ids, "sensor_ids")
        _check_id_list(self.endpoint_ids, "endpoint_ids")
        if not isinstance(self.source_ips, list) or not self.source_ips:
            raise ValidationError("source_ips must be a non-empty list")
        for source_ip in self.source_ips:
            _check_ip(source_ip, "source_ip")
        if self.source_quality not in SOURCE_QUALITIES:
            raise ValidationError(f"source_quality must be one of {sorted(SOURCE_QUALITIES)}")
        for asn in self.asns:
            _check_int(asn, "asn", minimum=0, maximum=4294967295)
        _check_sha256_list(self.canary_hashes, "canary_hashes")
        _check_sha256_list(self.fingerprints, "fingerprints")
        _check_sha256_list(self.evidence_hashes, "evidence_hashes")
        parse_iso8601(self.created_at, "created_at")
        parse_iso8601(self.updated_at, "updated_at")
        if self.evidence_package_id is not None:
            _check_id(self.evidence_package_id, "evidence_package_id")
        if self.legal_hold_id is not None:
            _check_id(self.legal_hold_id, "legal_hold_id")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

