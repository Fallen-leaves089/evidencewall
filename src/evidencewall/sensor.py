from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__
from .batch import MAX_BATCH_EVENTS, build_batch
from .canary import CanaryStore
from .config import (
    DEFAULT_BUFFER_MAX_BYTES,
    DEFAULT_BUFFER_MAX_EVENTS,
    DEFAULT_MIN_FREE_DISK_BYTES,
    SensorPaths,
    load_sensor_home,
    save_sensor_meta,
)
from .crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    canonical_json,
    public_key_text,
    sha256_hex,
    sign_payload,
)
from .domain import Endpoint, EndpointMatrix, Event, ValidationError, new_id, utc_now
from .net import NetworkError, get_json, normalize_base_url, post_json
from .profiles import get_profile
from .storage import SensorStore

HEALTH_SCHEMA_VERSION = 1
CLOCK_SKEW_WARNING_MS = 60_000
BUFFER_CACHE_SECONDS = 1.0
STORAGE_FAILURE_COOLDOWN_SECONDS = 5.0
BUFFER_DEGRADED_RATIO = 0.8
BUFFER_RECLAIM_COOLDOWN_SECONDS = 60.0


class SensorError(RuntimeError):
    pass


class SensorRuntime:
    def __init__(
        self,
        paths: SensorPaths,
        meta: dict[str, Any],
        matrix: EndpointMatrix,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
    ):
        self.paths = paths
        self.meta = meta
        self.matrix = matrix
        self.private_key = private_key
        self.public_key = public_key
        self.store = SensorStore(paths.buffer, meta["sensor_id"], meta["matrix_id"], private_key)
        self.canaries = CanaryStore.load(paths.canaries)
        self._last_canary_sync: str | None = None
        self._buffer_lock = threading.Lock()
        self._append_lock = threading.Lock()
        self._buffer_cache: dict[str, Any] | None = None
        self._buffer_cache_at = 0.0
        self._storage_failure_until = 0.0
        self._storage_failure_reason: str | None = None
        self._reclaim_lock = threading.Lock()
        self._last_reclaim_attempt: float | None = None
        self._last_reclaim_error: str | None = None

    @classmethod
    def open(cls, home: Path) -> "SensorRuntime":
        paths, meta, matrix, private_key, public_key = load_sensor_home(home)
        return cls(paths, meta, matrix, private_key, public_key)

    @property
    def sensor_id(self) -> str:
        return self.meta["sensor_id"]

    @property
    def matrix_id(self) -> str:
        return self.meta["matrix_id"]

    def choose_endpoint(self, endpoint_id: str | None = None) -> Endpoint:
        candidates = [endpoint for endpoint in self.matrix.endpoints if endpoint.enabled]
        if endpoint_id:
            for endpoint in candidates:
                if endpoint.endpoint_id == endpoint_id:
                    return endpoint
            raise ValidationError(f"enabled endpoint not found: {endpoint_id}")
        if not candidates:
            raise ValidationError("matrix has no enabled endpoints")
        return candidates[0]

    def make_test_event(
        self,
        *,
        endpoint_id: str | None = None,
        path: str = "/.env",
        source_ip: str = "198.51.100.10",
        source_port: int = 45678,
        canaries: list[str] | None = None,
    ) -> Event:
        endpoint = self.choose_endpoint(endpoint_id)
        is_http = endpoint.transport == "http1"
        event = Event(
            event_id=new_id("evt"),
            sensor_id=self.sensor_id,
            matrix_id=self.matrix_id,
            endpoint_id=endpoint.endpoint_id,
            sequence=0,
            observed_at=utc_now(),
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=endpoint.listen_ip,
            destination_port=endpoint.listen_port,
            advertised_ip=endpoint.advertised_ip,
            advertised_port=endpoint.advertised_port,
            transport=endpoint.transport,
            profile_id=endpoint.profile_id,
            source_quality=endpoint.source_quality,
            method="GET" if is_http else None,
            scheme="http" if is_http else None,
            host=endpoint.advertised_ip if is_http else None,
            path=path if is_http else None,
            headers_fingerprint=sha256_hex(b"evidencewall-test-headers") if is_http else None,
            body_size=0 if is_http else None,
            body_sha256=sha256_hex(b"") if is_http else None,
            first_payload_size=0,
            first_payload_sha256=sha256_hex(b""),
            canary_hashes=[sha256_hex(value) for value in (canaries or [])],
            response_status=200 if is_http else None,
            tarpit_ms=0,
        )
        event.validate(allow_unsequenced=True)
        return event

    def enqueue_test_event(self, **kwargs: Any) -> Event:
        return self.append_event(self.make_test_event(**kwargs))

    def _buffer_file_bytes(self) -> int:
        total = 0
        for path in (
            self.paths.buffer,
            self.paths.buffer.with_name(self.paths.buffer.name + "-wal"),
            self.paths.buffer.with_name(self.paths.buffer.name + "-shm"),
        ):
            try:
                total += path.stat().st_size
            except FileNotFoundError:
                pass
            except OSError:
                pass
        return total

    def _disk_free_bytes(self) -> int | None:
        try:
            return int(shutil.disk_usage(str(self.paths.buffer.parent)).free)
        except OSError:
            return None

    def _buffer_limit(self, key: str, default: int) -> int:
        value = self.meta.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return default
        return value

    def _buffer_limits(self) -> tuple[int, int, int]:
        return (
            self._buffer_limit("buffer_max_events", DEFAULT_BUFFER_MAX_EVENTS),
            self._buffer_limit("buffer_max_bytes", DEFAULT_BUFFER_MAX_BYTES),
            self._buffer_limit("min_free_disk_bytes", DEFAULT_MIN_FREE_DISK_BYTES),
        )

    def _attempt_buffer_reclaim(self, now: float) -> bool:
        if (
            self._last_reclaim_attempt is not None
            and now - self._last_reclaim_attempt < BUFFER_RECLAIM_COOLDOWN_SECONDS
        ):
            return False
        if not self._reclaim_lock.acquire(blocking=False):
            return False
        try:
            self._last_reclaim_attempt = now
            try:
                self.store.reclaim_space()
            except Exception as exc:
                self._last_reclaim_error = str(exc)[:256] or exc.__class__.__name__
            else:
                self._last_reclaim_error = None
            return True
        finally:
            self._reclaim_lock.release()

    def buffer_state(self, *, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._buffer_lock:
            if (
                not force
                and self._buffer_cache is not None
                and now - self._buffer_cache_at < BUFFER_CACHE_SECONDS
            ):
                return dict(self._buffer_cache)
            failure_until = self._storage_failure_until
            failure_reason = self._storage_failure_reason

        storage_error: str | None = None
        try:
            stats = self.store.stats()
        except Exception as exc:
            storage_error = str(exc)[:256] or exc.__class__.__name__
            stats = {
                "total_events": 0,
                "unsent_events": 0,
                "sent_events": 0,
                "last_sequence": 0,
                "pending_batches": 0,
            }
        buffer_bytes = self._buffer_file_bytes()
        disk_free_bytes = self._disk_free_bytes()
        max_events, max_bytes, min_free_disk_bytes = self._buffer_limits()
        if (
            storage_error is None
            and buffer_bytes >= max_bytes
            and int(stats["unsent_events"]) < max_events
            and disk_free_bytes is not None
            and disk_free_bytes > min_free_disk_bytes
            and self._attempt_buffer_reclaim(now)
        ):
            buffer_bytes = self._buffer_file_bytes()
            disk_free_bytes = self._disk_free_bytes()
        blocked_reasons: list[str] = []
        warnings: list[str] = []

        if storage_error is not None:
            blocked_reasons.append(f"cannot read local buffer state: {storage_error}")
        if int(stats["unsent_events"]) >= max_events:
            blocked_reasons.append(f"unsent event limit reached ({max_events})")
        if buffer_bytes >= max_bytes:
            detail = f"buffer byte limit reached ({max_bytes})"
            if self._last_reclaim_error:
                detail += f"; compaction failed: {self._last_reclaim_error}"
            blocked_reasons.append(detail)
        if disk_free_bytes is None:
            blocked_reasons.append("cannot determine free disk space")
        elif disk_free_bytes <= min_free_disk_bytes:
            blocked_reasons.append(
                f"low free disk space ({disk_free_bytes} <= {min_free_disk_bytes})"
            )
        if now < failure_until:
            blocked_reasons.append(failure_reason or "recent storage write failure")

        if int(stats["unsent_events"]) >= int(max_events * BUFFER_DEGRADED_RATIO):
            warnings.append("unsent event buffer is above 80% of its configured limit")
        if buffer_bytes >= int(max_bytes * BUFFER_DEGRADED_RATIO):
            warnings.append("buffer bytes are above 80% of the configured limit")
        if disk_free_bytes is not None and disk_free_bytes <= min_free_disk_bytes * 2:
            warnings.append("free disk space is within 2x the configured minimum")

        accepting = not blocked_reasons
        if blocked_reasons:
            status = "blocked"
        elif warnings:
            status = "degraded"
        else:
            status = "ok"
        state = {
            "status": status,
            "accepting": accepting,
            "blocked_reasons": blocked_reasons,
            "warnings": warnings,
            "total_events": int(stats["total_events"]),
            "unsent_events": int(stats["unsent_events"]),
            "sent_events": int(stats["sent_events"]),
            "last_sequence": int(stats["last_sequence"]),
            "pending_batches": int(stats["pending_batches"]),
            "buffer_bytes": buffer_bytes,
            "disk_free_bytes": disk_free_bytes,
            "max_events": max_events,
            "max_bytes": max_bytes,
            "min_free_disk_bytes": min_free_disk_bytes,
        }
        with self._buffer_lock:
            self._buffer_cache = state
            self._buffer_cache_at = now
        return dict(state)

    def mark_storage_failure(self, reason: str) -> None:
        with self._buffer_lock:
            self._storage_failure_until = max(
                self._storage_failure_until,
                time.monotonic() + STORAGE_FAILURE_COOLDOWN_SECONDS,
            )
            self._storage_failure_reason = reason[:256]
            self._buffer_cache = None

    def append_event(self, event: Event) -> Event:
        with self._append_lock:
            state = self.buffer_state()
            if not state["accepting"]:
                detail = "; ".join(state["blocked_reasons"]) or "buffer is blocked"
                raise SensorError(f"sensor buffer is not accepting events: {detail}")
            try:
                stored = self.store.append_event(event, max_events=state["max_events"])
            except Exception as exc:
                self.mark_storage_failure(f"storage write failed: {exc}")
                raise
            with self._buffer_lock:
                self._storage_failure_until = 0.0
                self._storage_failure_reason = None
                self._buffer_cache = None
            return stored

    def _default_endpoint_health(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for endpoint in self.matrix.endpoints:
            try:
                profile_version = get_profile(endpoint.profile_id).version
            except Exception:
                profile_version = None
            mapping_consistent = None
            if endpoint.exposure == "direct":
                mapping_consistent = (
                    endpoint.listen_ip == endpoint.advertised_ip
                    and endpoint.listen_port == endpoint.advertised_port
                )
            result.append(
                {
                    "endpoint_id": endpoint.endpoint_id,
                    "enabled": endpoint.enabled,
                    "listening": False,
                    "listen_ip": endpoint.listen_ip,
                    "listen_port": endpoint.listen_port,
                    "advertised_ip": endpoint.advertised_ip,
                    "advertised_port": endpoint.advertised_port,
                    "transport": endpoint.transport,
                    "profile_id": endpoint.profile_id,
                    "profile_version": profile_version,
                    "source_quality": endpoint.source_quality,
                    "mapping_consistent": mapping_consistent,
                }
            )
        return result

    def build_health_payload(
        self,
        *,
        sent_at: str | None = None,
        endpoint_health: list[dict[str, Any]] | None = None,
        signed: bool = True,
    ) -> dict[str, Any]:
        state = self.buffer_state()
        payload: dict[str, Any] = {
            "schema_version": HEALTH_SCHEMA_VERSION,
            "sensor_id": self.sensor_id,
            "matrix_id": self.matrix_id,
            "sent_at": sent_at or utc_now(),
            "version": __version__,
            "status": state["status"],
            "queue_depth": state["unsent_events"],
            "buffer_bytes": state["buffer_bytes"],
            "disk_free_bytes": state["disk_free_bytes"],
            "buffer": {
                "accepting": state["accepting"],
                "blocked_reasons": state["blocked_reasons"],
                "warnings": state["warnings"],
                "max_events": state["max_events"],
                "max_bytes": state["max_bytes"],
                "min_free_disk_bytes": state["min_free_disk_bytes"],
                "pending_batches": state["pending_batches"],
            },
            "endpoints": endpoint_health if endpoint_health is not None else self._default_endpoint_health(),
        }
        if signed:
            payload["sensor_signature"] = sign_payload(self.private_key, payload)
        return payload

    def report_health(
        self,
        *,
        collector_url: str | None = None,
        endpoint_health: list[dict[str, Any]] | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        configured = collector_url or self.meta.get("collector_url")
        if not configured:
            return {"status": "not_configured", "detail": "run sensor enroll or pass --collector-url"}
        payload = self.build_health_payload(endpoint_health=endpoint_health)
        try:
            status, body = post_json(
                f"{normalize_base_url(configured)}/v1/sensors/health",
                payload,
                timeout=timeout,
            )
        except NetworkError as exc:
            return {"status": "deferred", "detail": str(exc)}
        if status not in (200, 201) or body.get("status") not in {"accepted", "duplicate"}:
            return {
                "status": "rejected",
                "http_status": status,
                "response": body,
            }

        clock_skew_ms = body.get("clock_skew_ms")
        if isinstance(clock_skew_ms, bool) or not isinstance(clock_skew_ms, int):
            clock_skew_ms = None
        clock_skew_exceeded = body.get("clock_skew_exceeded")
        if not isinstance(clock_skew_exceeded, bool):
            clock_skew_exceeded = (
                abs(clock_skew_ms) > CLOCK_SKEW_WARNING_MS if clock_skew_ms is not None else None
            )
        now = utc_now()
        updated = dict(self.meta)
        updated["last_health"] = {
            "reported_at": now,
            "collector_time": body.get("collector_time"),
            "clock_skew_ms": clock_skew_ms,
            "clock_skew_exceeded": clock_skew_exceeded,
            "status": payload["status"],
            "collector_health_status": body.get("health_status"),
            "queue_depth": payload["queue_depth"],
            "buffer_bytes": payload["buffer_bytes"],
            "disk_free_bytes": payload["disk_free_bytes"],
            "endpoints": payload["endpoints"],
        }
        save_sensor_meta(self.paths, updated)
        self.meta = updated
        return {
            "status": body.get("status", "accepted"),
            "clock_skew_ms": clock_skew_ms,
            "clock_skew_exceeded": clock_skew_exceeded,
            "collector_time": body.get("collector_time"),
            "health_status": body.get("health_status"),
        }

    def enroll(self, collector_url: str, token: str, *, timeout: float = 10.0) -> dict[str, Any]:
        url = normalize_base_url(collector_url)
        payload = {
            "sensor_id": self.sensor_id,
            "matrix_id": self.matrix_id,
            "public_key": public_key_text(self.public_key),
            "endpoints": [endpoint.to_dict() for endpoint in self.matrix.endpoints],
            "canaries": self.canaries.deployment_payload(),
            "metadata": {"version": __version__},
        }
        status, body = post_json(
            f"{url}/v1/sensors/enroll",
            payload,
            headers={"X-Enroll-Token": token},
            timeout=timeout,
        )
        if status not in (200, 201):
            raise SensorError(f"enrollment failed with HTTP {status}: {body}")
        updated = dict(self.meta)
        updated["collector_url"] = url
        save_sensor_meta(self.paths, updated)
        self.meta = updated
        return body

    def _canary_snapshot_fingerprint(self) -> str:
        return sha256_hex(canonical_json(self.canaries.deployment_payload()))

    def sync_canaries(
        self,
        *,
        collector_url: str | None = None,
        timeout: float = 10.0,
        force: bool = False,
    ) -> dict[str, Any]:
        configured = collector_url or self.meta.get("collector_url")
        if not configured:
            return {"status": "not_configured", "detail": "run sensor enroll or pass --collector-url"}
        fingerprint = self._canary_snapshot_fingerprint()
        if not force and self._last_canary_sync == fingerprint:
            return {"status": "unchanged", "snapshot_sha256": fingerprint}
        url = normalize_base_url(configured)
        payload = self.canaries.build_sync_payload(
            self.private_key,
            sensor_id=self.sensor_id,
            matrix_id=self.matrix_id,
        )
        try:
            status, body = post_json(f"{url}/v1/sensors/canaries", payload, timeout=timeout)
        except NetworkError as exc:
            return {"status": "deferred", "snapshot_sha256": fingerprint, "detail": str(exc)}
        if status in (200, 201) and body.get("status") in {"accepted", "duplicate"}:
            self._last_canary_sync = fingerprint
            return {"status": body["status"], "snapshot_sha256": fingerprint, "response": body}
        return {
            "status": "rejected",
            "snapshot_sha256": fingerprint,
            "http_status": status,
            "response": body,
        }

    def flush_once(self, *, collector_url: str | None = None, timeout: float = 10.0) -> dict[str, Any]:
        configured = collector_url or self.meta.get("collector_url")
        if not configured:
            return {"status": "not_configured", "detail": "run sensor enroll or pass --collector-url"}
        canary_sync = self.sync_canaries(collector_url=configured, timeout=timeout)
        canary_summary = {
            key: value
            for key, value in canary_sync.items()
            if key in {"status", "snapshot_sha256", "http_status", "detail"}
        }
        url = normalize_base_url(configured)
        pending = self.store.get_pending_batch()
        if pending is None:
            events = self.store.get_unsent_events(MAX_BATCH_EVENTS)
            if not events:
                return {"status": "empty", "detail": "no unsent events", "canary_sync": canary_summary}
            batch = build_batch(events, self.private_key, self.sensor_id, self.matrix_id)
            pending = self.store.create_pending_batch(batch, [event.sequence for event in events])
        try:
            status, body = post_json(f"{url}/v1/events:batch", pending, timeout=timeout)
        except NetworkError as exc:
            return {"status": "deferred", "batch_id": pending["batch_id"], "detail": str(exc)}
        if status in (200, 201) and body.get("status") in {"accepted", "duplicate"}:
            self.store.mark_batch_sent(pending["batch_id"])
            return {
                "status": body["status"],
                "batch_id": pending["batch_id"],
                "response": body,
                "canary_sync": canary_summary,
            }
        return {
            "status": "rejected",
            "batch_id": pending["batch_id"],
            "http_status": status,
            "response": body,
            "canary_sync": canary_summary,
        }

    def flush_loop(self, *, interval: float = 5.0, once: bool = False) -> None:
        while True:
            result = self.flush_once()
            print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
            if once:
                return
            time.sleep(max(1.0, interval))

    def status(self) -> dict[str, Any]:
        state = self.buffer_state(force=True)
        last_health = self.meta.get("last_health")
        if not isinstance(last_health, dict):
            last_health = {}
        return {
            "sensor_id": self.sensor_id,
            "matrix_id": self.matrix_id,
            "collector_url": self.meta.get("collector_url"),
            "endpoint_count": len(self.matrix.endpoints),
            "buffer_status": state["status"],
            "accepting_events": state["accepting"],
            "blocked_reasons": state["blocked_reasons"],
            "warnings": state["warnings"],
            "buffer_bytes": state["buffer_bytes"],
            "disk_free_bytes": state["disk_free_bytes"],
            "buffer_limits": {
                "max_events": state["max_events"],
                "max_bytes": state["max_bytes"],
                "min_free_disk_bytes": state["min_free_disk_bytes"],
            },
            "last_health": last_health,
            "clock_skew_ms": last_health.get("clock_skew_ms"),
            "clock_skew_exceeded": last_health.get("clock_skew_exceeded"),
            "health_status": last_health.get("collector_health_status") or last_health.get("status"),
            "total_events": state["total_events"],
            "unsent_events": state["unsent_events"],
            "sent_events": state["sent_events"],
            "last_sequence": state["last_sequence"],
            "pending_batches": state["pending_batches"],
            **self.canaries.stats(),
        }

    def collector_health(self) -> dict[str, Any]:
        configured = self.meta.get("collector_url")
        if not configured:
            return {"status": "not_configured"}
        try:
            status, body = get_json(f"{normalize_base_url(configured)}/healthz")
        except (NetworkError, ValueError) as exc:
            return {"status": "unreachable", "detail": str(exc)}
        return {"status": "ok" if status == 200 else "error", "http_status": status, "response": body}

