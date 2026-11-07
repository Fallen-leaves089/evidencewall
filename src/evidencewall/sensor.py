from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import __version__
from .batch import MAX_BATCH_EVENTS, build_batch
from .canary import CanaryStore
from .config import SensorPaths, load_sensor_home, save_sensor_meta
from .crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    canonical_json,
    public_key_text,
    sha256_hex,
)
from .domain import Endpoint, EndpointMatrix, Event, ValidationError, new_id, utc_now
from .net import NetworkError, get_json, normalize_base_url, post_json
from .storage import SensorStore


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
        return self.store.append_event(self.make_test_event(**kwargs))

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
        buffer_bytes = 0
        for path in (
            self.paths.buffer,
            self.paths.buffer.with_name(self.paths.buffer.name + "-wal"),
            self.paths.buffer.with_name(self.paths.buffer.name + "-shm"),
        ):
            try:
                buffer_bytes += path.stat().st_size
            except FileNotFoundError:
                pass
        return {
            "sensor_id": self.sensor_id,
            "matrix_id": self.matrix_id,
            "collector_url": self.meta.get("collector_url"),
            "endpoint_count": len(self.matrix.endpoints),
            "buffer_bytes": buffer_bytes,
            **self.canaries.stats(),
            **self.store.stats(),
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

