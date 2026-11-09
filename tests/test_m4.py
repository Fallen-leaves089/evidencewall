from __future__ import annotations

import asyncio
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from evidencewall.batch import build_batch, verify_batch
from evidencewall.cli import main
from evidencewall.collector import CollectorRuntime
from evidencewall.config import (
    default_data_root,
    init_collector_home,
    init_sensor_home,
    load_collector_identity,
    save_matrix,
)
from evidencewall.crypto import CryptoError, public_key_text, sha256_hex
from evidencewall.domain import Endpoint, format_utc
from evidencewall.listener import SensorListenerService
from evidencewall.profiles import get_profile
from evidencewall.sensor import SensorError, SensorRuntime
from evidencewall.storage import CollectorStore, StorageError


def add_sensor(
    root: Path,
    index: int,
    *,
    exposure: str = "nat",
) -> tuple[SensorRuntime, Endpoint]:
    home = root / f"sensor-{index}"
    paths, meta, matrix = init_sensor_home(home)
    if exposure == "direct":
        advertised_ip = "127.0.0.1"
        advertised_port = 19000 + index
        source_quality = "direct"
    else:
        advertised_ip = f"203.0.113.{20 + index}"
        advertised_port = 19000 + index
        source_quality = "nat"
    endpoint = Endpoint(
        endpoint_id=f"ep_{index}",
        sensor_id=meta["sensor_id"],
        matrix_id=meta["matrix_id"],
        listen_ip="127.0.0.1",
        listen_port=19000 + index,
        advertised_ip=advertised_ip,
        advertised_port=advertised_port,
        transport="http1",
        profile_id="admin-panel",
        exposure=exposure,
        source_quality=source_quality,
    )
    matrix.add_endpoint(endpoint)
    save_matrix(paths, matrix)
    return SensorRuntime.open(home), endpoint


def enroll(
    store: CollectorStore,
    runtime: SensorRuntime,
    endpoints: list[Endpoint],
    token: str,
) -> None:
    store.create_enrollment_token(sha256_hex(token))
    store.enroll_sensor(
        token_hash=sha256_hex(token),
        sensor_id=runtime.sensor_id,
        matrix_id=runtime.matrix_id,
        public_key=public_key_text(runtime.public_key),
        endpoints=endpoints,
    )


def ingest_event(store: CollectorStore, runtime: SensorRuntime, **kwargs) -> str:
    event = runtime.enqueue_test_event(**kwargs)
    events = runtime.store.get_unsent_events(10)
    batch = build_batch(events, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
    verified = verify_batch(runtime.public_key, batch)
    runtime.store.create_pending_batch(batch, [item.sequence for item in events])
    result = store.ingest_batch(batch, verified)
    if result["status"] != "accepted":
        raise AssertionError(result)
    runtime.store.mark_batch_sent(batch["batch_id"])
    return event.event_id


class CollectorIdentityTests(unittest.TestCase):
    def test_missing_collector_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths, _meta, _token = init_collector_home(Path(temp) / "collector")
            paths.private_key.unlink()
            with self.assertRaises(CryptoError):
                load_collector_identity(paths)


class CollectorMigrationTests(unittest.TestCase):
    def test_existing_database_recreates_sensor_health_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "collector"
            paths, _meta, _token = init_collector_home(home)
            connection = sqlite3.connect(str(paths.database))
            try:
                with connection:
                    connection.execute("DROP TABLE sensor_health")
            finally:
                connection.close()

            CollectorRuntime.open(home)

            connection = sqlite3.connect(str(paths.database))
            try:
                row = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sensor_health'"
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(row[0], "sensor_health")


class SensorHealthApiTests(unittest.TestCase):
    def test_health_reporting_clock_skew_and_tamper_counting(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            runtime, endpoint = add_sensor(root, 1)
            enroll(collector.store, runtime, [endpoint], "health-token")
            client = TestClient(collector.app())

            future = format_utc(datetime.now(timezone.utc) + timedelta(seconds=120))
            health = runtime.build_health_payload(
                sent_at=future,
                endpoint_health=runtime._default_endpoint_health(),
            )
            response = client.post("/v1/sensors/health", json=health)
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["status"], "accepted")
            self.assertTrue(result["clock_skew_exceeded"])
            self.assertGreater(result["clock_skew_ms"], 60_000)

            sensors = client.get("/v1/sensors").json()["sensors"]
            self.assertEqual(len(sensors), 1)
            sensor_health = sensors[0]["health"]
            self.assertEqual(sensor_health["status"], "ok")
            self.assertTrue(sensor_health["clock_skew_exceeded"])
            self.assertIsNotNone(sensor_health["last_health_at"])

            endpoints = client.get("/v1/endpoints").json()["endpoints"]
            self.assertEqual(len(endpoints), 1)
            self.assertFalse(endpoints[0]["listening"])
            self.assertTrue(endpoints[0]["config_matches"])
            self.assertEqual(endpoints[0]["profile_version"], "2026.11")

            tampered = dict(health)
            tampered["queue_depth"] = int(tampered["queue_depth"]) + 1
            rejected = client.post("/v1/sensors/health", json=tampered)
            self.assertEqual(rejected.status_code, 400)
            after = client.get("/v1/sensors").json()["sensors"][0]["health"]
            self.assertEqual(after["signature_failures"], 1)

    def test_invalid_case_status_returns_400(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            init_collector_home(Path(temp) / "collector")
            collector = CollectorRuntime.open(Path(temp) / "collector")
            client = TestClient(collector.app())
            response = client.get("/v1/cases", params={"status": "invalid"})
            self.assertEqual(response.status_code, 400)


class SensorBufferLimitTests(unittest.TestCase):
    def test_event_limit_blocks_until_acknowledged_batch_is_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "sensor"
            paths, meta, matrix = init_sensor_home(home, buffer_max_events=1)
            endpoint = Endpoint(
                endpoint_id="ep_limit",
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                listen_ip="127.0.0.1",
                listen_port=19100,
                advertised_ip="203.0.113.30",
                advertised_port=19100,
                transport="http1",
                profile_id="admin-panel",
                exposure="nat",
                source_quality="nat",
            )
            matrix.add_endpoint(endpoint)
            save_matrix(paths, matrix)
            runtime = SensorRuntime.open(home)

            runtime.enqueue_test_event(path="/one")
            status = runtime.status()
            self.assertEqual(status["buffer_status"], "blocked")
            self.assertFalse(status["accepting_events"])
            with self.assertRaises(SensorError):
                runtime.enqueue_test_event(path="/two")

            events = runtime.store.get_unsent_events(10)
            batch = build_batch(events, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            runtime.store.create_pending_batch(batch, [item.sequence for item in events])
            self.assertTrue(runtime.store.mark_batch_sent(batch["batch_id"]))
            self.assertTrue(runtime.buffer_state(force=True)["accepting"])
            runtime.enqueue_test_event(path="/three")
            self.assertEqual(runtime.store.stats()["unsent_events"], 1)

    def test_byte_limit_blocks_new_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "sensor"
            paths, meta, matrix = init_sensor_home(home, buffer_max_bytes=1)
            endpoint = Endpoint(
                endpoint_id="ep_bytes",
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                listen_ip="127.0.0.1",
                listen_port=19101,
                advertised_ip="203.0.113.31",
                advertised_port=19101,
                transport="http1",
                profile_id="admin-panel",
                exposure="nat",
                source_quality="nat",
            )
            matrix.add_endpoint(endpoint)
            save_matrix(paths, matrix)
            runtime = SensorRuntime.open(home)
            self.assertEqual(runtime.buffer_state(force=True)["status"], "blocked")
            with self.assertRaises(SensorError):
                runtime.enqueue_test_event(path="/blocked")

    def test_byte_limit_recovers_after_sqlite_high_water(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            runtime, _endpoint = add_sensor(Path(temp), 4)
            runtime.meta["buffer_max_bytes"] = 128 * 1024
            runtime.meta["min_free_disk_bytes"] = 1024
            for index in range(80):
                runtime.store.append_event(
                    runtime.make_test_event(path=f"/{'x' * 900}-{index}")
                )
            self.assertGreater(runtime._buffer_file_bytes(), 128 * 1024)

            events = runtime.store.get_unsent_events(500)
            batch = build_batch(events, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            runtime.store.create_pending_batch(batch, [event.sequence for event in events])
            with patch("evidencewall.storage.SENT_EVENT_RETENTION", 10):
                self.assertTrue(runtime.store.mark_batch_sent(batch["batch_id"]))
            self.assertGreater(runtime._buffer_file_bytes(), 128 * 1024)

            state = runtime.buffer_state(force=True)
            self.assertTrue(state["accepting"], state["blocked_reasons"])
            self.assertLess(runtime._buffer_file_bytes(), 128 * 1024)
            next_event = runtime.store.append_event(runtime.make_test_event(path="/after-compaction"))
            self.assertGreater(next_event.sequence, 80)

    def test_low_disk_space_blocks_new_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "sensor"
            paths, meta, matrix = init_sensor_home(home)
            endpoint = Endpoint(
                endpoint_id="ep_disk",
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                listen_ip="127.0.0.1",
                listen_port=19102,
                advertised_ip="203.0.113.32",
                advertised_port=19102,
                transport="http1",
                profile_id="admin-panel",
                exposure="nat",
                source_quality="nat",
            )
            matrix.add_endpoint(endpoint)
            save_matrix(paths, matrix)
            runtime = SensorRuntime.open(home)
            with patch.object(runtime, "_disk_free_bytes", return_value=1024):
                state = runtime.buffer_state(force=True)
                self.assertFalse(state["accepting"])
                self.assertTrue(any("low free disk space" in item for item in state["blocked_reasons"]))
                with self.assertRaises(SensorError):
                    runtime.enqueue_test_event(path="/blocked")

    def test_storage_stats_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            runtime, _endpoint = add_sensor(Path(temp), 3)
            with patch.object(
                runtime.store,
                "stats",
                side_effect=sqlite3.OperationalError("database is locked"),
            ):
                state = runtime.buffer_state(force=True)
                self.assertEqual(state["status"], "blocked")
                self.assertFalse(state["accepting"])
                self.assertTrue(
                    any("cannot read local buffer state" in item for item in state["blocked_reasons"])
                )
                self.assertEqual(runtime.status()["buffer_status"], "blocked")
                with self.assertRaises(SensorError):
                    runtime.enqueue_test_event(path="/blocked")


class ListenerAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_admission_releases_source_count(self) -> None:
        class RecordingWriter:
            def __init__(self) -> None:
                self.closed = False

            def get_extra_info(self, name: str):
                return {
                    "peername": ("198.51.100.25", 40000),
                    "sockname": ("127.0.0.1", 19000),
                }.get(name)

            def is_closing(self) -> bool:
                return self.closed

            def close(self) -> None:
                self.closed = True

            async def wait_closed(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as temp:
            runtime, endpoint = add_sensor(Path(temp), 1)
            service = SensorListenerService(
                runtime,
                max_connections=1,
                max_connections_per_source=1,
            )
            writer = RecordingWriter()
            await service._connection_slots.acquire()
            task = asyncio.create_task(
                service._dispatch(
                    endpoint,
                    get_profile(endpoint.profile_id),
                    object(),
                    writer,
                )
            )
            for _ in range(20):
                if service._active_by_source.get("198.51.100.25") == 1:
                    break
                await asyncio.sleep(0)
            else:
                self.fail("dispatch did not reserve the source connection slot")

            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertNotIn("198.51.100.25", service._active_by_source)
            self.assertTrue(writer.closed)

            service._connection_slots.release()
            await asyncio.wait_for(service._connection_slots.acquire(), timeout=0.1)
            service._connection_slots.release()
            await service.close()


class AssociationHardeningTests(unittest.TestCase):
    def test_shared_canary_merges_direct_and_nat_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            nat, nat_endpoint = add_sensor(root, 1, exposure="nat")
            direct, direct_endpoint = add_sensor(root, 2, exposure="direct")
            enroll(collector.store, nat, [nat_endpoint], "nat-token")
            enroll(collector.store, direct, [direct_endpoint], "direct-token")
            canary_hash = sha256_hex(b"shared-cross-quality-canary")
            ingest_event(
                collector.store,
                nat,
                source_ip="198.51.100.10",
                canaries=[canary_hash],
            )
            ingest_event(
                collector.store,
                direct,
                source_ip="198.51.100.11",
                canaries=[canary_hash],
            )
            cases = collector.store.list_cases()
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["event_count"], 2)
            self.assertEqual(cases[0]["source_ips"], ["198.51.100.10", "198.51.100.11"])
            self.assertIn("distributed_canary_reuse", {item["type"] for item in cases[0]["scan_shape"]})


class EvidenceSnapshotConsistencyTests(unittest.TestCase):
    def test_tampered_case_summary_blocks_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            runtime, endpoint = add_sensor(root, 1)
            enroll(collector.store, runtime, [endpoint], "snapshot-token")
            ingest_event(collector.store, runtime, path="/.env")
            case = collector.store.list_cases()[0]
            snapshot = collector.store.evidence_snapshot(case["case_id"])
            self.assertEqual(len(snapshot["events"]), 1)

            connection = sqlite3.connect(str(collector.paths.database))
            try:
                with connection:
                    connection.execute(
                        "UPDATE cases SET event_count = 99 WHERE case_id = ?",
                        (case["case_id"],),
                    )
            finally:
                connection.close()
            with self.assertRaises(StorageError):
                collector.store.evidence_snapshot(case["case_id"])
            response = TestClient(collector.app()).post(
                f"/v1/cases/{case['case_id']}/export",
                json={"create_archive": False},
            )
            self.assertEqual(response.status_code, 500)
            self.assertIn("inconsistent", response.json()["detail"])


class CliAndPathTests(unittest.TestCase):
    def test_flush_only_runs_one_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "sensor"
            init_sensor_home(home)
            with patch.object(SensorRuntime, "flush_loop") as flush_loop:
                self.assertEqual(
                    main(["sensor", "run", "--home", str(home), "--flush-only"]),
                    0,
                )
                flush_loop.assert_called_once_with(interval=5.0, once=True)

    def test_environment_override_for_default_data_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {"EVIDENCEWALL_HOME": temp}):
                self.assertEqual(default_data_root(), Path(temp))


if __name__ == "__main__":
    unittest.main()
