from __future__ import annotations

import copy
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from fastapi.testclient import TestClient
import uvicorn

from evidencewall.batch import build_batch, verify_batch
from evidencewall.cli import main
from evidencewall.collector import CollectorRuntime
from evidencewall.config import init_collector_home, init_sensor_home, load_sensor_home, save_matrix
from evidencewall.crypto import (
    canonical_json,
    generate_private_key,
    load_public_key_text,
    public_key_text,
    sha256_hex,
    sign_payload,
    verify_payload,
)
from evidencewall.domain import Endpoint, EndpointMatrix, Event, ValidationError
from evidencewall.sensor import SensorRuntime
from evidencewall.storage import CollectorStore, SequenceError, StorageConflict
from evidencewall.net import get_json


def add_test_endpoint(home: Path, *, port: int = 18080, advertised_port: int = 18080) -> tuple:
    paths, meta, matrix = init_sensor_home(home)
    endpoint = Endpoint(
        endpoint_id="ep_test",
        sensor_id=meta["sensor_id"],
        matrix_id=meta["matrix_id"],
        listen_ip="127.0.0.1",
        listen_port=port,
        advertised_ip="203.0.113.10",
        advertised_port=advertised_port,
        transport="http1",
        profile_id="admin-panel",
        exposure="nat",
        source_quality="nat",
    )
    matrix.add_endpoint(endpoint)
    save_matrix(paths, matrix)
    return paths, meta, matrix, endpoint


def make_minimal_event() -> Event:
    event = Event(
        event_id="evt_test_1",
        sensor_id="sensor_test",
        matrix_id="matrix_test",
        endpoint_id="ep_test",
        sequence=1,
        observed_at="2026-11-07T00:00:00.000Z",
        source_ip="198.51.100.10",
        source_port=45678,
        destination_ip="127.0.0.1",
        destination_port=18080,
        advertised_ip="203.0.113.10",
        advertised_port=18080,
        transport="http1",
        profile_id="admin-panel",
        source_quality="nat",
        method="GET",
        scheme="http",
        host="203.0.113.10",
        path="/.env",
        body_size=0,
        body_sha256=sha256_hex(b""),
        first_payload_size=0,
        first_payload_sha256=sha256_hex(b""),
        response_status=200,
        tarpit_ms=0,
    )
    event.validate()
    return event


class DomainTests(unittest.TestCase):
    def test_matrix_roundtrip_and_duplicate_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths, meta, matrix, endpoint = add_test_endpoint(Path(temp) / "sensor")
            loaded = EndpointMatrix.from_dict(matrix.to_dict())
            self.assertEqual(loaded.sensor_id, meta["sensor_id"])
            self.assertEqual(len(loaded.endpoints), 1)
            duplicate_listen = Endpoint(
                endpoint_id="ep_duplicate_listen",
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                listen_ip="127.0.0.1",
                listen_port=18080,
                advertised_ip="203.0.113.11",
                advertised_port=18081,
                transport="http1",
                profile_id="admin-panel",
            )
            with self.assertRaises(ValidationError):
                loaded.add_endpoint(duplicate_listen)
            duplicate_advertised = Endpoint(
                endpoint_id="ep_duplicate_advertised",
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                listen_ip="127.0.0.2",
                listen_port=18082,
                advertised_ip="203.0.113.10",
                advertised_port=18080,
                transport="http1",
                profile_id="admin-panel",
            )
            with self.assertRaises(ValidationError):
                loaded.add_endpoint(duplicate_advertised)
            with self.assertRaises(ValidationError):
                Endpoint.from_dict(
                    {
                        **endpoint.to_dict(),
                        "advertised_ip": "0.0.0.0",
                    }
                )


class CryptoTests(unittest.TestCase):
    def test_event_signature_and_tamper_detection(self) -> None:
        private_key = generate_private_key()
        event = make_minimal_event()
        signature = sign_payload(private_key, event.to_signing_dict())
        signed = event.with_signature(signature)
        public_key = load_public_key_text(public_key_text(private_key.public_key()))
        self.assertTrue(verify_payload(public_key, signed.to_signing_dict(), signed.sensor_signature or ""))
        tampered = signed.with_signature(signature)
        tampered.path = "/admin"
        self.assertFalse(verify_payload(public_key, tampered.to_signing_dict(), signature))


class BufferTests(unittest.TestCase):
    def test_buffer_batch_and_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = Path(temp) / "sensor"
            add_test_endpoint(sensor_home)
            runtime = SensorRuntime.open(sensor_home)
            event = runtime.enqueue_test_event(path="/.env", canaries=["canary-demo"])
            self.assertEqual(event.sequence, 1)
            self.assertTrue(event.sensor_signature)
            self.assertEqual(runtime.status()["unsent_events"], 1)
            self.assertEqual(runtime.flush_once()["status"], "not_configured")
            events = runtime.store.get_unsent_events(10)
            batch = build_batch(events, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            verified = verify_batch(runtime.public_key, batch)
            self.assertEqual(len(verified), 1)
            pending = runtime.store.create_pending_batch(batch, [event.sequence])
            again = runtime.store.get_pending_batch()
            self.assertIsNotNone(again)
            self.assertEqual(pending["batch_id"], again["batch_id"])
            self.assertTrue(runtime.store.mark_batch_sent(batch["batch_id"]))
            stats = runtime.store.stats()
            self.assertEqual(stats["unsent_events"], 0)
            self.assertEqual(stats["pending_batches"], 0)
            self.assertEqual(stats["sent_events"], 1)


class CollectorStoreTests(unittest.TestCase):
    def test_token_rotation_revokes_old_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = Path(temp) / "sensor"
            _paths, meta, _matrix, endpoint = add_test_endpoint(sensor_home)
            runtime = SensorRuntime.open(sensor_home)
            store = CollectorStore(Path(temp) / "collector.db")
            store.create_enrollment_token(sha256_hex("old-token"))
            store.rotate_enrollment_token(sha256_hex("new-token"))
            common = dict(
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                public_key=public_key_text(runtime.public_key),
                endpoints=[endpoint],
            )
            with self.assertRaises(StorageConflict):
                store.enroll_sensor(token_hash=sha256_hex("old-token"), **common)
            result = store.enroll_sensor(token_hash=sha256_hex("new-token"), **common)
            self.assertEqual(result["endpoint_count"], 1)

    def test_enrollment_rejects_duplicate_endpoint_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = Path(temp) / "sensor"
            _paths, meta, _matrix, endpoint = add_test_endpoint(sensor_home)
            runtime = SensorRuntime.open(sensor_home)
            store = CollectorStore(Path(temp) / "collector.db")
            token = "test-enrollment-token"
            store.create_enrollment_token(sha256_hex(token))
            duplicate = Endpoint.from_dict({**endpoint.to_dict(), "endpoint_id": "ep_duplicate"})
            with self.assertRaises(ValidationError):
                store.enroll_sensor(
                    token_hash=sha256_hex(token),
                    sensor_id=meta["sensor_id"],
                    matrix_id=meta["matrix_id"],
                    public_key=public_key_text(runtime.public_key),
                    endpoints=[endpoint, duplicate],
                )
            result = store.enroll_sensor(
                token_hash=sha256_hex(token),
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                public_key=public_key_text(runtime.public_key),
                endpoints=[endpoint],
            )
            self.assertEqual(result["endpoint_count"], 1)

    def test_enrollment_ingest_duplicate_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = Path(temp) / "sensor"
            _paths, meta, _matrix, endpoint = add_test_endpoint(sensor_home)
            runtime = SensorRuntime.open(sensor_home)
            store = CollectorStore(Path(temp) / "collector.db")
            token = "test-enrollment-token"
            store.create_enrollment_token(sha256_hex(token))
            registered = store.enroll_sensor(
                token_hash=sha256_hex(token),
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                public_key=public_key_text(runtime.public_key),
                endpoints=[endpoint],
            )
            self.assertEqual(registered["endpoint_count"], 1)
            self.assertIsNotNone(store.get_sensor(meta["sensor_id"]))
            self.assertEqual(len(store.list_endpoints()), 1)

            first = runtime.enqueue_test_event(path="/.env")
            events = runtime.store.get_unsent_events(10)
            batch = build_batch(events, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            verified = verify_batch(runtime.public_key, batch)
            result = store.ingest_batch(batch, verified)
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["accepted_events"], 1)
            duplicate = store.ingest_batch(batch, verified)
            self.assertEqual(duplicate["status"], "duplicate")

            second = runtime.enqueue_test_event(path="/admin")
            events2 = runtime.store.get_unsent_events(10)
            batch2 = build_batch(events2, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            verified2 = verify_batch(runtime.public_key, batch2)
            self.assertEqual(store.ingest_batch(batch2, verified2)["status"], "accepted")
            replay = build_batch([verified[0]], runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            with self.assertRaises(SequenceError):
                store.ingest_batch(replay, [verified[0]])
            self.assertEqual(store.stats()["events"], 2)
            self.assertEqual(store.stats()["sensors"], 1)

    def test_duplicate_detection_requires_identical_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = Path(temp) / "sensor"
            _paths, meta, _matrix, endpoint = add_test_endpoint(sensor_home)
            runtime = SensorRuntime.open(sensor_home)
            store = CollectorStore(Path(temp) / "collector.db")
            token = "test-enrollment-token"
            store.create_enrollment_token(sha256_hex(token))
            store.enroll_sensor(
                token_hash=sha256_hex(token),
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                public_key=public_key_text(runtime.public_key),
                endpoints=[endpoint],
            )

            first = runtime.enqueue_test_event(path="/.env")
            batch = build_batch([first], runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            self.assertEqual(store.ingest_batch(batch, verify_batch(runtime.public_key, batch))["status"], "accepted")

            altered_payload = copy.deepcopy(batch)
            altered_event = Event.from_dict(altered_payload["events"][0])
            altered_event.path = "/tampered"
            altered_event = altered_event.with_signature(
                sign_payload(runtime.private_key, altered_event.to_signing_dict())
            )
            altered_payload["events"][0] = altered_event.to_dict()
            altered_payload["events_sha256"] = sha256_hex(canonical_json(altered_payload["events"]))
            altered_payload["sensor_signature"] = sign_payload(
                runtime.private_key,
                {key: value for key, value in altered_payload.items() if key != "sensor_signature"},
            )
            with self.assertRaises(StorageConflict):
                store.ingest_batch(altered_payload, verify_batch(runtime.public_key, altered_payload))

            second = runtime.enqueue_test_event(path="/admin")
            mixed = build_batch(
                [altered_event, second],
                runtime.private_key,
                runtime.sensor_id,
                runtime.matrix_id,
            )
            with self.assertRaises(StorageConflict):
                store.ingest_batch(mixed, verify_batch(runtime.public_key, mixed))

            replay_with_next = build_batch(
                [Event.from_dict(batch["events"][0]), second],
                runtime.private_key,
                runtime.sensor_id,
                runtime.matrix_id,
            )
            result = store.ingest_batch(
                replay_with_next,
                verify_batch(runtime.public_key, replay_with_next),
            )
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["accepted_events"], 1)
            self.assertEqual(result["duplicate_events"], 1)
            self.assertEqual(store.stats()["events"], 2)


class ApiTests(unittest.TestCase):
    def test_enroll_and_batch_api(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = Path(temp) / "sensor"
            collector_home = Path(temp) / "collector"
            add_test_endpoint(sensor_home)
            _collector_paths, _collector_meta, token = init_collector_home(collector_home)
            runtime = SensorRuntime.open(sensor_home)
            app = CollectorRuntime.open(collector_home).app()
            client = TestClient(app)
            self.assertEqual(client.get("/healthz").status_code, 200)
            chunked = client.post(
                "/v1/events:batch",
                content=iter([b"{}"]),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(chunked.status_code, 411, chunked.text)
            enroll_payload = {
                "sensor_id": runtime.sensor_id,
                "matrix_id": runtime.matrix_id,
                "public_key": public_key_text(runtime.public_key),
                "endpoints": [endpoint.to_dict() for endpoint in runtime.matrix.endpoints],
                "metadata": {"version": "test"},
            }
            wrong = client.post(
                "/v1/sensors/enroll",
                json=enroll_payload,
                headers={"X-Enroll-Token": "wrong-token"},
            )
            self.assertEqual(wrong.status_code, 409)
            enrolled = client.post(
                "/v1/sensors/enroll",
                json=enroll_payload,
                headers={"X-Enroll-Token": token},
            )
            self.assertEqual(enrolled.status_code, 200, enrolled.text)
            runtime.enqueue_test_event(path="/.env")
            events = runtime.store.get_unsent_events(10)
            batch = build_batch(events, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            accepted = client.post("/v1/events:batch", json=batch)
            self.assertEqual(accepted.status_code, 200, accepted.text)
            self.assertEqual(accepted.json()["status"], "accepted")
            duplicate = client.post("/v1/events:batch", json=batch)
            self.assertEqual(duplicate.status_code, 200)
            self.assertEqual(duplicate.json()["status"], "duplicate")
            runtime.enqueue_test_event(path="/admin")
            events2 = runtime.store.get_unsent_events(10)
            batch2 = build_batch(events2, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            batch2["events"][0]["path"] = "/tampered"
            tampered = client.post("/v1/events:batch", json=batch2)
            self.assertEqual(tampered.status_code, 400)
            self.assertEqual(len(client.get("/v1/sensors").json()["sensors"]), 1)
            self.assertEqual(len(client.get("/v1/endpoints").json()["endpoints"]), 1)


class RealHttpIntegrationTests(unittest.TestCase):
    def test_real_http_enroll_and_flush(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = Path(temp) / "sensor"
            collector_home = Path(temp) / "collector"
            add_test_endpoint(sensor_home)
            _collector_paths, _collector_meta, token = init_collector_home(collector_home)
            app = CollectorRuntime.open(collector_home).app()
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="off")
            server = uvicorn.Server(config)
            thread = threading.Thread(target=server.run, daemon=True)
            thread.start()
            try:
                healthy = False
                for _ in range(50):
                    if server.started:
                        status, body = get_json(f"http://127.0.0.1:{port}/healthz")
                        if status == 200 and body.get("status") == "ok":
                            healthy = True
                            break
                    time.sleep(0.1)
                self.assertTrue(healthy, "uvicorn server did not start")
                runtime = SensorRuntime.open(sensor_home)
                enrolled = runtime.enroll(f"http://127.0.0.1:{port}", token)
                self.assertEqual(enrolled["status"], "enrolled")
                event = runtime.enqueue_test_event(path="/.env")
                result = runtime.flush_once(collector_url=f"http://127.0.0.1:{port}")
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(result["response"]["accepted_events"], 1)
                self.assertEqual(runtime.store.stats()["pending_batches"], 0)
                status, sensors = get_json(f"http://127.0.0.1:{port}/v1/sensors")
                self.assertEqual(status, 200)
                self.assertEqual(len(sensors["sensors"]), 1)
                self.assertEqual(sensors["sensors"][0]["last_sequence"], event.sequence)
                status, endpoints = get_json(f"http://127.0.0.1:{port}/v1/endpoints")
                self.assertEqual(status, 200)
                self.assertEqual(len(endpoints["endpoints"]), 1)
            finally:
                server.should_exit = True
                thread.join(timeout=5)


class CliTests(unittest.TestCase):
    def test_cli_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = str(Path(temp) / "sensor")
            collector_home = str(Path(temp) / "collector")
            with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()):
                self.assertEqual(main(["sensor", "init", "--home", sensor_home]), 0)
                self.assertEqual(
                    main(
                        [
                            "endpoint",
                            "add",
                            "--home",
                            sensor_home,
                            "--listen-ip",
                            "127.0.0.1",
                            "--listen-port",
                            "18080",
                            "--transport",
                            "http",
                            "--profile",
                            "admin-panel",
                        ]
                    ),
                    0,
                )
                self.assertEqual(main(["endpoint", "list", "--home", sensor_home, "--json"]), 0)
                self.assertEqual(main(["sensor", "status", "--home", sensor_home]), 0)
                self.assertEqual(main(["collector", "init", "--home", collector_home]), 0)
                self.assertEqual(main(["collector", "status", "--home", collector_home]), 0)
            output = stdout.getvalue()
            self.assertIn("initialized", output)
            self.assertIn("endpoint_id", output)
            self.assertIn("unsent_events", output)
            self.assertIn("collector_id", output)


if __name__ == "__main__":
    unittest.main()

