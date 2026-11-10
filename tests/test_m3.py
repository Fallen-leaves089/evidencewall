from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from evidencewall.analysis import analyze_events
from evidencewall.batch import build_batch, verify_batch
from evidencewall.cli import main
from evidencewall.collector import CollectorRuntime
from evidencewall.config import init_collector_home, init_sensor_home, save_matrix
from evidencewall.crypto import (
    public_key_text,
    sha256_hex,
)
from evidencewall.domain import Endpoint, Event, ValidationError, format_utc, parse_iso8601
from evidencewall.evidence import EvidenceError, export_case_package, verify_package
from evidencewall.sensor import SensorRuntime
from evidencewall.storage import CollectorStore, StorageConflict

BASE_TIME = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)


def timestamp(hours: float = 0) -> str:
    return format_utc(BASE_TIME + timedelta(hours=hours))


def make_event(
    index: int,
    *,
    source_ip: str = "198.51.100.10",
    destination_ip: str = "203.0.113.10",
    destination_port: int = 80,
    observed_at: str | None = None,
    endpoint_id: str = "ep_analysis",
    path: str = "/api/config",
    headers_fingerprint: str | None = None,
    canary_hashes: list[str] | None = None,
) -> Event:
    event = Event(
        event_id=f"evt_analysis_{index}",
        sensor_id="sensor_analysis",
        matrix_id="matrix_analysis",
        endpoint_id=endpoint_id,
        sequence=index,
        observed_at=observed_at or timestamp(index),
        source_ip=source_ip,
        source_port=45000 + index,
        destination_ip=destination_ip,
        destination_port=destination_port,
        advertised_ip=destination_ip,
        advertised_port=destination_port,
        transport="http1",
        profile_id="admin-panel",
        source_quality="nat",
        method="GET",
        scheme="http",
        host=destination_ip,
        path=path,
        headers_fingerprint=headers_fingerprint or sha256_hex(b"shared-analysis-headers"),
        body_size=0,
        body_sha256=sha256_hex(b""),
        first_payload_size=0,
        first_payload_sha256=sha256_hex(b""),
        canary_hashes=list(canary_hashes or []),
        response_status=200,
        tarpit_ms=0,
    )
    event.validate()
    return event


def add_sensor(root: Path, index: int) -> tuple[SensorRuntime, Endpoint]:
    home = root / f"sensor-{index}"
    paths, meta, matrix = init_sensor_home(home)
    endpoint = Endpoint(
        endpoint_id=f"ep_{index}",
        sensor_id=meta["sensor_id"],
        matrix_id=meta["matrix_id"],
        listen_ip="127.0.0.1",
        listen_port=18080 + index,
        advertised_ip=f"203.0.113.{20 + index}",
        advertised_port=18080 + index,
        transport="http1",
        profile_id="admin-panel",
        exposure="nat",
        source_quality="nat",
    )
    matrix.add_endpoint(endpoint)
    save_matrix(paths, matrix)
    return SensorRuntime.open(home), endpoint


def enroll(store: CollectorStore, runtime: SensorRuntime, endpoint: Endpoint, token: str) -> None:
    store.create_enrollment_token(sha256_hex(token))
    store.enroll_sensor(
        token_hash=sha256_hex(token),
        sensor_id=runtime.sensor_id,
        matrix_id=runtime.matrix_id,
        public_key=public_key_text(runtime.public_key),
        endpoints=[endpoint],
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


class AnalysisTests(unittest.TestCase):
    def test_scan_shapes_use_sliding_24_hour_windows(self) -> None:
        canary_hash = sha256_hex(b"shared-canary")
        events = [
            make_event(1, observed_at=timestamp(-30), destination_port=80),
            make_event(2, observed_at=timestamp(0), destination_port=80, canary_hashes=[canary_hash]),
            make_event(3, observed_at=timestamp(1), destination_port=443, canary_hashes=[canary_hash]),
            make_event(4, observed_at=timestamp(2), destination_ip="203.0.113.11", destination_port=443),
            make_event(
                5,
                source_ip="198.51.100.11",
                destination_ip="203.0.113.12",
                destination_port=443,
                observed_at=timestamp(3),
                canary_hashes=[canary_hash],
            ),
            make_event(6, observed_at=timestamp(31), destination_ip="203.0.113.11", destination_port=443),
        ]
        analysis = analyze_events(events)
        shape_types = {item["type"] for item in analysis["scan_shape"]}
        self.assertIn("vertical_scan", shape_types)
        self.assertIn("horizontal_scan", shape_types)
        self.assertIn("service_targeting", shape_types)
        self.assertIn("distributed_canary_reuse", shape_types)
        self.assertIn("distributed_fingerprint_reuse", shape_types)
        self.assertTrue(all(item["window_seconds"] <= 24 * 60 * 60 for item in analysis["scan_shape"]))
        self.assertEqual(analysis["confidence"], "high")
        self.assertEqual(len(analysis["evidence_hashes"]), len(events))


class AssociationTests(unittest.TestCase):
    def test_shared_canary_merges_cross_source_cases_and_keeps_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _paths, _meta, _token = init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            first, first_endpoint = add_sensor(root, 1)
            second, second_endpoint = add_sensor(root, 2)
            enroll(collector.store, first, first_endpoint, "token-1")
            enroll(collector.store, second, second_endpoint, "token-2")
            ingest_event(
                collector.store,
                first,
                source_ip="198.51.100.10",
                path="/.env",
                canaries=["shared-canary-token"],
            )
            ingest_event(
                collector.store,
                second,
                source_ip="198.51.100.11",
                path="/.env",
                canaries=["shared-canary-token"],
            )
            cases = collector.store.list_cases()
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["event_count"], 2)
            self.assertEqual(cases[0]["source_ips"], ["198.51.100.10", "198.51.100.11"])
            self.assertIn("distributed_canary_reuse", {item["type"] for item in cases[0]["scan_shape"]})

            ingest_event(
                collector.store,
                second,
                source_ip="198.51.100.11",
                path="/admin",
            )
            cases = collector.store.list_cases()
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["event_count"], 3)


class HighwallTests(unittest.TestCase):
    def test_highwall_import_is_idempotent_redacted_and_auxiliary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            sensor, endpoint = add_sensor(root, 1)
            enroll(collector.store, sensor, endpoint, "token-highwall")
            ingest_event(
                collector.store,
                sensor,
                source_ip="198.51.100.10",
                path="/.env",
                canaries=["highwall-canary"],
            )
            case = collector.store.list_cases()[0]
            case_id = case["case_id"]
            observed_at = case["last_seen"]
            event = {
                "external_id": "hw-event-1",
                "event_type": "rule.match",
                "observed_at": observed_at,
                "source_ip": "198.51.100.10",
                "source_port": 45678,
                "destination_port": 443,
                "transport": "https",
                "method": "GET",
                "host": "example.invalid",
                "path": "/.env?token=super-secret",
                "action": "observe",
                "rule_id": "rule.env-probe",
                "severity": "high",
            }
            result = collector.store.import_highwall_events(source="highwall", events=[event])
            self.assertEqual(result["accepted"], 1)
            imported = collector.store.list_highwall_events(source="highwall")
            self.assertEqual(len(imported), 1)
            self.assertEqual(imported[0]["payload"]["path"], "/.env")
            self.assertNotIn("super-secret", json.dumps(imported))
            full_case = collector.store.get_case(case_id)
            self.assertEqual(len(full_case["highwall_events"]), 1)
            self.assertIn(
                "highwall_corroboration",
                {item["type"] for item in full_case["scan_shape"]},
            )

            duplicate = collector.store.import_highwall_events(source="highwall", events=[event])
            self.assertEqual(duplicate["status"], "duplicate")
            changed = dict(event)
            changed["event_type"] = "rule.other"
            with self.assertRaises(StorageConflict):
                collector.store.import_highwall_events(source="highwall", events=[changed])
            with self.assertRaises(ValidationError):
                collector.store.import_highwall_events(
                    source="highwall",
                    events=[{**event, "external_id": "hw-headers", "headers": {"Cookie": "secret"}}],
                )

            old_time = format_utc(
                parse_iso8601(observed_at, "observed_at") - timedelta(hours=48)
            )
            old = {
                "external_id": "hw-event-old",
                "event_type": "rule.match",
                "observed_at": old_time,
                "source_ip": "198.51.100.10",
            }
            collector.store.import_highwall_events(source="highwall", events=[old])
            full_case = collector.store.get_case(case_id)
            self.assertEqual(len(full_case["highwall_events"]), 1)

            output = root / "highwall-bundle"
            package = export_case_package(
                collector.store,
                case_id,
                output,
                collector_meta=collector.meta,
                private_key=collector.private_key,
                public_key=collector.public_key,
                actor="analyst@example.invalid",
            )
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["highwall_event_count"], 1)
            rows = [
                json.loads(line)
                for line in (output / "highwall.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(len(rows), 1)
            self.assertEqual(manifest["highwall_event_ids"], [rows[0]["highwall_event_id"]])
            self.assertEqual(rows[0]["payload"]["path"], "/.env")
            self.assertNotIn("super-secret", (output / "highwall.jsonl").read_text(encoding="utf-8"))
            report = verify_package(Path(package["archive_path"]), expected_public_key=collector.public_key)
            self.assertTrue(report["valid"], report)


class ReviewAndHoldTests(unittest.TestCase):
    def test_review_and_explicit_legal_hold_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            sensor, endpoint = add_sensor(root, 1)
            enroll(collector.store, sensor, endpoint, "token-review")
            ingest_event(collector.store, sensor, path="/.env")
            case_id = collector.store.list_cases()[0]["case_id"]

            review = collector.store.review_case(
                case_id,
                status="reviewing",
                note="Human review started",
                actor="analyst@example.invalid",
            )
            self.assertEqual(review["status"], "reviewing")
            case = collector.store.get_case(case_id)
            self.assertEqual(case["status"], "reviewing")
            self.assertEqual(case["reviews"][0]["note"], "Human review started")

            hold = collector.store.set_legal_hold(
                case_id,
                reason="Preserve for complaint",
                actor="analyst@example.invalid",
                expected_until=timestamp(720),
            )
            self.assertEqual(hold["status"], "active")
            case = collector.store.get_case(case_id)
            self.assertEqual(case["legal_hold_id"], hold["hold_id"])
            self.assertEqual(case["legal_holds"][0]["status"], "active")
            with self.assertRaises(StorageConflict):
                collector.store.set_legal_hold(case_id, reason="duplicate hold")

            with self.assertRaises(ValidationError):
                collector.store.release_legal_hold(
                    case_id,
                    reason="case closed",
                    confirm=False,
                )
            released = collector.store.release_legal_hold(
                case_id,
                reason="case closed",
                actor="analyst@example.invalid",
                confirm=True,
            )
            self.assertEqual(released["status"], "released")
            case = collector.store.get_case(case_id)
            self.assertIsNone(case["legal_hold_id"])
            self.assertEqual(case["legal_holds"][0]["status"], "released")


class CanarySyncTests(unittest.TestCase):
    def test_signed_canary_snapshot_sync_tamper_and_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            sensor, endpoint = add_sensor(root, 1)
            enroll(collector.store, sensor, endpoint, "token-canary-sync")
            group = sensor.canaries.create("api-key", [endpoint.endpoint_id])
            payload = sensor.canaries.build_sync_payload(
                sensor.private_key,
                sensor_id=sensor.sensor_id,
                matrix_id=sensor.matrix_id,
            )
            self.assertNotIn(group.token, json.dumps(payload))

            client = TestClient(collector.app())
            first = client.post("/v1/sensors/canaries", json=payload)
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(first.json()["status"], "accepted")
            self.assertNotIn(group.token, first.text)
            duplicate = client.post("/v1/sensors/canaries", json=payload)
            self.assertEqual(duplicate.status_code, 200, duplicate.text)
            self.assertEqual(duplicate.json()["status"], "duplicate")

            tampered = copy.deepcopy(payload)
            tampered["groups"][0]["token_type"] = "cookie"
            rejected = client.post("/v1/sensors/canaries", json=tampered)
            self.assertEqual(rejected.status_code, 400)

            replacement = sensor.canaries.rotate(group.group_id)
            rotated_payload = sensor.canaries.build_sync_payload(
                sensor.private_key,
                sensor_id=sensor.sensor_id,
                matrix_id=sensor.matrix_id,
            )
            rotated = client.post("/v1/sensors/canaries", json=rotated_payload)
            self.assertEqual(rotated.status_code, 200, rotated.text)
            deployments = collector.store.list_canary_deployments(sensor.sensor_id)
            by_id = {item["group_id"]: item for item in deployments}
            self.assertEqual(len(by_id), 2)
            self.assertFalse(by_id[group.group_id]["active"])
            self.assertTrue(by_id[replacement.group_id]["active"])


class EvidencePackageTests(unittest.TestCase):
    def test_export_verify_tamper_and_invalidation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            sensor, endpoint = add_sensor(root, 1)
            enroll(collector.store, sensor, endpoint, "token-evidence")
            ingest_event(
                collector.store,
                sensor,
                source_ip="198.51.100.10",
                path="/.env",
                canaries=["evidence-canary"],
            )
            case_id = collector.store.list_cases()[0]["case_id"]
            collector.store.review_case(case_id, status="confirmed", note="verified by analyst")
            collector.store.set_legal_hold(case_id, reason="complaint preparation")

            output = root / "bundle"
            package = export_case_package(
                collector.store,
                case_id,
                output,
                collector_meta=collector.meta,
                private_key=collector.private_key,
                public_key=collector.public_key,
                actor="analyst@example.invalid",
            )
            self.assertTrue(output.is_dir())
            self.assertTrue(Path(package["archive_path"]).is_file())
            for name in (
                "case.md",
                "events.jsonl",
                "timeline.md",
                "custody.jsonl",
                "not_checked.md",
                "highwall.jsonl",
                "manifest.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["case"]["status"], "confirmed")
            self.assertEqual(manifest["highwall_event_count"], 0)
            self.assertEqual((output / "highwall.jsonl").read_bytes(), b"")
            self.assertTrue(manifest["legal_holds"][0]["status"] == "active")
            self.assertNotIn("PRIVATE KEY", (output / "manifest.json").read_text(encoding="utf-8"))
            private_text = collector.paths.private_key.read_text(encoding="utf-8")
            for file_path in output.iterdir():
                if file_path.is_file():
                    self.assertNotIn(private_text.strip(), file_path.read_text(encoding="utf-8"))

            directory_report = verify_package(
                output,
                expected_public_key=collector.public_key,
            )
            self.assertTrue(directory_report["valid"], directory_report)
            archive_report = verify_package(
                Path(package["archive_path"]),
                expected_public_key=collector.public_key,
            )
            self.assertTrue(archive_report["valid"], archive_report)
            self.assertTrue(archive_report["trust_anchor_pinned"])
            current_case = collector.store.get_case(case_id)
            self.assertEqual(current_case["evidence_package_id"], package["package_id"])

            case_file = output / "case.md"
            case_file.write_bytes(case_file.read_bytes() + b"\ntampered\n")
            tampered = verify_package(output)
            self.assertFalse(tampered["valid"])
            self.assertTrue(any("file hash mismatch" in error for error in tampered["errors"]))

            ingest_event(collector.store, sensor, path="/admin")
            current_case = collector.store.get_case(case_id)
            self.assertIsNone(current_case["evidence_package_id"])
            stored_packages = collector.store.list_evidence_packages(case_id)
            self.assertEqual(stored_packages[0]["status"], "superseded")


class ApiM3Tests(unittest.TestCase):
    def test_case_review_hold_highwall_export_and_evidence_api(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_collector_home(root / "collector")
            collector = CollectorRuntime.open(root / "collector")
            sensor, endpoint = add_sensor(root, 1)
            enroll(collector.store, sensor, endpoint, "token-api-m3")
            ingest_event(collector.store, sensor, source_ip="198.51.100.10", path="/.env")
            case = collector.store.list_cases()[0]
            case_id = case["case_id"]
            client = TestClient(collector.app())

            reviewed = client.post(
                f"/v1/cases/{case_id}/review",
                json={"status": "confirmed", "note": "api review", "actor": "api-user"},
            )
            self.assertEqual(reviewed.status_code, 200, reviewed.text)
            self.assertEqual(reviewed.json()["review"]["status"], "confirmed")

            held = client.post(
                f"/v1/cases/{case_id}/hold",
                json={"action": "set", "reason": "api hold", "actor": "api-user"},
            )
            self.assertEqual(held.status_code, 200, held.text)
            hold_id = held.json()["hold"]["hold_id"]

            highwall = client.post(
                "/v1/highwall/events",
                json={
                    "source": "highwall",
                    "events": [
                        {
                            "external_id": "api-highwall-1",
                            "event_type": "rule.match",
                            "observed_at": case["last_seen"],
                            "source_ip": "198.51.100.10",
                            "path": "/.env?secret=remove-me",
                        }
                    ],
                },
            )
            self.assertEqual(highwall.status_code, 200, highwall.text)
            self.assertEqual(highwall.json()["accepted"], 1)

            exported = client.post(f"/v1/cases/{case_id}/export", json={})
            self.assertEqual(exported.status_code, 200, exported.text)
            package = exported.json()["package"]
            self.assertTrue(Path(package["archive_path"]).is_file())

            evidence = client.get(f"/v1/cases/{case_id}/evidence")
            self.assertEqual(evidence.status_code, 200, evidence.text)
            self.assertTrue(evidence.json()["latest_verification"]["valid"])

            Path(package["archive_path"]).unlink()
            directory_fallback = client.get(f"/v1/cases/{case_id}/evidence")
            self.assertEqual(directory_fallback.status_code, 200, directory_fallback.text)
            self.assertTrue(directory_fallback.json()["latest_verification"]["valid"])

            released = client.post(
                f"/v1/cases/{case_id}/hold",
                json={
                    "action": "release",
                    "reason": "api hold released",
                    "actor": "api-user",
                    "hold_id": hold_id,
                    "confirm": True,
                },
            )
            self.assertEqual(released.status_code, 200, released.text)
            self.assertEqual(released.json()["status"], "released")


class CliM3Tests(unittest.TestCase):
    def test_collector_remote_bind_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            collector_home = Path(temp) / "collector"
            init_collector_home(collector_home)

            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                refused = main(
                    [
                        "collector",
                        "run",
                        "--home",
                        str(collector_home),
                        "--host",
                        "0.0.0.0",
                    ]
                )
            self.assertEqual(refused, 2)
            self.assertIn("--allow-remote", stderr.getvalue())

            stderr = io.StringIO()
            with patch("uvicorn.run") as run:
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    allowed = main(
                        [
                            "collector",
                            "run",
                            "--home",
                            str(collector_home),
                            "--host",
                            "0.0.0.0",
                            "--allow-remote",
                        ]
                    )
            self.assertEqual(allowed, 0)
            run.assert_called_once()
            self.assertIn("warning:", stderr.getvalue())

    def test_case_review_export_and_offline_verify_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            collector_home = root / "collector"
            init_collector_home(collector_home)
            collector = CollectorRuntime.open(collector_home)
            sensor, endpoint = add_sensor(root, 1)
            enroll(collector.store, sensor, endpoint, "token-cli-m3")
            ingest_event(collector.store, sensor, path="/.env")
            case_id = collector.store.list_cases()[0]["case_id"]

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                reviewed = main(
                    [
                        "case",
                        "review",
                        case_id,
                        "--home",
                        str(collector_home),
                        "--status",
                        "confirmed",
                        "--note",
                        "cli review",
                    ]
                )
            self.assertEqual(reviewed, 0)

            output = root / "cli-bundle"
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exported = main(
                    [
                        "case",
                        "export",
                        case_id,
                        "--home",
                        str(collector_home),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(exported, 0)
            package = json.loads(stdout.getvalue())["package"]
            self.assertTrue(Path(package["archive_path"]).is_file())

            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                verified = main(
                    [
                        "evidence",
                        "verify",
                        package["archive_path"],
                        "--collector-key",
                        str(collector.paths.public_key),
                    ]
                )
            self.assertEqual(verified, 0)
            self.assertTrue(json.loads(stdout.getvalue())["valid"])

    def test_cli_surfaces_evidence_registration_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            collector_home = root / "collector"
            init_collector_home(collector_home)
            collector = CollectorRuntime.open(collector_home)
            sensor, endpoint = add_sensor(root, 1)
            enroll(collector.store, sensor, endpoint, "token-cli-export-error")
            ingest_event(collector.store, sensor, path="/.env")
            case_id = collector.store.list_cases()[0]["case_id"]

            stderr = io.StringIO()
            with patch(
                "evidencewall.cli.export_case_package",
                side_effect=EvidenceError("registration failed"),
            ):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    result = main(
                        [
                            "case",
                            "export",
                            case_id,
                            "--home",
                            str(collector_home),
                        ]
                    )
            self.assertEqual(result, 2)
            self.assertIn("registration failed", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
