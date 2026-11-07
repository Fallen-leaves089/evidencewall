from __future__ import annotations

import asyncio
import io
import json
import socket
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from fastapi.testclient import TestClient

from evidencewall.batch import build_batch, verify_batch
from evidencewall.canary import CanaryStore
from evidencewall.cli import main
from evidencewall.config import init_sensor_home, save_matrix
from evidencewall.crypto import public_key_text, sha256_hex
from evidencewall.domain import Endpoint, ValidationError
from evidencewall.listener import SensorListenerService
from evidencewall.profiles import HttpProfile, TcpProfile, get_profile, list_profiles
from evidencewall.sensor import SensorRuntime
from evidencewall.server import create_app
from evidencewall.storage import CollectorStore


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def add_endpoints(home: Path, specifications: list[dict]) -> tuple:
    paths, meta, matrix = init_sensor_home(home)
    for specification in specifications:
        endpoint = Endpoint(
            endpoint_id=specification["endpoint_id"],
            sensor_id=meta["sensor_id"],
            matrix_id=meta["matrix_id"],
            listen_ip="127.0.0.1",
            listen_port=specification["port"],
            advertised_ip=specification["advertised_ip"],
            advertised_port=specification["advertised_port"],
            transport=specification["transport"],
            profile_id=specification["profile_id"],
            exposure="nat",
            source_quality="nat",
        )
        matrix.add_endpoint(endpoint)
    save_matrix(paths, matrix)
    return paths, meta, matrix


class ProfileTests(unittest.TestCase):
    def test_builtin_profiles_render_without_code_execution(self) -> None:
        profiles = {profile.profile_id: profile for profile in list_profiles()}
        self.assertEqual(
            set(profiles),
            {"ollama", "comfyui", "admin-panel", "tcp-metadata"},
        )
        admin = get_profile("admin-panel")
        self.assertIsInstance(admin, HttpProfile)
        route_id, status, headers, body, delay_ms = admin.render(
            "GET",
            "/api/config",
            {"admin-token": "ew_admin_test-token"},
        )
        self.assertEqual(route_id, "config")
        self.assertEqual(status, 401)
        self.assertIn(b"ew_admin_test-token", body)
        self.assertNotIn("Content-Length", headers)
        self.assertGreaterEqual(delay_ms, 0)
        self.assertEqual(admin.select("GET", "/missing")[0], "fallback")
        self.assertIsInstance(get_profile("tcp-metadata"), TcpProfile)
        with self.assertRaises(ValidationError):
            get_profile("missing-profile")


class CanaryTests(unittest.TestCase):
    def test_create_match_rotate_and_hash_only_export(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "canaries.json"
            store = CanaryStore.load(path)
            group = store.create("api-key", ["ep_a", "ep_b"])
            self.assertEqual(sha256_hex(group.token), group.token_hash)
            public_json = json.dumps(store.public_groups())
            self.assertNotIn(group.token, public_json)
            self.assertEqual(store.match(("prefix " + group.token).encode()), [group.token_hash])
            self.assertEqual(
                store.active_values_for_endpoint("ep_a"),
                {"api-key": group.token},
            )

            replacement = store.rotate(group.group_id)
            self.assertFalse(group.active)
            self.assertEqual(group.replaced_by, replacement.group_id)
            self.assertTrue(replacement.active)
            self.assertEqual(store.match(group.token.encode()), [group.token_hash])
            self.assertEqual(
                store.active_values_for_endpoint("ep_b"),
                {"api-key": replacement.token},
            )
            reloaded = CanaryStore.load(path)
            self.assertEqual(len(reloaded.groups), 2)
            self.assertNotIn(group.token, json.dumps(reloaded.public_groups()))


class EnrollmentAndCaseTests(unittest.TestCase):
    def test_canary_mapping_and_cross_endpoint_case(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "sensor"
            paths, meta, matrix = add_endpoints(
                home,
                [
                    {
                        "endpoint_id": "ep_http_one",
                        "port": free_port(),
                        "advertised_ip": "203.0.113.10",
                        "advertised_port": 18080,
                        "transport": "http1",
                        "profile_id": "admin-panel",
                    },
                    {
                        "endpoint_id": "ep_http_two",
                        "port": free_port(),
                        "advertised_ip": "203.0.113.11",
                        "advertised_port": 18081,
                        "transport": "http1",
                        "profile_id": "ollama",
                    },
                ],
            )
            canaries = CanaryStore.load(paths.canaries)
            group = canaries.create("api-key", ["ep_http_one", "ep_http_two"])
            runtime = SensorRuntime.open(home)
            store = CollectorStore(Path(temp) / "collector.db")
            token = "m2-enrollment-token"
            store.create_enrollment_token(sha256_hex(token))
            enrolled = store.enroll_sensor(
                token_hash=sha256_hex(token),
                sensor_id=meta["sensor_id"],
                matrix_id=meta["matrix_id"],
                public_key=public_key_text(runtime.public_key),
                endpoints=matrix.endpoints,
                canaries=runtime.canaries.deployment_payload(),
            )
            self.assertEqual(enrolled["canary_group_count"], 1)
            deployments = store.list_canary_deployments()
            self.assertEqual(len(deployments), 1)
            self.assertNotIn(group.token, json.dumps(deployments))

            runtime.enqueue_test_event(
                endpoint_id="ep_http_one",
                path="/api/config",
                canaries=[group.token],
            )
            runtime.enqueue_test_event(
                endpoint_id="ep_http_two",
                path="/api/tags",
                canaries=[group.token],
            )
            events = runtime.store.get_unsent_events(10)
            batch = build_batch(events, runtime.private_key, runtime.sensor_id, runtime.matrix_id)
            result = store.ingest_batch(batch, verify_batch(runtime.public_key, batch))
            self.assertEqual(result["accepted_events"], 2)

            cases = store.list_cases()
            self.assertEqual(len(cases), 1)
            case = cases[0]
            self.assertEqual(case["event_count"], 2)
            self.assertEqual(case["endpoint_ids"], ["ep_http_one", "ep_http_two"])
            self.assertEqual(case["canary_hashes"], [group.token_hash])
            self.assertEqual(case["confidence"], "high")

            detail = store.get_case(case["case_id"])
            self.assertIsNotNone(detail)
            self.assertEqual(len(detail["timeline"]), 2)
            self.assertTrue(all(len(item["event_sha256"]) == 64 for item in detail["timeline"]))

            app = create_app(store, {"collector_id": "collector_test", "version": "test"})
            client = TestClient(app)
            case_response = client.get("/v1/cases")
            self.assertEqual(case_response.status_code, 200)
            self.assertEqual(case_response.json()["count"], 1)
            detail_response = client.get(f"/v1/cases/{case['case_id']}")
            self.assertEqual(detail_response.status_code, 200)
            canary_response = client.get("/v1/canaries")
            self.assertEqual(canary_response.status_code, 200)
            self.assertNotIn(group.token, canary_response.text)


class ListenerTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_and_tcp_listeners_record_real_socket_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "sensor"
            http_port = free_port()
            tcp_port = free_port()
            paths, meta, matrix = add_endpoints(
                home,
                [
                    {
                        "endpoint_id": "ep_live_http",
                        "port": http_port,
                        "advertised_ip": "203.0.113.10",
                        "advertised_port": 18080,
                        "transport": "http1",
                        "profile_id": "admin-panel",
                    },
                    {
                        "endpoint_id": "ep_live_tcp",
                        "port": tcp_port,
                        "advertised_ip": "203.0.113.11",
                        "advertised_port": 2222,
                        "transport": "tcp",
                        "profile_id": "tcp-metadata",
                    },
                ],
            )
            canaries = CanaryStore.load(paths.canaries)
            group = canaries.create("admin-token", ["ep_live_http"])
            runtime = SensorRuntime.open(home)
            service = SensorListenerService(runtime, canaries=canaries)
            await service.start()
            try:
                http_reader, http_writer = await asyncio.open_connection("127.0.0.1", http_port)
                request = (
                    "GET /api/config HTTP/1.1\r\n"
                    "Host: evil.example\r\n"
                    f"X-Canary: {group.token}\r\n"
                    "Authorization: Bearer super-secret-value\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                http_writer.write(request)
                await http_writer.drain()
                http_response = await asyncio.wait_for(http_reader.read(), timeout=5)
                http_writer.close()
                await http_writer.wait_closed()

                tcp_reader, tcp_writer = await asyncio.open_connection("127.0.0.1", tcp_port)
                tcp_writer.write(b"SSH-2.0-test-client\r\n")
                await tcp_writer.drain()
                await asyncio.wait_for(tcp_reader.read(), timeout=5)
                tcp_writer.close()
                await tcp_writer.wait_closed()
            finally:
                await service.close()

            events = runtime.store.get_unsent_events(10)
            self.assertEqual(len(events), 2)
            http_event = next(event for event in events if event.transport == "http1")
            tcp_event = next(event for event in events if event.transport == "tcp")
            self.assertIn(b"401 Unauthorized", http_response)
            self.assertIn(group.token.encode(), http_response)
            self.assertEqual(http_event.path, "/api/config")
            self.assertEqual(http_event.host, "evil.example")
            self.assertEqual(http_event.advertised_ip, "203.0.113.10")
            self.assertEqual(http_event.destination_port, http_port)
            self.assertEqual(http_event.response_status, 401)
            self.assertEqual(http_event.canary_hashes, [group.token_hash])
            self.assertGreaterEqual(http_event.tarpit_ms, 200)
            serialized = json.dumps(http_event.to_dict())
            self.assertNotIn("super-secret-value", serialized)
            self.assertNotIn(group.token, serialized)

            self.assertEqual(tcp_event.first_payload_size, 21)
            self.assertEqual(tcp_event.destination_port, tcp_port)
            self.assertEqual(tcp_event.advertised_port, 2222)
            self.assertGreaterEqual(tcp_event.tarpit_ms, 250)
            self.assertIsNone(tcp_event.path)


class CliM2Tests(unittest.TestCase):
    def test_profile_and_canary_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sensor_home = str(Path(temp) / "sensor")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
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
                            str(free_port()),
                            "--transport",
                            "http1",
                            "--profile",
                            "ollama",
                        ]
                    ),
                    0,
                )

            stdout = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["profile", "list", "--json"]), 0)

            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["canary", "create", "--home", sensor_home, "--type", "api-key"]),
                    0,
                )
            created = json.loads(stdout.getvalue())
            self.assertEqual(created["status"], "created")
            group_id = created["canary"]["group_id"]
            self.assertNotIn("token", created["canary"])

            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["canary", "list", "--home", sensor_home, "--json"]), 0)
            listed = json.loads(stdout.getvalue())
            self.assertEqual(listed["canary_groups"], 1)
            self.assertTrue(all("token" not in item for item in listed["groups"]))

            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["canary", "rotate", "--home", sensor_home, "--group-id", group_id]),
                    0,
                )

            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["canary", "list", "--home", sensor_home, "--json"]), 0)
            rotated = json.loads(stdout.getvalue())
            self.assertEqual(rotated["canary_groups"], 2)
            self.assertEqual(rotated["active_canary_groups"], 1)


if __name__ == "__main__":
    unittest.main()
