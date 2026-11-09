from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .canary import CanaryStore
from .collector import CollectorRuntime
from .config import (
    CollectorPaths,
    DEFAULT_BUFFER_MAX_BYTES,
    DEFAULT_BUFFER_MAX_EVENTS,
    DEFAULT_MIN_FREE_DISK_BYTES,
    SensorPaths,
    default_data_root,
    init_collector_home,
    init_sensor_home,
    load_sensor_home,
    rotate_collector_token,
    save_matrix,
)
from .crypto import CryptoError, load_public_key_pem
from .domain import (
    CASE_STATUSES,
    CANARY_TYPES,
    DEFAULT_SOURCE_QUALITY,
    EXPOSURES,
    SOURCE_QUALITIES,
    TRANSPORTS,
    Endpoint,
    ValidationError,
    new_id,
)
from .sensor import SensorError, SensorRuntime
from .storage import StorageError
from .listener import ListenerError, run_sensor_service
from .profiles import get_profile, list_profiles
from .evidence import EvidenceError, export_case_package, verify_package


DEFAULT_DATA_ROOT = default_data_root()
DEFAULT_SENSOR_HOME = DEFAULT_DATA_ROOT / "sensor"
DEFAULT_COLLECTOR_HOME = DEFAULT_DATA_ROOT / "collector"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _transport(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"http", "http1", "http/1.1"}:
        return "http1"
    if normalized == "tcp":
        return "tcp"
    raise argparse.ArgumentTypeError("transport must be http1/http or tcp")


def _add_home(parser: argparse.ArgumentParser, default: Path) -> None:
    parser.add_argument("--home", type=Path, default=default, help="data directory")


def _load_runtime(home: Path) -> SensorRuntime:
    return SensorRuntime.open(home)


def _is_loopback_bind(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _bind_check(endpoint: Endpoint) -> tuple[bool, str]:
    try:
        parsed = ipaddress.ip_address(endpoint.listen_ip)
        family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            if family == socket.AF_INET6:
                sock.bind((endpoint.listen_ip, endpoint.listen_port, 0, 0))
            else:
                sock.bind((endpoint.listen_ip, endpoint.listen_port))
        finally:
            sock.close()
        return True, ""
    except OSError as exc:
        return False, str(exc)


def cmd_matrix_init(args: argparse.Namespace) -> int:
    paths, meta, matrix = init_sensor_home(
        args.home,
        sensor_id=args.sensor_id,
        matrix_id=args.matrix_id,
        collector_url=args.collector_url,
        buffer_max_events=args.buffer_max_events,
        buffer_max_bytes=args.buffer_max_bytes,
        min_free_disk_bytes=args.min_free_disk_bytes,
    )
    print(_json({"status": "initialized", "home": str(paths.root), **meta, "endpoint_count": len(matrix.endpoints)}))
    return 0


def cmd_endpoint_add(args: argparse.Namespace) -> int:
    _paths, _meta, matrix, _private_key, _public_key = load_sensor_home(args.home)
    advertised_ip = args.advertised_ip or args.listen_ip
    advertised_port = args.advertised_port or args.listen_port
    same_address = advertised_ip == args.listen_ip and advertised_port == args.listen_port
    exposure = args.exposure or ("direct" if same_address else "nat")
    source_quality = args.source_quality or DEFAULT_SOURCE_QUALITY.get(exposure, "direct")
    transport = args.transport
    profile_id = args.profile or ("tcp-metadata" if transport == "tcp" else "admin-panel")
    profile = get_profile(profile_id)
    if profile.transport != transport:
        raise ValidationError(
            f"profile {profile.profile_id} is for {profile.transport}, not {transport}"
        )
    endpoint = Endpoint(
        endpoint_id=args.endpoint_id or new_id("ep"),
        sensor_id=matrix.sensor_id,
        matrix_id=matrix.matrix_id,
        listen_ip=args.listen_ip,
        listen_port=args.listen_port,
        advertised_ip=advertised_ip,
        advertised_port=advertised_port,
        transport=transport,
        profile_id=profile_id,
        exposure=exposure,
        source_quality=source_quality,
        enabled=not args.disabled,
        config_version=1,
    )
    added = matrix.add_endpoint(endpoint)
    save_matrix(_paths, matrix)
    print(_json({"status": "added", "endpoint": added.to_dict()}))
    return 0


def cmd_endpoint_list(args: argparse.Namespace) -> int:
    paths, _meta, matrix, _private_key, _public_key = load_sensor_home(args.home)
    if args.json:
        print(_json(matrix.to_dict()))
        return 0
    if not matrix.endpoints:
        print(f"no endpoints in {paths.matrix}")
        return 0
    print(f"{'ENDPOINT':<40} {'LISTEN':<24} {'ADVERTISED':<24} {'TRANSPORT':<9} {'PROFILE':<18} {'EXPOSURE':<8} ON")
    for endpoint in matrix.endpoints:
        listen = f"{endpoint.listen_ip}:{endpoint.listen_port}"
        advertised = f"{endpoint.advertised_ip}:{endpoint.advertised_port}"
        print(
            f"{endpoint.endpoint_id:<40} {listen:<24} {advertised:<24} "
            f"{endpoint.transport:<9} {endpoint.profile_id:<18} {endpoint.exposure:<8} "
            f"{'yes' if endpoint.enabled else 'no'}"
        )
    return 0


def cmd_endpoint_test(args: argparse.Namespace) -> int:
    _paths, _meta, matrix, _private_key, _public_key = load_sensor_home(args.home)
    selected = matrix.endpoints if not args.endpoint_id else [
        endpoint for endpoint in matrix.endpoints if endpoint.endpoint_id == args.endpoint_id
    ]
    if not selected:
        raise ValidationError("no matching endpoints")
    results = []
    failed = 0
    for endpoint in selected:
        ok, error = _bind_check(endpoint)
        if not ok:
            failed += 1
        results.append(
            {
                "endpoint_id": endpoint.endpoint_id,
                "listen": f"{endpoint.listen_ip}:{endpoint.listen_port}",
                "advertised": f"{endpoint.advertised_ip}:{endpoint.advertised_port}",
                "bind_ok": ok,
                "error": error or None,
            }
        )
    if args.json:
        print(_json({"results": results}))
    else:
        for result in results:
            marker = "OK" if result["bind_ok"] else "FAIL"
            print(f"{marker:<4} {result['endpoint_id']} {result['listen']} -> {result['advertised']}")
            if result["error"]:
                print(f"     {result['error']}")
        print("note: bind check only verifies the local listen address; router/NAT mapping must be checked separately")
    return 1 if failed else 0


def cmd_profile_list(args: argparse.Namespace) -> int:
    profiles = list_profiles(args.transport)
    payload = [
        {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "version": profile.version,
            "transport": profile.transport,
            "routes": len(profile.routes) if hasattr(profile, "routes") else 0,
        }
        for profile in profiles
    ]
    if args.json:
        print(_json({"profiles": payload}))
        return 0
    print(f"{'PROFILE':<18} {'TRANSPORT':<10} {'VERSION':<12} NAME")
    for item in payload:
        print(f"{item['profile_id']:<18} {item['transport']:<10} {item['version']:<12} {item['name']}")
    return 0


def _resolve_canary_endpoints(matrix, requested: list[str] | None) -> list[str]:
    if requested:
        endpoint_ids = sorted(set(requested))
        known = {endpoint.endpoint_id for endpoint in matrix.endpoints}
        missing = [endpoint_id for endpoint_id in endpoint_ids if endpoint_id not in known]
        if missing:
            raise ValidationError(f"unknown endpoint_id: {', '.join(missing)}")
        return endpoint_ids
    endpoint_ids = sorted(endpoint.endpoint_id for endpoint in matrix.endpoints if endpoint.enabled)
    if not endpoint_ids:
        raise ValidationError("matrix has no enabled endpoints")
    return endpoint_ids


def cmd_canary_create(args: argparse.Namespace) -> int:
    paths, _meta, matrix, _private_key, _public_key = load_sensor_home(args.home)
    store = CanaryStore.load(paths.canaries)
    endpoint_ids = _resolve_canary_endpoints(matrix, args.endpoint_id)
    group = store.create(args.type, endpoint_ids)
    print(_json({"status": "created", "canary": group.to_public_dict()}))
    return 0


def cmd_canary_list(args: argparse.Namespace) -> int:
    paths, _meta, _matrix, _private_key, _public_key = load_sensor_home(args.home)
    store = CanaryStore.load(paths.canaries)
    payload = {"groups": store.public_groups(), **store.stats()}
    if args.json:
        print(_json(payload))
        return 0
    if not store.groups:
        print("no canary groups configured")
        return 0
    print(f"{'GROUP':<40} {'TYPE':<16} {'ACTIVE':<7} ENDPOINTS")
    for group in store.public_groups():
        print(
            f"{group['group_id']:<40} {group['token_type']:<16} "
            f"{'yes' if group['active'] else 'no':<7} {', '.join(group['endpoint_ids'])}"
        )
    return 0


def cmd_canary_rotate(args: argparse.Namespace) -> int:
    paths, _meta, _matrix, _private_key, _public_key = load_sensor_home(args.home)
    store = CanaryStore.load(paths.canaries)
    group = store.rotate(args.group_id)
    print(_json({"status": "rotated", "canary": group.to_public_dict()}))
    return 0


def cmd_canary_sync(args: argparse.Namespace) -> int:
    runtime = _load_runtime(args.home)
    result = runtime.sync_canaries(collector_url=args.collector_url, force=True)
    print(_json(result))
    return 0 if result.get("status") in {"accepted", "duplicate", "unchanged"} else 1


def cmd_case_list(args: argparse.Namespace) -> int:
    runtime = CollectorRuntime.open(args.home)
    cases = runtime.store.list_cases(limit=args.limit, status=args.status)
    payload = {"cases": cases, "count": len(cases)}
    if args.json:
        print(_json(payload))
        return 0
    if not cases:
        print("no cases")
        return 0
    print(f"{'CASE':<40} {'LAST SEEN':<26} {'EVENTS':<7} {'CONF':<8} {'ENDPOINTS':<10} TITLE")
    for case in cases:
        print(
            f"{case['case_id']:<40} {case['last_seen']:<26} {case['event_count']:<7} "
            f"{case['confidence']:<8} {len(case['endpoint_ids']):<10} {case['title']}"
        )
    return 0


def cmd_case_show(args: argparse.Namespace) -> int:
    runtime = CollectorRuntime.open(args.home)
    case = runtime.store.get_case(args.case_id)
    if case is None:
        raise ValueError(f"case not found: {args.case_id}")
    print(_json(case))
    return 0


def cmd_case_review(args: argparse.Namespace) -> int:
    runtime = CollectorRuntime.open(args.home)
    result = runtime.store.review_case(
        args.case_id,
        status=args.status,
        note=args.note,
        actor=args.actor,
    )
    print(_json({"status": "reviewed", "review": result}))
    return 0


def cmd_case_hold(args: argparse.Namespace) -> int:
    runtime = CollectorRuntime.open(args.home)
    if args.release:
        result = runtime.store.release_legal_hold(
            args.case_id,
            reason=args.reason,
            actor=args.actor,
            confirm=args.confirm,
            hold_id=args.hold_id,
        )
        print(_json({"status": "released", "hold": result}))
    else:
        result = runtime.store.set_legal_hold(
            args.case_id,
            reason=args.reason,
            actor=args.actor,
            expected_until=args.expected_until,
        )
        print(_json({"status": "held", "hold": result}))
    return 0


def cmd_case_export(args: argparse.Namespace) -> int:
    runtime = CollectorRuntime.open(args.home)
    if runtime.store.get_case(args.case_id) is None:
        raise ValueError(f"case not found: {args.case_id}")
    if args.output:
        output_path = Path(args.output)
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        output_path = runtime.paths.exports / f"{args.case_id}-{timestamp}"
    result = export_case_package(
        runtime.store,
        args.case_id,
        output_path,
        collector_meta=runtime.meta,
        private_key=runtime.private_key,
        public_key=runtime.public_key,
        actor=args.actor,
        create_archive=not args.no_archive,
    )
    print(_json({"status": "exported", "package": result}))
    return 0


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    expected_key = None
    if args.collector_key:
        expected_key = load_public_key_pem(Path(args.collector_key).read_bytes())
    report = verify_package(Path(args.bundle), expected_public_key=expected_key)
    print(_json(report))
    return 0 if report.get("valid") else 1


def cmd_sensor_enroll(args: argparse.Namespace) -> int:
    token = sys.stdin.readline().strip() if args.token_stdin else args.token
    if not token:
        raise ValueError("enrollment token is empty")
    runtime = _load_runtime(args.home)
    result = runtime.enroll(args.collector_url, token, timeout=args.timeout)
    print(_json({"status": "enrolled", **result}))
    return 0


def cmd_sensor_emit_test(args: argparse.Namespace) -> int:
    runtime = _load_runtime(args.home)
    event = runtime.enqueue_test_event(
        endpoint_id=args.endpoint_id,
        path=args.path,
        source_ip=args.source_ip,
        source_port=args.source_port,
        canaries=args.canary,
    )
    print(
        _json(
            {
                "status": "queued_test_event",
                "event_id": event.event_id,
                "sequence": event.sequence,
                "endpoint_id": event.endpoint_id,
                "note": "synthetic M1 test event; not a real decoy connection",
            }
        )
    )
    return 0


def cmd_sensor_run(args: argparse.Namespace) -> int:
    runtime = _load_runtime(args.home)
    try:
        if args.once or args.flush_only:
            runtime.flush_loop(interval=args.interval, once=True)
        else:
            asyncio.run(run_sensor_service(runtime, interval=args.interval))
    except KeyboardInterrupt:
        return 0
    return 0


def cmd_sensor_status(args: argparse.Namespace) -> int:
    runtime = _load_runtime(args.home)
    print(_json(runtime.status()))
    return 0


def cmd_collector_init(args: argparse.Namespace) -> int:
    paths, meta, token = init_collector_home(args.home, collector_id=args.collector_id)
    print(_json({"status": "initialized", "home": str(paths.root), **meta}))
    print("")
    print("Enrollment token (shown once; store it temporarily and delete it after use):")
    print(token)
    return 0


def cmd_collector_run(args: argparse.Namespace) -> int:
    runtime = CollectorRuntime.open(args.home)
    if not _is_loopback_bind(args.host) and not args.allow_remote:
        print(
            "error: refusing to bind collector to a non-loopback address without --allow-remote; "
            "the management API has no built-in authentication or TLS",
            file=sys.stderr,
        )
        return 2
    if not _is_loopback_bind(args.host):
        print(
            "warning: collector is exposed beyond loopback; put it behind HTTPS, authentication, "
            "and source-address restrictions",
            file=sys.stderr,
        )
    import uvicorn

    uvicorn.run(runtime.app(), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_collector_token_rotate(args: argparse.Namespace) -> int:
    token = rotate_collector_token(args.home)
    print("New enrollment token (shown once; old unused tokens are revoked):")
    print(token)
    return 0


def cmd_collector_status(args: argparse.Namespace) -> int:
    runtime = CollectorRuntime.open(args.home)
    print(_json(runtime.status()))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []
    runtime: SensorRuntime | None = None
    try:
        runtime = _load_runtime(args.home)
        checks.append({"check": "identity", "ok": True, "detail": "sensor keypair loaded"})
        runtime.matrix.validate()
        checks.append({"check": "matrix", "ok": True, "detail": f"{len(runtime.matrix.endpoints)} endpoints"})
        checks.append({"check": "buffer", "ok": True, "detail": runtime.store.stats()})
    except Exception as exc:
        checks.append({"check": "sensor", "ok": False, "detail": str(exc)})
    if runtime is not None:
        for endpoint in runtime.matrix.endpoints:
            ok, error = _bind_check(endpoint)
            checks.append(
                {
                    "check": f"bind:{endpoint.endpoint_id}",
                    "ok": ok,
                    "detail": error or f"{endpoint.listen_ip}:{endpoint.listen_port}",
                }
            )
        health = runtime.collector_health()
        checks.append(
            {
                "check": "collector",
                "ok": health.get("status") in {"ok", "not_configured"},
                "detail": health,
            }
        )
    failed = [check for check in checks if not check["ok"]]
    if args.json:
        print(_json({"ok": not failed, "checks": checks}))
    else:
        for check in checks:
            marker = "OK" if check["ok"] else "FAIL"
            print(f"{marker:<4} {check['check']}: {check['detail']}")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidencewall",
        description="EvidenceWall evidence-first decoy traffic sensor",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    matrix = sub.add_parser("matrix", help="manage endpoint matrix")
    matrix_sub = matrix.add_subparsers(dest="matrix_command", required=True)
    matrix_init = matrix_sub.add_parser("init", help="initialize sensor identity and matrix")
    _add_home(matrix_init, DEFAULT_SENSOR_HOME)
    matrix_init.add_argument("--sensor-id")
    matrix_init.add_argument("--matrix-id")
    matrix_init.add_argument("--collector-url")
    matrix_init.add_argument("--buffer-max-events", type=int, default=DEFAULT_BUFFER_MAX_EVENTS)
    matrix_init.add_argument("--buffer-max-bytes", type=int, default=DEFAULT_BUFFER_MAX_BYTES)
    matrix_init.add_argument("--min-free-disk-bytes", type=int, default=DEFAULT_MIN_FREE_DISK_BYTES)
    matrix_init.set_defaults(func=cmd_matrix_init)

    sensor = sub.add_parser("sensor", help="sensor operations")
    sensor_sub = sensor.add_subparsers(dest="sensor_command", required=True)
    sensor_init = sensor_sub.add_parser("init", help="initialize sensor identity and matrix")
    _add_home(sensor_init, DEFAULT_SENSOR_HOME)
    sensor_init.add_argument("--sensor-id")
    sensor_init.add_argument("--matrix-id")
    sensor_init.add_argument("--collector-url")
    sensor_init.add_argument("--buffer-max-events", type=int, default=DEFAULT_BUFFER_MAX_EVENTS)
    sensor_init.add_argument("--buffer-max-bytes", type=int, default=DEFAULT_BUFFER_MAX_BYTES)
    sensor_init.add_argument("--min-free-disk-bytes", type=int, default=DEFAULT_MIN_FREE_DISK_BYTES)
    sensor_init.set_defaults(func=cmd_matrix_init)

    sensor_enroll = sensor_sub.add_parser("enroll", help="register sensor with collector")
    _add_home(sensor_enroll, DEFAULT_SENSOR_HOME)
    sensor_enroll.add_argument("--collector-url", required=True)
    token_group = sensor_enroll.add_mutually_exclusive_group(required=True)
    token_group.add_argument("--token")
    token_group.add_argument("--token-stdin", action="store_true")
    sensor_enroll.add_argument("--timeout", type=float, default=10.0)
    sensor_enroll.set_defaults(func=cmd_sensor_enroll)

    sensor_run = sensor_sub.add_parser("run", help="run decoy listeners and flush buffered events")
    _add_home(sensor_run, DEFAULT_SENSOR_HOME)
    sensor_run.add_argument("--once", action="store_true")
    sensor_run.add_argument("--flush-only", action="store_true")
    sensor_run.add_argument("--interval", type=float, default=5.0)
    sensor_run.set_defaults(func=cmd_sensor_run)

    sensor_emit = sensor_sub.add_parser("emit-test", help="queue a synthetic test event")
    _add_home(sensor_emit, DEFAULT_SENSOR_HOME)
    sensor_emit.add_argument("--endpoint-id")
    sensor_emit.add_argument("--path", default="/.env")
    sensor_emit.add_argument("--source-ip", default="198.51.100.10")
    sensor_emit.add_argument("--source-port", type=int, default=45678)
    sensor_emit.add_argument("--canary", action="append")
    sensor_emit.set_defaults(func=cmd_sensor_emit_test)

    sensor_status = sensor_sub.add_parser("status", help="show buffer and sensor status")
    _add_home(sensor_status, DEFAULT_SENSOR_HOME)
    sensor_status.set_defaults(func=cmd_sensor_status)

    endpoint = sub.add_parser("endpoint", help="manage matrix endpoints")
    endpoint_sub = endpoint.add_subparsers(dest="endpoint_command", required=True)
    endpoint_add = endpoint_sub.add_parser("add", help="add an endpoint")
    _add_home(endpoint_add, DEFAULT_SENSOR_HOME)
    endpoint_add.add_argument("--listen-ip", required=True)
    endpoint_add.add_argument("--listen-port", type=int, required=True)
    endpoint_add.add_argument("--advertised-ip")
    endpoint_add.add_argument("--advertised-port", type=int)
    endpoint_add.add_argument("--transport", type=_transport, default="http1")
    endpoint_add.add_argument("--profile")
    endpoint_add.add_argument("--exposure", choices=sorted(EXPOSURES))
    endpoint_add.add_argument("--source-quality", choices=sorted(SOURCE_QUALITIES))
    endpoint_add.add_argument("--endpoint-id")
    endpoint_add.add_argument("--disabled", action="store_true")
    endpoint_add.set_defaults(func=cmd_endpoint_add)

    endpoint_list = endpoint_sub.add_parser("list", help="list endpoints")
    _add_home(endpoint_list, DEFAULT_SENSOR_HOME)
    endpoint_list.add_argument("--json", action="store_true")
    endpoint_list.set_defaults(func=cmd_endpoint_list)

    endpoint_test = endpoint_sub.add_parser("test", help="test local bind addresses")
    _add_home(endpoint_test, DEFAULT_SENSOR_HOME)
    endpoint_test.add_argument("--endpoint-id")
    endpoint_test.add_argument("--json", action="store_true")
    endpoint_test.set_defaults(func=cmd_endpoint_test)

    profile = sub.add_parser("profile", help="inspect built-in profiles")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_sub.add_parser("list", help="list built-in profiles")
    profile_list.add_argument("--transport", choices=sorted(TRANSPORTS))
    profile_list.add_argument("--json", action="store_true")
    profile_list.set_defaults(func=cmd_profile_list)

    canary = sub.add_parser("canary", help="manage canary groups")
    canary_sub = canary.add_subparsers(dest="canary_command", required=True)
    canary_create = canary_sub.add_parser("create", help="create a canary group")
    _add_home(canary_create, DEFAULT_SENSOR_HOME)
    canary_create.add_argument("--type", required=True, choices=sorted(CANARY_TYPES))
    canary_create.add_argument("--endpoint-id", action="append")
    canary_create.set_defaults(func=cmd_canary_create)

    canary_list = canary_sub.add_parser("list", help="list canary groups without raw tokens")
    _add_home(canary_list, DEFAULT_SENSOR_HOME)
    canary_list.add_argument("--json", action="store_true")
    canary_list.set_defaults(func=cmd_canary_list)

    canary_rotate = canary_sub.add_parser("rotate", help="retire a canary group and create a replacement")
    _add_home(canary_rotate, DEFAULT_SENSOR_HOME)
    canary_rotate.add_argument("--group-id", required=True)
    canary_rotate.set_defaults(func=cmd_canary_rotate)

    canary_sync = canary_sub.add_parser("sync", help="send the signed public canary snapshot to Collector")
    _add_home(canary_sync, DEFAULT_SENSOR_HOME)
    canary_sync.add_argument("--collector-url")
    canary_sync.set_defaults(func=cmd_canary_sync)

    collector = sub.add_parser("collector", help="collector operations")
    collector_sub = collector.add_subparsers(dest="collector_command", required=True)
    collector_init = collector_sub.add_parser("init", help="initialize collector")
    _add_home(collector_init, DEFAULT_COLLECTOR_HOME)
    collector_init.add_argument("--collector-id")
    collector_init.set_defaults(func=cmd_collector_init)

    collector_run = collector_sub.add_parser("run", help="run collector API")
    _add_home(collector_run, DEFAULT_COLLECTOR_HOME)
    collector_run.add_argument("--host", default="127.0.0.1")
    collector_run.add_argument("--port", type=int, default=8787)
    collector_run.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow binding to a non-loopback address; only use behind an authenticated TLS proxy",
    )
    collector_run.set_defaults(func=cmd_collector_run)

    collector_token = collector_sub.add_parser("token", help="manage enrollment token")
    collector_token_sub = collector_token.add_subparsers(dest="token_command", required=True)
    collector_rotate = collector_token_sub.add_parser("rotate", help="rotate enrollment token")
    _add_home(collector_rotate, DEFAULT_COLLECTOR_HOME)
    collector_rotate.set_defaults(func=cmd_collector_token_rotate)

    collector_status = collector_sub.add_parser("status", help="show collector status")
    _add_home(collector_status, DEFAULT_COLLECTOR_HOME)
    collector_status.set_defaults(func=cmd_collector_status)

    case = sub.add_parser("case", help="review generated cases")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    case_list = case_sub.add_parser("list", help="list cases")
    _add_home(case_list, DEFAULT_COLLECTOR_HOME)
    case_list.add_argument("--limit", type=int, default=100)
    case_list.add_argument("--status", choices=sorted(CASE_STATUSES))
    case_list.add_argument("--json", action="store_true")
    case_list.set_defaults(func=cmd_case_list)

    case_show = case_sub.add_parser("show", help="show a case and its timeline")
    _add_home(case_show, DEFAULT_COLLECTOR_HOME)
    case_show.add_argument("case_id")
    case_show.set_defaults(func=cmd_case_show)

    case_review = case_sub.add_parser("review", help="record a human review decision")
    _add_home(case_review, DEFAULT_COLLECTOR_HOME)
    case_review.add_argument("case_id")
    case_review.add_argument(
        "--status",
        choices=sorted(CASE_STATUSES),
        default="reviewing",
    )
    case_review.add_argument("--note")
    case_review.add_argument("--actor")
    case_review.set_defaults(func=cmd_case_review)

    case_hold = case_sub.add_parser("hold", help="set or release a Legal Hold")
    _add_home(case_hold, DEFAULT_COLLECTOR_HOME)
    case_hold.add_argument("case_id")
    case_hold.add_argument("--reason", required=True)
    case_hold.add_argument("--actor")
    case_hold.add_argument("--expected-until")
    case_hold.add_argument("--release", action="store_true")
    case_hold.add_argument("--confirm", action="store_true")
    case_hold.add_argument("--hold-id")
    case_hold.set_defaults(func=cmd_case_hold)

    case_export = case_sub.add_parser("export", help="generate a signed Evidence Package")
    _add_home(case_export, DEFAULT_COLLECTOR_HOME)
    case_export.add_argument("case_id")
    case_export.add_argument("--output", type=Path)
    case_export.add_argument("--actor")
    case_export.add_argument("--no-archive", action="store_true")
    case_export.set_defaults(func=cmd_case_export)

    evidence = sub.add_parser("evidence", help="verify evidence packages offline")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_verify = evidence_sub.add_parser("verify", help="verify a package directory or ZIP")
    evidence_verify.add_argument("bundle", type=Path)
    evidence_verify.add_argument("--collector-key", type=Path)
    evidence_verify.set_defaults(func=cmd_evidence_verify)

    doctor = sub.add_parser("doctor", help="check sensor configuration and collector reachability")
    _add_home(doctor, DEFAULT_SENSOR_HOME)
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (
        FileNotFoundError,
        FileExistsError,
        ValidationError,
        CryptoError,
        StorageError,
        EvidenceError,
        SensorError,
        ListenerError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

