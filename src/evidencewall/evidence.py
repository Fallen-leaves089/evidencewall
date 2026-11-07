from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .batch import verify_batch
from .crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    canonical_json,
    load_public_key_text,
    public_key_to_pem,
    public_key_text,
    sha256_hex,
    sign_payload,
    verify_payload,
)
from .domain import Event, ValidationError, new_id, parse_iso8601, utc_now
from .storage import CollectorStore


PACKAGE_SCHEMA = "evidencewall.evidence-package.v1"
CORE_PACKAGE_FILES = (
    "case.md",
    "events.jsonl",
    "timeline.md",
    "custody.jsonl",
    "not_checked.md",
    "batches.jsonl",
    "sensors.jsonl",
    "chain.jsonl",
    "README.md",
)
PACKAGE_FILES = (*CORE_PACKAGE_FILES, "highwall.jsonl")
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
GENESIS_HASH = "0" * 64


class EvidenceError(RuntimeError):
    pass


def _json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    if pretty:
        return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    return canonical_json(value)


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json(row) + b"\n" for row in rows)


def _write_file(path: Path, data: bytes) -> None:
    with path.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _key_fingerprint(public_key: Ed25519PublicKey) -> str:
    return "sha256:" + sha256_hex(public_key_to_pem(public_key))


def _path_for_package(value: str) -> str:
    return value.split("?", 1)[0].split("#", 1)[0]


def _event_line(event: dict[str, Any], batch_id: str) -> str:
    method = event.get("method") or event.get("transport") or "-"
    target = event.get("path") or "-"
    if event.get("host"):
        target = f"{event['host']}{target if target != '-' else ''}"
    canaries = ", ".join(item[:16] for item in event.get("canary_hashes") or []) or "-"
    return (
        f"| {event['observed_at']} | {event['source_ip']}:{event['source_port']} | "
        f"{event['endpoint_id']} | {method} {_path_for_package(str(target))} | "
        f"{event.get('response_status', '-')} | {canaries} | {batch_id} |"
    )


def _render_case_md(snapshot: dict[str, Any], manifest: dict[str, Any]) -> str:
    case = snapshot["case"]
    lines = [
        f"# EvidenceWall case {case['case_id']}",
        "",
        f"- Title: {case['title']}",
        f"- Status: {case['status']}",
        f"- Confidence: {case['confidence']}",
        f"- First seen: {case['first_seen']}",
        f"- Last seen: {case['last_seen']}",
        f"- Events: {case['event_count']}",
        f"- Source quality: {case['source_quality']}",
        f"- Sources: {', '.join(case['source_ips'])}",
        f"- Endpoints: {', '.join(case['endpoint_ids'])}",
        f"- Sensors: {', '.join(case['sensor_ids'])}",
        f"- Highwall auxiliary events: {manifest['highwall_event_count']}",
        f"- Exported at: {manifest['generated_at']}",
        f"- Package ID: {manifest['package_id']}",
        "",
        "## Review warning",
        "",
        manifest["review_warning"]
        or "The case was confirmed before export. Confirmation still does not establish identity or legal attribution.",
        "",
        "## Confidence signals",
        "",
    ]
    lines.extend(f"- {item}" for item in case["confidence_signals"])
    lines.extend(["", "## Scan and correlation shapes", ""])
    if case["scan_shape"]:
        lines.append("| Type | Confidence | First seen | Last seen | Evidence |")
        lines.append("|---|---|---|---|---|")
        for item in case["scan_shape"]:
            evidence = ", ".join(
                str(value)
                for key, value in item.items()
                if key
                not in {
                    "type",
                    "confidence",
                    "first_seen",
                    "last_seen",
                    "window_seconds",
                    "event_count",
                }
            )
            lines.append(
                f"| {item['type']} | {item['confidence']} | {item['first_seen']} | "
                f"{item['last_seen']} | {evidence[:500]} |"
            )
    else:
        lines.append("No scan or cross-source correlation shape met the deterministic threshold.")
    lines.extend(["", "## Recommended actions", ""])
    lines.extend(f"- {item}" for item in case["recommended_actions"])
    lines.extend(["", "## Legal hold", ""])
    active_holds = [item for item in snapshot["legal_holds"] if item["status"] == "active"]
    if active_holds:
        for hold in active_holds:
            lines.append(
                f"- {hold['hold_id']}: {hold['reason']} (started {hold['started_at']})"
            )
    else:
        lines.append("No active Legal Hold at export time.")
    lines.extend(
        [
            "",
            "## Scope",
            "",
            "This package preserves decoy endpoint observations and selected Highwall audit events. "
            "It is not a full packet capture, does not identify a person, and does not prove who controlled a source address.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_timeline_md(snapshot: dict[str, Any]) -> str:
    lines = [
        "# Timeline",
        "",
        "| Observed (UTC) | Source | Endpoint | Request/transport | Response | Canary hash prefix | Batch |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in snapshot["events"]:
        lines.append(_event_line(item["event"], item["batch_id"]))
    lines.append("")
    return "\n".join(lines)


def _render_not_checked_md(snapshot: dict[str, Any], manifest: dict[str, Any]) -> str:
    limitations = list(snapshot["case"]["not_checked"])
    limitations.extend(
        [
            "No external RFC 3161 timestamp or notarization was obtained.",
            "The package signature proves internal consistency and Collector possession of its key; "
            "it does not by itself establish that the Collector key belongs to a trusted operator.",
            "Automatic retention deletion is not implemented in this version; Legal Hold is recorded "
            "but no deletion worker exists to be blocked.",
            "No full packet capture exists by design.",
            "Source addresses and ASN data are observational evidence, not person identity.",
            "Highwall events are auxiliary imports and are not independently re-verified by this package.",
        ]
    )
    lines = ["# Not checked and limitations", ""]
    lines.extend(f"- {item}" for item in limitations)
    lines.extend(["", "## Export-time warnings", ""])
    lines.extend(f"- {item}" for item in manifest["warnings"])
    lines.append("")
    return "\n".join(lines)


def _render_readme() -> str:
    return (
        "# EvidenceWall Evidence Package\n\n"
        "Verify this directory or archive offline with:\n\n"
        "```text\n"
        "evidencewall evidence verify <package-dir-or-zip>\n"
        "```\n\n"
        "For adversarial or third-party verification, pin the Collector public key:\n\n"
        "```text\n"
        "evidencewall evidence verify <package-dir-or-zip> --collector-key collector.pub\n"
        "```\n\n"
        "The verifier checks file hashes, the Collector manifest signature, Sensor event and batch "
        "signatures, the event hash chain, and the integrity of imported Highwall records. "
        "highwall.jsonl contains normalised, redacted Highwall imports; those upstream records are "
        "auxiliary evidence and are not signed by EvidenceWall Sensor identity. A self-contained "
        "signature detects in-place tampering but cannot detect wholesale replacement with a different "
        "key unless the expected key is pinned.\n"
    )


def _build_chain(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    chain: list[dict[str, Any]] = []
    previous = GENESIS_HASH
    for index, item in enumerate(events):
        step = {
            "index": index,
            "event_id": item["event"]["event_id"],
            "event_sha256": item["event_sha256"],
            "previous": previous,
        }
        chain_hash = sha256_hex(canonical_json(step))
        chain.append({**step, "chain_sha256": chain_hash})
        previous = chain_hash
    return chain, previous


def _sensor_key_map(snapshot: dict[str, Any]) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for sensor in snapshot["sensors"]:
        keys[sensor["sensor_id"]] = load_public_key_text(sensor["public_key"])
    return keys


def _verify_snapshot_integrity(snapshot: dict[str, Any]) -> None:
    errors: list[str] = []
    try:
        keys = _sensor_key_map(snapshot)
    except Exception as exc:
        raise ValidationError(f"cannot load Sensor public keys: {exc}") from exc
    for item in snapshot["events"]:
        try:
            event = Event.from_dict(item["event"])
            sensor_key = keys.get(event.sensor_id)
            if sensor_key is None:
                errors.append(f"missing Sensor key for {event.sensor_id}")
                continue
            if not event.sensor_signature or not verify_payload(
                sensor_key, event.to_signing_dict(), event.sensor_signature
            ):
                errors.append(f"invalid event signature: {event.event_id}")
            if sha256_hex(canonical_json(event.to_signing_dict())) != item["event_sha256"]:
                errors.append(f"event hash mismatch: {event.event_id}")
        except Exception as exc:
            errors.append(f"invalid stored event: {exc}")
    for batch in snapshot["batches"]:
        sensor_id = batch.get("sensor_id") if isinstance(batch, dict) else None
        sensor_key = keys.get(str(sensor_id)) if sensor_id else None
        if sensor_key is None:
            errors.append(f"missing Sensor key for batch {sensor_id}")
            continue
        try:
            verify_batch(sensor_key, batch)
        except Exception as exc:
            errors.append(f"invalid batch {batch.get('batch_id')}: {exc}")
    if errors:
        raise ValidationError("evidence integrity check failed before export: " + "; ".join(errors))


def _manifest_case_summary(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case["case_id"],
        "title": case["title"],
        "status": case["status"],
        "confidence": case["confidence"],
        "first_seen": case["first_seen"],
        "last_seen": case["last_seen"],
        "event_count": case["event_count"],
        "source_quality": case["source_quality"],
        "source_ips": case["source_ips"],
        "endpoint_ids": case["endpoint_ids"],
        "sensor_ids": case["sensor_ids"],
        "canary_hashes": case["canary_hashes"],
        "scan_shape": case["scan_shape"],
        "evidence_hashes": case["evidence_hashes"],
        "legal_hold_id": case.get("legal_hold_id"),
    }


def export_case_package(
    store: CollectorStore,
    case_id: str,
    output_path: Path,
    *,
    collector_meta: dict[str, Any],
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    actor: str | None = None,
    create_archive: bool = True,
) -> dict[str, Any]:
    snapshot = store.evidence_snapshot(case_id)
    _verify_snapshot_integrity(snapshot)
    output_path = Path(output_path)
    if output_path.exists():
        raise FileExistsError(f"evidence package output already exists: {output_path}")
    package_id = new_id("package")
    generated_at = utc_now()
    actor_name = actor or "local-operator"
    package_key = public_key_text(public_key)
    chain, chain_head = _build_chain(snapshot["events"])
    warnings = [
        "A self-contained Collector signature detects content changes, but not wholesale substitution "
        "by a different signing key. Pin the expected Collector public key for adversarial verification.",
        "No external timestamp or notarization is included.",
    ]
    review_warning = None
    if snapshot["case"]["status"] != "confirmed":
        review_warning = (
            f"Case status is {snapshot['case']['status']}; complete human review and confirm the case "
            "before using this package for external complaints or legal escalation."
        )
        warnings.append(review_warning)
    custody = list(snapshot["custody"])
    custody.append(
        {
            "id": None,
            "at": generated_at,
            "action": "evidence_exported",
            "actor": actor_name,
            "detail": {
                "case_id": case_id,
                "package_id": package_id,
                "note": "Evidence Package generated locally; source evidence was not modified.",
            },
        }
    )
    highwall_events = list(snapshot["highwall_events"])
    manifest: dict[str, Any] = {
        "schema": PACKAGE_SCHEMA,
        "package_id": package_id,
        "generated_at": generated_at,
        "collector": {
            "collector_id": collector_meta.get("collector_id"),
            "version": collector_meta.get("version"),
            "public_key": package_key,
            "key_fingerprint": _key_fingerprint(public_key),
        },
        "case": _manifest_case_summary(snapshot["case"]),
        "event_count": len(snapshot["events"]),
        "event_ids": [item["event"]["event_id"] for item in snapshot["events"]],
        "batch_ids": [item["batch_id"] for item in snapshot["batches"]],
        "sensor_ids": [item["sensor_id"] for item in snapshot["sensors"]],
        "highwall_event_count": len(highwall_events),
        "highwall_event_ids": [item["highwall_event_id"] for item in highwall_events],
        "evidence_chain": {
            "algorithm": "sha256(canonical-json(step))",
            "genesis": GENESIS_HASH,
            "head": chain_head,
            "length": len(chain),
        },
        "legal_holds": snapshot["legal_holds"],
        "review_warning": review_warning,
        "warnings": warnings,
        "files": {},
        "collector_signature": "",
    }
    content: dict[str, bytes] = {
        "case.md": (_render_case_md(snapshot, manifest) + "\n").encode("utf-8"),
        "events.jsonl": _jsonl_bytes(snapshot["events"]),
        "timeline.md": _render_timeline_md(snapshot).encode("utf-8"),
        "custody.jsonl": _jsonl_bytes(custody),
        "not_checked.md": _render_not_checked_md(snapshot, manifest).encode("utf-8"),
        "batches.jsonl": _jsonl_bytes(snapshot["batches"]),
        "sensors.jsonl": _jsonl_bytes(snapshot["sensors"]),
        "chain.jsonl": _jsonl_bytes(chain),
        "highwall.jsonl": _jsonl_bytes(highwall_events),
        "README.md": _render_readme().encode("utf-8"),
    }
    manifest["files"] = {
        name: {"sha256": sha256_hex(data), "size": len(data)}
        for name, data in sorted(content.items())
    }
    signed_manifest = {key: value for key, value in manifest.items() if key != "collector_signature"}
    manifest["collector_signature"] = sign_payload(private_key, signed_manifest)
    manifest_bytes = _json_bytes(manifest, pretty=True)

    archive_path = output_path.with_suffix(output_path.suffix + ".zip") if create_archive else None
    if archive_path is not None and archive_path.exists():
        raise FileExistsError(f"evidence package archive already exists: {archive_path}")
    staging = output_path.with_name(f".{output_path.name}.tmp-{package_id}")
    archive_staging = (
        archive_path.with_name(f".{archive_path.name}.tmp-{package_id}")
        if archive_path is not None
        else None
    )
    archive_sha256: str | None = None
    try:
        staging.mkdir(parents=True, exist_ok=False)
        for name, data in content.items():
            _write_file(staging / name, data)
        _write_file(staging / "manifest.json", manifest_bytes)
        if archive_path is not None and archive_staging is not None:
            with zipfile.ZipFile(archive_staging, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name in sorted([*content.keys(), "manifest.json"]):
                    archive.write(staging / name, arcname=name)
            archive_sha256 = sha256_hex(archive_staging.read_bytes())
        os.replace(staging, output_path)
        if archive_path is not None and archive_staging is not None:
            os.replace(archive_staging, archive_path)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if archive_staging is not None and archive_staging.exists():
            archive_staging.unlink(missing_ok=True)
        raise

    manifest_sha256 = sha256_hex(manifest_bytes)
    try:
        store.record_evidence_package(
            package_id=package_id,
            case_id=case_id,
            created_at=generated_at,
            directory_path=str(output_path),
            archive_path=str(archive_path) if archive_path is not None else None,
            manifest_sha256=manifest_sha256,
            package_sha256=archive_sha256,
            actor=actor_name,
        )
    except Exception as exc:
        raise EvidenceError(
            f"package files were written but package registration failed: {exc}; "
            "the stored case still points to the previous package"
        ) from exc
    return {
        "package_id": package_id,
        "case_id": case_id,
        "generated_at": generated_at,
        "directory_path": str(output_path),
        "archive_path": str(archive_path) if archive_path is not None else None,
        "manifest_sha256": manifest_sha256,
        "package_sha256": archive_sha256,
        "key_fingerprint": manifest["collector"]["key_fingerprint"],
        "review_warning": review_warning,
    }


def _load_package_files(path: Path) -> dict[str, bytes]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(str(path))
    files: dict[str, bytes] = {}
    if path.is_dir():
        total = 0
        for candidate in sorted(path.rglob("*")):
            if candidate.is_symlink():
                raise ValidationError(f"package contains a symlink: {candidate}")
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(path).as_posix()
            data = candidate.read_bytes()
            total += len(data)
            if total > MAX_PACKAGE_BYTES:
                raise ValidationError("package exceeds the maximum supported size")
            files[relative] = data
        return files
    if not path.is_file():
        raise ValidationError("package path must be a directory or ZIP archive")
    with zipfile.ZipFile(path, "r") as archive:
        total = 0
        seen: set[str] = set()
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise ValidationError("encrypted ZIP members are not supported")
            name = info.filename.replace("\\", "/")
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or not name:
                raise ValidationError(f"unsafe ZIP member path: {info.filename}")
            if name in seen:
                raise ValidationError(f"duplicate ZIP member: {name}")
            seen.add(name)
            if info.file_size > MAX_PACKAGE_BYTES:
                raise ValidationError(f"ZIP member is too large: {name}")
            total += info.file_size
            if total > MAX_PACKAGE_BYTES:
                raise ValidationError("ZIP package exceeds the maximum supported size")
            with archive.open(info, "r") as handle:
                files[name] = handle.read()
    return files


def _parse_json_file(files: dict[str, bytes], name: str) -> Any:
    data = files.get(name)
    if data is None:
        raise ValidationError(f"package is missing {name}")
    if name == "manifest.json" and len(data) > MAX_MANIFEST_BYTES:
        raise ValidationError("manifest is too large")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid JSON in {name}: {exc}") from exc


def _parse_jsonl(files: dict[str, bytes], name: str) -> list[Any]:
    data = files.get(name)
    if data is None:
        raise ValidationError(f"package is missing {name}")
    rows: list[Any] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{name} is not UTF-8") from exc
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"invalid JSONL in {name} line {line_number}: {exc}") from exc
    return rows


def verify_package(
    package_path: Path,
    *,
    expected_public_key: Ed25519PublicKey | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    report: dict[str, Any] = {
        "valid": False,
        "path": str(package_path),
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "trust_anchor_pinned": expected_public_key is not None,
    }

    def check(name: str, function) -> Any | None:
        try:
            value = function()
            checks.append({"check": name, "ok": True})
            return value
        except Exception as exc:
            checks.append({"check": name, "ok": False, "error": str(exc)})
            errors.append(f"{name}: {exc}")
            return None

    files = check("package_read", lambda: _load_package_files(package_path))
    if files is None:
        return report
    manifest = check("manifest_parse", lambda: _parse_json_file(files, "manifest.json"))
    if not isinstance(manifest, dict):
        if manifest is not None:
            errors.append("manifest_parse: manifest root must be an object")
        return report
    report["package_id"] = manifest.get("package_id")
    report["collector_id"] = (manifest.get("collector") or {}).get("collector_id")
    report["case_id"] = (manifest.get("case") or {}).get("case_id")
    report["key_fingerprint"] = (manifest.get("collector") or {}).get("key_fingerprint")

    def verify_manifest_signature() -> None:
        if manifest.get("schema") != PACKAGE_SCHEMA:
            raise ValidationError("unsupported evidence package schema")
        signature = manifest.get("collector_signature")
        if not isinstance(signature, str) or not signature:
            raise ValidationError("manifest is missing collector_signature")
        collector = manifest.get("collector")
        if not isinstance(collector, dict):
            raise ValidationError("manifest collector section is missing")
        key_text = collector.get("public_key")
        if not isinstance(key_text, str) or not key_text:
            raise ValidationError("manifest collector public_key is missing")
        embedded_key = load_public_key_text(key_text)
        if _key_fingerprint(embedded_key) != collector.get("key_fingerprint"):
            raise ValidationError("collector key fingerprint mismatch")
        signed = {key: value for key, value in manifest.items() if key != "collector_signature"}
        if not verify_payload(embedded_key, signed, signature):
            raise ValidationError("collector manifest signature verification failed")
        if expected_public_key is not None:
            if public_key_to_pem(expected_public_key) != public_key_to_pem(embedded_key):
                raise ValidationError("package Collector key does not match the pinned key")
            if not verify_payload(expected_public_key, signed, signature):
                raise ValidationError("manifest signature does not verify with the pinned key")

    check("collector_signature", verify_manifest_signature)

    def verify_file_hashes() -> None:
        declared = manifest.get("files")
        if not isinstance(declared, dict):
            raise ValidationError("manifest files section is missing")
        expected_names = set(declared) | {"manifest.json"}
        actual_names = set(files)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            extra = sorted(actual_names - expected_names)
            raise ValidationError(f"package file set mismatch; missing={missing}, extra={extra}")
        for name, metadata in declared.items():
            if not isinstance(metadata, dict):
                raise ValidationError(f"invalid file metadata: {name}")
            data = files[name]
            if sha256_hex(data) != metadata.get("sha256"):
                raise ValidationError(f"file hash mismatch: {name}")
            if len(data) != metadata.get("size"):
                raise ValidationError(f"file size mismatch: {name}")

    check("file_hashes", verify_file_hashes)

    sensors = check("sensor_records", lambda: _parse_jsonl(files, "sensors.jsonl"))
    events = check("event_records", lambda: _parse_jsonl(files, "events.jsonl"))
    batches = check("batch_records", lambda: _parse_jsonl(files, "batches.jsonl"))
    chain = check("chain_records", lambda: _parse_jsonl(files, "chain.jsonl"))
    highwall = (
        check("highwall_records", lambda: _parse_jsonl(files, "highwall.jsonl"))
        if "highwall.jsonl" in files
        else []
    )
    if any(value is None for value in (sensors, events, batches, chain, highwall)):
        return report

    sensor_keys: dict[str, Ed25519PublicKey] = {}

    def verify_sensors() -> None:
        for sensor in sensors:
            if not isinstance(sensor, dict):
                raise ValidationError("sensor record must be an object")
            sensor_id = sensor.get("sensor_id")
            if not isinstance(sensor_id, str) or not sensor_id:
                raise ValidationError("sensor record has no sensor_id")
            sensor_keys[sensor_id] = load_public_key_text(sensor.get("public_key"))
        declared_ids = manifest.get("sensor_ids")
        if sorted(sensor_keys) != sorted(declared_ids or []):
            raise ValidationError("manifest sensor_ids do not match sensor records")

    check("sensor_keys", verify_sensors)

    event_by_id: dict[str, dict[str, Any]] = {}

    def verify_events() -> None:
        ordered_ids: list[str] = []
        for item in events:
            if not isinstance(item, dict) or not isinstance(item.get("event"), dict):
                raise ValidationError("event record must contain an event object")
            event = Event.from_dict(item["event"])
            sensor_key = sensor_keys.get(event.sensor_id)
            if sensor_key is None:
                raise ValidationError(f"missing Sensor key for {event.sensor_id}")
            event_hash = sha256_hex(canonical_json(event.to_signing_dict()))
            if event_hash != item.get("event_sha256"):
                raise ValidationError(f"event hash mismatch: {event.event_id}")
            if not event.sensor_signature or not verify_payload(
                sensor_key, event.to_signing_dict(), event.sensor_signature
            ):
                raise ValidationError(f"event signature failed: {event.event_id}")
            if event.event_id in event_by_id:
                raise ValidationError(f"duplicate event record: {event.event_id}")
            event_by_id[event.event_id] = item
            ordered_ids.append(event.event_id)
        if ordered_ids != list(manifest.get("event_ids") or []):
            raise ValidationError("manifest event_ids do not match events.jsonl order")
        if len(ordered_ids) != manifest.get("event_count"):
            raise ValidationError("manifest event_count does not match events.jsonl")

    check("event_signatures", verify_events)

    def verify_batches() -> None:
        seen_batch_ids: list[str] = []
        for payload in batches:
            if not isinstance(payload, dict):
                raise ValidationError("batch record must be an object")
            sensor_key = sensor_keys.get(payload.get("sensor_id"))
            if sensor_key is None:
                raise ValidationError(f"missing Sensor key for batch {payload.get('sensor_id')}")
            verify_batch(sensor_key, payload)
            seen_batch_ids.append(payload["batch_id"])
        if seen_batch_ids != list(manifest.get("batch_ids") or []):
            raise ValidationError("manifest batch_ids do not match batches.jsonl")
        event_batch_ids = {item.get("batch_id") for item in event_by_id.values()}
        if not event_batch_ids.issubset(set(seen_batch_ids)):
            raise ValidationError("an event references a batch that is not included in the package")

    check("batch_signatures", verify_batches)

    def verify_highwall_records() -> None:
        if highwall is None:
            return
        declared_count = manifest.get("highwall_event_count")
        declared_ids = manifest.get("highwall_event_ids")
        if declared_count is None and declared_ids is None:
            if highwall:
                raise ValidationError(
                    "highwall.jsonl is present but the manifest does not declare Highwall records"
                )
            return
        if "highwall.jsonl" not in files:
            raise ValidationError("manifest declares Highwall records but highwall.jsonl is missing")
        if isinstance(declared_count, bool) or not isinstance(declared_count, int) or declared_count < 0:
            raise ValidationError("manifest highwall_event_count is invalid")
        if not isinstance(declared_ids, list) or any(
            not isinstance(item, str) or not item for item in declared_ids
        ):
            raise ValidationError("manifest highwall_event_ids is invalid")
        if declared_count != len(highwall):
            raise ValidationError("manifest highwall_event_count does not match highwall.jsonl")
        if declared_count != len(declared_ids):
            raise ValidationError("manifest highwall_event_ids length does not match count")

        ordered_ids: list[str] = []
        for item in highwall:
            if not isinstance(item, dict):
                raise ValidationError("Highwall record must be an object")
            highwall_event_id = item.get("highwall_event_id")
            source = item.get("source")
            external_id = item.get("external_id")
            event_type = item.get("event_type")
            observed_at = item.get("observed_at")
            received_at = item.get("received_at")
            payload_hash = item.get("payload_sha256")
            payload = item.get("payload")
            if not all(
                isinstance(value, str) and value
                for value in (highwall_event_id, source, external_id, event_type, observed_at, received_at)
            ):
                raise ValidationError("Highwall record has missing or invalid metadata")
            if not isinstance(payload_hash, str) or len(payload_hash) != 64:
                raise ValidationError("Highwall record has an invalid payload_sha256")
            if not isinstance(payload, dict):
                raise ValidationError("Highwall record has no payload object")
            expected_id = "hwe_" + sha256_hex(
                canonical_json({"source": source, "external_id": external_id})
            )
            if highwall_event_id != expected_id:
                raise ValidationError(f"Highwall event ID mismatch: {highwall_event_id}")
            if sha256_hex(canonical_json(payload)) != payload_hash:
                raise ValidationError(f"Highwall payload hash mismatch: {highwall_event_id}")
            parse_iso8601(observed_at, "observed_at")
            parse_iso8601(received_at, "received_at")
            for field_name, expected in (
                ("source", source),
                ("external_id", external_id),
                ("event_type", event_type),
                ("observed_at", observed_at),
            ):
                if payload.get(field_name) != expected:
                    raise ValidationError(
                        f"Highwall payload {field_name} does not match record metadata: {highwall_event_id}"
                    )
            if payload.get("source_ip") != item.get("source_ip"):
                raise ValidationError(
                    f"Highwall payload source_ip does not match record metadata: {highwall_event_id}"
                )
            ordered_ids.append(highwall_event_id)
        if ordered_ids != declared_ids:
            raise ValidationError("manifest highwall_event_ids does not match highwall.jsonl order")

    check("highwall_integrity", verify_highwall_records)

    def verify_chain() -> None:
        if len(chain) != len(events):
            raise ValidationError("chain length does not match event count")
        previous = GENESIS_HASH
        for index, step in enumerate(chain):
            if not isinstance(step, dict):
                raise ValidationError("chain step must be an object")
            event_item = events[index]
            if step.get("index") != index:
                raise ValidationError("chain index mismatch")
            if step.get("event_id") != event_item["event"]["event_id"]:
                raise ValidationError("chain event_id does not match events.jsonl")
            if step.get("event_sha256") != event_item["event_sha256"]:
                raise ValidationError("chain event hash does not match events.jsonl")
            if step.get("previous") != previous:
                raise ValidationError("chain previous hash mismatch")
            payload = {
                "index": index,
                "event_id": step["event_id"],
                "event_sha256": step["event_sha256"],
                "previous": previous,
            }
            chain_hash = sha256_hex(canonical_json(payload))
            if step.get("chain_sha256") != chain_hash:
                raise ValidationError("chain hash mismatch")
            previous = chain_hash
        evidence_chain = manifest.get("evidence_chain") or {}
        if evidence_chain.get("head") != previous:
            raise ValidationError("manifest chain head does not match chain.jsonl")
        if evidence_chain.get("length") != len(chain):
            raise ValidationError("manifest chain length does not match chain.jsonl")

    check("evidence_chain", verify_chain)

    def verify_required_documents() -> None:
        for name in CORE_PACKAGE_FILES:
            if name not in files or not files[name].strip():
                raise ValidationError(f"required package file is missing or empty: {name}")
        if "highwall_event_count" in manifest:
            if "highwall.jsonl" not in files:
                raise ValidationError("required package file is missing: highwall.jsonl")
            if manifest.get("highwall_event_count") and not files["highwall.jsonl"].strip():
                raise ValidationError("highwall.jsonl is empty but Highwall events are declared")

    check("required_documents", verify_required_documents)
    if expected_public_key is None:
        warnings.append(
            "Collector signature is self-contained. Pin the Collector public key for trust verification."
        )
    report["valid"] = not errors
    return report
