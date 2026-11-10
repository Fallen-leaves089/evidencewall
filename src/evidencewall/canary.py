from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    atomic_write_bytes,
    canonical_json,
    sha256_hex,
    sign_payload,
    verify_payload,
)
from .domain import (
    CANARY_TYPES,
    CanaryDeployment,
    CanaryGroup,
    ValidationError,
    new_id,
    parse_iso8601,
    utc_now,
)

SCHEMA_VERSION = 1
MAX_CANARY_GROUPS = 256
CANARY_SYNC_FIELDS = {
    "schema_version",
    "sensor_id",
    "matrix_id",
    "generated_at",
    "groups",
    "groups_sha256",
    "sensor_signature",
}


def build_canary_sync_payload(
    groups: list[dict[str, Any]],
    private_key: Ed25519PrivateKey,
    *,
    sensor_id: str,
    matrix_id: str,
) -> dict[str, Any]:
    if len(groups) > MAX_CANARY_GROUPS:
        raise ValidationError(f"canary sync exceeds {MAX_CANARY_GROUPS} groups")
    for item in groups:
        CanaryDeployment.from_dict(item)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sensor_id": sensor_id,
        "matrix_id": matrix_id,
        "generated_at": utc_now(),
        "groups": groups,
        "groups_sha256": sha256_hex(canonical_json(groups)),
    }
    payload["sensor_signature"] = sign_payload(private_key, payload)
    return payload


def verify_canary_sync_payload(
    public_key: Ed25519PublicKey,
    payload: dict[str, Any],
) -> list[CanaryDeployment]:
    if not isinstance(payload, dict):
        raise ValidationError("canary sync payload must be a JSON object")
    unknown = set(payload) - CANARY_SYNC_FIELDS
    if unknown:
        raise ValidationError(f"unknown canary sync fields: {sorted(unknown)}")
    for field_name in CANARY_SYNC_FIELDS:
        if field_name not in payload:
            raise ValidationError(f"canary sync missing required field: {field_name}")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ValidationError("unsupported canary sync schema_version")
    for field_name in ("sensor_id", "matrix_id"):
        if not isinstance(payload[field_name], str) or not payload[field_name]:
            raise ValidationError(f"{field_name} must be a non-empty string")
    parse_iso8601(payload["generated_at"], "generated_at")
    if not isinstance(payload["groups"], list) or len(payload["groups"]) > MAX_CANARY_GROUPS:
        raise ValidationError(f"groups must be a list of at most {MAX_CANARY_GROUPS} entries")
    if not isinstance(payload["groups_sha256"], str) or payload["groups_sha256"] != sha256_hex(
        canonical_json(payload["groups"])
    ):
        raise ValidationError("canary groups hash mismatch")
    signature = payload["sensor_signature"]
    if not isinstance(signature, str) or not signature:
        raise ValidationError("canary sync is missing sensor_signature")
    signed_payload = {key: value for key, value in payload.items() if key != "sensor_signature"}
    if not verify_payload(public_key, signed_payload, signature):
        raise ValidationError("canary sync signature verification failed")
    deployments = [CanaryDeployment.from_dict(item) for item in payload["groups"]]
    seen_group_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for deployment in deployments:
        if deployment.group_id in seen_group_ids:
            raise ValidationError(f"duplicate canary group_id: {deployment.group_id}")
        if deployment.token_hash in seen_hashes:
            raise ValidationError("duplicate canary token hash in sync")
        seen_group_ids.add(deployment.group_id)
        seen_hashes.add(deployment.token_hash)
    return deployments


def _new_token(token_type: str) -> str:
    random_part = secrets.token_urlsafe(32)
    if token_type == "api-key":
        return f"ew_live_{random_part}"
    if token_type == "download-url":
        return f"https://canary.invalid/download/{random_part}"
    if token_type == "webhook-url":
        return f"https://canary.invalid/webhook/{random_part}"
    if token_type == "cookie":
        return f"ew_session_{random_part}"
    if token_type == "admin-token":
        return f"ew_admin_{random_part}"
    if token_type == "object-url":
        return f"https://canary.invalid/object/{random_part}"
    raise ValidationError(f"unsupported canary token type: {token_type}")


class CanaryStore:
    def __init__(self, path: Path, groups: list[CanaryGroup] | None = None):
        self.path = path
        self.groups = list(groups or [])

    @classmethod
    def load(cls, path: Path) -> "CanaryStore":
        if not path.exists():
            return cls(path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"invalid canary file {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValidationError("canary file root must be an object")
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise ValidationError("unsupported canary schema_version")
        raw_groups = payload.get("groups")
        if not isinstance(raw_groups, list) or len(raw_groups) > MAX_CANARY_GROUPS:
            raise ValidationError(f"canary groups must be a list of at most {MAX_CANARY_GROUPS} entries")
        groups = [CanaryGroup.from_dict(item) for item in raw_groups]
        seen_group_ids: set[str] = set()
        seen_token_hashes: set[str] = set()
        for group in groups:
            if group.group_id in seen_group_ids:
                raise ValidationError(f"duplicate canary group_id: {group.group_id}")
            if group.token_hash in seen_token_hashes:
                raise ValidationError("duplicate canary token hash")
            if sha256_hex(group.token) != group.token_hash:
                raise ValidationError(f"canary token hash mismatch: {group.group_id}")
            seen_group_ids.add(group.group_id)
            seen_token_hashes.add(group.token_hash)
        return cls(path, groups)

    def save(self) -> None:
        if len(self.groups) > MAX_CANARY_GROUPS:
            raise ValidationError(f"canary store exceeds {MAX_CANARY_GROUPS} groups")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "groups": [group.to_dict() for group in self.groups],
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        atomic_write_bytes(self.path, text.encode("utf-8"), 0o600)

    def create(self, token_type: str, endpoint_ids: list[str]) -> CanaryGroup:
        if token_type not in CANARY_TYPES:
            raise ValidationError(f"token_type must be one of {sorted(CANARY_TYPES)}")
        if len(self.groups) >= MAX_CANARY_GROUPS:
            raise ValidationError(f"canary store has reached the {MAX_CANARY_GROUPS} group limit")
        token = _new_token(token_type)
        group = CanaryGroup(
            group_id=new_id("canary"),
            token_type=token_type,
            token=token,
            token_hash=sha256_hex(token),
            endpoint_ids=sorted(set(endpoint_ids)),
            created_at=utc_now(),
        )
        group.validate()
        self.groups.append(group)
        self.save()
        return group

    def rotate(self, group_id: str) -> CanaryGroup:
        current = next((group for group in self.groups if group.group_id == group_id), None)
        if current is None:
            raise ValidationError(f"canary group not found: {group_id}")
        if not current.active:
            raise ValidationError(f"canary group is already retired: {group_id}")
        replacement = self.create(current.token_type, list(current.endpoint_ids))
        current.active = False
        current.retired_at = utc_now()
        current.replaced_by = replacement.group_id
        current.validate()
        self.save()
        return replacement

    def active_values_for_endpoint(self, endpoint_id: str) -> dict[str, str]:
        selected: dict[str, CanaryGroup] = {}
        for group in self.groups:
            if not group.active or endpoint_id not in group.endpoint_ids:
                continue
            previous = selected.get(group.token_type)
            if previous is None or group.created_at > previous.created_at:
                selected[group.token_type] = group
        return {token_type: group.token for token_type, group in selected.items()}

    def match(self, payload: bytes) -> list[str]:
        if not payload or not self.groups:
            return []
        candidates = [payload]
        try:
            decoded = unquote(payload.decode("utf-8", errors="ignore")).encode("utf-8")
        except (UnicodeError, ValueError):
            decoded = b""
        if decoded and decoded != payload:
            candidates.append(decoded)
        hashes: set[str] = set()
        for group in self.groups:
            token = group.token.encode("utf-8")
            if any(token in candidate for candidate in candidates):
                hashes.add(group.token_hash)
        return sorted(hashes)

    def deployment_payload(self) -> list[dict[str, Any]]:
        return [group.to_public_dict() for group in self.groups]

    def build_sync_payload(
        self,
        private_key: Ed25519PrivateKey,
        *,
        sensor_id: str,
        matrix_id: str,
    ) -> dict[str, Any]:
        return build_canary_sync_payload(
            self.deployment_payload(),
            private_key,
            sensor_id=sensor_id,
            matrix_id=matrix_id,
        )

    def public_groups(self) -> list[dict[str, Any]]:
        return [group.to_public_dict() for group in self.groups]

    def stats(self) -> dict[str, int]:
        return {
            "canary_groups": len(self.groups),
            "active_canary_groups": sum(1 for group in self.groups if group.active),
            "retired_canary_groups": sum(1 for group in self.groups if not group.active),
        }
