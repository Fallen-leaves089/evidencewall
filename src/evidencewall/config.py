from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    load_or_create_identity,
    load_or_create_keypair,
    load_private_key_pem,
    load_public_key_pem,
    public_key_to_pem,
    sha256_hex,
)
from .domain import EndpointMatrix, SCHEMA_VERSION, ValidationError, new_id, utc_now


@dataclass(frozen=True)
class SensorPaths:
    root: Path

    @property
    def identity_dir(self) -> Path:
        return self.root / "identity"

    @property
    def private_key(self) -> Path:
        return self.identity_dir / "sensor.key"

    @property
    def public_key(self) -> Path:
        return self.identity_dir / "sensor.pub"

    @property
    def meta(self) -> Path:
        return self.root / "sensor.json"

    @property
    def matrix(self) -> Path:
        return self.root / "matrix.json"

    @property
    def canaries(self) -> Path:
        return self.root / "canaries.json"

    @property
    def buffer(self) -> Path:
        return self.root / "sensor.db"

    def ensure(self) -> None:
        self.identity_dir.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class CollectorPaths:
    root: Path

    @property
    def meta(self) -> Path:
        return self.root / "collector.json"

    @property
    def database(self) -> Path:
        return self.root / "collector.db"

    @property
    def exports(self) -> Path:
        return self.root / "exports"

    @property
    def identity_dir(self) -> Path:
        return self.root / "identity"

    @property
    def private_key(self) -> Path:
        return self.identity_dir / "collector.key"

    @property
    def public_key(self) -> Path:
        return self.identity_dir / "collector.pub"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.exports.mkdir(parents=True, exist_ok=True)
        self.identity_dir.mkdir(parents=True, exist_ok=True)


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def read_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"JSON root must be an object: {path}")
    return data


def init_sensor_home(
    home: Path,
    *,
    sensor_id: str | None = None,
    matrix_id: str | None = None,
    collector_url: str | None = None,
) -> tuple[SensorPaths, dict[str, Any], EndpointMatrix]:
    paths = SensorPaths(home)
    if paths.meta.exists() or paths.matrix.exists() or paths.private_key.exists():
        raise FileExistsError(f"sensor home is already initialized: {paths.root}")
    paths.ensure()
    private_key, _public_key, _created = load_or_create_identity(paths.identity_dir)
    sensor_id = sensor_id or new_id("sensor")
    matrix_id = matrix_id or new_id("matrix")
    matrix = EndpointMatrix(matrix_id=matrix_id, sensor_id=sensor_id, endpoints=[])
    matrix.validate()
    meta = {
        "schema_version": SCHEMA_VERSION,
        "sensor_id": sensor_id,
        "matrix_id": matrix_id,
        "collector_url": collector_url,
        "created_at": utc_now(),
        "version": __version__,
    }
    _atomic_write_json(paths.matrix, matrix.to_dict())
    _atomic_write_json(paths.meta, meta)
    from .storage import SensorStore

    SensorStore(paths.buffer, sensor_id, matrix_id, private_key)
    return paths, meta, matrix


def load_sensor_home(home: Path) -> tuple[SensorPaths, dict[str, Any], EndpointMatrix, Ed25519PrivateKey, Ed25519PublicKey]:
    paths = SensorPaths(home)
    meta = read_json_object(paths.meta)
    matrix = EndpointMatrix.from_dict(read_json_object(paths.matrix))
    if meta.get("sensor_id") != matrix.sensor_id or meta.get("matrix_id") != matrix.matrix_id:
        raise ValidationError("sensor.json and matrix.json disagree on sensor_id or matrix_id")
    private_key = load_private_key_pem(paths.private_key.read_bytes())
    public_key = load_public_key_pem(paths.public_key.read_bytes())
    if public_key_to_pem(public_key) != public_key_to_pem(private_key.public_key()):
        raise ValidationError("sensor public key does not match private key")
    return paths, meta, matrix, private_key, public_key


def save_sensor_meta(paths: SensorPaths, meta: dict[str, Any]) -> None:
    _atomic_write_json(paths.meta, meta)


def save_matrix(paths: SensorPaths, matrix: EndpointMatrix) -> None:
    matrix.validate()
    _atomic_write_json(paths.matrix, matrix.to_dict())


def init_collector_home(home: Path, *, collector_id: str | None = None) -> tuple[CollectorPaths, dict[str, Any], str]:
    paths = CollectorPaths(home)
    if paths.meta.exists() or paths.database.exists() or paths.private_key.exists():
        raise FileExistsError(f"collector home is already initialized: {paths.root}")
    paths.ensure()
    load_or_create_keypair(
        paths.identity_dir,
        private_name=paths.private_key.name,
        public_name=paths.public_key.name,
        label="collector",
    )
    collector_id = collector_id or new_id("collector")
    token = secrets.token_urlsafe(32)
    meta = {
        "schema_version": SCHEMA_VERSION,
        "collector_id": collector_id,
        "created_at": utc_now(),
        "db_path": paths.database.name,
        "version": __version__,
    }
    _atomic_write_json(paths.meta, meta)
    from .storage import CollectorStore

    store = CollectorStore(paths.database)
    store.create_enrollment_token(sha256_hex(token))
    return paths, meta, token


def load_collector_home(home: Path) -> tuple[CollectorPaths, dict[str, Any]]:
    paths = CollectorPaths(home)
    meta = read_json_object(paths.meta)
    return paths, meta


def load_collector_identity(
    paths: CollectorPaths,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, bool]:
    paths.ensure()
    return load_or_create_keypair(
        paths.identity_dir,
        private_name=paths.private_key.name,
        public_name=paths.public_key.name,
        label="collector",
    )


def rotate_collector_token(home: Path) -> str:
    paths, _meta = load_collector_home(home)
    token = secrets.token_urlsafe(32)
    from .storage import CollectorStore

    store = CollectorStore(paths.database)
    store.rotate_enrollment_token(sha256_hex(token))
    return token

