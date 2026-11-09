from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class CryptoError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CryptoError(f"cannot canonicalize JSON: {exc}") from exc
    return text.encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(data: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError) as exc:
        raise CryptoError("invalid Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise CryptoError("private key is not Ed25519")
    return key


def load_public_key_pem(data: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as exc:
        raise CryptoError("invalid Ed25519 public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise CryptoError("public key is not Ed25519")
    return key


def public_key_text(public_key: Ed25519PublicKey) -> str:
    return public_key_to_pem(public_key).decode("utf-8")


def load_public_key_text(text: str) -> Ed25519PublicKey:
    return load_public_key_pem(text.encode("utf-8"))


def sign_payload(private_key: Ed25519PrivateKey, payload: Any) -> str:
    signature = private_key.sign(canonical_json(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_payload(
    public_key: Ed25519PublicKey,
    payload: Any,
    signature_b64: str,
) -> bool:
    if not isinstance(signature_b64, str) or not signature_b64:
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        public_key.verify(signature, canonical_json(payload))
    except InvalidSignature:
        return False
    return True


def atomic_write_bytes(path: Path, data: bytes, mode: int) -> None:
    """Write a file atomically without creating a world-readable temp file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, mode)
        except OSError:
            pass
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    atomic_write_bytes(path, data, mode)


def write_private_key(path: Path, private_key: Ed25519PrivateKey) -> None:
    _atomic_write(path, private_key_to_pem(private_key), 0o600)


def write_public_key(path: Path, public_key: Ed25519PublicKey) -> None:
    _atomic_write(path, public_key_to_pem(public_key), 0o644)


def load_or_create_identity(identity_dir: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, bool]:
    return load_or_create_keypair(
        identity_dir,
        private_name="sensor.key",
        public_name="sensor.pub",
        label="sensor",
    )


def load_keypair(
    identity_dir: Path,
    *,
    private_name: str,
    public_name: str,
    label: str,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_path = identity_dir / private_name
    public_path = identity_dir / public_name
    has_private = private_path.exists()
    has_public = public_path.exists()
    if not has_private and not has_public:
        raise CryptoError(
            f"{label} identity is missing: {private_path} and {public_path}"
        )
    if has_private != has_public:
        raise CryptoError(f"incomplete {label} identity: private and public key must both exist")
    private_key = load_private_key_pem(private_path.read_bytes())
    public_key = load_public_key_pem(public_path.read_bytes())
    if public_key_to_pem(public_key) != public_key_to_pem(private_key.public_key()):
        raise CryptoError(f"{label} public key does not match private key")
    return private_key, public_key


def load_or_create_keypair(
    identity_dir: Path,
    *,
    private_name: str,
    public_name: str,
    label: str,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, bool]:
    private_path = identity_dir / private_name
    public_path = identity_dir / public_name
    if private_path.exists() or public_path.exists():
        private_key, public_key = load_keypair(
            identity_dir,
            private_name=private_name,
            public_name=public_name,
            label=label,
        )
        return private_key, public_key, False
    private_key = generate_private_key()
    public_key = private_key.public_key()
    write_private_key(private_path, private_key)
    write_public_key(public_path, public_key)
    return private_key, public_key, True

