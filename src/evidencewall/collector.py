from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import CollectorPaths, load_collector_home, load_collector_identity
from .crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    public_key_to_pem,
    sha256_hex,
)
from .storage import CollectorStore


class CollectorRuntime:
    def __init__(
        self,
        paths: CollectorPaths,
        meta: dict[str, Any],
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
    ):
        self.paths = paths
        self.meta = meta
        self.private_key = private_key
        self.public_key = public_key
        self.store = CollectorStore(paths.database)

    @classmethod
    def open(cls, home: Path) -> "CollectorRuntime":
        paths, meta = load_collector_home(home)
        private_key, public_key = load_collector_identity(paths)
        return cls(paths, meta, private_key, public_key)

    def app(self):
        from .server import create_app

        return create_app(
            self.store,
            self.meta,
            private_key=self.private_key,
            public_key=self.public_key,
            exports_dir=self.paths.exports,
        )

    def status(self) -> dict[str, Any]:
        return {
            "collector_id": self.meta.get("collector_id"),
            "version": self.meta.get("version"),
            "collector_key_fingerprint": sha256_hex(public_key_to_pem(self.public_key)),
            **self.store.stats(),
        }

