from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .domain import TRANSPORTS, ValidationError


PROFILE_SCHEMA_VERSION = 1
MAX_ROUTES = 64
MAX_BODY_BYTES = 64 * 1024
MAX_HEADERS = 32
MAX_HEADER_VALUE = 1024
HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_CANARY_SLOT_RE = re.compile(r"\{\{CANARY:([a-z0-9-]+)\}\}")


def _check_headers(value: Any, field_name: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > MAX_HEADERS:
        raise ValidationError(f"{field_name} must be an object with at most {MAX_HEADERS} entries")
    headers: dict[str, str] = {}
    for name, header_value in value.items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise ValidationError(f"{field_name} contains an invalid header name")
        lowered = name.lower()
        if lowered in {"content-length", "connection", "transfer-encoding"}:
            raise ValidationError(f"{field_name} must not set {name}")
        if not isinstance(header_value, str) or len(header_value) > MAX_HEADER_VALUE:
            raise ValidationError(f"{field_name}.{name} must be a string of at most {MAX_HEADER_VALUE} characters")
        if "\r" in header_value or "\n" in header_value or "\x00" in header_value:
            raise ValidationError(f"{field_name}.{name} contains an invalid control character")
        headers[name] = header_value
    return headers


def _check_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 2048:
        raise ValidationError("profile route paths must start with / and be at most 2048 characters")
    if "?" in value or "#" in value or "\x00" in value:
        raise ValidationError("profile route paths must not contain a query, fragment, or NUL")
    return value


def _render(text: str, canary_values: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        return canary_values.get(match.group(1), "")

    return _CANARY_SLOT_RE.sub(replace, text)


@dataclass(frozen=True)
class ResponseSpec:
    status: int
    headers: dict[str, str]
    body: str
    delay_ms: int

    @classmethod
    def from_dict(cls, data: Any, field_name: str, default_delay_ms: int) -> "ResponseSpec":
        if not isinstance(data, dict):
            raise ValidationError(f"{field_name} must be an object")
        allowed = {"status", "headers", "body", "delay_ms"}
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown {field_name} fields: {sorted(unknown)}")
        status = data.get("status", 404)
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise ValidationError(f"{field_name}.status must be between 100 and 599")
        headers = _check_headers(data.get("headers", {}), f"{field_name}.headers")
        body = data.get("body", "")
        if not isinstance(body, str):
            raise ValidationError(f"{field_name}.body must be a string")
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            raise ValidationError(f"{field_name}.body exceeds {MAX_BODY_BYTES} bytes")
        delay_ms = data.get("delay_ms", default_delay_ms)
        if isinstance(delay_ms, bool) or not isinstance(delay_ms, int) or not 0 <= delay_ms <= 60_000:
            raise ValidationError(f"{field_name}.delay_ms must be between 0 and 60000")
        return cls(status=status, headers=headers, body=body, delay_ms=delay_ms)

    def render(self, canary_values: dict[str, str]) -> tuple[int, dict[str, str], bytes, int]:
        headers = {name: _render(value, canary_values) for name, value in self.headers.items()}
        headers = {name: value for name, value in headers.items() if value}
        body = _render(self.body, canary_values).encode("utf-8")
        return self.status, headers, body, self.delay_ms


@dataclass(frozen=True)
class HttpRoute:
    route_id: str
    methods: frozenset[str]
    paths: tuple[str, ...]
    response: ResponseSpec

    def matches(self, method: str, path: str) -> bool:
        if self.methods and method not in self.methods:
            return False
        for pattern in self.paths:
            if pattern.endswith("*"):
                if path.startswith(pattern[:-1]):
                    return True
            elif path == pattern:
                return True
        return False


@dataclass(frozen=True)
class HttpProfile:
    profile_id: str
    name: str
    version: str
    transport: str
    routes: tuple[HttpRoute, ...]
    fallback: ResponseSpec

    def select(self, method: str, path: str) -> tuple[str, ResponseSpec]:
        for route in self.routes:
            if route.matches(method, path):
                return route.route_id, route.response
        return "fallback", self.fallback

    def render(
        self,
        method: str,
        path: str,
        canary_values: dict[str, str],
    ) -> tuple[str, int, dict[str, str], bytes, int]:
        route_id, response = self.select(method, path)
        status, headers, body, delay_ms = response.render(canary_values)
        if "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = "text/plain; charset=utf-8"
        return route_id, status, headers, body, delay_ms


@dataclass(frozen=True)
class TcpProfile:
    profile_id: str
    name: str
    version: str
    transport: str
    banner: bytes
    tarpit_ms: int
    read_limit: int
    read_timeout_ms: int


Profile = HttpProfile | TcpProfile


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot load profile {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValidationError(f"profile {path.name} root must be an object")
    return payload


def _load_profile(path: Path) -> Profile:
    data = _load_json(path)
    if data.get("schema_version") != PROFILE_SCHEMA_VERSION:
        raise ValidationError(f"profile {path.name} has unsupported schema_version")
    profile_id = data.get("profile_id")
    if not isinstance(profile_id, str) or profile_id != path.stem:
        raise ValidationError(f"profile {path.name} profile_id must match the file name")
    name = data.get("name")
    version = data.get("version")
    transport = data.get("transport")
    if not isinstance(name, str) or not name or len(name) > 128:
        raise ValidationError(f"profile {profile_id} has an invalid name")
    if not isinstance(version, str) or not version or len(version) > 64:
        raise ValidationError(f"profile {profile_id} has an invalid version")
    if transport not in TRANSPORTS:
        raise ValidationError(f"profile {profile_id} has an invalid transport")
    if transport == "tcp":
        banner = data.get("banner", "")
        if not isinstance(banner, str) or len(banner.encode("utf-8")) > 1024:
            raise ValidationError(f"profile {profile_id} banner must be at most 1024 bytes")
        tarpit_ms = data.get("tarpit_ms", 300)
        read_limit = data.get("read_limit", 256)
        read_timeout_ms = data.get("read_timeout_ms", 1500)
        for value, field_name, maximum in (
            (tarpit_ms, "tarpit_ms", 60_000),
            (read_limit, "read_limit", 4096),
            (read_timeout_ms, "read_timeout_ms", 30_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValidationError(f"profile {profile_id} {field_name} must be between 0 and {maximum}")
        return TcpProfile(
            profile_id=profile_id,
            name=name,
            version=version,
            transport="tcp",
            banner=banner.encode("utf-8"),
            tarpit_ms=tarpit_ms,
            read_limit=read_limit,
            read_timeout_ms=read_timeout_ms,
        )

    default_delay_ms = data.get("tarpit_ms", 100)
    if isinstance(default_delay_ms, bool) or not isinstance(default_delay_ms, int) or not 0 <= default_delay_ms <= 60_000:
        raise ValidationError(f"profile {profile_id} tarpit_ms must be between 0 and 60000")
    raw_routes = data.get("routes")
    if not isinstance(raw_routes, list) or not 1 <= len(raw_routes) <= MAX_ROUTES:
        raise ValidationError(f"profile {profile_id} routes must contain 1..{MAX_ROUTES} entries")
    routes: list[HttpRoute] = []
    seen_route_ids: set[str] = set()
    for raw_route in raw_routes:
        if not isinstance(raw_route, dict):
            raise ValidationError(f"profile {profile_id} route must be an object")
        route_id = raw_route.get("route_id")
        if not isinstance(route_id, str) or not route_id or len(route_id) > 64 or route_id in seen_route_ids:
            raise ValidationError(f"profile {profile_id} has an invalid or duplicate route_id")
        seen_route_ids.add(route_id)
        raw_methods = raw_route.get("methods", [])
        if not isinstance(raw_methods, list) or len(raw_methods) > len(HTTP_METHODS):
            raise ValidationError(f"profile {profile_id} route {route_id} has invalid methods")
        methods = frozenset(str(method).upper() for method in raw_methods)
        if any(method not in HTTP_METHODS for method in methods):
            raise ValidationError(f"profile {profile_id} route {route_id} has an unsupported method")
        raw_paths = raw_route.get("paths")
        if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= 64:
            raise ValidationError(f"profile {profile_id} route {route_id} paths must contain 1..64 entries")
        paths = tuple(_check_path(item) for item in raw_paths)
        response_data = {
            key: raw_route[key]
            for key in ("status", "headers", "body", "delay_ms")
            if key in raw_route
        }
        response = ResponseSpec.from_dict(
            response_data,
            f"profile {profile_id} route {route_id}",
            default_delay_ms,
        )
        routes.append(HttpRoute(route_id=route_id, methods=methods, paths=paths, response=response))
    fallback_data = data.get("fallback")
    if not isinstance(fallback_data, dict):
        raise ValidationError(f"profile {profile_id} fallback must be an object")
    fallback = ResponseSpec.from_dict(fallback_data, f"profile {profile_id} fallback", default_delay_ms)
    return HttpProfile(
        profile_id=profile_id,
        name=name,
        version=version,
        transport="http1",
        routes=tuple(routes),
        fallback=fallback,
    )


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Profile]:
    profile_dir = Path(__file__).with_name("profiles")
    profiles: dict[str, Profile] = {}
    for path in sorted(profile_dir.glob("*.json")):
        profile = _load_profile(path)
        profiles[profile.profile_id] = profile
    if not profiles:
        raise ValidationError("no built-in profiles are available")
    return profiles


def get_profile(profile_id: str) -> Profile:
    profiles = load_catalog()
    try:
        return profiles[profile_id]
    except KeyError as exc:
        raise ValidationError(f"unknown profile: {profile_id}") from exc


def list_profiles(transport: str | None = None) -> list[Profile]:
    profiles = list(load_catalog().values())
    if transport is not None:
        profiles = [profile for profile in profiles if profile.transport == transport]
    return sorted(profiles, key=lambda profile: profile.profile_id)
