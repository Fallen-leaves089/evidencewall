from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from . import __version__
from .crypto import canonical_json

MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class NetworkError(RuntimeError):
    pass


def normalize_base_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("collector URL must be a non-empty string")
    value = url.strip().rstrip("/")
    if not value.startswith(("http://", "https://")):
        raise ValueError("collector URL must start with http:// or https://")
    return value


def _decode_body(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"error": body[:4096].decode("utf-8", errors="replace")}
    return parsed if isinstance(parsed, dict) else {"data": parsed}


def _request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    request_headers = {
        "Accept": "application/json",
        "User-Agent": f"evidencewall/{__version__}",
    }
    if headers:
        request_headers.update(headers)
    data = None
    if payload is not None:
        data = canonical_json(payload)
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise NetworkError("collector response is too large")
            return response.status, _decode_body(body)
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise NetworkError("collector error response is too large") from exc
        return exc.code, _decode_body(body)
    except urllib.error.URLError as exc:
        raise NetworkError(f"cannot reach collector: {exc.reason}") from exc


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    return _request_json("POST", url, payload=payload, headers=headers, timeout=timeout)


def get_json(url: str, *, timeout: float = 5.0) -> tuple[int, dict[str, Any]]:
    return _request_json("GET", url, timeout=timeout)

