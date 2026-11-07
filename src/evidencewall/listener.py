from __future__ import annotations

import asyncio
import json
import logging
import time
from http import HTTPStatus
from typing import Any
from urllib.parse import urlsplit

from .canary import CanaryStore
from .crypto import sha256_hex
from .domain import Endpoint, Event, ValidationError, new_id, utc_now
from .profiles import HttpProfile, TcpProfile, get_profile
from .sensor import SensorRuntime


LOGGER = logging.getLogger(__name__)
HTTP_READ_TIMEOUT_SECONDS = 2.0
MAX_HEADER_BYTES = 32 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_FIRST_PAYLOAD_BYTES = 256
MAX_HEADER_COUNT = 100


class ListenerError(RuntimeError):
    pass


def _socket_address(value: Any, field_name: str) -> tuple[str, int]:
    if not isinstance(value, tuple) or len(value) < 2:
        raise ListenerError(f"cannot determine {field_name} from accepted socket")
    host = str(value[0]).split("%", 1)[0]
    try:
        port = int(value[1])
    except (TypeError, ValueError) as exc:
        raise ListenerError(f"cannot determine {field_name} port") from exc
    return host, port


def _request_path(target: str) -> str:
    if not target:
        return "/"
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        return parsed.path or "/"
    return target.split("?", 1)[0] or "/"


def _parse_head(head: bytes) -> dict[str, Any]:
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("iso-8859-1", errors="replace") if lines else ""
    parts = request_line.split(" ", 2)
    method = parts[0] if parts and parts[0].isalpha() and len(parts[0]) <= 32 else None
    target = parts[1] if len(parts) >= 2 and len(parts[1]) <= 8192 else None
    headers: list[tuple[str, str]] = []
    host: str | None = None
    content_length: int | None = None
    valid = method is not None and target is not None
    for raw_line in lines[1:]:
        if not raw_line:
            continue
        if len(headers) >= MAX_HEADER_COUNT or b":" not in raw_line:
            valid = False
            break
        raw_name, raw_value = raw_line.split(b":", 1)
        name = raw_name.decode("iso-8859-1", errors="replace").strip()
        value = raw_value.decode("iso-8859-1", errors="replace").strip()
        if not name or len(name) > 128 or len(value) > 4096:
            valid = False
            break
        headers.append((name, value))
        lowered = name.lower()
        if lowered == "host" and host is None:
            host = value[:255].replace("\x00", "\ufffd")
        elif lowered == "content-length" and content_length is None:
            try:
                parsed_length = int(value)
            except ValueError:
                valid = False
                break
            if parsed_length < 0:
                valid = False
                break
            content_length = parsed_length
    return {
        "valid": valid,
        "method": method.upper() if method else None,
        "target": target,
        "path": _request_path(target).replace("\x00", "\ufffd")[:4096] if target else None,
        "host": host,
        "content_length": content_length,
        "headers_fingerprint": sha256_hex(b"\r\n".join(lines[1:])) if len(lines) > 1 else None,
    }


def _http_status_line(status: int) -> bytes:
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = ""
    return f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")


def _render_http_response(
    status: int,
    headers: dict[str, str],
    body: bytes,
    *,
    head_only: bool,
) -> bytes:
    output_headers = dict(headers)
    output_headers["Content-Length"] = str(len(body))
    output_headers["Connection"] = "close"
    head = [_http_status_line(status)]
    for name, value in output_headers.items():
        head.append(f"{name}: {value}\r\n".encode("latin-1", errors="replace"))
    head.append(b"\r\n")
    return b"".join(head) + (b"" if head_only else body)


class SensorListenerService:
    def __init__(self, runtime: SensorRuntime, canaries: CanaryStore | None = None):
        self.runtime = runtime
        self.canaries = canaries or CanaryStore.load(runtime.paths.canaries)
        self._servers: list[tuple[Endpoint, asyncio.AbstractServer]] = []
        self._profiles: dict[str, HttpProfile | TcpProfile] = {}
        for endpoint in runtime.matrix.endpoints:
            if not endpoint.enabled:
                continue
            profile = get_profile(endpoint.profile_id)
            if profile.transport != endpoint.transport:
                raise ValidationError(
                    f"endpoint {endpoint.endpoint_id} transport {endpoint.transport} does not match profile {profile.profile_id}"
                )
            self._profiles[endpoint.profile_id] = profile

    async def start(self) -> list[dict[str, Any]]:
        started: list[dict[str, Any]] = []
        for endpoint in self.runtime.matrix.endpoints:
            if not endpoint.enabled:
                continue
            profile = self._profiles[endpoint.profile_id]
            if isinstance(profile, HttpProfile):
                async def handler(reader, writer, ep=endpoint, prof=profile):
                    await self._handle_http(ep, prof, reader, writer)
            else:
                async def handler(reader, writer, ep=endpoint, prof=profile):
                    await self._handle_tcp(ep, prof, reader, writer)
            try:
                server = await asyncio.start_server(
                    handler,
                    host=endpoint.listen_ip,
                    port=endpoint.listen_port,
                    limit=MAX_HEADER_BYTES + MAX_BODY_BYTES,
                )
            except OSError as exc:
                await self.close()
                raise ListenerError(
                    f"cannot listen on {endpoint.listen_ip}:{endpoint.listen_port}: {exc}"
                ) from exc
            self._servers.append((endpoint, server))
            started.append(
                {
                    "endpoint_id": endpoint.endpoint_id,
                    "listen": f"{endpoint.listen_ip}:{endpoint.listen_port}",
                    "advertised": f"{endpoint.advertised_ip}:{endpoint.advertised_port}",
                    "transport": endpoint.transport,
                    "profile_id": endpoint.profile_id,
                }
            )
        return started

    async def close(self) -> None:
        servers = self._servers
        self._servers = []
        for _endpoint, server in servers:
            server.close()
        for _endpoint, server in servers:
            await server.wait_closed()

    def _event(
        self,
        endpoint: Endpoint,
        *,
        observed_at: str,
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        method: str | None,
        host: str | None,
        path: str | None,
        headers_fingerprint: str | None,
        body_size: int | None,
        body_sha256: str | None,
        first_payload: bytes,
        canary_hashes: list[str],
        response_status: int | None,
        tarpit_ms: int,
    ) -> Event:
        event = Event(
            event_id=new_id("evt"),
            sensor_id=self.runtime.sensor_id,
            matrix_id=self.runtime.matrix_id,
            endpoint_id=endpoint.endpoint_id,
            sequence=0,
            observed_at=observed_at,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            advertised_ip=endpoint.advertised_ip,
            advertised_port=endpoint.advertised_port,
            transport=endpoint.transport,
            profile_id=endpoint.profile_id,
            source_quality=endpoint.source_quality,
            method=method,
            scheme="http" if endpoint.transport == "http1" else None,
            host=host,
            path=path,
            headers_fingerprint=headers_fingerprint,
            body_size=body_size,
            body_sha256=body_sha256,
            first_payload_size=len(first_payload),
            first_payload_sha256=sha256_hex(first_payload),
            canary_hashes=canary_hashes,
            response_status=response_status,
            tarpit_ms=tarpit_ms,
        )
        event.validate(allow_unsequenced=True)
        return event

    async def _record(self, event: Event) -> None:
        try:
            await asyncio.to_thread(self.runtime.store.append_event, event)
        except Exception:
            LOGGER.exception("failed to append decoy event to the local buffer")

    async def _handle_http(
        self,
        endpoint: Endpoint,
        profile: HttpProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        observed_at = utc_now()
        started = time.monotonic()
        first_payload = b""
        canary_hashes: list[str] = []
        method: str | None = None
        host: str | None = None
        path: str | None = None
        headers_fingerprint: str | None = None
        body_size: int | None = 0
        body_hash: str | None = sha256_hex(b"")
        response_status: int | None = None
        sent = False
        tarpit_seconds = 0.0
        try:
            source_ip, source_port = _socket_address(writer.get_extra_info("peername"), "source")
            destination_ip, destination_port = _socket_address(writer.get_extra_info("sockname"), "destination")
            buffer = bytearray()
            header_deadline = time.monotonic() + HTTP_READ_TIMEOUT_SECONDS
            while b"\r\n\r\n" not in buffer and len(buffer) < MAX_HEADER_BYTES:
                remaining_time = header_deadline - time.monotonic()
                if remaining_time <= 0:
                    break
                chunk = await asyncio.wait_for(
                    reader.read(min(4096, MAX_HEADER_BYTES - len(buffer))),
                    timeout=remaining_time,
                )
                if not chunk:
                    break
                buffer.extend(chunk)
            header_end = buffer.find(b"\r\n\r\n")
            if header_end < 0:
                first_payload = bytes(buffer[:MAX_FIRST_PAYLOAD_BYTES])
                canary_hashes = self.canaries.match(bytes(buffer))
                return
            head = bytes(buffer[:header_end])
            initial_body = bytes(buffer[header_end + 4 :])
            parsed = _parse_head(head)
            method = parsed["method"]
            host = parsed["host"]
            path = parsed["path"]
            headers_fingerprint = parsed["headers_fingerprint"]
            first_payload = (head + initial_body)[:MAX_FIRST_PAYLOAD_BYTES]
            if not parsed["valid"]:
                response_status = 400
                response = _render_http_response(
                    400,
                    {"Content-Type": "text/plain; charset=utf-8"},
                    b"Bad Request\n",
                    head_only=False,
                )
                writer.write(response)
                await writer.drain()
                sent = True
                first_payload = (head + initial_body)[:MAX_FIRST_PAYLOAD_BYTES]
                canary_hashes = self.canaries.match(head + initial_body)
                return

            content_length = parsed["content_length"]
            body_for_match = initial_body
            if content_length is None:
                body_size = len(initial_body)
                body_hash = sha256_hex(initial_body)
            elif content_length <= MAX_BODY_BYTES:
                remaining = max(0, content_length - len(initial_body))
                if remaining:
                    try:
                        initial_body += await asyncio.wait_for(
                            reader.readexactly(remaining),
                            timeout=HTTP_READ_TIMEOUT_SECONDS,
                        )
                    except asyncio.IncompleteReadError as exc:
                        initial_body += exc.partial
                        body_for_match = initial_body[:content_length]
                        body_size = len(body_for_match)
                        body_hash = sha256_hex(body_for_match)
                        first_payload = (head + body_for_match)[:MAX_FIRST_PAYLOAD_BYTES]
                        raise
                body_for_match = initial_body[:content_length]
                body_size = content_length
                body_hash = sha256_hex(body_for_match)
            else:
                body_size = content_length
                body_hash = None
                body_for_match = initial_body[:MAX_BODY_BYTES]

            first_payload = (head + body_for_match)[:MAX_FIRST_PAYLOAD_BYTES]
            canary_hashes = self.canaries.match(head + body_for_match)
            canary_values = self.canaries.active_values_for_endpoint(endpoint.endpoint_id)
            _route_id, status, response_headers, response_body, delay_ms = profile.render(
                method or "GET",
                path or "/",
                canary_values,
            )
            tarpit_seconds = delay_ms / 1000.0
            if tarpit_seconds:
                await asyncio.sleep(tarpit_seconds)
            response_status = status
            writer.write(
                _render_http_response(
                    status,
                    response_headers,
                    response_body,
                    head_only=(method == "HEAD"),
                )
            )
            await writer.drain()
            sent = True
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            tarpit_ms = int((time.monotonic() - started) * 1000) if tarpit_seconds else 0
            try:
                source_ip, source_port = _socket_address(writer.get_extra_info("peername"), "source")
                destination_ip, destination_port = _socket_address(writer.get_extra_info("sockname"), "destination")
                event = self._event(
                    endpoint,
                    observed_at=observed_at,
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    method=method,
                    host=host,
                    path=path,
                    headers_fingerprint=headers_fingerprint,
                    body_size=body_size,
                    body_sha256=body_hash,
                    first_payload=first_payload,
                    canary_hashes=canary_hashes,
                    response_status=response_status if sent else None,
                    tarpit_ms=tarpit_ms,
                )
                await self._record(event)
            except Exception:
                LOGGER.exception("failed to build HTTP decoy event")
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _handle_tcp(
        self,
        endpoint: Endpoint,
        profile: TcpProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        observed_at = utc_now()
        started = time.monotonic()
        first_payload = b""
        canary_hashes: list[str] = []
        tarpit_seconds = profile.tarpit_ms / 1000.0
        try:
            try:
                first_payload = await asyncio.wait_for(
                    reader.read(profile.read_limit),
                    timeout=profile.read_timeout_ms / 1000.0,
                )
            except asyncio.TimeoutError:
                first_payload = b""
            canary_hashes = self.canaries.match(first_payload)
            if tarpit_seconds:
                await asyncio.sleep(tarpit_seconds)
            if profile.banner:
                writer.write(profile.banner)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            tarpit_ms = int((time.monotonic() - started) * 1000) if tarpit_seconds else 0
            try:
                source_ip, source_port = _socket_address(writer.get_extra_info("peername"), "source")
                destination_ip, destination_port = _socket_address(writer.get_extra_info("sockname"), "destination")
                event = self._event(
                    endpoint,
                    observed_at=observed_at,
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    method=None,
                    host=None,
                    path=None,
                    headers_fingerprint=None,
                    body_size=None,
                    body_sha256=None,
                    first_payload=first_payload,
                    canary_hashes=canary_hashes,
                    response_status=None,
                    tarpit_ms=tarpit_ms,
                )
                await self._record(event)
            except Exception:
                LOGGER.exception("failed to build TCP decoy event")
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def run_sensor_service(runtime: SensorRuntime, *, interval: float = 5.0) -> None:
    service = SensorListenerService(runtime)
    started = await service.start()
    print(json.dumps({"status": "listening", "endpoints": started}, ensure_ascii=False, sort_keys=True), flush=True)
    previous_status: str | None = None
    try:
        while True:
            result = await asyncio.to_thread(runtime.flush_once)
            status = str(result.get("status"))
            if status != "empty" and (status != previous_status or status in {"accepted", "duplicate", "rejected"}):
                print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
            previous_status = status
            await asyncio.sleep(max(1.0, interval))
    finally:
        await service.close()
