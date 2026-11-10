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
MAX_CONCURRENT_CONNECTIONS = 256
MAX_CONNECTIONS_PER_SOURCE = 32
CONNECTION_ACQUIRE_TIMEOUT_SECONDS = 0.1


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
    def __init__(
        self,
        runtime: SensorRuntime,
        canaries: CanaryStore | None = None,
        *,
        max_connections: int = MAX_CONCURRENT_CONNECTIONS,
        max_connections_per_source: int = MAX_CONNECTIONS_PER_SOURCE,
    ):
        self.runtime = runtime
        self.canaries = canaries or CanaryStore.load(runtime.paths.canaries)
        self._servers: list[tuple[Endpoint, asyncio.AbstractServer]] = []
        self._profiles: dict[str, HttpProfile | TcpProfile] = {}
        self._max_connections = max(1, int(max_connections))
        self._max_connections_per_source = max(1, int(max_connections_per_source))
        self._connection_slots = asyncio.Semaphore(self._max_connections)
        self._active_by_source: dict[str, int] = {}
        self._accepting = True
        for endpoint in runtime.matrix.endpoints:
            if not endpoint.enabled:
                continue
            profile = get_profile(endpoint.profile_id)
            if profile.transport != endpoint.transport:
                raise ValidationError(
                    f"endpoint {endpoint.endpoint_id} transport {endpoint.transport} does not match profile {profile.profile_id}"
                )
            self._profiles[endpoint.profile_id] = profile

    @property
    def is_listening(self) -> bool:
        return self._accepting and bool(self._servers)

    async def start(self) -> list[dict[str, Any]]:
        if self._servers:
            return self._listener_descriptors()
        self._accepting = True
        started: list[dict[str, Any]] = []
        try:
            for endpoint in self.runtime.matrix.endpoints:
                if not endpoint.enabled:
                    continue
                profile = self._profiles[endpoint.profile_id]

                async def handler(reader, writer, ep=endpoint, prof=profile):
                    await self._dispatch(ep, prof, reader, writer)

                server = await asyncio.start_server(
                    handler,
                    host=endpoint.listen_ip,
                    port=endpoint.listen_port,
                    limit=MAX_HEADER_BYTES + MAX_BODY_BYTES,
                )
                self._servers.append((endpoint, server))
                started.append(self._listener_descriptor(endpoint))
        except OSError as exc:
            failed_endpoint = endpoint if "endpoint" in locals() else None
            await self.pause_listeners()
            address = (
                f"{failed_endpoint.listen_ip}:{failed_endpoint.listen_port}"
                if failed_endpoint is not None
                else "configured endpoint"
            )
            raise ListenerError(f"cannot listen on {address}: {exc}") from exc
        return started

    def _listener_descriptor(self, endpoint: Endpoint) -> dict[str, Any]:
        return {
            "endpoint_id": endpoint.endpoint_id,
            "listen": f"{endpoint.listen_ip}:{endpoint.listen_port}",
            "advertised": f"{endpoint.advertised_ip}:{endpoint.advertised_port}",
            "transport": endpoint.transport,
            "profile_id": endpoint.profile_id,
        }

    def _listener_descriptors(self) -> list[dict[str, Any]]:
        return [self._listener_descriptor(endpoint) for endpoint, _server in self._servers]

    async def pause_listeners(self) -> None:
        self._accepting = False
        servers = self._servers
        self._servers = []
        for _endpoint, server in servers:
            server.close()
        for _endpoint, server in servers:
            await server.wait_closed()

    async def resume_listeners(self) -> list[dict[str, Any]]:
        if self._servers:
            self._accepting = True
            return self._listener_descriptors()
        return await self.start()

    async def close(self) -> None:
        await self.pause_listeners()

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    async def _dispatch(
        self,
        endpoint: Endpoint,
        profile: HttpProfile | TcpProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if not self._accepting:
            await self._close_writer(writer)
            return
        try:
            source_ip, _source_port = _socket_address(
                writer.get_extra_info("peername"), "source"
            )
        except ListenerError:
            await self._close_writer(writer)
            return
        active_for_source = self._active_by_source.get(source_ip, 0)
        if active_for_source >= self._max_connections_per_source:
            await self._close_writer(writer)
            return
        self._active_by_source[source_ip] = active_for_source + 1
        try:
            await asyncio.wait_for(
                self._connection_slots.acquire(),
                timeout=CONNECTION_ACQUIRE_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            self._release_source(source_ip)
            await self._close_writer(writer)
            return
        except asyncio.CancelledError:
            self._release_source(source_ip)
            if not writer.is_closing():
                writer.close()
            raise

        try:
            if isinstance(profile, HttpProfile):
                await self._handle_http(endpoint, profile, reader, writer)
            else:
                await self._handle_tcp(endpoint, profile, reader, writer)
        except Exception:
            LOGGER.exception("unhandled decoy connection failure")
        finally:
            self._release_source(source_ip)
            self._connection_slots.release()
            if not writer.is_closing():
                await self._close_writer(writer)

    def _release_source(self, source_ip: str) -> None:
        remaining = self._active_by_source.get(source_ip, 1) - 1
        if remaining > 0:
            self._active_by_source[source_ip] = remaining
        else:
            self._active_by_source.pop(source_ip, None)

    def health_endpoints(self) -> list[dict[str, Any]]:
        listening_ids = {endpoint.endpoint_id for endpoint, _server in self._servers}
        result: list[dict[str, Any]] = []
        for endpoint in self.runtime.matrix.endpoints:
            profile = self._profiles.get(endpoint.profile_id)
            if profile is None:
                try:
                    profile = get_profile(endpoint.profile_id)
                except Exception:
                    profile = None
            mapping_consistent = None
            if endpoint.exposure == "direct":
                mapping_consistent = (
                    endpoint.listen_ip == endpoint.advertised_ip
                    and endpoint.listen_port == endpoint.advertised_port
                )
            result.append(
                {
                    "endpoint_id": endpoint.endpoint_id,
                    "enabled": endpoint.enabled,
                    "listening": self._accepting and endpoint.endpoint_id in listening_ids,
                    "listen_ip": endpoint.listen_ip,
                    "listen_port": endpoint.listen_port,
                    "advertised_ip": endpoint.advertised_ip,
                    "advertised_port": endpoint.advertised_port,
                    "transport": endpoint.transport,
                    "profile_id": endpoint.profile_id,
                    "profile_version": profile.version if profile is not None else None,
                    "source_quality": endpoint.source_quality,
                    "mapping_consistent": mapping_consistent,
                }
            )
        return result

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
            await asyncio.to_thread(self.runtime.append_event, event)
        except Exception as exc:
            self.runtime.mark_storage_failure(f"append failed: {exc}")
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


async def run_sensor_service(
    runtime: SensorRuntime,
    *,
    interval: float = 5.0,
    health_interval: float = 30.0,
) -> None:
    service = SensorListenerService(runtime)
    initial_state = await asyncio.to_thread(runtime.buffer_state)
    if initial_state["accepting"]:
        started = await service.start()
        print(json.dumps({"status": "listening", "endpoints": started}, ensure_ascii=False, sort_keys=True), flush=True)
    else:
        print(
            json.dumps(
                {
                    "status": "buffer_blocked",
                    "reasons": initial_state["blocked_reasons"],
                    "message": "decoy listeners stay closed until the buffer recovers",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )
    previous_status: str | None = None
    previous_health_status: str | None = None
    next_health_at = 0.0
    try:
        while True:
            state = await asyncio.to_thread(runtime.buffer_state, force=True)
            if state["accepting"] and not service.is_listening:
                started = await service.resume_listeners()
                print(json.dumps({"status": "listening", "endpoints": started}, ensure_ascii=False, sort_keys=True), flush=True)
            elif not state["accepting"] and service.is_listening:
                await service.pause_listeners()
                print(
                    json.dumps(
                        {
                            "status": "buffer_blocked",
                            "reasons": state["blocked_reasons"],
                            "message": "decoy listeners were closed to protect evidence",
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    flush=True,
                )

            try:
                result = await asyncio.to_thread(runtime.flush_once)
            except Exception as exc:
                result = {"status": "error", "detail": str(exc)}
            status = str(result.get("status"))
            if status != "empty" and (status != previous_status or status in {"accepted", "duplicate", "rejected"}):
                print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
            previous_status = status

            now = time.monotonic()
            if now >= next_health_at:
                try:
                    health = await asyncio.to_thread(
                        runtime.report_health,
                        endpoint_health=service.health_endpoints(),
                    )
                except Exception as exc:
                    health = {"status": "error", "detail": str(exc)}
                health_status = str(health.get("status"))
                if health_status in {"rejected", "error"} or health.get("clock_skew_exceeded"):
                    print(json.dumps({"health": health}, ensure_ascii=False, sort_keys=True), flush=True)
                elif health_status != previous_health_status and health_status in {"accepted", "duplicate"}:
                    print(json.dumps({"health": health}, ensure_ascii=False, sort_keys=True), flush=True)
                previous_health_status = health_status
                next_health_at = now + max(5.0, float(health_interval))

            await asyncio.sleep(max(1.0, interval))
    finally:
        await service.close()
