from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from . import __version__
from .batch import verify_batch
from .canary import verify_canary_sync_payload
from .crypto import (
    CryptoError,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    load_public_key_text,
    sha256_hex,
    verify_payload,
)
from .domain import Endpoint, ValidationError, utc_now
from .evidence import EvidenceError, export_case_package, verify_package
from .storage import CollectorStore, SequenceError, StorageConflict, StorageError

MAX_REQUEST_BYTES = 2 * 1024 * 1024


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str
    matrix_id: str
    public_key: str
    endpoints: list[dict[str, Any]]
    canaries: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    note: str | None = None
    actor: str | None = None


class HoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["set", "release"]
    reason: str
    actor: str | None = None
    expected_until: str | None = None
    hold_id: str | None = None
    confirm: bool = False


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str | None = None
    create_archive: bool = True


class CanarySyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    sensor_id: str
    matrix_id: str
    generated_at: str
    groups: list[dict[str, Any]]
    groups_sha256: str
    sensor_signature: str


class SensorBufferHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    accepting: bool
    blocked_reasons: list[Annotated[str, Field(max_length=256)]] = Field(
        default_factory=list, max_length=32
    )
    warnings: list[Annotated[str, Field(max_length=256)]] = Field(
        default_factory=list, max_length=32
    )
    max_events: int = Field(ge=1, le=10_000_000)
    max_bytes: int = Field(ge=1, le=10**13)
    min_free_disk_bytes: int = Field(ge=0, le=10**13)
    pending_batches: int = Field(ge=0, le=1_000_000)


class SensorEndpointHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    endpoint_id: str = Field(min_length=1, max_length=128)
    enabled: bool
    listening: bool
    listen_ip: str = Field(min_length=1, max_length=64)
    listen_port: int = Field(ge=1, le=65535)
    advertised_ip: str = Field(min_length=1, max_length=64)
    advertised_port: int = Field(ge=1, le=65535)
    transport: str = Field(min_length=1, max_length=16)
    profile_id: str = Field(min_length=1, max_length=128)
    profile_version: str | None = Field(default=None, min_length=1, max_length=64)
    source_quality: str = Field(min_length=1, max_length=32)
    mapping_consistent: bool | None = None


class SensorHealthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: int
    sensor_id: str = Field(min_length=1, max_length=128)
    matrix_id: str = Field(min_length=1, max_length=128)
    sent_at: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=128)
    status: str = Field(pattern="^(ok|degraded|blocked|unknown)$")
    queue_depth: int = Field(ge=0, le=10_000_000)
    buffer_bytes: int = Field(ge=0, le=10**13)
    disk_free_bytes: int | None = Field(default=None, ge=0, le=10**13)
    buffer: SensorBufferHealth
    endpoints: list[SensorEndpointHealth] = Field(max_length=256)
    sensor_signature: str = Field(min_length=1, max_length=1024)


class HighwallEventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_id: str
    event_type: str
    observed_at: str
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    transport: str | None = None
    method: str | None = None
    host: str | None = None
    path: str | None = None
    action: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    request_sha256: str | None = None


class HighwallImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = "highwall"
    events: list[HighwallEventInput] = Field(min_length=1, max_length=500)


def create_app(
    store: CollectorStore,
    collector_meta: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey | None = None,
    public_key: Ed25519PublicKey | None = None,
    exports_dir: Path | None = None,
) -> FastAPI:
    app = FastAPI(
        title="EvidenceWall Collector",
        version=collector_meta.get("version", __version__),
        docs_url=None,
        redoc_url=None,
    )
    package_root = Path(exports_dir) if exports_dir is not None else store.path.parent / "exports"
    package_root.mkdir(parents=True, exist_ok=True)

    @app.exception_handler(ValidationError)
    async def validation_error_handler(_request: Request, exc: ValidationError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.middleware("http")
    async def enforce_body_limit(request: Request, call_next):
        if request.headers.get("transfer-encoding"):
            return JSONResponse(
                status_code=411,
                content={"detail": "chunked request bodies are not supported; send Content-Length"},
            )
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "invalid Content-Length"})
            if length < 0:
                return JSONResponse(status_code=400, content={"detail": "invalid Content-Length"})
            if length > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "request body is too large"})
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "collector_id": collector_meta.get("collector_id"),
            "version": collector_meta.get("version", __version__),
            "time": utc_now(),
        }

    @app.post("/v1/sensors/enroll")
    def enroll(
        request: EnrollRequest,
        x_enroll_token: str | None = Header(default=None, alias="X-Enroll-Token"),
    ) -> dict[str, Any]:
        if not x_enroll_token:
            raise HTTPException(status_code=401, detail="missing X-Enroll-Token")
        try:
            load_public_key_text(request.public_key)
            endpoints = [Endpoint.from_dict(item) for item in request.endpoints]
            for endpoint in endpoints:
                if endpoint.sensor_id != request.sensor_id or endpoint.matrix_id != request.matrix_id:
                    raise ValidationError("endpoint belongs to a different sensor or matrix")
        except (CryptoError, ValidationError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            result = store.enroll_sensor(
                token_hash=sha256_hex(x_enroll_token),
                sensor_id=request.sensor_id,
                matrix_id=request.matrix_id,
                public_key=request.public_key,
                endpoints=endpoints,
                canaries=request.canaries,
                metadata=request.metadata,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "enrolled", **result}

    @app.post("/v1/events:batch")
    def ingest_batch(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        sensor_id = payload.get("sensor_id")
        if not isinstance(sensor_id, str) or not sensor_id:
            raise HTTPException(status_code=400, detail="missing sensor_id")
        sensor = store.get_sensor(sensor_id, include_public_key=True)
        if not sensor:
            raise HTTPException(status_code=404, detail="unknown sensor")
        if payload.get("matrix_id") != sensor["matrix_id"]:
            raise HTTPException(status_code=409, detail="batch matrix_id does not match registered sensor")
        try:
            public_key = load_public_key_text(sensor["public_key"])
            events = verify_batch(public_key, payload)
        except (CryptoError, ValidationError) as exc:
            if "signature" in str(exc).lower():
                store.record_signature_failure(sensor_id)
            store.audit(
                "batch_rejected",
                sensor_id,
                {"batch_id": payload.get("batch_id"), "error": str(exc)},
            )
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            return store.ingest_batch(payload, events)
        except SequenceError as exc:
            store.audit(
                "batch_rejected_sequence",
                sensor_id,
                {"batch_id": payload.get("batch_id"), "error": str(exc)},
            )
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except StorageConflict as exc:
            store.audit(
                "batch_rejected_conflict",
                sensor_id,
                {"batch_id": payload.get("batch_id"), "error": str(exc)},
            )
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except StorageError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/v1/sensors")
    def list_sensors() -> dict[str, Any]:
        return {"sensors": store.list_sensors()}

    @app.get("/v1/endpoints")
    def list_endpoints() -> dict[str, Any]:
        return {"endpoints": store.list_endpoints()}

    @app.post("/v1/sensors/health")
    def sensor_health(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        try:
            request = SensorHealthRequest.model_validate(payload)
        except PydanticValidationError as exc:
            details = exc.errors(include_url=False, include_input=False)
            raise HTTPException(status_code=400, detail=f"invalid sensor health payload: {details}") from exc
        if request.schema_version != 1:
            raise HTTPException(status_code=400, detail="unsupported sensor health schema_version")
        sensor = store.get_sensor(request.sensor_id, include_public_key=True)
        if sensor is None:
            raise HTTPException(status_code=404, detail="unknown sensor")
        signed_payload = {key: value for key, value in payload.items() if key != "sensor_signature"}
        try:
            public_key = load_public_key_text(sensor["public_key"])
        except CryptoError as exc:
            raise HTTPException(status_code=500, detail="registered sensor key is invalid") from exc
        if not verify_payload(public_key, signed_payload, request.sensor_signature):
            store.record_signature_failure(request.sensor_id)
            store.audit(
                "sensor_health_rejected",
                request.sensor_id,
                {"error": "signature verification failed"},
            )
            raise HTTPException(status_code=400, detail="health signature verification failed")
        if request.matrix_id != sensor["matrix_id"]:
            raise HTTPException(status_code=409, detail="health matrix_id does not match registered sensor")
        try:
            return store.record_sensor_health(
                sensor_id=request.sensor_id,
                matrix_id=request.matrix_id,
                sent_at=request.sent_at,
                version=request.version,
                health_status=request.status,
                queue_depth=request.queue_depth,
                buffer_bytes=request.buffer_bytes,
                disk_free_bytes=request.disk_free_bytes,
                endpoint_health=[item.model_dump() for item in request.endpoints],
                buffer=request.buffer.model_dump(),
                metadata={"source": "sensor_health"},
            )
        except ValidationError as exc:
            store.audit(
                "sensor_health_rejected",
                request.sensor_id,
                {"error": str(exc)},
            )
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/v1/cases")
    def list_cases(
        limit: int = Query(default=100, ge=1, le=500),
        status: str | None = Query(default=None),
    ) -> dict[str, Any]:
        cases = store.list_cases(limit=limit, status=status)
        return {"cases": cases, "count": len(cases)}

    @app.get("/v1/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        case = store.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        return case

    @app.post("/v1/cases/{case_id}/review")
    def review_case(case_id: str, request: ReviewRequest) -> dict[str, Any]:
        if store.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        try:
            review = store.review_case(
                case_id,
                status=request.status,
                note=request.note,
                actor=request.actor,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "reviewed", "review": review}

    @app.post("/v1/cases/{case_id}/hold")
    def legal_hold(case_id: str, request: HoldRequest) -> dict[str, Any]:
        if store.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        try:
            if request.action == "set":
                hold = store.set_legal_hold(
                    case_id,
                    reason=request.reason,
                    actor=request.actor,
                    expected_until=request.expected_until,
                )
                return {"status": "held", "hold": hold}
            hold = store.release_legal_hold(
                case_id,
                reason=request.reason,
                actor=request.actor,
                confirm=request.confirm,
                hold_id=request.hold_id,
            )
            return {"status": "released", "hold": hold}
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/cases/{case_id}/export")
    def export_case(case_id: str, request: ExportRequest) -> dict[str, Any]:
        if private_key is None or public_key is None:
            raise HTTPException(status_code=503, detail="Collector signing identity is not configured")
        if store.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        timestamp = (
            utc_now()
            .replace(":", "")
            .replace("-", "")
            .replace(".", "")
            .replace("T", "-")
            .rstrip("Z")
        )
        output_path = package_root / f"{case_id}-{timestamp}"
        try:
            package = export_case_package(
                store,
                case_id,
                output_path,
                collector_meta=collector_meta,
                private_key=private_key,
                public_key=public_key,
                actor=request.actor,
                create_archive=request.create_archive,
            )
        except FileExistsError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"cannot export evidence package: {exc}",
            ) from exc
        except EvidenceError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"status": "exported", "package": package}

    @app.get("/v1/cases/{case_id}/evidence")
    def case_evidence(case_id: str) -> dict[str, Any]:
        if store.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        packages = store.list_evidence_packages(case_id)
        response: dict[str, Any] = {"case_id": case_id, "packages": packages}
        if packages:
            latest = packages[0]
            candidate = next(
                (
                    path
                    for path in (latest.get("archive_path"), latest.get("directory_path"))
                    if path and Path(path).exists()
                ),
                None,
            )
            if candidate:
                response["latest_verification"] = verify_package(Path(candidate))
            else:
                response["latest_verification"] = {
                    "valid": False,
                    "errors": ["registered evidence package path is missing"],
                }
        return response

    @app.get("/v1/canaries")
    def list_canaries(sensor_id: str | None = Query(default=None)) -> dict[str, Any]:
        deployments = store.list_canary_deployments(sensor_id)
        return {"canaries": deployments, "count": len(deployments)}

    @app.post("/v1/sensors/canaries")
    def sync_canaries(request: CanarySyncRequest) -> dict[str, Any]:
        sensor = store.get_sensor(request.sensor_id, include_public_key=True)
        if sensor is None:
            raise HTTPException(status_code=404, detail="unknown sensor")
        if request.matrix_id != sensor["matrix_id"]:
            raise HTTPException(status_code=409, detail="canary matrix_id does not match registered sensor")
        try:
            public_key = load_public_key_text(sensor["public_key"])
            deployments = verify_canary_sync_payload(public_key, request.model_dump())
            return store.sync_canary_deployments(
                sensor_id=request.sensor_id,
                matrix_id=request.matrix_id,
                generated_at=request.generated_at,
                snapshot_sha256=request.groups_sha256,
                deployments=deployments,
            )
        except (CryptoError, ValidationError) as exc:
            if "signature" in str(exc).lower():
                store.record_signature_failure(request.sensor_id)
            store.audit(
                "canary_sync_rejected",
                request.sensor_id,
                {"groups_sha256": request.groups_sha256, "error": str(exc)},
            )
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/highwall/events")
    def highwall_events(request: HighwallImportRequest) -> dict[str, Any]:
        try:
            return store.import_highwall_events(
                source=request.source,
                events=[item.model_dump(exclude_none=True) for item in request.events],
            )
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/highwall/events")
    def list_highwall_events(
        source: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        events = store.list_highwall_events(source=source, limit=limit)
        return {"events": events, "count": len(events)}

    return app

