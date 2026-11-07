from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from .crypto import canonical_json, sha256_hex
from .domain import Event, ValidationError, format_utc, parse_iso8601


ASSOCIATION_WINDOW_SECONDS = 24 * 60 * 60
SERVICE_TARGET_MIN_EVENTS = 3
DISTRIBUTED_MIN_SOURCES = 2


def event_fingerprints(event: Event) -> list[str]:
    fingerprints: set[str] = set()
    if event.headers_fingerprint:
        fingerprints.add(event.headers_fingerprint)
    if event.tls_fingerprint:
        fingerprints.add(event.tls_fingerprint)
    if event.transport == "tcp" and event.first_payload_sha256:
        fingerprints.add(event.first_payload_sha256)
    return sorted(fingerprints)


def event_sha256(event: Event) -> str:
    return sha256_hex(canonical_json(event.to_signing_dict()))


def _parse_event_time(event: Event) -> datetime:
    return parse_iso8601(event.observed_at, "observed_at")


def _window_record(
    *,
    shape_type: str,
    confidence: str,
    first_seen: datetime,
    last_seen: datetime,
    **detail: Any,
) -> dict[str, Any]:
    return {
        "type": shape_type,
        "confidence": confidence,
        "first_seen": format_utc(first_seen),
        "last_seen": format_utc(last_seen),
        "window_seconds": max(0, int((last_seen - first_seen).total_seconds())),
        **detail,
    }


def _best_window_indices(times: list[datetime]) -> tuple[int, int] | None:
    if not times:
        return None
    ordered = sorted(times)
    best = (0, 0)
    left = 0
    for right, current in enumerate(ordered):
        while (current - ordered[left]).total_seconds() > ASSOCIATION_WINDOW_SECONDS:
            left += 1
        if right - left > best[1] - best[0]:
            best = (left, right)
    return best


def analyze_events(
    events: list[Event],
    *,
    highwall_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not events:
        raise ValidationError("case analysis requires at least one event")

    ordered = sorted(events, key=lambda item: (item.observed_at, item.sequence))
    event_times = [_parse_event_time(event) for event in ordered]
    first_seen = min(event_times)
    last_seen = max(event_times)

    sensor_ids = sorted({event.sensor_id for event in ordered})
    endpoint_ids = sorted({event.endpoint_id for event in ordered})
    source_ips = sorted({event.source_ip for event in ordered})
    asns = sorted({event.source_asn for event in ordered if event.source_asn is not None})
    canary_hashes = sorted({value for event in ordered for value in event.canary_hashes})
    fingerprints = sorted({value for event in ordered for value in event_fingerprints(event)})
    evidence_hashes = sorted({event_sha256(event) for event in ordered})
    qualities = sorted({event.source_quality for event in ordered})
    source_quality = ordered[0].source_quality

    scan_shape: list[dict[str, Any]] = []
    not_checked: list[str] = [
        "ASN and GeoIP enrichment is not enabled",
        "No full packet capture by design",
        "Source IP is observational evidence, not a person identity",
    ]
    if len(qualities) > 1:
        not_checked.append(
            "Case contains mixed source qualities; source_quality shows the first event's value"
        )

    vertical: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    horizontal: dict[tuple[str, str, int], list[Event]] = defaultdict(list)
    services: dict[tuple[str, str, str, str | None], list[Event]] = defaultdict(list)
    by_canary: dict[str, list[Event]] = defaultdict(list)
    by_fingerprint: dict[str, list[Event]] = defaultdict(list)

    for event in ordered:
        vertical[(event.source_quality, event.source_ip, event.destination_ip)].append(event)
        horizontal[(event.source_quality, event.source_ip, event.destination_port)].append(event)
        if event.profile_id:
            services[(event.source_quality, event.source_ip, event.profile_id, event.path)].append(event)
        for value in event.canary_hashes:
            by_canary[value].append(event)
        for value in event_fingerprints(event):
            by_fingerprint[value].append(event)

    for (quality, source_ip, destination_ip), group in vertical.items():
        ordered_group = sorted(group, key=lambda item: item.observed_at)
        indices = _best_window_indices([_parse_event_time(event) for event in ordered_group])
        if indices is None:
            continue
        selected = ordered_group[indices[0] : indices[1] + 1]
        ports = sorted({event.destination_port for event in selected})
        if len(ports) < 2:
            continue
        selected_times = [_parse_event_time(event) for event in selected]
        window = (min(selected_times), max(selected_times))
        scan_shape.append(
            _window_record(
                shape_type="vertical_scan",
                confidence="medium",
                first_seen=window[0],
                last_seen=window[1],
                source_quality=quality,
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_ports=ports,
                endpoint_ids=sorted({event.endpoint_id for event in selected}),
                event_count=len(selected),
            )
        )

    for (quality, source_ip, destination_port), group in horizontal.items():
        ordered_group = sorted(group, key=lambda item: item.observed_at)
        indices = _best_window_indices([_parse_event_time(event) for event in ordered_group])
        if indices is None:
            continue
        selected = ordered_group[indices[0] : indices[1] + 1]
        destination_ips = sorted({event.destination_ip for event in selected})
        if len(destination_ips) < 2:
            continue
        selected_times = [_parse_event_time(event) for event in selected]
        window = (min(selected_times), max(selected_times))
        scan_shape.append(
            _window_record(
                shape_type="horizontal_scan",
                confidence="medium",
                first_seen=window[0],
                last_seen=window[1],
                source_quality=quality,
                source_ip=source_ip,
                destination_ips=destination_ips,
                destination_port=destination_port,
                endpoint_ids=sorted({event.endpoint_id for event in selected}),
                event_count=len(selected),
            )
        )

    for (quality, source_ip, profile_id, path), group in services.items():
        ordered_group = sorted(group, key=lambda item: item.observed_at)
        indices = _best_window_indices([_parse_event_time(event) for event in ordered_group])
        if indices is None:
            continue
        selected = ordered_group[indices[0] : indices[1] + 1]
        if len(selected) < SERVICE_TARGET_MIN_EVENTS:
            continue
        selected_times = [_parse_event_time(event) for event in selected]
        window = (min(selected_times), max(selected_times))
        scan_shape.append(
            _window_record(
                shape_type="service_targeting",
                confidence="medium",
                first_seen=window[0],
                last_seen=window[1],
                source_quality=quality,
                source_ip=source_ip,
                profile_id=profile_id,
                path=path,
                event_count=len(selected),
                endpoint_ids=sorted({event.endpoint_id for event in selected}),
                methods=sorted({event.method for event in selected if event.method}),
            )
        )

    for token_hash, group in by_canary.items():
        ordered_group = sorted(group, key=lambda item: item.observed_at)
        indices = _best_window_indices([_parse_event_time(event) for event in ordered_group])
        if indices is None:
            continue
        selected = ordered_group[indices[0] : indices[1] + 1]
        source_set = sorted({event.source_ip for event in selected})
        if len(source_set) < DISTRIBUTED_MIN_SOURCES:
            continue
        selected_times = [_parse_event_time(event) for event in selected]
        window = (min(selected_times), max(selected_times))
        scan_shape.append(
            _window_record(
                shape_type="distributed_canary_reuse",
                confidence="high",
                first_seen=window[0],
                last_seen=window[1],
                canary_hash=token_hash,
                source_ips=source_set,
                endpoint_ids=sorted({event.endpoint_id for event in selected}),
                event_count=len(selected),
            )
        )

    for fingerprint, group in by_fingerprint.items():
        ordered_group = sorted(group, key=lambda item: item.observed_at)
        indices = _best_window_indices([_parse_event_time(event) for event in ordered_group])
        if indices is None:
            continue
        selected = ordered_group[indices[0] : indices[1] + 1]
        source_set = sorted({event.source_ip for event in selected})
        if len(source_set) < DISTRIBUTED_MIN_SOURCES:
            continue
        selected_times = [_parse_event_time(event) for event in selected]
        window = (min(selected_times), max(selected_times))
        scan_shape.append(
            _window_record(
                shape_type="distributed_fingerprint_reuse",
                confidence="medium",
                first_seen=window[0],
                last_seen=window[1],
                fingerprint=fingerprint,
                source_ips=source_set,
                endpoint_ids=sorted({event.endpoint_id for event in selected}),
                event_count=len(selected),
            )
        )

    highwall = list(highwall_events or [])
    if highwall:
        ordered_highwall = sorted(highwall, key=lambda item: str(item["observed_at"]))
        highwall_times = [
            parse_iso8601(str(item["observed_at"]), "observed_at") for item in ordered_highwall
        ]
        indices = _best_window_indices(highwall_times)
        selected_highwall = (
            ordered_highwall[indices[0] : indices[1] + 1] if indices is not None else []
        )
        selected_highwall_times = [
            parse_iso8601(str(item["observed_at"]), "observed_at") for item in selected_highwall
        ]
        scan_shape.append(
            _window_record(
                shape_type="highwall_corroboration",
                confidence="auxiliary",
                first_seen=min(selected_highwall_times),
                last_seen=max(selected_highwall_times),
                highwall_event_ids=sorted(
                    str(item["highwall_event_id"]) for item in selected_highwall
                ),
                source_ips=sorted(
                    {str(item["source_ip"]) for item in selected_highwall if item.get("source_ip")}
                ),
                event_types=sorted(
                    {str(item.get("event_type") or "unknown") for item in selected_highwall}
                ),
                event_count=len(selected_highwall),
            )
        )

    confidence = "low"
    signals: list[str] = []
    if canary_hashes:
        confidence = "high"
        signals.append("A configured canary token was observed in the request")
    if any(item["type"] == "distributed_canary_reuse" for item in scan_shape):
        confidence = "high"
        signals.append("The same canary was reused across multiple source IPs")
    if len(endpoint_ids) > 1:
        if confidence == "low":
            confidence = "medium"
        signals.append(f"Activity spans {len(endpoint_ids)} endpoints")
    if any(item["type"].endswith("_scan") for item in scan_shape):
        if confidence == "low":
            confidence = "medium"
        signals.append("Endpoint and destination mapping matches a scan shape within the 24-hour window")
    if any(item["type"] == "service_targeting" for item in scan_shape):
        if confidence == "low":
            confidence = "medium"
        signals.append("Repeated access targets the same profile or path")
    if any(item["type"] == "distributed_fingerprint_reuse" for item in scan_shape):
        if confidence == "low":
            confidence = "medium"
        signals.append("The same request fingerprint was reused across multiple source IPs")
    if highwall:
        if confidence == "low":
            confidence = "medium"
        signals.append("Imported Highwall events corroborate the same source/time window")
    if len(ordered) >= 3:
        if confidence == "low":
            confidence = "medium"
        signals.append(f"Repeated activity: {len(ordered)} events from this case")
    if not signals:
        signals.append("Single-source activity without a canary or cross-endpoint signal")

    recommended_actions = [
        "Review the endpoint and request timeline",
        "Preserve related gateway and application logs",
        "Do not block automatically without operator approval",
    ]
    if canary_hashes:
        recommended_actions.insert(0, "Check other endpoints for reuse of the same canary hash")
    if any(item["type"] in {"vertical_scan", "horizontal_scan"} for item in scan_shape):
        recommended_actions.insert(0, "Compare upstream firewall or proxy logs for the scan window")
    if highwall:
        recommended_actions.insert(0, "Review the corroborating Highwall event IDs before confirming the case")

    return {
        "first_seen": format_utc(first_seen),
        "last_seen": format_utc(last_seen),
        "sensor_ids": sensor_ids,
        "endpoint_ids": endpoint_ids,
        "source_ips": source_ips,
        "source_quality": source_quality,
        "asns": asns,
        "canary_hashes": canary_hashes,
        "fingerprints": fingerprints,
        "scan_shape": scan_shape,
        "confidence": confidence,
        "confidence_signals": signals,
        "recommended_actions": recommended_actions,
        "not_checked": not_checked,
        "evidence_hashes": evidence_hashes,
        "event_count": len(ordered),
    }
