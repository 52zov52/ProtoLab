"""Executes a validated :class:`QueryPlan` against the index.

The executor is the only place that touches the database for assistant queries,
and it only ever accepts a plan object - never SQL, never an expression string.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Capture, Message, Packet, Stream, TcpSession
from .assistant import QueryPlan, redact_secrets


class QueryExecutionError(Exception):
    pass


def execute_plan(plan: QueryPlan, session: Session, *, now: float | None = None) -> dict[str, Any]:
    current = now if now is not None else time.time()
    handlers = {
        "messages": _run_messages,
        "sessions": _run_sessions,
        "streams": _run_streams,
        "packets": _run_packets,
        "captures": _run_captures,
    }
    handler = handlers[plan.entity]
    return handler(plan, session, current)


def _capture_filter(plan: QueryPlan):
    if not plan.capture_ids:
        return None
    return [c.strip() for c in plan.capture_ids][:64]


def _run_messages(plan: QueryPlan, session: Session, now: float) -> dict[str, Any]:
    query = select(Message, Stream.direction).join(Stream, Stream.id == Message.stream_id)
    captures = _capture_filter(plan)
    if captures:
        query = query.where(Message.capture_id.in_(captures))

    rows = session.execute(query.order_by(Message.stream_id, Message.index_in_stream)).all()
    matches: list[dict[str, Any]] = []
    for message, direction in rows:
        features = message.features or {}
        context: dict[str, Any] = {
            "payload_length": message.present_length,
            "entropy": features.get("entropy"),
            "index_in_stream": message.index_in_stream,
            "start_offset": message.start_offset,
            "end_offset": message.end_offset,
            "complete": message.complete,
            "confidence": message.confidence,
            "declared_length": message.declared_length,
            "framing_method": message.framing_method,
            "timestamp": message.timestamp,
            "direction": direction,
            "payload": bytes.fromhex(message.body_preview or ""),
        }
        verdict = _match_all(plan, context, now)
        if verdict is None:
            matches.append(_message_row(message, direction, context))
    rows_out = matches[: plan.limit]
    return {
        "entity": "messages",
        "count": len(matches),
        "truncated": len(matches) > plan.limit,
        "items": rows_out,
        "navigate_to": [
            {"message_id": r["id"], "stream_id": r["stream_id"], "capture_id": r["capture_id"]}
            for r in rows_out[:20]
        ],
    }


def _message_row(message: Message, direction: str, context: dict[str, Any]) -> dict[str, Any]:
    features = message.features or {}
    return {
        "id": message.id,
        "entity_type": "message",
        "stream_id": message.stream_id,
        "capture_id": message.capture_id,
        "session_id": message.session_id,
        "direction": direction,
        "index_in_stream": message.index_in_stream,
        "start_offset": message.start_offset,
        "end_offset": message.end_offset,
        "length": message.present_length,
        "entropy": features.get("entropy"),
        "timestamp": message.timestamp,
        "complete": message.complete,
        "framing_method": message.framing_method,
        "preview": (message.body_preview or "")[:256],
    }


def _run_sessions(plan: QueryPlan, session: Session, now: float) -> dict[str, Any]:
    query = select(TcpSession)
    captures = _capture_filter(plan)
    if captures:
        query = query.where(TcpSession.capture_id.in_(captures))
    rows = session.execute(query.order_by(TcpSession.start_time)).scalars().all()
    out: list[dict[str, Any]] = []
    for row in rows:
        summary = (row.diagnostics or {}).get("summary", {})
        duration = max(1e-6, row.end_time - row.start_time)
        packets = int(summary.get("packet_count", 0) or 0)
        context = {
            "duration": row.end_time - row.start_time,
            "packet_count": packets,
            "bytes_a_to_b": int(summary.get("bytes_a_to_b", 0) or 0),
            "bytes_b_to_a": int(summary.get("bytes_b_to_a", 0) or 0),
            "completeness": row.completeness_status,
            "endpoint": row.endpoint_a,
            "role_confidence": row.role_confidence,
            "messages_per_second": packets / duration,
        }
        if _match_all(plan, context, now) is None:
            out.append(
                {
                    "id": row.id,
                    "entity_type": "session",
                    "capture_id": row.capture_id,
                    "session_identity": row.session_identity,
                    "endpoint_a": row.endpoint_a,
                    "endpoint_b": row.endpoint_b,
                    "completeness": row.completeness_status,
                    "packets": packets,
                    "duration": round(context["duration"], 4),
                    "role_confidence": row.role_confidence,
                }
            )
    return {
        "entity": "sessions",
        "count": len(out),
        "truncated": len(out) > plan.limit,
        "items": out[: plan.limit],
    }


def _run_streams(plan: QueryPlan, session: Session, now: float) -> dict[str, Any]:
    query = select(Stream, TcpSession.capture_id).join(
        TcpSession, TcpSession.id == Stream.session_id
    )
    captures = _capture_filter(plan)
    if captures:
        query = query.where(TcpSession.capture_id.in_(captures))
    rows = session.execute(query.order_by(Stream.id)).all()
    out: list[dict[str, Any]] = []
    for stream, capture_id in rows:
        context = {
            "stream_length": stream.stream_length,
            "present_bytes": stream.present_bytes,
            "has_holes": bool(stream.holes),
            "protocol": stream.protocol_label,
            "hole_count": len(stream.holes or []),
            "conflict_count": len(stream.conflicts or []),
        }
        if _match_all(plan, context, now) is None:
            out.append(
                {
                    "id": stream.id,
                    "entity_type": "stream",
                    "capture_id": capture_id,
                    "session_id": stream.session_id,
                    "direction": stream.direction,
                    "stream_length": stream.stream_length,
                    "present_bytes": stream.present_bytes,
                    "protocol": stream.protocol_label,
                    "holes": stream.holes,
                }
            )
    return {
        "entity": "streams",
        "count": len(out),
        "truncated": len(out) > plan.limit,
        "items": out[: plan.limit],
    }


def _run_packets(plan: QueryPlan, session: Session, now: float) -> dict[str, Any]:
    query = select(Packet)
    captures = _capture_filter(plan)
    if captures:
        query = query.where(Packet.capture_id.in_(captures))
    rows = session.execute(query.order_by(Packet.packet_index).limit(20_000)).scalars().all()
    out: list[dict[str, Any]] = []
    for row in rows:
        context = {
            "payload_length": row.payload_length,
            "flags": row.tcp_flags or 0,
            "address": row.source_address,
            "port": row.source_port,
            "timestamp": row.timestamp,
        }
        if _match_all(plan, context, now) is None:
            out.append(
                {
                    "id": row.packet_index,
                    "entity_type": "packet",
                    "capture_id": row.capture_id,
                    "packet_index": row.packet_index,
                    "source": f"{row.source_address}:{row.source_port}",
                    "destination": f"{row.destination_address}:{row.destination_port}",
                    "payload_length": row.payload_length,
                    "flags": row.tcp_flags,
                }
            )
    return {
        "entity": "packets",
        "count": len(out),
        "truncated": len(out) > plan.limit,
        "items": out[: plan.limit],
    }


def _run_captures(plan: QueryPlan, session: Session, now: float) -> dict[str, Any]:
    rows = session.execute(select(Capture).order_by(Capture.imported_at.desc())).scalars().all()
    out = [
        {
            "id": r.id,
            "entity_type": "capture",
            "name": r.name,
            "sha256": r.sha256,
            "bytes": r.file_size,
            "analysis_status": r.analysis_status,
            "imported_at": r.imported_at,
        }
        for r in rows
    ]
    return {"entity": "captures", "count": len(out), "truncated": False, "items": out[: plan.limit]}


# --------------------------------------------------------------------------- #


def _match_all(plan: QueryPlan, context: dict[str, Any], now: float) -> str | None:
    for item in plan.filters:
        outcome = _match(item, context, now)
        if outcome is not None:
            return f"{item.field} {item.operator} {item.value!r}: {outcome}"
    return None


def _match(item, context: dict[str, Any], now: float) -> str | None:
    field = item.field
    operator = item.operator

    if operator in ("byte_equals_at", "prefix_equals"):
        payload = context.get("payload") or b""
        width = int(item.value or 1)
        if len(payload) < width:
            return f"message shorter than {width} bytes"
        prefixes: set[bytes] = context.setdefault("_prefixes", set())
        chunk = payload[:width]
        if not prefixes:
            prefixes.add(chunk)
            return None if len(prefixes) == 1 else f"leading {width} bytes differ from the first message"
        if chunk != next(iter(prefixes)):
            prefixes.add(chunk)
            return f"leading {width} bytes differ from the first message"
        return None

    if operator == "jwt_claim_equals":
        from ..interpretation.extractor import looks_like_jwt, scan_for_jwt

        payload = context.get("payload") or b""
        hits = scan_for_jwt(payload)
        return None if hits else "no JWT-shaped value found in the plaintext payload"

    if field not in context:
        return f"field {field!r} is not available for this entity"

    value = context[field]
    if operator == "is_null":
        return None if value is None else "field is present"
    if operator == "is_not_null":
        return None if value is not None else "field is absent"
    if value is None:
        return f"field {field!r} is not available for this record"

    if operator == "greater_than":
        return None if float(value) > float(item.value) else f"{value} <= {item.value}"
    if operator == "greater_or_equal":
        return None if float(value) >= float(item.value) else f"{value} < {item.value}"
    if operator == "less_than":
        return None if float(value) < float(item.value) else f"{value} >= {item.value}"
    if operator == "less_or_equal":
        return None if float(value) <= float(item.value) else f"{value} > {item.value}"
    if operator == "equals":
        return None if value == item.value else f"{value} != {item.value}"
    if operator == "not_equals":
        return None if value != item.value else f"{value} == {item.value}"
    if operator == "in":
        return None if value in (item.value or []) else f"{value} not in {item.value}"
    if operator == "contains":
        text = value if isinstance(value, str) else context.get("payload", b"").decode("latin-1", "replace")
        return None if str(item.value).lower() in text.lower() else "substring not present"
    if operator == "starts_with":
        text = value if isinstance(value, str) else context.get("payload", b"").decode("latin-1", "replace")
        return None if text.lower().startswith(str(item.value).lower()) else "prefix differs"
    if operator == "between":
        low, high = (item.value or [0, 0])[:2]
        return None if float(low) <= float(value) <= float(high) else f"{value} outside [{low}, {high}]"
    return f"operator {operator!r} is not supported by the executor"


def count_entities(session: Session, entity: str, capture_ids: list[str]) -> int:
    if entity == "messages":
        query = select(func.count(Message.id))
        if capture_ids:
            query = query.where(Message.capture_id.in_(capture_ids))
        return int(session.scalar(query) or 0)
    return 0


_ = redact_secrets