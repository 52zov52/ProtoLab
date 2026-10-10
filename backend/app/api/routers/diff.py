"""Capture comparison endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import select

from ...analyzers.pcap_diff import (
    SessionSignature,
    diff_bytes,
    endpoint_delta,
    format_report,
    heatmap,
)
from ...core.errors import NotFound, ValidationFailed
from ...models import Capture, Message, Stream, TcpSession
from ...schemas import DiffRequest
from ..context import SessionDep, StorageDep, load_capture

router = APIRouter(prefix="/captures")


@router.post("/diff")
def compare_captures(payload: DiffRequest, session: SessionDep, storage: StorageDep) -> dict[str, Any]:
    base = load_capture(session, payload.base_capture_id)
    compare = load_capture(session, payload.compare_capture_id)
    if base.id == compare.id:
        raise ValidationFailed("Choose two different captures to compare.")

    base_sessions = _signatures(session, base.id)
    compare_sessions = _signatures(session, compare.id)
    matches = heatmap(base_sessions, compare_sessions)

    result: dict[str, Any] = {
        "base_capture": {"id": base.id, "name": base.name, "sha256": base.sha256},
        "compare_capture": {"id": compare.id, "name": compare.name, "sha256": compare.sha256},
        "focus": payload.focus,
        "sessions": matches,
        "session_counts": {
            "base": len(base_sessions),
            "compare": len(compare_sessions),
        },
        "version": "capture-diff/1.1",
        "interpretation_note": (
            "Everything listed here is a *difference from the baseline*. Differences "
            "are not, by themselves, anomalies or evidence of anything malicious."
        ),
    }

    base_endpoints = {e for _, sig in base_sessions for e in (sig.endpoint_a, sig.endpoint_b)}
    compare_endpoints = {e for _, sig in compare_sessions for e in (sig.endpoint_a, sig.endpoint_b)}
    if payload.focus in ("endpoints", "all"):
        result["endpoints"] = endpoint_delta(base_endpoints, compare_endpoints)

    if payload.focus in ("messages", "bytes", "all"):
        result["messages"] = _message_diff(session, base.id, compare.id, payload.max_bytes)

    if payload.focus in ("diagnostics", "all"):
        result["diagnostics"] = _diagnostic_delta(session, base.id, compare.id)

    result["report"] = format_report(matches)
    return result


def _signatures(session, capture_id: str) -> list[tuple[str, SessionSignature]]:
    rows = (
        session.execute(select(TcpSession).where(TcpSession.capture_id == capture_id))
        .scalars()
        .all()
    )
    out: list[tuple[str, SessionSignature]] = []
    for row in rows:
        summary = (row.diagnostics or {}).get("summary", {})
        lengths_a: list[int] = []
        lengths_b: list[int] = []
        for stream in (
            session.execute(
                select(Stream).where(Stream.session_id == row.id)
            ).scalars().all()
        ):
            messages = (
                session.execute(
                    select(Message.present_length)
                    .where(Message.stream_id == stream.id)
                    .order_by(Message.index_in_stream)
                    .limit(256)
                )
                .scalars()
                .all()
            )
            if stream.direction == "a2b":
                lengths_a.extend(int(m) for m in messages)
            else:
                lengths_b.extend(int(m) for m in messages)
        out.append(
            (
                row.id,
                SessionSignature(
                    endpoint_a=row.endpoint_a,
                    endpoint_b=row.endpoint_b,
                    packets=int(summary.get("packet_count", 0) or 0),
                    bytes_a_to_b=int(summary.get("bytes_a_to_b", 0) or 0),
                    bytes_b_to_a=int(summary.get("bytes_b_to_a", 0) or 0),
                    duration=float(row.end_time - row.start_time),
                    message_lengths_a_to_b=tuple(lengths_a),
                    message_lengths_b_to_a=tuple(lengths_b),
                ),
            )
        )
    return out


def _message_diff(session, base_id: str, compare_id: str, max_bytes: int) -> list[dict[str, Any]]:
    """Compare the first N messages of each capture positionally, per direction."""
    out: list[dict[str, Any]] = []
    for direction in ("a2b", "b2a"):
        base_messages = _first_messages(session, base_id, direction, limit=50)
        compare_messages = _first_messages(session, compare_id, direction, limit=50)
        for index in range(max(len(base_messages), len(compare_messages))):
            base_msg = base_messages[index] if index < len(base_messages) else None
            compare_msg = compare_messages[index] if index < len(compare_messages) else None
            if base_msg is None or compare_msg is None:
                out.append(
                    {
                        "direction": direction,
                        "index": index,
                        "status": "added" if base_msg is None else "removed",
                        "base": base_msg and {"id": base_msg[0], "length": base_msg[1]},
                        "compare": compare_msg and {"id": compare_msg[0], "length": compare_msg[1]},
                    }
                )
                continue
            if base_msg[1] != compare_msg[1]:
                delta = diff_bytes(base_msg[2][:max_bytes], compare_msg[2][:max_bytes], max_bytes=max_bytes)
                out.append(
                    {
                        "direction": direction,
                        "index": index,
                        "status": "length_changed",
                        "base": {"id": base_msg[0], "length": base_msg[1]},
                        "compare": {"id": compare_msg[0], "length": compare_msg[1]},
                        **delta.to_dict(),
                    }
                )
    return out


def _first_messages(session, capture_id: str, direction: str, limit: int):
    rows = (
        session.execute(
            select(Message.id, Message.present_length, Message.body_preview)
            .join(Stream, Stream.id == Message.stream_id)
            .where(Message.capture_id == capture_id, Stream.direction == direction)
            .order_by(Stream.id, Message.index_in_stream)
            .limit(limit)
        )
        .all()
    )
    return [
        (r.id, r.present_length, bytes.fromhex(r.body_preview or ""))
        for r in rows
    ]


def _diagnostic_delta(session, base_id: str, compare_id: str) -> dict[str, Any]:
    def counts(capture_id: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for row in session.execute(
            select(TcpSession).where(TcpSession.capture_id == capture_id)
        ).scalars():
            summary = (row.diagnostics or {}).get("summary", {})
            for entry in summary.get("duplicate_ack_runs", []) or []:
                out["duplicate_ack_runs"] = out.get("duplicate_ack_runs", 0) + 1
            if not row.completeness_status == "complete":
                out[f"completeness_{row.completeness_status}"] = (
                    out.get(f"completeness_{row.completeness_status}", 0) + 1
                )
        for stream in session.execute(
            select(Stream).where(
                Stream.session_id.in_(
                    select(TcpSession.id).where(TcpSession.capture_id == capture_id)
                )
            )
        ).scalars():
            for conflict in stream.conflicts or []:
                out["stream_conflicts"] = out.get("stream_conflicts", 0) + 1
            for hole in stream.holes or []:
                if hole.get("reason") == "missing_segments":
                    out["missing_segments"] = out.get("missing_segments", 0) + 1
        return out

    base_counts = counts(base_id)
    compare_counts = counts(compare_id)
    keys = sorted(set(base_counts) | set(compare_counts))
    return {
        "base": base_counts,
        "compare": compare_counts,
        "deltas": {
            key: compare_counts.get(key, 0) - base_counts.get(key, 0)
            for key in keys
            if compare_counts.get(key, 0) != base_counts.get(key, 0)
        },
    }


_ = NotFound