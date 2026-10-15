"""TCP session endpoints: metadata, state timeline and diagnostics."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import select

from ...analyzers.capture_reader import describe_flags
from ... import prose
from ...core.errors import NotFound
from ...models import Capture, Message, Packet, Stream, TcpSession
from ...schemas import SessionOut, StreamOut
from ..context import SessionDep, StorageDep, load_capture

router = APIRouter()


@router.get("/sessions/{session_id}", response_model=SessionOut)
def get_session(session_id: str, session: SessionDep) -> TcpSession:
    row = session.get(TcpSession, session_id)
    if row is None:
        raise NotFound(f"TCP session {session_id!r} does not exist.")
    return row


@router.get("/sessions/{session_id}/streams", response_model=list[StreamOut])
def session_streams(session_id: str, session: SessionDep) -> list[Stream]:
    row = session.get(TcpSession, session_id)
    if row is None:
        raise NotFound(f"TCP session {session_id!r} does not exist.")
    return list(
        session.execute(select(Stream).where(Stream.session_id == session_id)).scalars().all()
    )


@router.get("/sessions/{session_id}/timeline")
def session_timeline(session_id: str, session: SessionDep) -> dict[str, Any]:
    """Observed TCP events for one connection, as a simplified state diagram.

    This is a visualisation of *observed* events, not a reconstruction of the
    peers' TCP state machines: packets missing from the capture are simply
    unknown, and the diagram says so.
    """
    row = session.get(TcpSession, session_id)
    if row is None:
        raise NotFound(f"TCP session {session_id!r} does not exist.")
    summary = (row.diagnostics or {}).get("summary", {})
    packets = (
        session.execute(
            select(Packet)
            .where(Packet.capture_id == row.capture_id, Packet.transport_protocol == "tcp")
            .order_by(Packet.packet_index)
        )
        .scalars()
        .all()
    )
    endpoints = {row.endpoint_a, row.endpoint_b}
    events: list[dict[str, Any]] = []
    for packet in packets:
        src = f"{packet.source_address}:{packet.source_port}"
        dst = f"{packet.destination_address}:{packet.destination_port}"
        if src not in endpoints and dst not in endpoints:
            continue
        events.append(
            {
                "packet_index": packet.packet_index,
                "timestamp": packet.timestamp,
                "direction": "a2b" if src == row.endpoint_a else "b2a",
                "source": src,
                "destination": dst,
                "sequence": packet.tcp_sequence,
                "acknowledgment": packet.tcp_acknowledgment,
                "flags": packet.tcp_flags or 0,
                "flags_text": describe_flags(packet.tcp_flags or 0),
                "window": packet.tcp_window,
                "payload_length": packet.payload_length,
                "options": packet.tcp_options,
            }
        )
    return {
        "session_id": session_id,
        "capture_id": row.capture_id,
        "completeness": row.completeness_status,
        "role_confidence": row.role_confidence,
        "role_rationale": (row.diagnostics or {}).get("role_rationale", ""),
        "split_reason": summary.get("split_reason"),
        "saw_syn": any("SYN" in e["flags_text"] for e in events),
        "saw_fin": any("FIN" in e["flags_text"] for e in events),
        "saw_rst": any("RST" in e["flags_text"] for e in events),
        "duplicate_ack_runs": summary.get("duplicate_ack_runs", []),
        "events": events,
        "disclaimer": prose.TIMELINE_DISCLAIMER,
    }


@router.get("/sessions/{session_id}/diagnostics")
def session_diagnostics(session_id: str, session: SessionDep, storage: StorageDep) -> dict[str, Any]:
    """Every diagnostic recorded while reconstructing this session."""
    row = session.get(TcpSession, session_id)
    if row is None:
        raise NotFound(f"TCP session {session_id!r} does not exist.")
    capture = load_capture(session, row.capture_id)
    streams = (
        session.execute(select(Stream).where(Stream.session_id == session_id)).scalars().all()
    )
    per_stream = []
    for stream in streams:
        diagnostics = stream.diagnostics or {}
        per_stream.append(
            {
                "stream_id": stream.id,
                "direction": stream.direction,
                "retransmissions": diagnostics.get("retransmissions", []),
                "out_of_order": diagnostics.get("out_of_order", []),
                "duplicates": diagnostics.get("duplicates", []),
                "conflicts": stream.conflicts or [],
                "holes": stream.holes or [],
                "zero_windows": diagnostics.get("zero_windows", []),
                "window_updates": diagnostics.get("window_updates", []),
                "is_truncated_start": diagnostics.get("is_truncated_start"),
                "is_truncated_end": diagnostics.get("is_truncated_end"),
                "conflict_policy": diagnostics.get("conflict_policy"),
            }
        )
    return {
        "session_id": session_id,
        "completeness": row.completeness_status,
        "role_confidence": row.role_confidence,
        "role_rationale": (row.diagnostics or {}).get("role_rationale", ""),
        "reconstruction_policy": row.reconstruction_policy,
        "session_events": (row.diagnostics or {}).get("summary", {}).get("diagnostics", []),
        "streams": per_stream,
        "explanations": {
            "retransmission": "A segment whose sequence range was already fully received with identical bytes. It is recorded, not re-inserted into the stream.",
            "out_of_order": "A segment carrying bytes behind the highest offset observed so far, indicating reordering on the path.",
            "duplicate_acks": "Adjacent pure ACKs repeating one acknowledgement value. This is a heuristic, not proof of fast retransmit.",
            "zero_window": "The peer advertised a zero receive window, meaning it had no buffer space at that moment.",
            "window_update": "The advertised window grew by more than 2x, usually after the reader drained its buffer.",
            "hole": "Bytes that no segment covered. They are shown as missing and are never replaced with zeros.",
            "conflict": "Two segments disagreed about the bytes for one sequence range. Both variants are preserved.",
            "checksum_offload": "TCP/IP checksums may be wrong because the capture host captured before the checksum was computed. This tool does not verify checksums.",
        },
    }


@router.get("/sessions/{session_id}/messages")
def session_messages(
    session_id: str,
    session: SessionDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> dict[str, Any]:
    rows = (
        session.execute(
            select(Message)
            .join(Stream, Stream.id == Message.stream_id)
            .where(Stream.session_id == session_id)
            .order_by(Stream.direction, Message.index_in_stream)
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "session_id": session_id,
        "items": [
            {
                "id": r.id,
                "stream_id": r.stream_id,
                "index_in_stream": r.index_in_stream,
                "start_offset": r.start_offset,
                "end_offset": r.end_offset,
                "present_length": r.present_length,
                "declared_length": r.declared_length,
                "timestamp": r.timestamp,
                "framing_method": r.framing_method,
                "complete": r.complete,
                "features": r.features,
            }
            for r in rows
        ],
        "offset": offset,
        "limit": limit,
    }


_ = Capture