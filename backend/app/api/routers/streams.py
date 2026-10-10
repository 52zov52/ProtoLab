"""TCP session and stream exploration: state timeline, hex view, provenance."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from ...analyzers.byte_analysis import align_messages, group_by_length, hexdump
from ...analyzers.capture_reader import describe_flags
from ...analyzers.framing import FramingConfig, suggest_framing
from ...analyzers.tcp_reassembly import summarise_timeline
from ...core.errors import NotFound
from ...models import Capture, Message, Packet, Stream, TcpSession
from ...schemas import CompareRequest, MessageOut, SessionOut, StreamOut
from ..context import SessionDep, StorageDep, load_capture, load_project

router = APIRouter()

MAX_HEX_BYTES = 65536


def _store(capture: Capture, storage):
    from ...services.stream_store import StreamStore

    paths = storage.capture_paths(capture.project_id, capture.id, capture.format)
    store = StreamStore(paths.stream_blob, paths.stream_index)
    return paths, store


def _load_stream(session, stream_id: str) -> Stream:
    stream = session.get(Stream, stream_id)
    if stream is None:
        raise NotFound(f"Stream {stream_id!r} does not exist.")
    return stream


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #


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
        session.execute(select(Stream).where(Stream.session_id == session_id))
        .scalars()
        .all()
    )


@router.get("/sessions/{session_id}/timeline")
def session_timeline(session_id: str, session: SessionDep, storage: StorageDep) -> dict:
    """Observed TCP events, per direction, as a simplified state diagram.

    This is a visualisation of *observed* events, not a reconstruction of the
    peer's TCP state machine.
    """
    row = session.get(TcpSession, session_id)
    if row is None:
        raise NotFound(f"TCP session {session_id!r} does not exist.")
    capture = load_capture(session, row.capture_id)
    paths, store = _store(capture, storage)
    if not store.available:
        raise NotFound(
            "This capture has not been analysed yet, so no reconstructed stream "
            "artefact exists."
        )
    packets = (
        session.execute(
            select(Packet)
            .where(
                Packet.capture_id == capture.id,
                Packet.transport_protocol == "tcp",
            )
            .order_by(Packet.packet_index)
        )
        .scalars()
        .all()
    )
    endpoints = {row.endpoint_a, row.endpoint_b}
    events: list[dict] = []
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
        "completeness": row.completeness_status,
        "role_confidence": row.role_confidence,
        "role_rationale": (row.diagnostics or {}).get("role_rationale", ""),
        "saw_syn": "SYN" in "".join(e["flags_text"] for e in events),
        "saw_fin": any("FIN" in e["flags_text"] for e in events),
        "saw_rst": any("RST" in e["flags_text"] for e in events),
        "events": events,
        "disclaimer": (
            "This timeline shows events observed in the capture. It does not prove "
            "the internal state of either TCP stack, and packets absent from the "
            "capture are simply unknown."
        ),
    }


# --------------------------------------------------------------------------- #
# Streams
# --------------------------------------------------------------------------- #


@router.get("/streams/{stream_id}", response_model=StreamOut)
def get_stream(stream_id: str, session: SessionDep) -> Stream:
    return _load_stream(session, stream_id)


@router.get("/streams/{stream_id}/bytes")
def stream_bytes(
    stream_id: str,
    session: SessionDep,
    storage: StorageDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    length: Annotated[int, Query(ge=1, le=MAX_HEX_BYTES)] = 1024,
) -> dict:
    """A hex window plus the coverage map, with gaps rendered explicitly."""
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    if not store.available:
        raise NotFound("The reconstructed stream artefact is missing.")
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound(f"Stream {stream_id!r} has no artefact entry.")
    descriptor.capture_id = capture.id
    rebuilt = store.build(descriptor)
    lines = []
    for run_offset, chunk in rebuilt.contiguous_bytes(offset, offset + length):
        lines.extend(
            hexdump(chunk, base_offset=run_offset)
        )
    return {
        "stream_id": stream_id,
        "offset": offset,
        "requested_length": length,
        "stream_length": rebuilt.stream_length,
        "present_bytes": rebuilt.present_bytes,
        "holes": rebuilt.hole_list(),
        "coverage": rebuilt.coverage(),
        "lines": lines,
        "packet_references": rebuilt.packet_references(offset, length),
    }


def _capture_id(session, stream_row: Stream) -> str:
    row = session.execute(
        select(TcpSession.capture_id).where(TcpSession.id == stream_row.session_id)
    ).scalar()
    if row is None:
        raise NotFound("The parent TCP session for this stream no longer exists.")
    return row


@router.get("/streams/{stream_id}/messages")
def stream_messages(
    stream_id: str,
    session: SessionDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> dict:
    rows = list(
        session.execute(
            select(Message)
            .where(Message.stream_id == stream_id)
            .order_by(Message.index_in_stream)
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            MessageOut(
                id=r.id,
                stream_id=r.stream_id,
                index_in_stream=r.index_in_stream,
                start_offset=r.start_offset,
                end_offset=r.end_offset,
                present_length=r.present_length,
                declared_length=r.declared_length,
                timestamp=r.timestamp,
                framing_method=r.framing_method,
                framing_rule_version=r.framing_rule_version,
                confidence=r.confidence,
                complete=r.complete,
                packet_references=r.packet_references,
                diagnostics=r.diagnostics,
                features=r.features,
            ).model_dump()
            for r in rows
        ],
        "total": session.scalar(
            select(func.count(Message.id)).where(Message.stream_id == stream_id)
        ),
        "offset": offset,
        "limit": limit,
    }


@router.get("/streams/{stream_id}/framing-suggestions")
def framing_suggestions(stream_id: str, session: SessionDep, storage: StorageDep) -> dict:
    """Rank framing rules for this stream with the evidence behind each."""
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)
    suggestions = suggest_framing(rebuilt)
    return {
        "stream_id": stream_id,
        "suggestions": suggestions,
        "disclaimer": (
            "These are candidates scored from observed bytes, not conclusions. "
            "Apply one and validate it against a corpus before treating it as the "
            "protocol's framing."
        ),
    }


@router.get("/streams/{stream_id}/messages/{message_id}/hex")
def message_hex(
    stream_id: str, message_id: str, session: SessionDep, storage: StorageDep
) -> dict:
    message = session.get(Message, message_id)
    if message is None or message.stream_id != stream_id:
        raise NotFound(f"Message {message_id!r} is not part of stream {stream_id!r}.")
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)
    payload = rebuilt.read(message.start_offset, message.end_offset - message.start_offset)
    holes = [
        (h.start, h.end)
        for h in rebuilt.holes
        if h.end > message.start_offset and h.start < message.end_offset
    ]
    return {
        "message_id": message_id,
        "start_offset": message.start_offset,
        "end_offset": message.end_offset,
        "declared_length": message.declared_length,
        "present_length": len(payload),
        "complete": message.complete,
        "hex": payload.hex(),
        "lines": hexdump(payload, base_offset=message.start_offset, holes=holes),
        "packet_references": message.packet_references,
        "features": message.features,
        "diagnostics": message.diagnostics,
    }


@router.post("/streams/{stream_id}/compare")
def compare_messages(
    stream_id: str, payload: CompareRequest, session: SessionDep, storage: StorageDep
) -> dict:
    """Side-by-side byte comparison with per-offset alignment."""
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)

    chosen: list[dict] = []
    for message_id in payload.message_ids:
        message = session.get(Message, message_id)
        if message is None:
            raise NotFound(f"Message {message_id!r} does not exist.")
        blob = rebuilt.read(message.start_offset, message.end_offset - message.start_offset)
        chosen.append(
            {
                "message_id": message.id,
                "index_in_stream": message.index_in_stream,
                "start_offset": message.start_offset,
                "length": len(blob),
                "declared_length": message.declared_length,
                "complete": message.complete,
                "timestamp": message.timestamp,
                "hex": blob.hex(),
            }
        )
    blobs = [bytes.fromhex(item["hex"]) for item in chosen]
    method, rows = align_messages(blobs)
    identical = [i for i, row in enumerate(rows) if not row.changed]
    return {
        "stream_id": stream_id,
        "alignment": {
            "method": method,
            "description": (
                "Bytes are aligned by absolute offset within the message. A null "
                "value means the message is shorter than that offset: those "
                "positions are absent, not zero."
            ),
        },
        "messages": chosen,
        "rows": [
            {
                "offset": row.offset,
                "values": row.values,
                "changed": row.changed,
                "present_count": row.present_count,
            }
            for row in rows
        ],
        "identical_offsets": identical,
        "length_groups": group_by_length(blobs),
    }


@router.get("/streams/{stream_id}/field-statistics")
def field_statistics(
    stream_id: str,
    session: SessionDep,
    storage: StorageDep,
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
) -> dict:
    """Per-offset statistics over the framed messages of a stream."""
    from ...analyzers.field_inference import infer_fields

    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)
    rows = (
        session.execute(
            select(Message)
            .where(Message.stream_id == stream_id)
            .order_by(Message.index_in_stream)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    blobs = [
        rebuilt.read(r.start_offset, r.end_offset - r.start_offset)
        for r in rows
        if r.complete
    ]
    result = infer_fields(blobs)
    return {
        "stream_id": stream_id,
        "message_count": len(blobs),
        **result.to_dict(),
    }


_ = (FramingConfig, summarise_timeline, load_project)