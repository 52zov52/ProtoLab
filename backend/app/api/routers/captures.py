"""Capture import, analysis and packet browsing."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile, status
from sqlalchemy import func, select

from ...core.errors import LimitExceeded, NotFound, ValidationFailed
from ...core.logging import AuditEvent, get_logger
from ...core.security import safe_display_filename
from ...models import Capture, Message, Packet, Stream, TcpSession
from ...schemas import AnalyzeRequest, CaptureOut, MessageOut, PacketOut, SessionOut
from ...services.capture_analysis import AnalysisOptions, CaptureAnalyzer
from ..context import (
    SessionDep,
    StorageDep,
    get_context,
    load_capture,
    load_project,
)

router = APIRouter()
log = get_logger("mplab.captures")

STREAM_CHUNK = 1024 * 1024


@router.get("/captures/{capture_id}", response_model=CaptureOut)
def get_capture(capture_id: str, session: SessionDep) -> Capture:
    return load_capture(session, capture_id)


@router.post("/captures/{capture_id}/analyze")
def analyze_capture(
    capture_id: str, payload: AnalyzeRequest, session: SessionDep, storage: StorageDep
) -> dict:
    """Index packets, split sessions, reassemble streams and frame messages."""
    from ...core.config import get_settings

    settings = get_settings()
    capture = load_capture(session, capture_id)
    capture.analysis_status = "running"
    session.commit()

    paths = storage.capture_paths(capture.project_id, capture.id, capture.format)
    if not paths.original.exists():
        capture.analysis_status = "failed"
        session.commit()
        raise NotFound(
            "The original capture file is missing from storage, so the analysis "
            "cannot be reproduced. Re-import the capture to restore the source."
        )

    options = AnalysisOptions(
        flow_policy=payload.flow_policy,
        idle_timeout=payload.idle_timeout,
        conflict_policy=payload.conflict_policy,
        framing=payload.framing,
        detect_protocol=payload.detect_protocol,
        max_sessions=settings.limits.max_tcp_sessions_per_capture,
        max_messages_per_stream=settings.limits.max_messages_per_stream,
    )
    analyzer = CaptureAnalyzer(
        session, capture, paths.original, storage, options, settings.limits
    )
    try:
        summary = analyzer.run()
    except Exception as exc:
        capture.analysis_status = "failed"
        capture.diagnostics = {"error": type(exc).__name__}
        session.commit()
        log.exception("analysis failed for capture %s", capture_id)
        raise
    capture.analysis_status = "completed"
    capture.stats = summary
    session.commit()
    return summary


@router.get("/captures/{capture_id}/packets")
def list_packets(
    capture_id: str,
    session: SessionDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    transport: str | None = Query(default=None, max_length=16),
    source: str | None = Query(default=None, max_length=45),
    destination: str | None = Query(default=None, max_length=45),
    min_payload: Annotated[int, Query(ge=0)] = 0,
    search: str | None = Query(default=None, max_length=64),
) -> dict:
    capture = load_capture(session, capture_id)
    query = select(Packet).where(Packet.capture_id == capture.id)
    if transport:
        query = query.where(Packet.transport_protocol == transport)
    if source:
        query = query.where(Packet.source_address == source)
    if destination:
        query = query.where(Packet.destination_address == destination)
    if min_payload:
        query = query.where(Packet.payload_length >= min_payload)
    if search:
        query = query.where(Packet.source_address.like(f"%{search}%"))

    total = int(
        session.scalar(select(func.count()).select_from(query.subquery())) or 0
    )
    rows = (
        session.execute(
            query.order_by(Packet.packet_index).offset(offset).limit(limit)
        )
        .scalars()
        .all()
    )
    items = [
        PacketOut(
            packet_index=r.packet_index,
            timestamp=r.timestamp,
            captured_length=r.captured_length,
            original_length=r.original_length,
            source_address=r.source_address,
            destination_address=r.destination_address,
            source_port=r.source_port,
            destination_port=r.destination_port,
            transport_protocol=r.transport_protocol,
            tcp_sequence=r.tcp_sequence,
            tcp_acknowledgment=r.tcp_acknowledgment,
            tcp_flags=r.tcp_flags,
            tcp_window=r.tcp_window,
            tcp_options=r.tcp_options,
            payload_length=r.payload_length,
            truncated=r.truncated,
            session_id=r.session_id,
        )
        for r in rows
    ]
    return {
        "items": [i.model_dump() for i in items],
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(items) < total,
    }


@router.get("/captures/{capture_id}/packets/{packet_index}/raw")
def packet_bytes(
    capture_id: str, packet_index: int, session: SessionDep, storage: StorageDep
) -> Response:
    """The original on-disk bytes of one packet.

    Served from the immutable capture file, so what the analyst sees is exactly
    what was imported.
    """
    from ...core.config import get_settings

    capture = load_capture(session, capture_id)
    packet = (
        session.execute(
            select(Packet).where(
                Packet.capture_id == capture.id, Packet.packet_index == packet_index
            )
        )
        .scalars()
        .first()
    )
    if packet is None:
        raise NotFound(f"Packet {packet_index} is not present in capture {capture_id!r}.")
    paths = storage.capture_paths(capture.project_id, capture.id, capture.format)
    if not paths.original.exists():
        raise NotFound("The original capture file is missing from storage.")
    with paths.original.open("rb") as handle:
        handle.seek(packet.payload_offset or 0)
        blob = handle.read(max(0, packet.captured_length))
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={
            "X-Packet-Sequence": str(packet.tcp_sequence),
            "X-Packet-Flags": str(packet.tcp_flags),
        },
    )


@router.get("/captures/{capture_id}/sessions")
def list_sessions(
    capture_id: str,
    session: SessionDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    completeness: str | None = Query(default=None, max_length=32),
) -> dict:
    capture = load_capture(session, capture_id)
    query = select(TcpSession).where(TcpSession.capture_id == capture.id)
    if completeness:
        query = query.where(TcpSession.completeness_status == completeness)
    total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = (
        session.execute(query.order_by(TcpSession.start_time).offset(offset).limit(limit))
        .scalars()
        .all()
    )
    items = [
        SessionOut(
            id=r.id,
            capture_id=r.capture_id,
            session_identity=r.session_identity,
            endpoint_a=r.endpoint_a,
            endpoint_b=r.endpoint_b,
            client_endpoint=r.client_endpoint,
            server_endpoint=r.server_endpoint,
            role_confidence=r.role_confidence,
            start_time=r.start_time,
            end_time=r.end_time,
            completeness_status=r.completeness_status,
            diagnostics=r.diagnostics,
            analyzer_version=r.analyzer_version,
        ).model_dump()
        for r in rows
    ]
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(items) < total,
    }


@router.get("/projects/{project_id}/captures", response_model=list[CaptureOut])
def project_captures(project_id: str, session: SessionDep) -> list[Capture]:
    """Every capture in a project, for corpus selection and integrity views."""
    load_project(session, project_id)
    return list(
        session.execute(
            select(Capture).where(Capture.project_id == project_id).order_by(Capture.imported_at)
        )
        .scalars()
        .all()
    )


@router.post("/captures", response_model=CaptureOut, status_code=status.HTTP_201_CREATED)
async def upload_capture(
    session: SessionDep,
    storage: StorageDep,
    file: Annotated[UploadFile, File()],
    project_id: Annotated[str, Form()],
    name: Annotated[str | None, Form()] = None,
) -> Capture:
    """Import one capture file.

    The upload is streamed to a temporary file under the OS temp dir with a hard
    size ceiling, hashed, then copied into managed storage under a random
    server-side name.  The user-supplied name is display-only and never becomes
    a path.
    """
    from ..context import project_service
    from ...core.config import get_settings

    settings = get_settings()
    project = load_project(session, project_id)
    service = project_service(session, storage, settings.limits)

    display = safe_display_filename(name or file.filename)
    written = 0
    limit = settings.limits.max_upload_bytes
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".upload") as handle:
            temp_path = Path(handle.name)
            while True:
                chunk = await file.read(STREAM_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > limit:
                    raise LimitExceeded(
                        "The uploaded file exceeds the maximum accepted size.",
                        details={"limit_bytes": limit},
                    )
                handle.write(chunk)
        capture = service.import_capture(
            project, name=name or display, source=temp_path
        )
        return capture
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)


@router.post("/captures/{capture_id}/rename", response_model=CaptureOut)
def rename_capture(
    capture_id: str, session: SessionDep, storage: StorageDep, name: Annotated[str, Form()]
) -> Capture:
    from ..context import project_service
    from ...core.config import get_settings

    capture = load_capture(session, capture_id)
    service = project_service(session, storage, get_settings().limits)
    from ...services.project_service import _validate_capture_name

    capture.name = _validate_capture_name(name)
    session.commit()
    return capture


@router.delete("/captures/{capture_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_capture(capture_id: str, session: SessionDep, storage: StorageDep) -> Response:
    from ..context import project_service
    from ...core.config import get_settings

    service = project_service(session, storage, get_settings().limits)
    service.delete_capture(capture_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/captures/{capture_id}/messages")
def list_messages(
    capture_id: str,
    session: SessionDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    stream_id: str | None = Query(default=None, max_length=32),
    min_length: Annotated[int, Query(ge=0)] = 0,
    max_length: Annotated[int | None, Query(ge=0)] = None,
    direction: str | None = Query(default=None, max_length=8),
) -> dict:
    capture = load_capture(session, capture_id)
    query = (
        select(Message)
        .join(Stream, Stream.id == Message.stream_id)
        .where(Message.capture_id == capture.id)
    )
    if stream_id:
        query = query.where(Message.stream_id == stream_id)
    if direction:
        query = query.where(Stream.direction == direction)
    if min_length:
        query = query.where(Message.present_length >= min_length)
    if max_length is not None:
        query = query.where(Message.present_length <= max_length)
    total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = (
        session.execute(query.order_by(Message.stream_id, Message.index_in_stream)
                        .offset(offset).limit(limit))
        .scalars()
        .all()
    )
    items = [
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
    ]
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(items) < total,
    }


@router.post("/captures/{capture_id}/export-pcapng")
def export_pcapng(
    capture_id: str, session: SessionDep, storage: StorageDep
) -> dict:
    from ...services.pcapng_export import export_annotated_pcapng

    capture = load_capture(session, capture_id)
    result = export_annotated_pcapng(capture, session, storage)
    return result


_ = (AuditEvent, get_context, shutil, ValidationFailed)