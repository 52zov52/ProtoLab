"""Annotated pcapng export.

Guarantees, all of them verified before the endpoint reports success:

* the original capture is never modified;
* packet bytes, original lengths and timestamps are preserved;
* per-packet annotations are written as pcapng **packet block comments**, the
  only construct that genuinely binds text to an individual packet;
* the exported file is re-read to confirm the comments and the packets survived.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analyzers.pcapng_writer import (
    PacketRecord,
    PcapngWriter,
    read_comments,
    verify_round_trip,
)
from ..analyzers.capture_reader import CaptureReader
from ..core.logging import AuditEvent, get_logger
from ..models import Annotation, Capture, Evidence, Hypothesis, Message, Packet
from ..services.storage import ProjectStorage

log = get_logger("mplab.pcapng")

MAX_COMMENT_CHARS = 400


def export_annotated_pcapng(
    capture: Capture, session: Session, storage: ProjectStorage
) -> dict[str, Any]:
    paths = storage.capture_paths(capture.project_id, capture.id, capture.format)
    source = paths.original
    if not source.exists():
        from ..core.errors import NotFound

        raise NotFound("The original capture file is missing from storage.")

    annotations = _packet_annotations(session, capture.id)
    hypotheses = _hypothesis_tags(session, capture.project_id)

    writer = PcapngWriter(
        interface_comment=(
            f"Madrigal Protocol Lab export of capture {capture.id} "
            f"({capture.name}); sha256 {capture.sha256}"
        )
    )
    written = 0
    reader = CaptureReader(
        source, max_packets=5_000_000, max_packet_bytes=64 * 1024 * 1024
    )
    with source.open("rb") as handle:
        reader.read_header(handle)
        for raw in reader.iter_packets():
            handle.seek(raw.data_offset)
            data = handle.read(raw.captured_length)
            comment = annotations.get(raw.index)
            if comment:
                comment = "; ".join(comment)[:MAX_COMMENT_CHARS]
            writer.add(
                PacketRecord(
                    timestamp=raw.timestamp,
                    data=data,
                    original_length=raw.original_length,
                    comment=comment,
                )
            )
            written += 1

    exports_dir = storage.exports_dir(capture.project_id, capture.id)
    target = exports_dir / "annotated.pcapng"
    writer.write(target)

    verification = verify_round_trip(source, target)
    comments = read_comments(target)
    expected = {i for i, notes in annotations.items() if notes}

    missing = sorted(expected - set(comments))
    result = {
        "capture_id": capture.id,
        "path": target.name,
        "packets_written": written,
        "packets_annotated": len(expected),
        "comments_verified": len(comments),
        "missing_comments": missing,
        "round_trip": verification,
        "hypothesis_tags": hypotheses,
        "success": bool(verification.get("verified")) and not missing,
        "notes": [
            "Annotations are stored as pcapng packet-block comments. The section and "
            "interface header comments identify the export itself and do not annotate "
            "individual packets.",
            "This file carries annotations only. It does not contain the project's "
            "hypotheses, validation history or reports; use the .mplab project export "
            "to transfer a full investigation.",
        ],
    }
    from ..services.project_service import AuditLog

    AuditLog(session).record(
        AuditEvent(
            "export.pcapng",
            project_id=capture.project_id,
            object_type="capture",
            object_id=capture.id,
            details={"packets": written, "annotated": len(expected), "verified": result["success"]},
        )
    )
    session.commit()
    return result


def _packet_annotations(session: Session, capture_id: str) -> dict[int, list[str]]:
    """Collect per-packet notes from messages, evidence and manual annotations."""
    out: dict[int, list[str]] = {}

    for message in (
        session.execute(select(Message).where(Message.capture_id == capture_id))
        .scalars()
        .all()
    ):
        label = (
            f"msg {message.index_in_stream} @stream+{message.start_offset} "
            f"len={message.present_length} framing={message.framing_method}"
        )
        for ref in message.packet_references or []:
            index = ref.get("packet_index")
            if isinstance(index, int):
                out.setdefault(index, []).append(label)

    for evidence in (
        session.execute(select(Evidence).where(Evidence.source_id == capture_id))
        .scalars()
        .all()
    ):
        label = f"evidence: {evidence.description or evidence.entity_type}"
        for index in evidence.packet_indexes or []:
            if isinstance(index, int):
                out.setdefault(index, []).append(label)

    for annotation in (
        session.execute(select(Annotation).where(Annotation.target_type == "packet"))
        .scalars()
        .all()
    ):
        if not annotation.target_id:
            continue
        try:
            index = int(annotation.target_id)
        except ValueError:
            continue
        out.setdefault(index, []).append(annotation.text[:200])

    return {k: v[:4] for k, v in out.items()}


def _hypothesis_tags(session: Session, project_id: str) -> list[dict[str, Any]]:
    rows = (
        session.execute(select(Hypothesis).where(Hypothesis.project_id == project_id))
        .scalars()
        .all()
    )
    return [
        {"id": h.id, "name": h.name, "status": h.status, "version": h.version}
        for h in rows[:100]
    ]


_ = (Path, Packet)