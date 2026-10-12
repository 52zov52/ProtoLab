"""Capture import + TCP reassembly pipeline.

This is the pipeline behind ``POST /api/captures/{id}/analyze``:

    read capture (streaming, bounded)
      -> index packets
      -> split TCP conversations
      -> reassemble both directions
      -> persist streams as artefacts
      -> detect the application protocol
      -> frame messages (if a framing rule is configured)

Everything is deterministic: same file + same settings => same rows, so a
validation run can be repeated months later and produce identical output.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..analyzers.capture_reader import CaptureReader, decode_frame
from ..analyzers.flow_manager import (
    FLOW_VERSION,
    DEFAULT_IDLE_TIMEOUT,
    FlowPacket,
    FlowSplitter,
    TcpFlow,
    summarise_flow,
)
from ..analyzers.framing import FramingConfig, frame_stream
from ..analyzers.protocol_detection import detect_for_directions
from ..analyzers.tcp_reassembly import ANALYZER_VERSION as REASSEMBLY_VERSION
from ..analyzers.tcp_reassembly import ReassembledStream, reassemble
from ..core.errors import LimitExceeded
from ..core.logging import get_logger
from ..db.base import new_id
from ..models import Capture, Message, Packet, Stream, StreamRange, TcpSession
from .storage import ProjectStorage

ANALYZER_VERSION = f"capture-analysis/{REASSEMBLY_VERSION}+{FLOW_VERSION}"

log = get_logger("mplab.analysis")

ProgressFn = Callable[[float, str], None]


@dataclass
class AnalysisOptions:
    flow_policy: str = "syn_fin_rst_idle"
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT
    conflict_policy: str = "first_writer_wins"
    framing: dict | None = None
    detect_protocol: bool = True
    max_sessions: int = 20_000
    max_messages_per_stream: int = 500_000

    def to_dict(self) -> dict:
        return {
            "flow_policy": self.flow_policy,
            "idle_timeout": self.idle_timeout,
            "conflict_policy": self.conflict_policy,
            "framing": self.framing,
            "detect_protocol": self.detect_protocol,
        }


class CaptureAnalyzer:
    def __init__(
        self,
        session: Session,
        capture: Capture,
        source_path: Path,
        storage: ProjectStorage,
        options: AnalysisOptions,
        limits,
        *,
        progress: ProgressFn | None = None,
    ) -> None:
        self.db = session
        self.capture = capture
        self.source = source_path
        self.storage = storage
        self.options = options
        self.limits = limits
        self.progress = progress or (lambda _p, _s: None)

    # -- entry point ------------------------------------------------------ #

    def run(self) -> dict:
        reader = CaptureReader(
            self.source,
            max_packets=self.limits.max_packets_per_capture,
            max_packet_bytes=self.limits.max_packet_bytes,
            max_file_bytes=self.limits.max_capture_bytes,
        )
        self.progress(0.05, "Reading capture file")
        splitter = FlowSplitter(
            policy=self.options.flow_policy,
            idle_timeout=self.options.idle_timeout,
            max_sessions=min(self.options.max_sessions, self.limits.max_tcp_sessions_per_capture),
        )

        packet_rows: list[dict] = []
        with self.source.open("rb") as handle:
            for raw in reader.iter_packets():
                handle.seek(raw.data_offset)
                frame = handle.read(raw.captured_length)
                decoded = decode_frame(raw.link_type, frame, expected_length=raw.original_length)
                row = {
                    "capture_id": self.capture.id,
                    "packet_index": raw.index,
                    "timestamp": raw.timestamp,
                    "captured_length": raw.captured_length,
                    "original_length": raw.original_length,
                    "payload_offset": raw.data_offset,
                    "payload_length": 0,
                    "truncated": raw.truncated,
                }
                if decoded is None:
                    row.update(
                        source_address="0.0.0.0",
                        destination_address="0.0.0.0",
                        source_port=0,
                        destination_port=0,
                        transport_protocol="",
                        payload_offset=None,
                        payload_length=0,
                    )
                    packet_rows.append(row)
                    continue
                row.update(
                    source_address=decoded.source_address,
                    destination_address=decoded.destination_address,
                    source_port=decoded.source_port or 0,
                    destination_port=decoded.destination_port or 0,
                    transport_protocol="tcp" if decoded.ip_protocol == 6 else f"ip{decoded.ip_protocol}",
                    tcp_sequence=decoded.tcp_sequence,
                    tcp_acknowledgment=decoded.tcp_acknowledgment,
                    tcp_flags=decoded.tcp_flags,
                    tcp_window=decoded.tcp_window,
                    tcp_options=decoded.tcp_options,
                    payload_offset=(
                        raw.data_offset + decoded.payload_offset_in_frame
                        if decoded.payload_offset_in_frame is not None
                        else None
                    ),
                    payload_length=decoded.payload_length,
                )
                if decoded.ip_protocol == 6 and decoded.tcp_sequence is not None:
                    splitter.add(
                        FlowPacket(
                            packet_index=raw.index,
                            timestamp=raw.timestamp,
                            source_ip=decoded.source_address,
                            source_port=decoded.source_port or 0,
                            dest_ip=decoded.destination_address,
                            dest_port=decoded.destination_port or 0,
                            seq=decoded.tcp_sequence,
                            ack=decoded.tcp_acknowledgment or 0,
                            flags=decoded.tcp_flags or 0,
                            window=decoded.tcp_window or 0,
                            payload=frame[decoded.payload_offset_in_frame : decoded.payload_offset_in_frame + decoded.payload_length]
                            if decoded.payload_offset_in_frame is not None
                            else b"",
                            options=decoded.tcp_options,
                            frame_truncated=decoded.truncated,
                            anomalies=list(decoded.anomalies),
                        )
                    )
                packet_rows.append(row)

        self.progress(0.4, "Indexing packets")
        self._flush_packets(packet_rows)
        splitter.assign_roles()

        flows = list(splitter.flows())
        self.progress(0.55, f"Reconstructing {len(flows)} TCP sessions")
        summary = self._persist_sessions(flows)
        summary["reader_diagnostics"] = reader.diagnostics
        summary["analyzer_version"] = ANALYZER_VERSION
        summary["options"] = self.options.to_dict()
        return summary

    # -- packet lookup ---------------------------------------------------- #

    def _packet_time_index(self, descriptor: dict) -> dict[int, float]:
        """Lazily load timestamps for the packets that feed one stream."""
        indexes = sorted(
            {c["packet_index"] for c in descriptor["contributors"] if c["packet_index"] is not None}
        )
        if not indexes:
            return {}
        rows = (
            self.db.query(Packet.packet_index, Packet.timestamp)
            .filter(
                Packet.capture_id == self.capture.id,
                Packet.packet_index.in_(indexes),
            )
            .all()
        )
        return {int(index): float(ts) for index, ts in rows}

    # -- persistence ------------------------------------------------------ #

    def _flush_packets(self, rows: list[dict]) -> None:
        """Replace this capture's derived rows.

        Re-analysis must be idempotent, so every artefact of the previous run is
        removed first.  Validation results that referenced old messages are not
        silently re-pointed: they are marked stale by the interpretation service.
        """
        stream_ids = [
            row[0]
            for row in self.db.query(Stream.id).filter(
                Stream.session_id.in_(
                    select(TcpSession.id).where(TcpSession.capture_id == self.capture.id)
                )
            ).all()
        ]
        if stream_ids:
            self.db.execute(delete(Message).where(Message.stream_id.in_(stream_ids)))
            self.db.execute(delete(StreamRange).where(StreamRange.stream_id.in_(stream_ids)))
            self.db.execute(delete(Stream).where(Stream.id.in_(stream_ids)))
        self.db.execute(delete(TcpSession).where(TcpSession.capture_id == self.capture.id))
        self.db.execute(delete(Packet).where(Packet.capture_id == self.capture.id))
        self.db.flush()
        # Insert in batches so a 250k-packet capture never builds one huge
        # transaction in memory.
        batch_size = 2000
        for index in range(0, len(rows), batch_size):
            self.db.bulk_insert_mappings(Packet, rows[index : index + batch_size])
            self.db.flush()
        self.db.commit()

    def _persist_sessions(self, flows: list[TcpFlow]) -> dict:
        paths = self.storage.capture_paths(
            self.capture.project_id, self.capture.id, self.capture.format
        )
        blob_path = paths.stream_blob
        index: list[dict] = []
        total_sessions = 0
        problem_sessions = 0
        total_messages = 0

        with blob_path.open("wb") as blob:
            for order, flow in enumerate(flows):
                self.progress(
                    0.55 + 0.4 * (order / max(1, len(flows))),
                    f"Session {flow.session_identity}",
                )
                row = TcpSession(
                    capture_id=self.capture.id,
                    project_id=self.capture.project_id,
                    session_identity=flow.session_identity,
                    endpoint_a=flow.endpoint_a,
                    endpoint_b=flow.endpoint_b,
                    client_endpoint=flow.client_endpoint,
                    server_endpoint=flow.server_endpoint,
                    role_confidence=flow.role_confidence,
                    start_time=flow.start_time,
                    end_time=flow.end_time,
                    completeness_status=flow.completeness(),
                    reconstruction_policy={
                        "conflict_policy": self.options.conflict_policy,
                        "flow_policy": self.options.flow_policy,
                        "idle_timeout": self.options.idle_timeout,
                        "analyzer_version": ANALYZER_VERSION,
                    },
                    diagnostics={
                        "summary": summarise_flow(flow),
                        "role_rationale": flow.role_rationale,
                    },
                    analyzer_version=ANALYZER_VERSION,
                )
                self.db.add(row)
                self.db.flush()

                streams = {}
                for role in ("a2b", "b2a"):
                    local = flow.endpoint_a if role == "a2b" else flow.endpoint_b
                    remote = flow.endpoint_b if role == "a2b" else flow.endpoint_a
                    isn = flow.a_to_b_isn if role == "a2b" else flow.b_to_a_isn
                    stream = reassemble(
                        direction=role,
                        local_endpoint=local,
                        remote_endpoint=remote,
                        segments=flow.segments(role),
                        isn=isn,
                        conflict_policy=self.options.conflict_policy,
                    )
                    streams[role] = stream

                protocol = {"protocol": "unknown_binary", "confidence": 0.0}
                if self.options.detect_protocol:
                    protocol = detect_for_directions(streams["a2b"], streams["b2a"])

                for role, stream in streams.items():
                    if stream.stream_length == 0 and stream.segment_count == 0:
                        continue
                    offset, descriptor = self._write_stream(
                        blob, index, row.id, flow, stream, protocol
                    )
                    messages = 0
                    if self.options.framing:
                        messages = self._write_messages(
                            row.id, stream, descriptor, self.options.framing
                        )
                        total_messages += messages
                    index.append(descriptor)

                if self._session_has_problems(flow, streams):
                    problem_sessions += 1
                total_sessions += 1
                self.db.flush()

        paths.stream_index.write_text(
            json.dumps({"streams": index}, separators=(",", ":")),
            encoding="utf-8",
        )
        self.db.commit()
        return {
            "sessions": total_sessions,
            "streams": len(index),
            "messages": total_messages,
            "sessions_with_problems": problem_sessions,
            "stream_artifact": paths.stream_index.name,
        }

    def _session_has_problems(
        self, flow: TcpFlow, streams: dict[str, ReassembledStream]
    ) -> bool:
        if flow.completeness() not in ("complete",):
            return True
        for stream in streams.values():
            if stream.conflicts or stream.has_gaps or stream.is_truncated_start:
                return True
        return False

    def _write_stream(
        self, blob, index: list[dict], session_id: str, flow: TcpFlow,
        stream: ReassembledStream, protocol: dict
    ) -> tuple[int, dict]:
        offset = blob.tell()
        runs: list[dict] = []
        contributions: list[dict] = []
        for run in stream.runs:
            # Each run records its own blob offset: a stream with a hole is stored
            # as several discontiguous pieces, so one base offset cannot describe
            # it and slicing by stream offset would read the wrong bytes.
            runs.append(
                {
                    "start": run.start,
                    "end": run.end,
                    "blob_offset": blob.tell(),
                    "length": len(run.data),
                }
            )
            for contributor in run.contributors:
                contributions.append(
                    {
                        "start": contributor.start,
                        "end": contributor.end,
                        "packet_index": contributor.packet_index,
                    }
                )
            blob.write(run.data)
        descriptor = {
            "session_identity": flow.session_identity,
            "direction": stream.direction,
            "blob_offset": offset,
            "runs": runs,
            "stream_length": stream.stream_length,
            "present_bytes": stream.present_bytes,
            "coverage": stream.coverage(),
            "holes": stream.hole_list(),
            "contributors": contributions,
            "diagnostics": {
                "retransmissions": stream.retransmissions[:500],
                "out_of_order": stream.out_of_order[:500],
                "duplicates": [d.to_dict() for d in stream.duplicates[:500]],
                "conflicts": [c.to_dict() for c in stream.conflicts[:200]],
                "zero_windows": stream.zero_windows[:200],
                "window_updates": stream.window_updates[:200],
                "overlapping": stream.overlapping[:500],
                "is_truncated_start": stream.is_truncated_start,
                "is_truncated_end": stream.is_truncated_end,
                "isn": stream.isn,
                "conflict_policy": self.options.conflict_policy,
            },
            "protocol": {
                "label": protocol.get("protocol", "unknown_binary"),
                "confidence": protocol.get("confidence", 0.0),
            },
        }
        stream_row = Stream(
            session_id=session_id,
            direction=stream.direction,
            local_endpoint=stream.local_endpoint,
            remote_endpoint=stream.remote_endpoint,
            first_sequence=stream.isn if stream.isn is not None else 0,
            stream_length=stream.stream_length,
            present_bytes=stream.present_bytes,
            artifact_path=f"{stream.direction}",
            holes=stream.hole_list(),
            coverage_map=stream.coverage(),
            diagnostics=descriptor["diagnostics"],
            conflicts=descriptor["diagnostics"]["conflicts"],
            protocol_label=protocol.get("protocol", "unknown_binary"),
            protocol_confidence=float(protocol.get("confidence", 0.0)),
            protocol_signals=protocol,
            analyzer_version=ANALYZER_VERSION,
        )
        self.db.add(stream_row)
        self.db.flush()
        descriptor["_session_id"] = stream_row.session_id
        descriptor["stream_id"] = stream_row.id
        return offset, descriptor

    def _write_messages(
        self, session_id: str, stream: ReassembledStream, descriptor: dict, framing: dict
    ) -> int:
        cfg = FramingConfig.parse(framing)
        framed = frame_stream(stream, cfg)
        if len(framed) > self.options.max_messages_per_stream:
            raise LimitExceeded(
                "The framing rule produced more messages than the configured maximum.",
                details={"limit": self.options.max_messages_per_stream, "produced": len(framed)},
            )
        stream_id = descriptor["stream_id"]
        packet_times = self._packet_time_index(descriptor)
        # A large capture frames hundreds of thousands of messages, so rows are
        # collected and inserted in bulk.  The ORM object-by-object path turned
        # a 240k-message capture into a seven-minute analysis; the rows carry no
        # behaviour that requires an ORM identity.
        message_rows: list[dict] = []
        range_rows: list[dict] = []
        for index, message in enumerate(framed):
            payload = stream.read(message.start_offset, message.length)
            diagnostics = dict(message.diagnostics)
            if not message.complete:
                diagnostics["partial"] = True
            message_rows.append(
                {
                    "id": new_id(),
                    "stream_id": stream_id,
                    "session_id": session_id,
                    "capture_id": self.capture.id,
                    "index_in_stream": index,
                    "start_offset": message.start_offset,
                    "end_offset": message.end_offset,
                    "present_length": message.present_length,
                    "declared_length": message.declared_length,
                    "timestamp": _timestamp_for(stream, message.start_offset, packet_times),
                    "framing_method": message.method,
                    "framing_rule_version": cfg.rule_version,
                    "confidence": message.confidence,
                    "complete": message.complete,
                    "packet_references": message.packet_references,
                    "diagnostics": diagnostics,
                    "features": _message_features(payload),
                    "body_preview": payload[:512].hex(),
                }
            )
            for run in stream.runs_intersecting(message.start_offset, message.end_offset):
                lo = max(message.start_offset, run.start)
                hi = min(message.end_offset, run.end)
                if hi > lo:
                    range_rows.append(
                        {
                            "id": new_id(),
                            "stream_id": stream_id,
                            "start_offset": lo,
                            "end_offset": hi,
                            "packet_references": stream.packet_references(lo, hi - lo),
                            "completeness": "complete"
                            if stream.is_present(message.start_offset, message.length)
                            else "partial",
                            "conflict_status": "conflict"
                            if _overlaps_conflict(stream, lo, hi)
                            else "none",
                        }
                    )
        if message_rows:
            self.db.bulk_insert_mappings(Message, message_rows)
        if range_rows:
            self.db.bulk_insert_mappings(StreamRange, range_rows)
        return len(framed)


def _overlaps_conflict(stream: ReassembledStream, start: int, end: int) -> bool:
    return any(c.start_offset < end and c.end_offset > start for c in stream.conflicts)


def _timestamp_for(
    stream: ReassembledStream, offset: int, packet_times: dict[int, float]
) -> float:
    """Best-effort message timestamp.

    The exact instant a message was *transmitted* is not recoverable from a
    capture (a message can be assembled from several segments).  We report the
    time of the first packet that contributed a byte and label it as such in the
    UI rather than inventing precision.
    """
    refs = stream.packet_references(offset, 1)
    if not refs:
        return 0.0
    return packet_times.get(int(refs[0]["packet_index"]), 0.0)


def _message_features(payload: bytes) -> dict:
    from ..analyzers.byte_analysis import (
        printable_ratio,
        repeating_pattern_score,
        shannon_entropy,
        unique_byte_count,
        zero_ratio,
    )

    return {
        "length": len(payload),
        "entropy": round(shannon_entropy(payload), 4),
        "unique_bytes": unique_byte_count(payload),
        "zero_ratio": round(zero_ratio(payload), 4),
        "printable_ratio": round(printable_ratio(payload), 4),
        "repeating_score": round(repeating_pattern_score(payload), 4),
    }


def iter_stream_runs(index_path: Path) -> Iterator[dict]:  # pragma: no cover - helper
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    yield from payload.get("streams", [])


def read_stream_bytes(blob_path: Path, descriptor: dict) -> bytes:
    with blob_path.open("rb") as handle:
        handle.seek(descriptor["blob_offset"])
        return handle.read(descriptor["present_bytes"])


def pack_u32(value: int) -> bytes:  # pragma: no cover - utility
    return struct.pack("<I", value & 0xFFFFFFFF)