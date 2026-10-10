"""Reading reconstructed streams back out of the artefact files.

The hex viewer, the framing engine and the validator all need the *same* bytes.
Having one reader guarantees they cannot disagree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..analyzers.tcp_reassembly import ReassembledStream


@dataclass
class StreamDescriptor:
    stream_id: str
    session_id: str
    session_identity: str
    capture_id: str
    direction: str
    blob_offset: int
    runs: list[dict[str, Any]]
    stream_length: int
    present_bytes: int
    coverage: list[dict[str, int]]
    holes: list[dict[str, Any]]
    contributors: list[dict[str, Any]]
    diagnostics: dict[str, Any]
    protocol: dict[str, Any]
    local_endpoint: str
    remote_endpoint: str


class StreamStore:
    """Loads the per-capture stream index and reconstructs streams on demand."""

    def __init__(self, blob_path: Path, index_path: Path) -> None:
        self.blob_path = blob_path
        self.index_path = index_path
        self._descriptors: dict[str, StreamDescriptor] | None = None
        self._blob: bytes | None = None

    @property
    def available(self) -> bool:
        return self.blob_path.exists() and self.index_path.exists()

    def descriptors(self) -> dict[str, StreamDescriptor]:
        if self._descriptors is None:
            payload = json.loads(self.index_path.read_text(encoding="utf-8"))
            out: dict[str, StreamDescriptor] = {}
            for item in payload.get("streams", []):
                descriptor = StreamDescriptor(
                    stream_id=item["stream_id"],
                    session_id=item.get("_session_id", ""),
                    session_identity=item["session_identity"],
                    capture_id="",
                    direction=item["direction"],
                    blob_offset=int(item["blob_offset"]),
                    runs=item.get("runs", []),
                    stream_length=int(item["stream_length"]),
                    present_bytes=int(item["present_bytes"]),
                    coverage=item["coverage"],
                    holes=item["holes"],
                    contributors=item["contributors"],
                    diagnostics=item["diagnostics"],
                    protocol=item["protocol"],
                    local_endpoint="",
                    remote_endpoint="",
                )
                out[descriptor.stream_id] = descriptor
            self._descriptors = out
        return self._descriptors

    def _raw(self) -> bytes:
        if self._blob is None:
            self._blob = self.blob_path.read_bytes()
        return self._blob

    def get(self, stream_id: str) -> StreamDescriptor | None:
        return self.descriptors().get(stream_id)

    def build(self, descriptor: StreamDescriptor) -> ReassembledStream:
        """Materialise a :class:`ReassembledStream` from the artefact."""
        from ..analyzers.tcp_reassembly import Contributor, Hole, ReassembledStream, Run

        raw = self._raw()
        stream = ReassembledStream(
            direction=descriptor.direction,
            local_endpoint=descriptor.local_endpoint,
            remote_endpoint=descriptor.remote_endpoint,
            isn=descriptor.diagnostics.get("isn"),
            stream_length=descriptor.stream_length,
        )
        by_start: dict[int, list[dict[str, Any]]] = {}
        for item in descriptor.contributors:
            by_start.setdefault(item["start"], []).append(item)

        # Each run carries its own blob offset, so a stream with holes is
        # reconstructed byte-exactly rather than by slicing from a base.
        for span in descriptor.runs or (
            [{"start": s["start"], "end": s["end"], "blob_offset": descriptor.blob_offset + (s["start"] - _run_base(descriptor)), "length": s["end"] - s["start"]} for s in descriptor.coverage]
        ):
            start = int(span["start"])
            end = int(span["end"])
            length = int(span.get("length", end - start))
            base = int(span.get("blob_offset", descriptor.blob_offset))
            data = bytearray(raw[base : base + length])
            contributors = [
                Contributor(start=int(c["start"]), end=int(c["end"]), packet_index=c["packet_index"])
                for c in sorted(by_start.get(start, []), key=lambda c: c["start"])
            ]
            if not contributors:
                contributors = [Contributor(start=start, end=end, packet_index=None)]
            stream.runs.append(Run(start=start, data=data, contributors=contributors))
        stream.runs.sort(key=lambda r: r.start)
        stream._reindex()
        stream.holes = [
            Hole(start=int(h["start"]), end=int(h["end"]), reason=str(h["reason"]))
            for h in descriptor.holes
        ]
        stream.conflicts = _rebuild_conflicts(descriptor.diagnostics.get("conflicts", []))
        stream.diagnostics = dict(descriptor.diagnostics)
        stream.is_truncated_start = bool(
            descriptor.diagnostics.get("is_truncated_start")
        )
        stream.is_truncated_end = bool(descriptor.diagnostics.get("is_truncated_end"))
        return stream


def _run_base(descriptor: StreamDescriptor) -> int:
    return descriptor.coverage[0]["start"] if descriptor.coverage else 0


def _rebuild_conflicts(items: list[dict[str, Any]]):
    from ..analyzers.tcp_reassembly import StreamConflict

    return [
        StreamConflict(
            start_offset=int(i["start_offset"]),
            end_offset=int(i["end_offset"]),
            kept_source_packet=i.get("kept_source_packet"),
            rejected_packet=i.get("rejected_packet"),
            kept_hex=i.get("kept_hex", ""),
            rejected_hex=i.get("rejected_hex", ""),
            resolution=i.get("resolution", "first_writer_wins"),
        )
        for i in items
    ]


@lru_cache(maxsize=8)
def _noop() -> None:  # pragma: no cover - placeholder for future caches
    return None