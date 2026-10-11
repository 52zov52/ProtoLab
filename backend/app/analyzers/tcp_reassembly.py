"""TCP sequence-space arithmetic and the reassembly buffer.

Sequence numbers are 32-bit and wrap.  Everything in this module works in
*relative* sequence numbers: distance from the Initial Sequence Number, so the
stream coordinate system is monotonic and comparable.

The reassembly policy is explicit and reproducible:

``first_writer_wins`` (default)
    When two segments disagree about the bytes covering the same sequence
    range, the earliest-observed bytes are kept and the disagreement is recorded
    as a :class:`StreamConflict`.  This is what the first receiver would have
    delivered.

``last_writer_wins``
    Later bytes overwrite earlier ones; the original bytes stay in the conflict
    record so the analyst can still see both variants.

In both cases the conflict is a first-class diagnostic, never silently
resolved.  Gaps are never filled with zeros, and a segment that spans a gap is
rejected for the missing part rather than fabricating data.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31
ANALYZER_VERSION = "tcp-reassembly/1.2"


def relative_sequence(seq: int, isn: int) -> int:
    """Map a 32-bit sequence number into a monotonically increasing space."""
    return (seq - isn) & 0xFFFFFFFF


@dataclass(slots=True)
class Segment:
    packet_index: int
    timestamp: float
    sequence: int  # absolute 32-bit seq of the first payload byte
    payload: bytes
    flags: int
    window: int
    options: str | None = None

    @property
    def length(self) -> int:
        return len(self.payload)


@dataclass(slots=True)
class Contributor:
    """One packet's contribution to a run of reconstructed bytes."""

    start: int
    end: int
    packet_index: int | None


@dataclass(slots=True)
class Run:
    """A contiguous run of reconstructed bytes with no hole inside it."""

    start: int
    data: bytearray
    contributors: list[Contributor] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.start + len(self.data)

    def clip_contributors(self, lo: int, hi: int) -> list[Contributor]:
        out: list[Contributor] = []
        for c in self.contributors:
            a = max(c.start, lo)
            b = min(c.end, hi)
            if b > a:
                out.append(Contributor(start=a, end=b, packet_index=c.packet_index))
        return out


@dataclass(slots=True)
class Hole:
    start: int
    end: int
    reason: str = "missing_segments"

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(slots=True)
class StreamConflict:
    start_offset: int
    end_offset: int
    kept_source_packet: int | None
    rejected_packet: int | None
    kept_hex: str
    rejected_hex: str
    resolution: str

    def to_dict(self) -> dict[str, object]:
        return {
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "kept_source_packet": self.kept_source_packet,
            "rejected_packet": self.rejected_packet,
            "kept_hex": self.kept_hex,
            "rejected_hex": self.rejected_hex,
            "resolution": self.resolution,
            "length": self.end_offset - self.start_offset,
        }


@dataclass(slots=True)
class DuplicateObservation:
    """A retransmission carrying byte-identical data (expected, benign)."""

    packet_index: int
    original_packet_index: int | None
    start_offset: int
    end_offset: int

    def to_dict(self) -> dict[str, object]:
        return {
            "packet_index": self.packet_index,
            "original_packet_index": self.original_packet_index,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "length": self.end_offset - self.start_offset,
        }


@dataclass
class ReassembledStream:
    """The reconstructed one-way byte stream plus everything we know about it.

    ``runs`` cover only bytes actually observed.  ``holes`` describes the gaps
    between them, including an open hole at the end when the capture stopped
    mid-stream.
    """

    direction: str
    local_endpoint: str
    remote_endpoint: str
    isn: int | None
    stream_length: int
    runs: list[Run] = field(default_factory=list)
    holes: list[Hole] = field(default_factory=list)
    conflicts: list[StreamConflict] = field(default_factory=list)
    duplicates: list[DuplicateObservation] = field(default_factory=list)
    retransmissions: list[dict[str, object]] = field(default_factory=list)
    out_of_order: list[dict[str, object]] = field(default_factory=list)
    zero_windows: list[dict[str, object]] = field(default_factory=list)
    window_updates: list[dict[str, object]] = field(default_factory=list)
    overlapping: list[dict[str, object]] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    segment_count: int = 0
    payload_segment_count: int = 0
    byte_count: int = 0
    is_truncated_start: bool = False
    is_truncated_end: bool = False
    diagnostics: dict[str, object] = field(default_factory=dict)
    _starts: list[int] = field(default_factory=list, repr=False)

    # -- queries ---------------------------------------------------------- #

    @property
    def present_bytes(self) -> int:
        return sum(len(r.data) for r in self.runs)

    @property
    def has_gaps(self) -> bool:
        return any(h.reason == "missing_segments" for h in self.holes)

    def coverage(self) -> list[dict[str, int]]:
        return [{"start": r.start, "end": r.end} for r in self.runs]

    def hole_list(self) -> list[dict[str, object]]:
        return [
            {"start": h.start, "end": h.end, "length": h.length, "reason": h.reason}
            for h in self.holes
        ]

    def _index(self) -> None:
        self._starts = [r.start for r in self.runs]

    def _reindex(self) -> None:
        self.runs.sort(key=lambda r: r.start)
        self._index()

    def _runs_intersecting(self, start: int, end: int) -> Iterable[Run]:
        if not self.runs:
            return []
        if len(self._starts) != len(self.runs):
            self._index()
        idx = max(0, bisect.bisect_right(self._starts, start) - 1)
        out: list[Run] = []
        while idx < len(self.runs):
            run = self.runs[idx]
            if run.start >= end:
                break
            if run.end > start:
                out.append(run)
            idx += 1
        return out

    def read(self, offset: int, length: int) -> bytes:
        """Concatenate the *present* bytes in ``[offset, offset+length)``.

        Hole bytes are skipped, so the returned buffer may be shorter than
        ``length``.  Use :meth:`coverage_of` to know how much is really there.
        """
        if length <= 0:
            return b""
        out = bytearray()
        for run in self._runs_intersecting(offset, offset + length):
            lo = max(offset, run.start)
            hi = min(offset + length, run.end)
            out.extend(run.data[lo - run.start : hi - run.start])
        return bytes(out)

    def coverage_of(self, offset: int, length: int) -> int:
        """How many of ``length`` bytes starting at ``offset`` are present."""
        if length <= 0:
            return 0
        present = 0
        for run in self._runs_intersecting(offset, offset + length):
            lo = max(offset, run.start)
            hi = min(offset + length, run.end)
            present += max(0, hi - lo)
        return present

    def is_present(self, offset: int, length: int) -> bool:
        return self.coverage_of(offset, length) == length

    def packets_for_offset(self, offset: int) -> list[int]:
        """Every packet that delivered a byte at ``offset``."""
        out: list[int] = []
        for run in self._runs_intersecting(offset, offset + 1):
            for c in run.contributors:
                if c.start <= offset < c.end and c.packet_index is not None:
                    out.append(c.packet_index)
        return out

    def packet_references(self, offset: int, length: int) -> list[dict[str, object]]:
        """Which packets contributed the bytes in ``[offset, offset+length)``.

        This is the byte-to-packet provenance the UI needs, including the case
        where a range was assembled from several segments.
        """
        merged: dict[tuple[int | None, int], tuple[int, int]] = {}
        for run in self._runs_intersecting(offset, offset + length):
            for c in run.contributors:
                a = max(offset, c.start)
                b = min(offset + length, c.end)
                if b <= a:
                    continue
                key = (c.packet_index, c.end)
                if key in merged:
                    lo, hi = merged[key]
                    merged[key] = (min(lo, a), max(hi, b))
                else:
                    merged[key] = (a, b)
        refs = [
            {"packet_index": pkt, "start_offset": lo, "end_offset": hi}
            for (pkt, _), (lo, hi) in merged.items()
        ]
        refs.sort(key=lambda r: (r["start_offset"], r["packet_index"]))  # type: ignore[arg-type]
        return refs

    def contiguous_bytes(self, start: int = 0, end: int | None = None) -> Iterable[tuple[int, bytes]]:
        """Yield only present ``(offset, bytes)`` chunks, skipping holes."""
        for run in self.runs:
            lo = max(start, run.start)
            if end is not None and lo >= end:
                break
            hi = run.end if end is None else min(end, run.end)
            if hi > lo:
                yield lo, bytes(run.data[lo - run.start : hi - run.start])

    def present_bytes_between(self, start: int, end: int) -> int:
        return self.coverage_of(start, end - start)


def _cut_run(run: Run, lo: int, hi: int) -> tuple[Run | None, Run | None]:
    """Remove ``[lo, hi)`` from ``run``; return the surviving left/right parts."""
    if hi <= run.start or lo >= run.end:
        return run, None
    left: Run | None = None
    right: Run | None = None
    if lo > run.start:
        left = Run(
            start=run.start,
            data=bytearray(run.data[: lo - run.start]),
            contributors=run.clip_contributors(run.start, lo),
        )
    if hi < run.end:
        right = Run(
            start=hi,
            data=bytearray(run.data[hi - run.start :]),
            contributors=run.clip_contributors(hi, run.end),
        )
    return left, right


def _insert(
    stream: ReassembledStream,
    start: int,
    data: bytearray,
    contributors: list[Contributor],
) -> None:
    if not data:
        return
    stream.runs.append(Run(start=start, data=data, contributors=list(contributors)))
    stream._reindex()


def _apply_segment(
    stream: ReassembledStream,
    start: int,
    seg: Segment,
    policy: str,
) -> tuple[list[StreamConflict], int]:
    """Splice ``seg`` into the run list.

    Returns the conflicts found and the number of bytes in the segment that were
    *newly* observed (i.e. not already present).
    """
    payload = seg.payload
    end = start + len(payload)
    overlapping = list(stream._runs_intersecting(start, end))

    # --- snapshot existing bytes in the overlap ------------------------- #
    existing: dict[int, tuple[int, int]] = {}  # stream offset -> (byte, packet)
    covered_runs: list[tuple[Run, int, int]] = []
    for run in overlapping:
        lo = max(start, run.start)
        hi = min(end, run.end)
        covered_runs.append((run, lo, hi))
        for offset in range(lo, hi):
            source = next(
                (c.packet_index for c in run.contributors if c.start <= offset < c.end),
                None,
            )
            existing[offset] = (run.data[offset - run.start], source)

    # --- detect conflicts ----------------------------------------------- #
    conflicts: list[StreamConflict] = []
    differing = sorted(o for o in existing if existing[o][0] != payload[o - start])
    if differing:
        group_start = differing[0]
        group_prev = differing[0]
        for offset in differing[1:] + [None]:  # type: ignore[list-item]
            if offset is not None and offset == group_prev + 1:
                group_prev = offset
                continue
            _emit_conflict(
                conflicts,
                stream_offset_start=group_start,
                stream_offset_end=group_prev + 1,
                existing=existing,
                payload=payload,
                seg_start=start,
                policy=policy,
                packet_index=seg.packet_index,
            )
            if offset is not None:
                group_start = offset
                group_prev = offset

    # --- decide what ends up in the new run ------------------------------ #
    new_data = bytearray(payload)
    if policy == "first_writer_wins":
        for offset, (byte, _src) in existing.items():
            new_data[offset - start] = byte
    contributors = [Contributor(start=start, end=end, packet_index=seg.packet_index)]
    # Preserve the original contributor records for bytes we did not author.
    for run, lo, hi in covered_runs:
        if policy == "first_writer_wins":
            for c in run.clip_contributors(lo, hi):
                contributors.append(c)
    if policy == "first_writer_wins":
        contributors = _dedupe_contributors(contributors)
        contributors.sort(key=lambda c: (c.start, -c.end))

    # --- remove the covered slices, then insert -------------------------- #
    covered_ids = {id(run) for run in overlapping}
    survivors: list[Run] = [r for r in stream.runs if id(r) not in covered_ids]
    for run in overlapping:
        lo = max(start, run.start)
        hi = min(end, run.end)
        left, right = _cut_run(run, lo, hi)
        if left is not None:
            survivors.append(left)
        if right is not None:
            survivors.append(right)
    stream.runs = survivors
    stream._reindex()
    _insert(stream, start, new_data, contributors)

    return conflicts, len(existing)


def _dedupe_contributors(contributors: list[Contributor]) -> list[Contributor]:
    seen: set[tuple[int, int]] = set()
    out: list[Contributor] = []
    for c in contributors:
        key = (c.start, c.end)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _emit_conflict(
    conflicts: list[StreamConflict],
    *,
    stream_offset_start: int,
    stream_offset_end: int,
    existing: dict[int, tuple[int, int]],
    payload: bytes,
    seg_start: int,
    policy: str,
    packet_index: int,
) -> None:
    length = stream_offset_end - stream_offset_start
    kept_source: int | None = None
    kept = bytearray()
    for offset in range(stream_offset_start, stream_offset_end):
        byte, source = existing[offset]
        if kept_source is None:
            kept_source = source
        kept.append(byte)
    rejected = payload[stream_offset_start - seg_start : stream_offset_end - seg_start]
    if policy == "last_writer_wins":
        kept, rejected = bytearray(rejected), bytes(kept)
        kept_source = packet_index
    conflicts.append(
        StreamConflict(
            start_offset=stream_offset_start,
            end_offset=stream_offset_end,
            kept_source_packet=kept_source,
            rejected_packet=packet_index,
            kept_hex=bytes(kept).hex(),
            rejected_hex=bytes(rejected).hex(),
            resolution=policy,
        )
    )


def reassemble(
    *,
    direction: str,
    local_endpoint: str,
    remote_endpoint: str,
    segments: Sequence[Segment],
    isn: int | None,
    conflict_policy: str = "first_writer_wins",
    assume_open_end: bool = True,
) -> ReassembledStream:
    """Rebuild one direction of a TCP conversation.

    ``segments`` must be in capture order; the resulting bytes are independent
    of that order (given the stated conflict policy) while ordering anomalies
    are still reported.
    """
    if conflict_policy not in ("first_writer_wins", "last_writer_wins"):
        raise ValueError(f"unknown conflict policy {conflict_policy!r}")

    ordered = sorted(segments, key=lambda s: s.packet_index)
    diagnostics: dict[str, object] = {"conflict_policy": conflict_policy}

    has_syn = any(s.flags & 0x02 for s in ordered)
    if isn is not None:
        base_abs = (isn + 1) & 0xFFFFFFFF
    elif ordered:
        base_abs = ordered[0].sequence
        diagnostics["isn_source"] = "inferred_from_first_payload"
    else:
        base_abs = 0
        diagnostics["isn_source"] = "unknown_empty_stream"
    if isn is None and not ordered:
        isn = None

    def to_stream(seq: int) -> int:
        # 32-bit wraparound is expected and handled by the mask.  A value in the
        # upper half of the space means the segment lies *before* the base
        # (ISN+1), which a normal connection cannot produce: without this guard a
        # single such segment would place its bytes ~4 GiB out and blow up the
        # stream length and hole map.
        return (seq - base_abs) & 0xFFFFFFFF

    stream = ReassembledStream(
        direction=direction,
        local_endpoint=local_endpoint,
        remote_endpoint=remote_endpoint,
        isn=isn,
        stream_length=0,
        diagnostics=diagnostics,
    )

    max_end = 0
    frontier = 0  # highest stream offset contiguous from the base
    before_base: list[dict[str, object]] = []
    for seg in ordered:
        stream.segment_count += 1
        length = len(seg.payload)
        if length == 0:
            continue
        start = to_stream(seg.sequence)
        if start > SEQ_HALF:
            # The segment's bytes precede the stream base. That is contradictory
            # for an ordinary connection (or means the inferred ISN is wrong), so
            # the bytes are reported and excluded rather than turned into a hole
            # spanning gigabytes.
            before_base.append(
                {
                    "packet_index": seg.packet_index,
                    "sequence": seg.sequence,
                    "length": length,
                }
            )
            stream.byte_count += length
            continue
        end = start + length
        max_end = max(max_end, end)
        stream.byte_count += length

        # Provenance must be sampled *before* the splice, otherwise the
        # retransmission itself would appear to be the original source.
        prior_source = _origin_packet(stream, start)
        conflicts, already_present = _apply_segment(stream, start, seg, conflict_policy)
        new_conflicts = [c for c in conflicts if c.kept_hex != c.rejected_hex]
        stream.conflicts.extend(new_conflicts)

        if already_present == length:
            if new_conflicts:
                kind = "conflicting_retransmission"
            else:
                stream.duplicates.append(
                    DuplicateObservation(
                        packet_index=seg.packet_index,
                        original_packet_index=prior_source,
                        start_offset=start,
                        end_offset=end,
                    )
                )
                kind = "exact_duplicate"
            stream.retransmissions.append(
                {
                    "packet_index": seg.packet_index,
                    "start_offset": start,
                    "end_offset": end,
                    "length": length,
                    "kind": kind,
                }
            )
        elif already_present:
            stream.retransmissions.append(
                {
                    "packet_index": seg.packet_index,
                    "start_offset": start,
                    "end_offset": end,
                    "length": length,
                    "kind": "partial_overlap",
                    "overlap_length": already_present,
                }
            )
            stream.overlapping.append(
                {
                    "packet_index": seg.packet_index,
                    "start_offset": start,
                    "end_offset": end,
                    "overlap_length": already_present,
                }
            )
        elif start > frontier:
            stream.overlapping.append(
                {
                    "packet_index": seg.packet_index,
                    "start_offset": start,
                    "end_offset": end,
                    "gap_before": start - frontier,
                }
            )

        if start < frontier and already_present < length:
            stream.out_of_order.append(
                {
                    "packet_index": seg.packet_index,
                    "start_offset": start,
                    "end_offset": end,
                    "frontier_at_arrival": frontier,
                }
            )

        if end > frontier:
            frontier = end

    stream._reindex()
    stream.stream_length = max_end
    if before_base:
        diagnostics["segments_before_base"] = before_base
        diagnostics["segments_before_base_count"] = len(before_base)
    _build_holes(stream, has_syn=has_syn, assume_open_end=assume_open_end)
    _detect_anomalies(stream, ordered, to_stream)
    stream.start_time = ordered[0].timestamp if ordered else 0.0
    stream.end_time = ordered[-1].timestamp if ordered else 0.0
    stream.payload_segment_count = sum(1 for s in ordered if s.payload)
    return stream


def _origin_packet(stream: ReassembledStream, offset: int) -> int | None:
    packets = stream.packets_for_offset(offset)
    return packets[0] if packets else None


def _build_holes(
    stream: ReassembledStream, *, has_syn: bool, assume_open_end: bool
) -> None:
    holes: list[Hole] = []
    if not stream.runs:
        stream.holes = holes
        stream.is_truncated_start = True
        stream.is_truncated_end = True
        return

    cursor = 0
    for run in stream.runs:
        if run.start > cursor:
            holes.append(Hole(start=cursor, end=run.start, reason="missing_segments"))
        cursor = max(cursor, run.end)
    if has_syn and stream.runs[0].start > 0:
        # SYN consumed one sequence number, so offset 0 is the first data byte.
        stream.is_truncated_start = True
    if stream.diagnostics.get("isn_source") == "inferred_from_first_payload":
        # Without a SYN we anchored offset 0 on the first payload we happened to
        # capture: earlier bytes may exist but were not recorded.
        stream.is_truncated_start = True
    if assume_open_end and cursor < stream.stream_length:
        holes.append(Hole(start=cursor, end=stream.stream_length, reason="capture_ended"))
        stream.is_truncated_end = True
    stream.holes = holes


def _detect_anomalies(
    stream: ReassembledStream, segments: Sequence[Segment], to_stream: Callable[[int], int]
) -> None:
    last_window: int | None = None
    for seg in segments:
        if seg.flags & 0x04:  # RST carries no window semantics
            last_window = None
            continue
        if seg.window == 0 and seg.flags & 0x10:
            stream.zero_windows.append(
                {
                    "packet_index": seg.packet_index,
                    "timestamp": seg.timestamp,
                    "receiver": "peer",
                    "ack": seg.sequence,
                }
            )
        if last_window is not None and last_window > 0 and seg.window > last_window * 2:
            stream.window_updates.append(
                {
                    "packet_index": seg.packet_index,
                    "previous_window": last_window,
                    "window": seg.window,
                    "timestamp": seg.timestamp,
                }
            )
        last_window = seg.window


def summarise_timeline(
    segments: Sequence[Segment],
    *,
    to_stream: Callable[[int], int],
    limit: int = 20_000,
) -> list[dict[str, object]]:
    """Per-packet view used by the UI state diagram."""
    events: list[dict[str, object]] = []
    for seg in segments[:limit]:
        entry: dict[str, object] = {
            "packet_index": seg.packet_index,
            "timestamp": seg.timestamp,
            "flags": seg.flags,
            "window": seg.window,
            "payload_length": len(seg.payload),
            "options": seg.options,
        }
        if seg.payload:
            start = to_stream(seg.sequence)
            entry["start_offset"] = start
            entry["end_offset"] = start + len(seg.payload)
        events.append(entry)
    return events


def find_duplicate_ack_runs(
    segments: Sequence[Any], *, min_run: int = 3
) -> list[dict[str, object]]:
    """Heuristic duplicate-ACK detection.

    Only *adjacent* ACKs with an identical acknowledgement value and no payload in
    between are counted, because anything looser produces false positives on a
    lossy link.  The result is explicitly a heuristic, not a proof of fast-retransmit
    behaviour.

    Accepts both :class:`Segment` (which uses ``sequence``) and decoded flow
    packets (which use ``seq``).
    """
    events: list[dict[str, object]] = []
    run_start: int | None = None
    run_count = 0
    last_ack: int | None = None
    for seg in segments:
        payload = getattr(seg, "payload", b"")
        flags = getattr(seg, "flags", 0) or 0
        ack = getattr(seg, "ack", None)
        if ack is None:
            ack = getattr(seg, "sequence", None)
        # A duplicate ACK is a pure ACK (no payload) repeating an acknowledgement
        # value.  Any segment carrying data, or a new ACK value, ends the run.
        if payload or not (flags & 0x10) or ack is None:
            last_ack = None
            run_start = None
            run_count = 0
            continue
        if last_ack is not None and ack == last_ack:
            run_count += 1
        else:
            run_start = seg.packet_index
            run_count = 1
            last_ack = ack
        if run_count >= min_run:
            events.append(
                {
                    "first_packet_index": run_start,
                    "packet_index": seg.packet_index,
                    "acknowledgement": ack,
                    "count": run_count,
                }
            )
    return events