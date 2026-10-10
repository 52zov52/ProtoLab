"""Field inference: propose candidate structures from observed bytes.

Everything produced here is a *hypothesis candidate* with its supporting and
contradicting evidence attached.  Nothing is asserted as fact: the product
requires the analyst to accept, revise or reject each candidate, and the status
is carried through validation.

The scorers deliberately prefer conservative naming (``field_at_4`` over
``checksum``) because a semantic label is a claim, and a claim needs evidence
this module does not have.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Sequence

from .byte_analysis import (
    ANALYZER_VERSION as BYTE_ANALYZER_VERSION,
    ColumnStats,
    correlation,
    column_statistics,
    find_constant_prefix,
    shannon_entropy,
)
from .tcp_reassembly import ReassembledStream

INFERENCE_VERSION = f"field-inference/1.0 (byte-analysis {BYTE_ANALYZER_VERSION})"

CANDIDATE_ROLES = (
    "magic",
    "version",
    "message_type",
    "length",
    "sequence",
    "identifier",
    "parameter",
    "status",
    "checksum",
    "timestamp",
    "payload",
    "unknown",
)


@dataclass
class FieldCandidate:
    name: str
    offset: int
    size: int
    endianness: str
    role: str
    confidence: float
    rationale: str
    supporting_message_ids: list[int] = field(default_factory=list)
    contradicting_message_ids: list[int] = field(default_factory=list)
    observed_values: list[int] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "endianness": self.endianness,
            "role": self.role,
            "confidence": round(self.confidence, 4),
            "rationale": self.rationale,
            "support_count": len(self.supporting_message_ids),
            "contradiction_count": len(self.contradicting_message_ids),
            "supporting_examples": self.supporting_message_ids[:10],
            "contradicting_examples": self.contradicting_message_ids[:10],
            "observed_values": self.observed_values[:16],
            "score": round(self.score, 4),
        }


@dataclass
class InferenceResult:
    analyzer_version: str
    message_count: int
    column_stats: list[ColumnStats]
    candidates: list[FieldCandidate]
    constant_prefix_length: int
    length_histogram: dict[int, int]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "analyzer_version": self.analyzer_version,
            "message_count": self.message_count,
            "constant_prefix_length": self.constant_prefix_length,
            "length_histogram": self.length_histogram,
            "column_stats": [c.to_dict() for c in self.column_stats],
            "candidates": [c.to_dict() for c in self.candidates],
            "notes": self.notes,
        }


def infer_fields(
    messages: Sequence[bytes],
    *,
    extra_series: dict[str, Sequence[float]] | None = None,
    max_messages: int = 20_000,
) -> InferenceResult:
    """Propose field candidates for a corpus of messages.

    ``extra_series`` lets the caller correlate byte positions with experiment
    parameters (for example a known parameter value) without the inference code
    knowing anything about the device.
    """
    corpus = [m for m in messages[:max_messages] if m]
    if not corpus:
        return InferenceResult(
            analyzer_version=INFERENCE_VERSION,
            message_count=0,
            column_stats=[],
            candidates=[],
            constant_prefix_length=0,
            length_histogram={},
            notes=["No messages were supplied, so no field candidates could be inferred."],
        )

    stats = column_statistics(corpus)
    lengths = [len(m) for m in corpus]
    histogram = dict(sorted(Counter(lengths).items()))
    prefix = find_constant_prefix(corpus)

    candidates: list[FieldCandidate] = []
    notes: list[str] = []

    # --- magic / constant prefix ----------------------------------------- #
    if prefix >= 2:
        samples = [m[:prefix] for m in corpus]
        candidates.append(
            FieldCandidate(
                name="leading_signature",
                offset=0,
                size=prefix,
                endianness="n/a",
                role="magic",
                confidence=1.0,
                rationale=(
                    f"The first {prefix} bytes are identical in all {len(corpus)} messages."
                ),
                supporting_message_ids=list(range(len(corpus))),
                observed_values=[int.from_bytes(corpus[0][:prefix], "big")],
                score=0.55,
            )
        )
        _ = samples
    else:
        notes.append(
            "No constant leading signature: byte 0 already varies across the corpus."
        )

    # --- length field ------------------------------------------------------ #
    for candidate in _length_candidates(corpus, stats, prefix):
        candidates.append(candidate)

    # --- discrete enumerations (message type / status) --------------------- #
    for stat in stats:
        if stat.offset < prefix or stat.unique_values < 2:
            continue
        if stat.unique_values <= 16 and stat.present_count == len(corpus):
            share = stat.unique_values / max(1, stat.present_count)
            if share < 0.35:
                candidates.append(
                    FieldCandidate(
                        name=f"field_at_{stat.offset}",
                        offset=stat.offset,
                        size=1,
                        endianness="n/a",
                        role="message_type",
                        confidence=0.6,
                        rationale=(
                            f"Only {stat.unique_values} distinct values across "
                            f"{stat.present_count} messages, which suggests a small "
                            "enumeration such as a message type or status code."
                        ),
                        supporting_message_ids=list(range(len(corpus))),
                        observed_values=[v for v, _ in stat.most_common],
                        score=0.4 + 0.3 * (1 - share),
                    )
                )

    # --- counters / identifiers -------------------------------------------- #
    for size, endian in ((2, "big"), (4, "big"), (2, "little"), (4, "little")):
        for stat in stats:
            end = stat.offset + size
            if end > max(lengths):
                continue
            if end <= prefix:
                continue
            values = _read_values(corpus, stat.offset, size, endian)
            if len(values) != len(corpus):
                continue
            if len(set(values)) < 2:
                continue
            deltas = [values[i] - values[i - 1] for i in range(1, len(values))]
            monotonic = sum(1 for d in deltas if d > 0) / len(deltas) if deltas else 0.0
            if monotonic >= 0.8:
                candidates.append(
                    FieldCandidate(
                        name=f"counter_at_{stat.offset}",
                        offset=stat.offset,
                        size=size,
                        endianness=endian,
                        role="sequence",
                        confidence=0.5 + 0.3 * monotonic,
                        rationale=(
                            f"Increases in {monotonic:.0%} of consecutive pairs, which is "
                            "consistent with a request id or counter (a hypothesis, not proof)."
                        ),
                        supporting_message_ids=list(range(min(12, len(corpus)))),
                        observed_values=values[:16],
                        score=0.35 + 0.25 * monotonic,
                    )
                )

    # --- experiment correlation --------------------------------------------- #
    if extra_series:
        for label, series in extra_series.items():
            aligned = [v for v, m in zip(series, messages) if m]
            if len(aligned) < 4:
                continue
            for size, endian in ((2, "big"), (4, "big")):
                for stat in stats:
                    end = stat.offset + size
                    if end > max(lengths):
                        continue
                    values = _read_values(corpus, stat.offset, size, endian)
                    if len(values) != len(aligned):
                        continue
                    rho = correlation([float(v) for v in values], [float(v) for v in aligned])
                    if rho is not None and abs(rho) >= 0.85:
                        candidates.append(
                            FieldCandidate(
                                name=f"parameter_at_{stat.offset}",
                                offset=stat.offset,
                                size=size,
                                endianness=endian,
                                role="parameter",
                                confidence=min(0.95, abs(rho)),
                                rationale=(
                                    f"Correlates with the logged experiment parameter "
                                    f"{label!r} (Pearson r={rho:.3f}). Correlation does not "
                                    "prove this is the encoded value, but it is strong evidence."
                                ),
                                supporting_message_ids=list(range(len(aligned))),
                                observed_values=values[:16],
                                score=0.4 + 0.3 * abs(rho),
                            )
                        )

    # --- trailing entropy regions ------------------------------------------- #
    if len(histogram) > 1:
        max_len = max(lengths)
        tail_start = max_len
        for stat in reversed(stats):
            if stat.present_count and stat.present_count > len(corpus) * 0.4:
                tail_start = min(tail_start, stat.offset)
            else:
                break
        if tail_start < max_len:
            notes.append(
                f"Bytes {tail_start}..{max_len - 1} vary in length across messages and are "
                "the prime candidates for a variable-length payload region."
            )

    candidates.sort(key=lambda c: c.score, reverse=True)
    notes.append(
        "All candidates are hypotheses generated from observed data. Support a hypothesis "
        "only after checking the listed contradicting examples."
    )
    return InferenceResult(
        analyzer_version=INFERENCE_VERSION,
        message_count=len(corpus),
        column_stats=stats,
        candidates=candidates,
        constant_prefix_length=prefix,
        length_histogram=histogram,
        notes=notes,
    )


def _read_values(messages: Sequence[bytes], offset: int, size: int, endian: str) -> list[int]:
    out: list[int] = []
    order = "little" if endian == "little" else "big"
    for message in messages:
        if len(message) < offset + size:
            return []
        out.append(int.from_bytes(message[offset : offset + size], order))
    return out


def _length_candidates(
    messages: Sequence[bytes], stats: Sequence[ColumnStats], prefix: int
) -> list[FieldCandidate]:
    """Test each offset/size/endianness for 'length of the message'."""
    lengths = [len(m) for m in messages]
    out: list[FieldCandidate] = []
    total = len(messages)
    for offset in range(0, min(8, max(lengths))):
        for size in (1, 2, 4):
            for endian in ("big", "little"):
                values = _read_values(messages, offset, size, endian)
                if len(values) != total:
                    continue
                # Convention A: field == full message length.
                matches_a = [i for i, v in enumerate(values) if v == lengths[i]]
                # Convention B: field == body length (full length minus header).
                header_size = offset + size
                matches_b = [i for i, v in enumerate(values) if v + header_size == lengths[i]]
                best, best_b = matches_a, matches_b
                if len(best) <= len(best_b):
                    chosen, convention = best_b, f"body length (field + {header_size} = total)"
                else:
                    chosen, convention = best, "total message length"
                ratio = len(chosen) / total
                if ratio < 0.5:
                    continue
                if offset + size <= prefix:
                    # Already explained as part of a constant signature.
                    continue
                stragglers = total - len(chosen)
                tail = (
                    f" The remaining {stragglers} message(s) do not fit and are the "
                    "counterexamples to inspect."
                    if stragglers
                    else (
                        " Every message in this corpus fits, which is support for this "
                        "reading and not proof of it: other data may not."
                    )
                )
                out.append(
                    FieldCandidate(
                        name=f"length_at_{offset}",
                        offset=offset,
                        size=size,
                        endianness=endian,
                        role="length",
                        confidence=ratio,
                        rationale=(
                            f"Interpreting these bytes as {endian}-endian {size * 8}-bit "
                            f"{convention} matches the observed message length in "
                            f"{len(chosen)} of {total} messages ({ratio:.1%})." + tail
                        ),
                        supporting_message_ids=chosen,
                        contradicting_message_ids=[
                            i for i in range(total) if i not in set(chosen)
                        ],
                        observed_values=values[:16],
                        score=0.5 + 0.45 * ratio
                        # A length field at offset 0 explains the whole header;
                        # one further in leaves leading bytes unexplained, so it
                        # is weaker evidence for the same match ratio.
                        - 0.04 * offset,
                    )
                )
    out.sort(key=lambda c: c.score, reverse=True)
    return out[:3]


def stream_structure_report(
    stream: ReassembledStream, messages: Sequence[bytes]
) -> dict[str, object]:
    """Lightweight overview used by the Workbench header."""
    data = stream.read(0, min(stream.stream_length, 1 << 20))
    return {
        "stream_length": stream.stream_length,
        "present_bytes": stream.present_bytes,
        "holes": stream.hole_list(),
        "entropy": round(shannon_entropy(data), 4),
        "message_count": len(messages),
        "distinct_lengths": sorted({len(m) for m in messages}),
        "analyzer_version": INFERENCE_VERSION,
    }