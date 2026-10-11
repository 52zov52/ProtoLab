"""Byte-level statistics: entropy, column profiles, alignment, diffing.

Every function here is pure and deterministic so results can be recomputed and
compared across runs.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Iterable, Sequence

ANALYZER_VERSION = "byte-analysis/1.1"

_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\n\r"


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0).

    High entropy is *not* proof of encryption: compressed or high-cardinality
    binary payloads look the same.  Callers must phrase conclusions accordingly.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )
    # ``-0.0`` would render as "-0.0" and look like a bug; normalise it.
    return entropy + 0.0


def byte_histogram(data: bytes) -> dict[int, int]:
    return dict(Counter(data))


def unique_byte_count(data: bytes) -> int:
    return len(set(data))


def zero_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return data.count(0) / len(data)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


def ascii_render(chunk: bytes) -> str:
    out = []
    for byte in chunk:
        if byte in (0x20, 0x09):
            out.append(chr(byte))
        elif 0x20 < byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(".")
    return "".join(out)


def hexdump(data: bytes, base_offset: int = 0, *, holes: Sequence[tuple[int, int]] = ()) -> list[dict[str, object]]:
    """Classic hex + ASCII rendering used by the API.

    Holes inside ``data`` are rendered as explicit ``gap`` rows so the UI can
    show that bytes are *missing* instead of showing fabricated zeros.
    """
    lines: list[dict[str, object]] = []
    gap_spans = _merge_spans(holes)
    pos = 0
    total = len(data)
    while pos < total:
        row_len = min(16, total - pos)
        chunk = data[pos : pos + row_len]
        hex_cells = [f"{b:02x}" for b in chunk]
        ascii_cells = [ascii_render(chunk)]
        if gap_spans:
            row_start = base_offset + pos
            row_end = row_start + row_len
            for gs, ge in gap_spans:
                if ge > row_start and gs < row_end:
                    hex_cells.append("GAP")
                    ascii_cells.append(f"[gap {ge - gs}B]")
                    break
        lines.append(
            {
                "offset": base_offset + pos,
                "hex": hex_cells,
                "ascii": ascii_cells,
                "length": row_len,
            }
        )
        pos += row_len
    return lines


def _merge_spans(spans: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    ordered = sorted((s for s in spans if s[1] > s[0]))
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


@dataclass
class ColumnStats:
    """Statistics for one byte position across a message corpus."""

    offset: int
    present_count: int = 0
    absent_count: int = 0
    unique_values: int = 0
    min_value: int | None = None
    max_value: int | None = None
    entropy: float = 0.0
    change_rate: float = 0.0
    monotonic_ratio: float = 0.0
    zero_count: int = 0
    most_common: list[tuple[int, int]] = field(default_factory=list)
    values_sample: list[int] = field(default_factory=list)
    classification: str = "unknown"
    classification_rationale: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


#: The byte-column classes.  They describe the *shape* of a column, never the
#: meaning of a field: "counter" says the byte rises across messages, not that
#: it is a request id.
COLUMN_CLASSES = (
    "absent",
    "constant",
    "counter",
    "enum",
    "high_entropy",
    "variable",
)

#: A byte that is essentially uniform over 256 values carries ~8 bits; 6.5 is a
#: deliberately high bar so ordinary numeric fields are not called random.
_HIGH_ENTROPY_BITS = 6.5
_MONOTONIC_MIN = 0.8
_ENUM_MAX_UNIQUE = 16


def classify_column(
    *,
    present_count: int,
    unique_values: int,
    entropy: float,
    change_rate: float,
    monotonic_ratio: float,
) -> tuple[str, str]:
    """Classify one byte column from its statistics, with a stated reason.

    The classes are ordered so the strongest reading wins.  ``high_entropy``
    folds together random, compressed, encrypted and checksum bytes on purpose:
    statistics alone cannot separate those, so the rationale says so instead of
    guessing "checksum".
    """
    if present_count == 0:
        return "absent", "This offset is not present in any message of the corpus."
    if unique_values <= 1:
        return (
            "constant",
            f"The same value in all {present_count} messages that reach this offset.",
        )
    if monotonic_ratio >= _MONOTONIC_MIN and unique_values >= 3:
        return (
            "counter",
            f"Non-decreasing in {monotonic_ratio:.0%} of consecutive messages "
            "(equal values allowed); consistent with a counter or running id, a "
            "hypothesis rather than proof.",
        )
    if unique_values <= _ENUM_MAX_UNIQUE:
        return (
            "enum",
            f"Only {unique_values} distinct values across {present_count} messages, "
            "which suggests a small enumeration such as a type or status code.",
        )
    if entropy >= _HIGH_ENTROPY_BITS and change_rate >= 0.8:
        return (
            "high_entropy",
            f"Near-uniform over {unique_values} values (entropy {entropy:.2f} bits) "
            "and almost always changing. Random, compressed, encrypted and checksum "
            "bytes all look like this, so no single label among them is claimed.",
        )
    return (
        "variable",
        f"{unique_values} distinct values over {present_count} messages, but not "
        "monotonic and not near-uniform; no stronger reading is supported.",
    )


def column_statistics(messages: Sequence[bytes], *, max_messages: int = 20_000) -> list[ColumnStats]:
    """Per-offset statistics over a corpus of messages.

    Absent positions (message shorter than the offset) are counted separately
    and never substituted with zero.
    """
    corpus = [m for m in messages[:max_messages] if m]
    if not corpus:
        return []
    max_len = max(len(m) for m in corpus)
    stats: list[ColumnStats] = []
    for offset in range(max_len):
        present = [m[offset] for m in corpus if len(m) > offset]
        absent = len(corpus) - len(present)
        counts = Counter(present)
        ordered = [
            m[offset]
            for m in corpus
            if len(m) > offset
        ]
        changes = sum(1 for i in range(1, len(ordered)) if ordered[i] != ordered[i - 1])
        increases = sum(1 for i in range(1, len(ordered)) if ordered[i] >= ordered[i - 1])
        change_rate = (changes / (len(ordered) - 1)) if len(ordered) > 1 else 0.0
        monotonic_ratio = (increases / (len(ordered) - 1)) if len(ordered) > 1 else 0.0
        entropy = shannon_entropy(bytes(present))
        classification, rationale = classify_column(
            present_count=len(present),
            unique_values=len(counts),
            entropy=entropy,
            change_rate=change_rate,
            monotonic_ratio=monotonic_ratio,
        )
        entry = ColumnStats(
            offset=offset,
            present_count=len(present),
            absent_count=absent,
            unique_values=len(counts),
            min_value=min(present) if present else None,
            max_value=max(present) if present else None,
            entropy=entropy,
            change_rate=change_rate,
            monotonic_ratio=monotonic_ratio,
            zero_count=sum(1 for b in present if b == 0),
            most_common=[(value, count) for value, count in counts.most_common(6)],
            values_sample=present[:32],
            classification=classification,
            classification_rationale=rationale,
        )
        stats.append(entry)
    return stats


def find_constant_prefix(messages: Sequence[bytes]) -> int:
    """Length of the byte prefix shared by every message."""
    if not messages:
        return 0
    shortest = min(len(m) for m in messages)
    index = 0
    while index < shortest:
        value = messages[0][index]
        if any(m[index] != value for m in messages):
            break
        index += 1
    return index


def correlation(a: Sequence[float], b: Sequence[float]) -> float | None:
    """Pearson correlation; ``None`` when it is undefined."""
    if len(a) != len(b) or len(a) < 2:
        return None
    mean_a = sum(a) / len(a)
    mean_b = sum(b) / len(b)
    num = sum((x - mean_a) * (y - mean_b) for x, y in zip(a, b))
    den_a = math.sqrt(sum((x - mean_a) ** 2 for x in a))
    den_b = math.sqrt(sum((y - mean_b) ** 2 for y in b))
    if den_a == 0 or den_b == 0:
        return None
    return num / (den_a * den_b)


@dataclass
class MessageDiff:
    offset: int
    values: list[int | None]
    changed: bool
    present_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def align_messages(messages: Sequence[bytes]) -> tuple[str, list[MessageDiff]]:
    """Align messages of different lengths by absolute offset.

    ``None`` in ``values`` means *absent*, never "zero".  The alignment is
    explicitly positional (no edit-distance realignment) because an unknown
    binary protocol has no defensible insertion/deletion model; the caller is
    told which positions were missing.
    """
    if not messages:
        return "none", []
    max_len = max(len(m) for m in messages)
    rows: list[MessageDiff] = []
    for offset in range(max_len):
        values = [m[offset] if len(m) > offset else None for m in messages]
        present = [v for v in values if v is not None]
        unique = set(present)
        rows.append(
            MessageDiff(
                offset=offset,
                values=values,
                changed=len(unique) > 1 or len(present) < len(messages),
                present_count=len(present),
            )
        )
    differing = sum(1 for row in rows if row.changed)
    method = "positional"
    if differing == 0:
        method = "identical"
    return method, rows


def repeating_pattern_score(data: bytes, *, min_period: int = 2, max_period: int = 32) -> float:
    """Fraction of positions explained by a small repeating period."""
    if not data:
        return 0.0
    best = 0.0
    for period in range(min_period, min(max_period, len(data) // 2) + 1):
        matches = sum(
            1 for i in range(len(data) - period) if data[i] == data[i + period]
        )
        score = matches / (len(data) - period)
        if score > best:
            best = score
    return best


def delta_encode(values: Sequence[int]) -> list[int]:
    """Deltas between consecutive messages, used for the diff heat map."""
    return [values[i] - values[i - 1] for i in range(1, len(values))]


def group_by_length(messages: Sequence[bytes]) -> dict[int, list[int]]:
    grouped: dict[int, list[int]] = {}
    for index, message in enumerate(messages):
        grouped.setdefault(len(message), []).append(index)
    return dict(sorted(grouped.items()))


def iter_ngrams(data: bytes, size: int) -> Iterable[tuple[int, bytes]]:
    for i in range(0, max(0, len(data) - size + 1)):
        yield i, data[i : i + size]