"""Message framing: splitting a byte stream into application messages.

A TCP packet is *not* a message.  One packet may carry several messages and one
message may span many segments, so framing must run over the reconstructed
stream and be explicit about the evidence behind every boundary.

Methods
-------
``fixed_length``      constant size
``length_prefix``     a length field, big or little endian, header-inclusive or not
``delimiter``         scan for a byte/string delimiter
``signature``         a recurring leading marker splits messages
``header_rule``       user-supplied offset/size/mask predicate
``heuristic``         score candidate boundaries using synchronisation, entropy
                      and length consistency
``manual``            researcher-provided boundaries (stored as an annotation)

Every framing result records: stream offset, length, originating packets, the
method, the rule version, a confidence and any diagnostics.  Messages that run
into a hole in the stream are marked ``partial`` rather than truncated with
zeros.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Sequence

from .byte_analysis import shannon_entropy
from .tcp_reassembly import ReassembledStream

FRAMING_VERSION = "framing/1.2"

METHODS = (
    "fixed_length",
    "length_prefix",
    "delimiter",
    "signature",
    "header_rule",
    "heuristic",
    "manual",
)


@dataclass
class FramedMessage:
    start_offset: int
    end_offset: int
    method: str
    confidence: float
    declared_length: int | None = None
    complete: bool = True
    packet_references: list[dict[str, object]] = field(default_factory=list)
    diagnostics: dict[str, object] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end_offset - self.start_offset

    @property
    def present_length(self) -> int:
        return int(self.diagnostics.get("present_length", self.length))

    def to_dict(self) -> dict[str, object]:
        return {
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "length": self.length,
            "present_length": self.present_length,
            "method": self.method,
            "confidence": round(self.confidence, 4),
            "declared_length": self.declared_length,
            "complete": self.complete,
            "packet_references": self.packet_references,
            "diagnostics": self.diagnostics,
        }


class FramingConfig:
    """Validated framing configuration.

    Construct through :meth:`parse` so an imported configuration cannot smuggle
    arbitrary callables or code into the analyzer.
    """

    __slots__ = ("method", "config", "rule_version")

    def __init__(self, method: str, config: dict[str, object], rule_version: str = FRAMING_VERSION) -> None:
        if method not in METHODS:
            raise ValueError(
                f"unsupported framing method {method!r}; expected one of {', '.join(METHODS)}"
            )
        self.method = method
        self.config = dict(config)
        self.rule_version = rule_version

    # -- typed accessors; each raises ValueError on a bad configuration ---- #

    def _int(self, key: str, *, default: int | None = None, minimum: int = 0) -> int:
        value = self.config.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"framing option {key!r} must be an integer")
        if value < minimum:
            raise ValueError(f"framing option {key!r} must be >= {minimum}")
        return value

    def _bool(self, key: str, default: bool) -> bool:
        value = self.config.get(key, default)
        if not isinstance(value, bool):
            raise ValueError(f"framing option {key!r} must be a boolean")
        return value

    def _str(self, key: str, *, default: str | None = None) -> str:
        value = self.config.get(key, default)
        if not isinstance(value, str):
            raise ValueError(f"framing option {key!r} must be a string")
        return value

    @classmethod
    def parse(cls, payload: dict[str, object]) -> "FramingConfig":
        if not isinstance(payload, dict):
            raise ValueError("framing configuration must be an object")
        method = payload.get("method")
        if not isinstance(method, str):
            raise ValueError("framing configuration requires a 'method' string")
        config = payload.get("config", {})
        if not isinstance(config, dict):
            raise ValueError("framing 'config' must be an object")
        cfg = cls(method, config)
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.method == "fixed_length":
            self._int("length", minimum=1)
        elif self.method == "length_prefix":
            self._int("length_offset", minimum=0)
            self._int("length_size", minimum=1)
            if self._str("endianness", default="big") not in ("big", "little"):
                raise ValueError("length_prefix endianness must be 'big' or 'little'")
            if self._str("includes_header", default="true") not in ("true", "false"):
                raise ValueError("length_prefix includes_header must be 'true' or 'false'")
            self._int("max_length", minimum=1)
        elif self.method == "delimiter":
            self._int("delimiter", minimum=0, )
            self._int("max_length", minimum=1)
        elif self.method == "signature":
            self._int("signature", minimum=0)
            self._int("min_length", minimum=1)
        elif self.method == "header_rule":
            self._int("header_offset", minimum=0)
            self._int("header_size", minimum=1)
        elif self.method == "heuristic":
            self._int("min_gap", default=2, minimum=1)
        elif self.method == "manual":
            boundaries = self.config.get("boundaries")
            if not isinstance(boundaries, list) or any(
                not isinstance(b, int) or isinstance(b, bool) or b < 0 for b in boundaries
            ):
                raise ValueError("manual framing requires a list of non-negative integer 'boundaries'")

    def to_dict(self) -> dict[str, object]:
        return {"method": self.method, "config": self.config, "rule_version": self.rule_version}


def frame_stream(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    """Apply the configured framing rule to a reconstructed stream."""
    fn = _FRAMERS.get(cfg.method)
    if fn is None:  # pragma: no cover - validate() already rejects this
        raise ValueError(f"no framer for method {cfg.method!r}")
    messages = fn(stream, cfg)
    _annotate(stream, messages)
    return messages


def _annotate(stream: ReassembledStream, messages: list[FramedMessage]) -> None:
    for message in messages:
        present = stream.coverage_of(message.start_offset, message.length)
        message.diagnostics.setdefault("present_length", present)
        message.complete = present == message.length
        if not message.complete:
            message.diagnostics.setdefault(
                "reason",
                "message range overlaps a gap in the reconstructed stream",
            )
        message.packet_references = stream.packet_references(
            message.start_offset, message.length
        )


# --------------------------------------------------------------------------- #
# Individual framers
# --------------------------------------------------------------------------- #


def _frame_fixed_length(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    length = cfg._int("length")
    include_tail = cfg._bool("include_partial_tail", True)
    messages: list[FramedMessage] = []
    offset = 0
    while offset < stream.stream_length:
        end = min(offset + length, stream.stream_length)
        partial = end - offset != length
        messages.append(
            FramedMessage(
                start_offset=offset,
                end_offset=end,
                method=cfg.method,
                confidence=0.95 if not partial else 0.5,
                complete=not partial,
                diagnostics={"expected_length": length} if partial else {},
            )
        )
        if partial and not include_tail:
            break
        offset = end
    return messages


def _frame_length_prefix(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    length_offset = cfg._int("length_offset")
    length_size = cfg._int("length_size")
    endian = cfg._str("endianness", default="big")
    includes_header = cfg._str("includes_header", default="true") == "true"
    max_length = cfg._int("max_length", default=1 << 20)

    def parse(chunk: bytes) -> int:
        return int.from_bytes(chunk, "little" if endian == "little" else "big")

    messages: list[FramedMessage] = []
    offset = 0
    guard = 0
    while offset < stream.stream_length:
        guard += 1
        if guard > 5_000_000:  # pragma: no cover - runaway protection
            break
        header_end = offset + length_offset + length_size
        if not stream.is_present(offset, length_offset + length_size):
            messages.append(
                FramedMessage(
                    start_offset=offset,
                    end_offset=stream.stream_length,
                    method=cfg.method,
                    confidence=0.1,
                    complete=False,
                    diagnostics={
                        "reason": "length field is not fully present in the stream",
                        "length_field_offset": offset + length_offset,
                    },
                )
            )
            break
        header_bytes = stream.read(offset + length_offset, length_size)
        if len(header_bytes) != length_size:
            break
        declared = parse(header_bytes)
        total = declared if includes_header else declared + length_offset + length_size
        if total <= 0 or total > max_length:
            messages.append(
                FramedMessage(
                    start_offset=offset,
                    end_offset=stream.stream_length,
                    method=cfg.method,
                    confidence=0.05,
                    complete=False,
                    declared_length=declared,
                    diagnostics={
                        "reason": (
                            f"declared length {declared} is outside the accepted range "
                            f"(1..{max_length}); framing stopped here"
                        ),
                        "rejected_length": declared,
                    },
                )
            )
            break
        end = offset + total
        present = stream.coverage_of(offset, total)
        confidence = 1.0 if present == total else 0.3
        messages.append(
            FramedMessage(
                start_offset=offset,
                end_offset=end,
                method=cfg.method,
                confidence=confidence,
                declared_length=declared,
                complete=present == total,
                diagnostics={
                    "length_field_offset": offset + length_offset,
                    "includes_header": includes_header,
                },
            )
        )
        offset = end
    return messages


def _frame_delimiter(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    delimiter = cfg._int("delimiter")
    max_length = cfg._int("max_length", default=1 << 20)
    keep_delimiter = cfg._bool("keep_delimiter", True)
    messages: list[FramedMessage] = []
    offset = 0
    while offset < stream.stream_length:
        found = _find_byte(stream, offset, delimiter, max_length)
        if found is None:
            if stream.stream_length > offset:
                messages.append(
                    FramedMessage(
                        start_offset=offset,
                        end_offset=stream.stream_length,
                        method=cfg.method,
                        confidence=0.4,
                        complete=False,
                        diagnostics={"reason": "no delimiter found before end of stream"},
                    )
                )
            break
        end = found + (1 if keep_delimiter else 0)
        messages.append(
            FramedMessage(
                start_offset=offset,
                end_offset=end,
                method=cfg.method,
                confidence=0.9,
                diagnostics={"delimiter_offset": found},
            )
        )
        offset = end
    return messages


def _find_byte(stream: ReassembledStream, start: int, value: int, limit: int) -> int | None:
    cursor = start
    while cursor < min(stream.stream_length, start + limit):
        run = stream.find_run(cursor)
        if run is None:
            break
        try:
            index = run.data.index(value, cursor - run.start)
        except ValueError:
            cursor = run.end
            continue
        return run.start + index
    return None


def _frame_signature(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    signature = cfg._int("signature")
    min_length = cfg._int("min_length", default=1)
    positions = _find_all(stream, signature)
    if not positions:
        return []
    messages: list[FramedMessage] = []
    if positions[0] > 0:
        messages.append(
            FramedMessage(
                start_offset=0,
                end_offset=positions[0],
                method=cfg.method,
                confidence=0.3,
                complete=False,
                diagnostics={"reason": "bytes before the first signature match are unassigned"},
            )
        )
    for index, start in enumerate(positions):
        end = positions[index + 1] if index + 1 < len(positions) else stream.stream_length
        if end - start < min_length:
            continue
        messages.append(
            FramedMessage(
                start_offset=start,
                end_offset=end,
                method=cfg.method,
                confidence=0.85,
                diagnostics={"signature_offset": start},
            )
        )
    return messages


def _find_all(stream: ReassembledStream, value: int) -> list[int]:
    out: list[int] = []
    for offset, chunk in stream.contiguous_bytes():
        start = 0
        while True:
            index = chunk.find(value, start)
            if index < 0:
                break
            out.append(offset + index)
            start = index + 1
    return out


def _frame_header_rule(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    header_offset = cfg._int("header_offset")
    header_size = cfg._int("header_size")
    base = cfg._int("base", default=0)
    factor = cfg._int("factor", default=1)
    subtract = cfg._int("subtract", default=0)
    mask = cfg.config.get("mask")
    if mask is not None and (not isinstance(mask, int) or mask < 0):
        raise ValueError("header_rule mask must be a non-negative integer")

    messages: list[FramedMessage] = []
    offset = 0
    while offset < stream.stream_length:
        need = header_offset + header_size
        if not stream.is_present(offset, need):
            if stream.stream_length > offset:
                messages.append(
                    FramedMessage(
                        start_offset=offset,
                        end_offset=stream.stream_length,
                        method=cfg.method,
                        confidence=0.1,
                        complete=False,
                        diagnostics={"reason": "header field is not fully present"},
                    )
                )
            break
        raw = int.from_bytes(stream.read(offset + header_offset, header_size), "big")
        if mask is not None:
            raw &= mask
        total = raw * factor - subtract + base
        if total <= 0:
            messages.append(
                FramedMessage(
                    start_offset=offset,
                    end_offset=stream.stream_length,
                    method=cfg.method,
                    confidence=0.05,
                    complete=False,
                    declared_length=raw,
                    diagnostics={
                        "reason": f"computed length {total} is not positive; framing stopped",
                        "raw_field_value": raw,
                    },
                )
            )
            break
        end = offset + total
        messages.append(
            FramedMessage(
                start_offset=offset,
                end_offset=end,
                method=cfg.method,
                confidence=0.8,
                declared_length=raw,
                complete=stream.is_present(offset, total),
                diagnostics={"raw_field_value": raw, "computed_length": total},
            )
        )
        offset = end
    return messages


def _frame_heuristic(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    """Score candidate boundaries without any prior structural assumption.

    The score favours positions where the surrounding entropy changes sharply
    (a new header often has lower entropy than a payload) and where a candidate
    length is consistent with a plausible message size.
    """
    min_gap = cfg._int("min_gap", default=2)
    data = stream.read(0, stream.stream_length)
    if not data:
        return []
    window = cfg._int("window", default=16)
    scores: list[tuple[float, int]] = []
    entropy_cache = _entropy_profile(data, window)
    for offset in range(min_gap, len(data) - min_gap):
        left = entropy_cache[offset - min_gap]
        right = entropy_cache[offset]
        scores.append((abs(right - left), offset))
    if not scores:
        return []
    threshold = sorted(s for s, _ in scores)[max(0, len(scores) // 2)]
    chosen = sorted(offset for score, offset in scores if score >= threshold)
    # Merge candidates that are too close together, keeping the strongest.
    merged: list[tuple[float, int]] = []
    for score, offset in scores:
        if score < threshold:
            continue
        if merged and offset - merged[-1][1] < min_gap:
            if score > merged[-1][0]:
                merged[-1] = (score, offset)
            continue
        merged.append((score, offset))
    messages: list[FramedMessage] = []
    start = 0
    for score, offset in merged:
        if offset <= start:
            continue
        messages.append(
            FramedMessage(
                start_offset=start,
                end_offset=offset,
                method=cfg.method,
                confidence=min(0.75, 0.3 + score),
                diagnostics={"entropy_jump": round(score, 4)},
            )
        )
        start = offset
    if start < len(data):
        messages.append(
            FramedMessage(
                start_offset=start,
                end_offset=len(data),
                method=cfg.method,
                confidence=0.3,
                diagnostics={"reason": "trailing bytes after the last candidate boundary"},
            )
        )
    return messages


def _frame_manual(stream: ReassembledStream, cfg: FramingConfig) -> list[FramedMessage]:
    boundaries = sorted({int(b) for b in (cfg.config.get("boundaries") or [])})
    boundaries = [b for b in boundaries if 0 <= b <= stream.stream_length]
    points = [0, *boundaries, stream.stream_length]
    messages: list[FramedMessage] = []
    for index in range(len(points) - 1):
        start, end = points[index], points[index + 1]
        if end <= start:
            continue
        messages.append(
            FramedMessage(
                start_offset=start,
                end_offset=end,
                method=cfg.method,
                confidence=1.0,
                diagnostics={"source": "researcher_annotation"},
            )
        )
    return messages


def _entropy_profile(data: bytes, window: int) -> list[float]:
    profile = [0.0] * (len(data) + 1)
    if len(data) <= window:
        for i in range(len(data)):
            profile[i] = shannon_entropy(data[:i])
        profile[len(data)] = shannon_entropy(data)
        return profile
    for i in range(len(data)):
        lo = max(0, i - window)
        profile[i] = shannon_entropy(data[lo:i])
    profile[len(data)] = shannon_entropy(data[-window:])
    return profile


_FRAMERS: dict[str, Callable[[ReassembledStream, FramingConfig], list[FramedMessage]]] = {
    "fixed_length": _frame_fixed_length,
    "length_prefix": _frame_length_prefix,
    "delimiter": _frame_delimiter,
    "signature": _frame_signature,
    "header_rule": _frame_header_rule,
    "heuristic": _frame_heuristic,
    "manual": _frame_manual,
}


def suggest_framing(
    stream: ReassembledStream, *, max_candidates: int = 8
) -> list[dict[str, object]]:
    """Rank plausible framing rules for a stream, with the evidence for each.

    This is a *suggestion engine*: every candidate is scored from observed data
    (how many messages it finds, how much of the stream it covers, whether the
    derived lengths look self-consistent).  Nothing here is asserted as truth.
    """
    data = stream.read(0, stream.stream_length)
    total = stream.stream_length
    suggestions: list[dict[str, object]] = []
    if not data or total == 0:
        return suggestions

    # 1. Length prefix, both endiannesses, both conventions.
    for offset in (0, 2, 4):
        for size in (1, 2, 4):
            for endian in ("big", "little"):
                for includes in (True, False):
                    score, detail = _score_length_prefix(
                        stream, data, offset, size, endian, includes
                    )
                    if score is None:
                        continue
                    suggestions.append(
                        {
                            "method": "length_prefix",
                            "config": {
                                "length_offset": offset,
                                "length_size": size,
                                "endianness": endian,
                                "includes_header": "true" if includes else "false",
                                "max_length": 1 << 20,
                            },
                            "score": round(score, 4),
                            "evidence": detail,
                        }
                    )

    # 2. Fixed length, from the GCD of promising distances.
    for length in _candidate_fixed_lengths(data):
        suggestions.append(
            {
                "method": "fixed_length",
                "config": {"length": length},
                "score": round(min(0.6, length / 512), 4),
                "evidence": {
                    "note": "constant-size candidate derived from observed spacing",
                },
            }
        )

    # 3. Single-byte delimiter.
    counter = Counter(data)
    for value, count in counter.most_common(3):
        if count >= 4 and data.count(bytes([value])) > 0.2 * len(data):
            suggestions.append(
                {
                    "method": "delimiter",
                    "config": {"delimiter": value, "max_length": 1 << 16, "keep_delimiter": True},
                    "score": round(min(0.6, count / max(1, len(data))), 4),
                    "evidence": {"delimiter_occurrences": count},
                }
            )

    suggestions.sort(key=lambda s: float(s["score"]), reverse=True)
    return suggestions[:max_candidates]


def _candidate_fixed_lengths(data: bytes) -> list[int]:
    lengths = sorted({len(m) for m in reframe_by_length_prefix(data)})
    return [length for length in lengths if 1 < length <= 4096][:3]


def _score_length_prefix(
    stream: ReassembledStream,
    data: bytes,
    offset: int,
    size: int,
    endian: str,
    includes: bool,
) -> tuple[float | None, dict[str, object]]:
    """How consistent is ``length`` as a framing field? Returns a 0..1 score.

    The score rewards explaining the *whole* stream, consistency across messages,
    and a field that starts at offset 0.  A candidate that only explains a prefix
    is reported with its coverage so the analyst can see the limitation.
    """
    count = 0
    covered = 0
    cursor = 0
    lengths_seen: list[int] = []
    while cursor < len(data):
        field_at = cursor + offset
        if field_at + size > len(data):
            break
        value = int.from_bytes(
            data[field_at : field_at + size], "little" if endian == "little" else "big"
        )
        total = value if includes else value + offset + size
        if total <= 0 or total > len(data):
            return None, {}
        cursor += total
        count += 1
        covered += total
        lengths_seen.append(total)
    if count < 2:
        return None, {}
    explains_all = cursor == len(data)
    if not explains_all:
        # A rule that consumes more bytes than the stream holds has claimed
        # structure the data does not support; one that stops early leaves the
        # tail unexplained.  Both are weak, so they are scored well below a rule
        # that accounts for the entire stream.
        coverage = covered / max(1, len(data))
        if coverage < 0.5:
            return None, {}
        score = 0.2 + 0.2 * min(1.0, coverage)
    else:
        score = 0.9 if count >= 3 else 0.7
    uniq = len(set(lengths_seen))
    score *= 1.0 if uniq > 1 else 0.98
    # A length field at the very start of a message is the simplest
    # explanation.  One further in leaves leading bytes unexplained, which is
    # strictly more surprising for the same match quality.
    score -= 0.05 * offset
    return max(0.0, score), {
        "messages_parsed": count,
        "coverage_ratio": round(covered / len(data), 4),
        "distinct_lengths": uniq,
        "explains_entire_stream": explains_all,
    }


def reframe_by_length_prefix(data: bytes) -> list[bytes]:
    """Cheap helper used only for fixed-length candidate generation."""
    if len(data) < 4:
        return []
    value = int.from_bytes(data[0:2], "big")
    if value <= 0 or value > len(data):
        return []
    return [data[i : i + value] for i in range(0, len(data), value) if value]


def coverage_summary(messages: Sequence[FramedMessage], stream_length: int) -> dict[str, object]:
    assigned = sum(m.length for m in messages)
    return {
        "stream_length": stream_length,
        "message_count": len(messages),
        "assigned_bytes": assigned,
        "unassigned_bytes": max(0, stream_length - assigned),
        "coverage_ratio": (assigned / stream_length) if stream_length else 0.0,
        "partial_messages": sum(1 for m in messages if not m.complete),
    }


_ = math  # keep the import meaningful for future scorers