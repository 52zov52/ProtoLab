"""Structural diff between two captures.

Comparing by packet number is useless once the behaviour changes, so sessions
are matched on a *feature vector* (endpoints, direction, stream sizes, timing
shape and message-length profile) and then compared at the message level.

A difference from the baseline is reported as a difference, not as an anomaly:
"the capture changed" and "the change is suspicious" are separate claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

DIFF_VERSION = "capture-diff/1.1"


@dataclass
class SessionSignature:
    endpoint_a: str
    endpoint_b: str
    packets: int
    bytes_a_to_b: int
    bytes_b_to_a: int
    duration: float
    message_lengths_a_to_b: tuple[int, ...]
    message_lengths_b_to_a: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_a": self.endpoint_a,
            "endpoint_b": self.endpoint_b,
            "packets": self.packets,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "duration": round(self.duration, 6),
            "message_count_a_to_b": len(self.message_lengths_a_to_b),
            "message_count_b_to_a": len(self.message_lengths_b_to_a),
            "distinct_lengths_a_to_b": sorted(set(self.message_lengths_a_to_b)),
            "distinct_lengths_b_to_a": sorted(set(self.message_lengths_b_to_a)),
        }


@dataclass
class SessionMatch:
    base: SessionSignature | None
    compare: SessionSignature | None
    score: float
    reasons: list[str] = field(default_factory=list)
    base_id: str | None = None
    compare_id: str | None = None

    @property
    def status(self) -> str:
        if self.base is None:
            return "added"
        if self.compare is None:
            return "removed"
        return "changed" if self.score < 0.999 else "unchanged"


def match_sessions(
    base: Sequence[tuple[str, SessionSignature]],
    compare: Sequence[tuple[str, SessionSignature]],
    *,
    threshold: float = 0.55,
) -> list[SessionMatch]:
    """Greedy best-match pairing on a normalised similarity score."""
    scored: list[tuple[float, int, int]] = []
    for i, (_, a) in enumerate(base):
        for j, (_, b) in enumerate(compare):
            score = similarity(a, b)
            if score >= threshold:
                scored.append((score, i, j))
    scored.sort(key=lambda t: (-t[0], t[1], t[2]))

    used_a: set[int] = set()
    used_b: set[int] = set()
    matches: list[SessionMatch] = []
    for score, i, j in scored:
        if i in used_a or j in used_b:
            continue
        used_a.add(i)
        used_b.add(j)
        a_id, a = base[i]
        b_id, b = compare[j]
        matches.append(
            SessionMatch(
                base=a,
                compare=b,
                score=round(score, 4),
                reasons=_match_reasons(a, b),
                base_id=a_id,
                compare_id=b_id,
            )
        )
    for i, (session_id, signature) in enumerate(base):
        if i not in used_a:
            matches.append(SessionMatch(base=signature, compare=None, score=0.0, base_id=session_id))
    for j, (session_id, signature) in enumerate(compare):
        if j not in used_b:
            matches.append(
                SessionMatch(base=None, compare=signature, score=0.0, compare_id=session_id)
            )
    matches.sort(key=lambda m: (m.status, m.compare_id or m.base_id or ""))
    return matches


def _host(endpoint: str) -> str:
    return endpoint.rpartition(":")[0] or endpoint


def similarity(a: SessionSignature, b: SessionSignature) -> float:
    """Weighted similarity in 0..1.

    Matching on the exact 4-tuple is unreliable: two recordings of the same
    behaviour usually come from different ephemeral client ports.  The score is
    therefore split into a *hard* term (do these two hosts talk to each other at
    all?) and a *soft* term (does the exchange look the same?).  The hard term
    dominates, so unrelated sessions are never paired just because their byte
    counts resemble each other.
    """
    hosts_a = {_host(a.endpoint_a), _host(a.endpoint_b)}
    hosts_b = {_host(b.endpoint_a), _host(b.endpoint_b)}
    hard = 1.0 if hosts_a == hosts_b else 0.0

    if a.endpoint_a == b.endpoint_a and a.endpoint_b == b.endpoint_b:
        exact = 1.0
    elif {a.endpoint_a, a.endpoint_b} == {b.endpoint_a, b.endpoint_b}:
        exact = 0.95  # roles swapped
    else:
        exact = 0.0

    size_score = _ratio(a.bytes_a_to_b + a.bytes_b_to_a, b.bytes_a_to_b + b.bytes_b_to_a)
    shape_score = _length_profile_similarity(
        a.message_lengths_a_to_b + a.message_lengths_b_to_a,
        b.message_lengths_a_to_b + b.message_lengths_b_to_a,
    )
    packet_score = _ratio(a.packets, b.packets)
    soft = 0.4 * exact + 0.2 * size_score + 0.3 * shape_score + 0.1 * packet_score
    return round(0.55 * hard + 0.45 * soft, 4)


def _ratio(a: int, b: int) -> float:
    if a == b:
        return 1.0
    if a == 0 or b == 0:
        return 0.0
    return round(min(a, b) / max(a, b), 4)


def _length_profile_similarity(a: Sequence[int], b: Sequence[int]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    common = len(set(a) & set(b))
    return round(2 * common / (len(set(a)) + len(set(b))), 4)


def _match_reasons(a: SessionSignature, b: SessionSignature) -> list[str]:
    reasons: list[str] = []
    if a.endpoint_a == b.endpoint_a and a.endpoint_b == b.endpoint_b:
        reasons.append("endpoints match exactly")
    elif {a.endpoint_a, a.endpoint_b} == {b.endpoint_a, b.endpoint_b}:
        reasons.append("same endpoint pair with client/server roles swapped")
    if a.bytes_a_to_b != b.bytes_a_to_b:
        reasons.append(f"client->server bytes {a.bytes_a_to_b} vs {b.bytes_b_to_a}")
    if a.bytes_b_to_a != b.bytes_b_to_a:
        reasons.append(f"server->client bytes {a.bytes_b_to_a} vs {b.bytes_b_to_a}")
    la = set(a.message_lengths_a_to_b + a.message_lengths_b_to_a)
    lb = set(b.message_lengths_a_to_b + b.message_lengths_b_to_a)
    if la != lb:
        reasons.append(f"message length sets differ: only in base {sorted(la - lb)}, only in compare {sorted(lb - la)}")
    return reasons


@dataclass
class ByteDelta:
    base_offset: int
    compare_offset: int
    base_hex: str
    compare_hex: str
    changed_offsets: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_offset": self.base_offset,
            "compare_offset": self.compare_offset,
            "base_hex": self.base_hex,
            "compare_hex": self.compare_hex,
            "changed_offsets": self.changed_offsets,
            "changed_count": len(self.changed_offsets),
        }


def diff_bytes(base: bytes, compare: bytes, *, max_bytes: int) -> ByteDelta:
    limit = min(len(base), len(compare), max_bytes)
    changed = [i for i in range(limit) if base[i] != compare[i]]
    return ByteDelta(
        base_offset=0,
        compare_offset=0,
        base_hex=base[:max_bytes].hex(),
        compare_hex=compare[:max_bytes].hex(),
        changed_offsets=changed[:4096],
    )


def endpoint_delta(
    base_endpoints: set[str], compare_endpoints: set[str]
) -> dict[str, list[str]]:
    return {
        "added": sorted(compare_endpoints - base_endpoints),
        "removed": sorted(base_endpoints - compare_endpoints),
        "common": sorted(base_endpoints & compare_endpoints),
    }


def heatmap(
    base: Sequence[tuple[str, SessionSignature]],
    compare: Sequence[tuple[str, SessionSignature]],
) -> list[dict[str, Any]]:
    """Flatten session matches into a UI-ready heat map."""
    out: list[dict[str, Any]] = []
    for match in match_sessions(base, compare):
        row: dict[str, Any] = {
            "status": match.status,
            "similarity": match.score,
            "base_session_id": match.base_id,
            "compare_session_id": match.compare_id,
            "reasons": match.reasons,
            "endpoints": (
                match.compare.endpoint_a if match.compare else match.base.endpoint_a  # type: ignore[union-attr]
            ),
        }
        if match.base and match.compare:
            row["byte_delta"] = (
                (match.compare.bytes_a_to_b + match.compare.bytes_b_to_a)
                - (match.base.bytes_a_to_b + match.base.bytes_b_to_a)
            )
            row["packet_delta"] = match.compare.packets - match.base.packets
            row["message_type_changes"] = {
                "only_in_base": sorted(
                    set(match.base.message_lengths_a_to_b)
                    - set(match.compare.message_lengths_a_to_b)
                ),
                "only_in_compare": sorted(
                    set(match.compare.message_lengths_a_to_b)
                    - set(match.base.message_lengths_a_to_b)
                ),
            }
        out.append(row)
    return out


def format_report(matches: list[dict[str, Any]]) -> str:
    lines = ["Capture comparison heat map", "=" * 26]
    for row in matches:
        lines.append(
            f"[{row['status'].upper():9s}] similarity={row['similarity']:.2f} "
            f"{row['endpoints']}"
        )
        for reason in row["reasons"]:
            lines.append(f"    - {reason}")
    lines.append("")
    lines.append(
        "A difference from the baseline is not, by itself, an indication of "
        "anything suspicious."
    )
    return "\n".join(lines)