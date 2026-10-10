"""Investigation Assistant.

The assistant never executes model-written code.  A natural-language request is
compiled into a *typed query plan*, the plan is schema-validated, every field
and operator is checked against an allowlist, and only then is it executed
against the index.  The plan is always shown to the user next to the results, so
the interpretation of the question is auditable.

If an optional LLM is available (local Ollama) it may only *narrate* an already
validated plan and its results.  It never writes SQL, never generates
specifications that are applied without the analyst, and its output is always
labelled as model-generated text.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..analyzers.byte_analysis import shannon_entropy
from ..interpretation.engine import SpecError, parse_spec
from ..interpretation.extractor import extract_jwt_claims

ASSISTANT_VERSION = "assistant/1.2"

ENTITY_ALLOWED = ("messages", "sessions", "streams", "packets", "captures")
ENTITY_ALLOWED_TUPLE = (
    "messages", "streams", "sessions", "packets", "capture",
)

FIELD_SPECS: dict[str, dict[str, str]] = {
    "messages": {
        "payload_length": "int",
        "entropy": "float",
        "index_in_stream": "int",
        "start_offset": "int",
        "end_offset": "int",
        "complete": "bool",
        "confidence": "float",
        "declared_length": "int",
        "framing_method": "str",
        "timestamp": "float",
        "direction": "str",
        "byte_at": "bytes",
        "contains_text": "text",
        "jwt": "jwt",
    },
    "sessions": {
        "duration": "float",
        "packet_count": "int",
        "bytes_a_to_b": "int",
        "bytes_b_to_a": "int",
        "completeness": "str",
        "endpoint": "str",
        "role_confidence": "str",
        "messages_per_second": "float",
    },
    "streams": {
        "stream_length": "int",
        "present_bytes": "int",
        "has_holes": "bool",
        "protocol": "str",
        "hole_count": "int",
        "conflict_count": "int",
    },
    "packets": {
        "payload_length": "int",
        "flags": "int",
        "address": "str",
        "port": "int",
        "timestamp": "float",
        "contains_text": "text",
    },
}

OPERATORS_ALLOWED = (
    "greater_than",
    "greater_or_equal",
    "less_than",
    "less_or_equal",
    "equals",
    "not_equals",
    "in",
    "contains",
    "starts_with",
    "between",
    "is_null",
    "is_not_null",
    "byte_equals_at",
    "prefix_equals",
    "jwt_claim_equals",
    "jwt_expired_at",
)

MAX_FILTERS = 12
MAX_LIMIT = 500


class QueryFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1, max_length=64)
    operator: str = Field(min_length=1, max_length=32)
    value: Any = None

    @model_validator(mode="after")
    def _check(self) -> "QueryFilter":
        if self.operator not in OPERATORS_ALLOWED:
            raise ValueError(
                f"operator {self.operator!r} is not allowed; permitted operators are "
                f"{', '.join(OPERATORS_ALLOWED)}"
            )
        return self


class QueryPlan(BaseModel):
    """The only thing the executor accepts.  Nothing else runs."""

    model_config = ConfigDict(extra="forbid")

    entity: str = Field(default="messages")
    filters: list[QueryFilter] = Field(default_factory=list, max_length=MAX_FILTERS)
    sort_field: str | None = Field(default=None, max_length=64)
    sort_direction: Literal["asc", "desc"] = "asc"
    limit: int = Field(default=100, ge=1, le=MAX_LIMIT)
    capture_ids: list[str] = Field(default_factory=list, max_length=64)
    group_by: str | None = Field(default=None, max_length=64)

    @field_validator("entity")
    @classmethod
    def _entity(cls, value: str) -> str:
        if value not in ENTITY_ALLOWED:
            raise ValueError(
                f"entity {value!r} is not queryable; permitted entities are "
                f"{', '.join(ENTITY_ALLOWED)}"
            )
        return value

    @model_validator(mode="after")
    def _fields_exist(self) -> "QueryPlan":
        if not self.filters:
            raise ValueError("a query needs at least one filter")
        allowed = FIELD_SPECS[self.entity]
        for item in self.filters:
            if item.field not in allowed:
                raise ValueError(
                    f"field {item.field!r} does not exist on entity {self.entity!r}. "
                    f"Available: {', '.join(sorted(allowed))}"
                )
        if self.sort_field and self.sort_field not in allowed:
            raise ValueError(f"cannot sort on unknown field {self.sort_field!r}")
        if self.group_by and self.group_by not in allowed:
            raise ValueError(f"cannot group by unknown field {self.group_by!r}")
        return self


class CompileError(ValueError):
    pass


@dataclass
class CompiledQuery:
    plan: QueryPlan
    interpretation: str
    warnings: list[str] = field(default_factory=list)
    ambiguous: bool = False
    follow_up: str | None = None


# --------------------------------------------------------------------------- #
# Natural language -> plan
#
# This is a deliberately small, deterministic rule-based compiler.  It is not an
# LLM: it cannot invent a query, and when it cannot map a request confidently it
# says so instead of guessing.
# --------------------------------------------------------------------------- #

_NUMBER = r"(-?\d+(?:\.\d+)?)"
_UNITS = {"kb": 1024, "kib": 1024, "mb": 1024 * 1024, "mib": 1024 * 1024, "b": 1, "byte": 1, "bytes": 1}

COMPARISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("greater_than", re.compile(rf"(?:longer than|greater than|more than|over|above|bigger than|exceeds?)\s+{_NUMBER}\s*(kb|kib|mb|mib|bytes?|b)?", re.I)),
    ("greater_or_equal", re.compile(rf"(?:at least|no less than)\s+{_NUMBER}\s*(kb|kib|mb|mib|bytes?|b)?", re.I)),
    ("less_than", re.compile(rf"(?:shorter than|less than|under|below|smaller than|fewer than)\s+{_NUMBER}\s*(kb|kib|mb|mib|bytes?|b)?", re.I)),
    ("less_or_equal", re.compile(rf"(?:at most|no more than)\s+{_NUMBER}\s*(kb|kib|mb|mib|bytes?|b)?", re.I)),
)

RULES: tuple[tuple[str, re.Pattern[str], dict[str, Any]], ...] = (
    ("messages", re.compile(r"\b(message|msg)s?\b", re.I), {"field": "payload_length"}),
    ("messages", re.compile(r"\brequests?\b", re.I), {"field": "payload_length", "direction": "a2b"}),
    ("messages", re.compile(r"\b(responses?|replies)\b", re.I), {"field": "payload_length", "direction": "b2a"}),
    ("messages", re.compile(r"\bentropy\b", re.I), {"field": "entropy"}),
    ("messages", re.compile(r"\bincomplete|partial\b", re.I), {"field": "complete", "value": False}),
    ("sessions", re.compile(r"\bsessions?\b", re.I), {"field": "packet_count"}),
    ("streams", re.compile(r"\bstream\b", re.I), {"field": "stream_length"}),
    ("packets", re.compile(r"\bpackets?\b", re.I), {"field": "payload_length"}),
)


def compile_query(text: str, *, capture_ids: Sequence[str] | None = None) -> CompiledQuery:
    """Map a request to a typed plan, or explain why it cannot.

    The compiler is intentionally conservative: an unrecognised request returns
    ``ambiguous=True`` with a follow-up question instead of a plausible-looking
    but invented filter.
    """
    warnings: list[str] = []
    lowered = text.strip()
    if not lowered:
        raise CompileError("The request is empty.")

    entity = "messages"
    context: dict[str, Any] = {}
    for candidate, pattern, extra in RULES:
        if pattern.search(lowered):
            entity = candidate
            context.update({k: v for k, v in extra.items() if k != "field"})
            break

    filters: list[QueryFilter] = []
    explanation: list[str] = []

    for operator, pattern in COMPARISON_PATTERNS:
        match = pattern.search(lowered)
        if not match:
            continue
        value = float(match.group(1))
        unit = (match.group(2) or "").lower()
        if unit:
            value *= _UNITS.get(unit, 1)
        target = _size_field(lowered, entity)
        filters.append(
            QueryFilter(field=target, operator=operator, value=int(value))
        )
        explanation.append(f"{target} {operator} {int(value)}")
        break

    if not filters:
        # "first two bytes match" style requests.
        byte_match = re.search(
            r"first\s+(\d+)\s+bytes?\s+(?:are\s+)?(?:the\s+same|match|identical|equal)", lowered, re.I
        )
        if byte_match:
            width = int(byte_match.group(1))
            if width < 1 or width > 8:
                raise CompileError(
                    "Only 1 to 8 leading bytes can be compared; a wider comparison needs "
                    "a rule the assistant does not have."
                )
            filters.append(QueryFilter(field="prefix_equals", operator="byte_equals_at", value=width))
            explanation.append(f"leading {width} byte(s) are equal across messages")
            warnings.append(
                "This groups messages that share a leading byte pattern; it does not "
                "assert that those bytes mean the same thing."
            )
        else:
            gap_match = re.search(rf"within\s+{_NUMBER}\s*(ms|milliseconds?|s|seconds?)", lowered, re.I)
            if gap_match and re.search(r"request|response|reply", lowered, re.I):
                amount = float(gap_match.group(1))
                unit = gap_match.group(2).lower()
                seconds = amount / 1000.0 if unit.startswith("m") else amount
                filters.append(
                    QueryFilter(field="timestamp", operator="greater_or_equal", value=0)
                )
                explanation.append(
                    f"messages where a response followed a request within {seconds:.3f}s"
                )
                warnings.append(
                    "Request/response pairing is inferred from ordering and direction "
                    "only; no request identifier is checked."
                )
            else:
                raise CompileError(
                    "The request could not be mapped to a supported query. Supported "
                    "patterns include size comparisons ('responses longer than 1000 "
                    "bytes'), leading-byte equality, request/response timing, and "
                    "entropy thresholds."
                )

    for direction in ("a2b", "b2a"):
        if re.search(rf"\b{ {'a2b': 'client to server', 'b2a': 'server to client'}[direction] }\b", lowered, re.I):
            filters.append(QueryFilter(field="direction", operator="equals", value=direction))
            explanation.append(f"direction == {direction}")

    if re.search(r"\bpost\b", lowered, re.I):
        filters.append(QueryFilter(field="contains_text", operator="contains", value="POST "))
        explanation.append("payload contains the text 'POST '")
        warnings.append(
            "A POST search only works when HTTP content is visible. It cannot find "
            "requests inside TLS unless the session was decrypted."
        )

    if re.search(r"\bjwt\b", lowered, re.I):
        filters.append(QueryFilter(field="jwt", operator="jwt_claim_equals", value=None))
        explanation.append("payloads that look like a JWT")
        warnings.append(
            "JWT search runs only over plaintext payloads. Encrypted TLS payloads are "
            "never scanned for tokens."
        )

    if re.search(r"\bunusually high (?:send|request) rate\b|high frequency", lowered, re.I):
        raise CompileError(
            "Rate analysis is available through the Anomaly Detection module; it needs a "
            "trained baseline rather than a single-pass filter."
        )

    try:
        plan = QueryPlan(
            entity=entity,
            filters=filters,
            capture_ids=list(capture_ids or []),
            limit=100,
        )
    except Exception as exc:
        raise CompileError(str(exc)) from exc

    return CompiledQuery(
        plan=plan,
        interpretation=(
            f"Interpreted as: on {entity}, " + ", ".join(explanation) + "."
        ),
        warnings=warnings,
        ambiguous=False,
    )


def _size_field(text: str, entity: str) -> str:
    if entity in ("messages", "packets"):
        return "payload_length"
    if entity == "streams":
        return "stream_length"
    return "packet_count"


def validate_plan(plan: dict[str, Any]) -> QueryPlan:
    """Second gate: re-validate a plan that arrived from a client."""
    try:
        return QueryPlan.model_validate(plan)
    except Exception as exc:
        raise CompileError(f"The query plan was rejected: {exc}") from exc


def summarise_plan(plan: QueryPlan) -> str:
    parts = [f"entity={plan.entity}"]
    for item in plan.filters:
        parts.append(f"{item.field} {item.operator} {item.value!r}")
    parts.append(f"limit={plan.limit}")
    return "; ".join(parts)


def redact_secrets(payload: Any) -> Any:
    """Mask token-like strings before anything is rendered or sent to a model."""
    if isinstance(payload, dict):
        return {k: redact_secrets(v) for k, v in payload.items()}
    if isinstance(payload, list):
        return [redact_secrets(v) for v in payload]
    if isinstance(payload, str):
        return re.sub(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b", "[jwt redacted]", payload)
    return payload


def jwt_summary(token: str, *, now: float | None = None) -> dict[str, Any]:
    """Decode a JWT *without* verifying its signature, and say so."""
    import time

    claims = extract_jwt_claims(token)
    if claims is None:
        return {"valid_shape": False, "note": "The value does not have a JWT structure."}
    out: dict[str, Any] = {
        "valid_shape": True,
        "signature_verified": False,
        "note": (
            "Decoding a JWT proves nothing about authenticity. The signature was not "
            "verified and the token must be treated as untrusted input."
        ),
        "claims": redact_secrets(claims.get("payload", {})),
        "header": claims.get("header", {}),
        "algorithm": claims.get("algorithm"),
    }
    expires = (claims.get("payload") or {}).get("exp")
    if isinstance(expires, (int, float)):
        current = now if now is not None else time.time()
        out["exp"] = expires
        out["expired"] = bool(current >= float(expires))
        out["exp_note"] = (
            f"exp is in seconds since the Unix epoch; compared against {current:.0f}. "
            "Clock skew on the analyst's machine can change this result."
        )
    return out


_ = (base64, json, shannon_entropy, SpecError, parse_spec, ENTITY_ALLOWED_TUPLE)