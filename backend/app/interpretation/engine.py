"""Declarative protocol specifications and the engine that applies them.

A specification is *data*, never code.  It is parsed with Pydantic (strict
types, depth and length limits) and interpreted by a bounded evaluator with no
``eval``, no dynamic import and no filesystem/network access.  Constructs the
format does not support raise an explicit error rather than being skipped, so a
specification can never silently under-report what it did.

Supported field kinds
---------------------
``uint8|16|32|64``, ``int8|16|32|64`` (endianness selectable),
``bytes``, ``ascii``, ``float32``, ``float64``, ``enum`` (lookup table),
``unknown`` (explicit opaque span), ``if`` (conditional), ``repeat`` (a
length-delimited repeated group).

Supported framing
-----------------
``fixed_length``, ``length_prefix``, ``delimiter``, ``none`` (use externally
framed messages).
"""

from __future__ import annotations

import struct
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .. import prose

SPEC_SCHEMA_VERSION = "1.0"
ENGINE_VERSION = "interpretation-engine/1.2"

MAX_SPEC_BYTES = 256 * 1024
MAX_FIELDS = 256
MAX_NESTING_DEPTH = 4
MAX_REPEAT_ITEMS = 8192

FieldKind = Literal[
    "uint8", "uint16", "uint32", "uint64",
    "int8", "int16", "int32", "int64",
    "float32", "float64",
    "bytes", "ascii", "enum", "unknown",
    "if", "repeat",
]

_INT_FORMATS = {
    "uint8": (">B", "<B", 1),
    "uint16": (">H", "<H", 2),
    "uint32": (">I", "<I", 4),
    "uint64": (">Q", "<Q", 8),
    "int8": (">b", "<b", 1),
    "int16": (">h", "<h", 2),
    "int32": (">i", "<i", 4),
    "int64": (">q", "<q", 8),
    "float32": (">f", "<f", 4),
    "float64": (">d", "<d", 8),
}


class SpecError(ValueError):
    """Raised for an unsupported or invalid specification construct."""


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #


class StrictModel(BaseModel):
    # ``extra="forbid"`` is what stops an imported specification from smuggling
    # unrecognised keys past validation.  Whitespace stripping is deliberately
    # *not* enabled: a framing delimiter such as "\r\n" is legitimate data and
    # silently trimming it would change the protocol the analyst described.
    model_config = ConfigDict(extra="forbid")


class LengthField(StrictModel):
    offset: int = Field(ge=0, le=4096)
    size: Literal[1, 2, 4, 8]
    endianness: Literal["big", "little"] = "big"
    includes_header: bool = True
    multiplier: int = Field(default=1, ge=1, le=1_048_576)
    subtract: int = Field(default=0, ge=0, le=1_048_576)
    #: Bytes from the start of a message to its first payload byte.  ``None``
    #: means "the field ends where the body begins" (``offset + size``), which is
    #: the common layout; a protocol whose fixed header is wider than the length
    #: field states the real body start here.
    header_size: int | None = Field(default=None, ge=0, le=4096)


class FramingSpec(StrictModel):
    method: Literal["fixed_length", "length_prefix", "delimiter", "none"]
    length_field: LengthField | None = None
    fixed_length: int | None = Field(default=None, ge=1, le=1 << 30)
    delimiter: str | None = Field(default=None, max_length=16)
    include_delimiter: bool = True

    @model_validator(mode="after")
    def _check(self) -> "FramingSpec":
        if self.method == "length_prefix" and self.length_field is None:
            raise ValueError("framing.method='length_prefix' requires 'length_field'")
        if self.method == "fixed_length" and not self.fixed_length:
            raise ValueError("framing.method='fixed_length' requires 'fixed_length'")
        if self.method == "delimiter" and not self.delimiter:
            raise ValueError("framing.method='delimiter' requires 'delimiter'")
        if self.delimiter is not None:
            try:
                self.delimiter.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise ValueError("framing.delimiter must be latin-1 encodable") from exc
        return self


class Constraint(StrictModel):
    """A declarative, side-effect-free bound check on an extracted value."""

    kind: Literal["range", "enum", "constant"]
    minimum: float | None = None
    maximum: float | None = None
    values: list[Any] | None = Field(default=None, max_length=1024)
    value: Any | None = None
    description: str = Field(default="", max_length=512)


class FieldSpec(StrictModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    kind: FieldKind
    offset: int | None = Field(default=None, ge=0, le=1 << 20)
    size: int | None = Field(default=None, ge=1, le=1 << 24)
    endianness: Literal["big", "little"] = "big"
    semantic_status: Literal["observed", "hypothesis", "assumed", "unknown"] = "hypothesis"
    description: str = Field(default="", max_length=1024)
    values: dict[str, Any] | None = None
    constraint: Constraint | None = None
    optional: bool = False
    encoding: Literal["hex", "utf-8", "latin-1"] = "hex"
    # Conditional / repeated groups
    condition: "Condition | None" = None
    items: list["FieldSpec"] | None = Field(default=None, max_length=MAX_FIELDS)
    length_from: str | None = None
    count_from: str | None = None
    max_items: int | None = Field(default=None, ge=1, le=MAX_REPEAT_ITEMS)
    until_offset: int | None = Field(default=None, ge=0)

    @field_validator("size")
    @classmethod
    def _size_cap(cls, value: int | None) -> int | None:
        if value is not None and value > (1 << 24):
            raise ValueError("field size is too large")
        return value

    @model_validator(mode="after")
    def _check(self) -> "FieldSpec":
        if self.kind == "if" and self.condition is None:
            raise ValueError("a conditional field requires 'condition'")
        if self.kind == "repeat":
            if not self.items:
                raise ValueError("a repeated field requires a non-empty 'items' list")
            if self.length_from is None and self.count_from is None:
                raise ValueError(
                    "a repeated field requires 'length_from' or 'count_from' to bound it"
                )
        if self.kind == "repeat" and self.size is not None:
            raise ValueError("a repeated field must not declare a fixed 'size'")
        if self.kind != "repeat" and self.offset is None and self.kind != "if":
            raise ValueError(f"field {self.name!r} requires an explicit 'offset'")
        if self.kind == "enum" and not self.values:
            raise ValueError("an enum field requires a 'values' mapping")
        return self


class Condition(StrictModel):
    field: str = Field(min_length=1, max_length=128)
    operator: Literal["equals", "not_equals", "in", "exists", "greater_than", "less_than"]
    value: Any | None = None

    @model_validator(mode="after")
    def _check(self) -> "Condition":
        if self.operator in ("equals", "not_equals", "in", "greater_than", "less_than"):
            if self.value is None:
                raise ValueError(f"operator {self.operator!r} requires a 'value'")
        if self.operator == "in" and not isinstance(self.value, list):
            raise ValueError("operator 'in' requires a list value")
        return self


class MessageTypeRule(StrictModel):
    """Matches a message against a type discriminator and names the variant."""

    name: str = Field(min_length=1, max_length=128)
    when: Condition
    description: str = Field(default="", max_length=512)


class InterpretationSpec(StrictModel):
    schema_version: str = "1.0"
    protocol_name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4096)
    direction: Literal["a2b", "b2a", "both"] = "both"
    framing: FramingSpec
    fields: list[FieldSpec] = Field(default_factory=list, max_length=MAX_FIELDS)
    message_types: list[MessageTypeRule] = Field(default_factory=list, max_length=128)
    notes: str = Field(default="", max_length=4096)
    # Provenance metadata: accepted so a document produced by ``export_spec``
    # can be re-imported unchanged, but never used during interpretation.
    checksum: str | None = Field(default=None, max_length=64)
    engine_version: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _check(self) -> "InterpretationSpec":
        if self.schema_version != SPEC_SCHEMA_VERSION:
            raise SpecError(
                f"unsupported schema_version {self.schema_version!r}; "
                f"this build understands {SPEC_SCHEMA_VERSION!r}. Refusing to "
                "silently reinterpret an unknown format."
            )
        if not self.fields and self.framing.method != "none":
            raise ValueError("a specification with framing must declare at least one field")
        names = [f.name for f in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("duplicate field names are not allowed")
        _check_depth(self.fields, depth=1)
        # Every referenced field name must exist.
        known = set(names)
        for field_spec in self.fields:
            if field_spec.length_from and field_spec.length_from not in known:
                raise SpecError(
                    f"field {field_spec.name!r} references unknown length source "
                    f"{field_spec.length_from!r}"
                )
            if field_spec.count_from and field_spec.count_from not in known:
                raise SpecError(
                    f"field {field_spec.name!r} references unknown count source "
                    f"{field_spec.count_from!r}"
                )
            if field_spec.condition and field_spec.condition.field not in known:
                raise SpecError(
                    f"field {field_spec.name!r} condition references unknown field "
                    f"{field_spec.condition.field!r}"
                )
        for rule in self.message_types:
            if rule.when.field not in known:
                raise SpecError(
                    f"message type rule {rule.name!r} references unknown field "
                    f"{rule.when.field!r}"
                )
        return self

    def compute_checksum(self) -> str:
        import hashlib
        import json

        # Provenance metadata is excluded so the digest identifies the *protocol
        # description*, not the tool that happened to write it.  That keeps the
        # checksum stable across an export/import round trip.
        payload = self.model_dump(mode="json", exclude={"checksum", "engine_version"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def _check_depth(fields: Sequence[FieldSpec], depth: int) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise SpecError(
            f"field nesting exceeds the supported depth of {MAX_NESTING_DEPTH}"
        )
    for field_spec in fields:
        if field_spec.items:
            _check_depth(field_spec.items, depth + 1)


FieldSpec.model_rebuild()
Condition.model_rebuild()


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class ExtractionResult:
    __slots__ = ("fields", "unknown_ranges", "diagnostics", "consumed", "message_type")

    def __init__(self) -> None:
        self.fields: dict[str, Any] = {}
        self.unknown_ranges: list[dict[str, int]] = []
        self.diagnostics: list[dict[str, Any]] = []
        self.consumed = 0
        self.message_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": self.fields,
            "unknown_ranges": self.unknown_ranges,
            "diagnostics": self.diagnostics,
            "consumed": self.consumed,
            "message_type": self.message_type,
        }

    @property
    def ok(self) -> bool:
        return not any(d.get("severity") == "error" for d in self.diagnostics)


class InterpretationEngine:
    """Applies a validated :class:`InterpretationSpec` to raw message bytes."""

    def __init__(self, spec: InterpretationSpec) -> None:
        self.spec = spec

    # -- framing ---------------------------------------------------------- #

    def split_messages(self, data: bytes) -> tuple[list[tuple[int, int]], list[dict[str, Any]]]:
        """Return ``[(start, end), ...]`` plus any framing diagnostics."""
        framing = self.spec.framing
        diagnostics: list[dict[str, Any]] = []
        spans: list[tuple[int, int]] = []
        if framing.method == "none":
            spans.append((0, len(data)))
            return spans, diagnostics
        if framing.method == "fixed_length":
            length = framing.fixed_length or 0
            cursor = 0
            while cursor < len(data):
                end = min(cursor + length, len(data))
                spans.append((cursor, end))
                cursor = end
            return spans, diagnostics
        if framing.method == "delimiter":
            delimiter = (framing.delimiter or "").encode("latin-1")
            if not delimiter:
                raise SpecError("delimiter framing requires a delimiter")
            cursor = 0
            while cursor <= len(data):
                index = data.find(delimiter, cursor)
                if index < 0:
                    if cursor < len(data):
                        spans.append((cursor, len(data)))
                    break
                end = index + (len(delimiter) if framing.include_delimiter else 0)
                spans.append((cursor, end))
                cursor = index + len(delimiter)
            return spans, diagnostics

        lf = framing.length_field
        assert lf is not None  # validated in the schema
        cursor = 0
        guard = 0
        while cursor < len(data):
            guard += 1
            if guard > 1_000_000:  # pragma: no cover - runaway guard
                diagnostics.append(
                    {"severity": "error", "code": "framing_guard", "message": "framing aborted after 1e6 iterations"}
                )
                break
            field_at = cursor + lf.offset
            if field_at + lf.size > len(data):
                diagnostics.append(
                    {
                        "severity": "error",
                        "code": "truncated_length_field",
                        "message": (
                            f"length field at offset {field_at} extends past the end of the "
                            "available bytes; the final message is partial"
                        ),
                        "offset": field_at,
                    }
                )
                spans.append((cursor, len(data)))
                break
            raw = int.from_bytes(
                data[field_at : field_at + lf.size],
                "little" if lf.endianness == "little" else "big",
            )
            total = raw * lf.multiplier - lf.subtract
            if not lf.includes_header:
                header_size = lf.header_size if lf.header_size is not None else lf.offset + lf.size
                total += header_size
            if total <= 0:
                diagnostics.append(
                    {
                        "severity": "error",
                        "code": "invalid_length",
                        "message": (
                            f"declared length {raw} at offset {field_at} does not produce a "
                            "positive message size; framing stopped"
                        ),
                        "offset": field_at,
                        "declared": raw,
                    }
                )
                spans.append((cursor, len(data)))
                break
            end = cursor + total
            spans.append((cursor, min(end, len(data))))
            if end > len(data):
                # The rule says this message is longer than the bytes we hold.
                # Validating one framed message, that contradicts the rule's
                # framing convention rather than describing a capture gap.
                diagnostics.append(
                    {
                        "severity": "error",
                        "code": "declared_length_exceeds_message",
                        "message": (
                            f"the length field at offset {field_at} declares {total} bytes "
                            f"but the message holds only {len(data) - cursor}. This "
                            "framing convention does not hold for the message."
                        ),
                        "offset": field_at,
                        "declared": raw,
                        "computed": total,
                        "available": len(data) - cursor,
                    }
                )
                break
            cursor = end
        return spans, diagnostics

    # -- field extraction -------------------------------------------------- #

    def parse(self, data: bytes, *, base_offset: int = 0) -> ExtractionResult:
        result = ExtractionResult()
        try:
            self._parse_fields(self.spec.fields, data, 0, result, depth=0)
        except SpecError:
            raise
        except struct.error as exc:
            result.diagnostics.append(
                {"severity": "error", "code": "decode_failed", "message": str(exc)}
            )
        result.consumed = len(data)
        for rule in self.spec.message_types:
            if _condition_holds(rule.when, result.fields):
                result.message_type = rule.name
                break
        return result

    def _parse_fields(
        self,
        fields: Sequence[FieldSpec],
        data: bytes,
        base: int,
        result: ExtractionResult,
        *,
        depth: int,
    ) -> None:
        """Read ``fields`` from ``data`` starting at absolute offset ``base``.

        Field offsets are **absolute within their scope** (the message, or the
        enclosing repeat group).  They never accumulate, so a specification
        reads the same way whether or not an earlier field was present.
        """
        if depth > MAX_NESTING_DEPTH:
            raise SpecError(f"field nesting exceeds the supported depth of {MAX_NESTING_DEPTH}")
        for spec in fields:
            if spec.kind == "repeat":
                self._parse_repeat(spec, data, base, result, depth=depth)
                continue
            if spec.kind == "if":
                if spec.condition is None:
                    raise SpecError(f"conditional field {spec.name!r} has no condition")
                if not _condition_holds(spec.condition, result.fields):
                    result.fields.setdefault(spec.name, None)
                    continue
                self._parse_fields(spec.items or [], data, base, result, depth=depth + 1)
                continue
            if spec.offset is None:
                raise SpecError(f"field {spec.name!r} has no offset")
            value, _size = self._read_field(spec, data, base, result)
            if value is _MISSING:
                continue
            result.fields[spec.name] = value

    def _read_field(
        self, spec: FieldSpec, data: bytes, base: int, result: ExtractionResult
    ) -> tuple[Any, int]:
        offset = spec.offset or 0
        absolute = base + offset
        size = spec.size
        if spec.kind in _INT_FORMATS:
            size = size or _INT_FORMATS[spec.kind][2]
            if absolute + size > len(data):
                if spec.optional:
                    return _MISSING, 0
                result.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "field_out_of_bounds",
                        "message": (
                            f"field {spec.name!r} needs bytes [{absolute}, {absolute + size}) "
                            f"but only {len(data)} bytes are available"
                        ),
                        "offset": absolute,
                        "field": spec.name,
                    }
                )
                return _MISSING, 0
            fmt = _INT_FORMATS[spec.kind][0 if spec.endianness == "big" else 1]
            value = struct.unpack(fmt, data[absolute : absolute + size])[0]
            if spec.constraint:
                self._apply_constraint(spec, value, result)
            if spec.values and value not in spec.values:
                result.diagnostics.append(
                    {
                        "severity": "info",
                        "code": "unmapped_value",
                        "message": (
                            f"field {spec.name!r} took value {value}, which is not in the "
                            "declared value map"
                        ),
                        "field": spec.name,
                    }
                )
            return value, size
        if spec.kind == "enum":
            size = size or 1
            if absolute + size > len(data):
                if spec.optional:
                    return _MISSING, 0
                result.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "field_out_of_bounds",
                        "message": f"field {spec.name!r} extends past the end of the message",
                        "offset": absolute,
                        "field": spec.name,
                    }
                )
                return _MISSING, 0
            raw = data[absolute]
            label = (spec.values or {}).get(raw) or (spec.values or {}).get(str(raw))
            if label is None:
                result.diagnostics.append(
                    {
                        "severity": "info",
                        "code": "unmapped_value",
                        "message": (
                            f"enum field {spec.name!r} took value {raw}, which has no label in "
                            "the specification; the raw value is preserved"
                        ),
                        "field": spec.name,
                    }
                )
                label = None
            return {"raw": raw, "label": label}, size
        if spec.kind in ("bytes", "ascii", "unknown"):
            size = size or 1
            if absolute + size > len(data):
                if spec.optional:
                    return _MISSING, 0
                result.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "field_out_of_bounds",
                        "message": f"field {spec.name!r} extends past the end of the message",
                        "offset": absolute,
                        "field": spec.name,
                    }
                )
                return _MISSING, 0
            chunk = data[absolute : absolute + size]
            if spec.kind == "ascii":
                text = chunk.decode("utf-8", "replace")
                return text, size
            if spec.kind == "bytes":
                return chunk.hex(), size
            result.unknown_ranges.append({"start": absolute, "end": absolute + size})
            return None, size
        raise SpecError(f"field {spec.name!r} uses unsupported kind {spec.kind!r}")

    def _parse_repeat(
        self,
        spec: FieldSpec,
        data: bytes,
        base: int,
        result: ExtractionResult,
        *,
        depth: int,
    ) -> None:
        if spec.offset is None:
            raise SpecError(f"repeated field {spec.name!r} has no offset")
        group_start = base + spec.offset
        if spec.length_from:
            raw = result.fields.get(spec.length_from)
            if not isinstance(raw, int):
                raise SpecError(
                    f"repeated field {spec.name!r} needs an integer length from "
                    f"{spec.length_from!r}, which is not available"
                )
            group_end = group_start + raw
        else:
            raw_count = result.fields.get(spec.count_from)  # type: ignore[arg-type]
            if not isinstance(raw_count, int):
                raise SpecError(
                    f"repeated field {spec.name!r} needs an integer count from "
                    f"{spec.count_from!r}, which is not available"
                )
            if spec.items and spec.items[0].size:
                group_end = group_start + raw_count * spec.items[0].size
            else:
                group_end = min(group_start + raw_count, len(data))
        if group_end > len(data):
            result.diagnostics.append(
                {
                    "severity": "error",
                    "code": "repeat_out_of_bounds",
                    "message": (
                        f"repeated field {spec.name!r} declares a span ending at "
                        f"{group_end} but the message is only {len(data)} bytes"
                    ),
                    "field": spec.name,
                }
            )
            group_end = len(data)

        items: list[dict[str, Any]] = []
        inner = group_start
        while inner < group_end:
            if spec.max_items is not None and len(items) >= spec.max_items:
                break
            if len(items) > MAX_REPEAT_ITEMS:
                raise SpecError(
                    f"repeated field {spec.name!r} exceeded {MAX_REPEAT_ITEMS} items; "
                    "the declared bound is probably wrong"
                )
            sub = ExtractionResult()
            self._parse_fields(spec.items or [], data, inner, sub, depth=depth + 1)
            advanced = _advance(spec.items or [], inner)
            if advanced <= inner:
                raise SpecError(
                    f"repeated field {spec.name!r} made no progress; its items must consume bytes"
                )
            items.append(sub.fields)
            inner = advanced
        result.fields[spec.name] = items

    def _apply_constraint(self, spec: FieldSpec, value: Any, result: ExtractionResult) -> None:
        constraint = spec.constraint
        if constraint is None or not isinstance(value, (int, float)):
            return
        if constraint.kind == "range":
            if constraint.minimum is not None and value < constraint.minimum:
                result.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "constraint_violated",
                        "message": (
                            f"field {spec.name!r} = {value} is below the declared minimum "
                            f"{constraint.minimum}"
                        ),
                        "field": spec.name,
                    }
                )
            if constraint.maximum is not None and value > constraint.maximum:
                result.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "constraint_violated",
                        "message": (
                            f"field {spec.name!r} = {value} is above the declared maximum "
                            f"{constraint.maximum}"
                        ),
                        "field": spec.name,
                    }
                )
        elif constraint.kind == "enum":
            if constraint.values and value not in constraint.values:
                result.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "constraint_violated",
                        "message": f"field {spec.name!r} = {value} is not an allowed value",
                        "field": spec.name,
                    }
                )
        elif constraint.kind == "constant":
            if value != constraint.value:
                result.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "constraint_violated",
                        "message": (
                            f"field {spec.name!r} = {value} differs from the declared constant "
                            f"{constraint.value}"
                        ),
                        "field": spec.name,
                    }
                )


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<MISSING>"


_MISSING = _Missing()


def _advance(fields: Sequence[FieldSpec], start: int) -> int:
    """How far a set of fields reaches, relative to ``start``."""
    cursor = start
    for spec in fields:
        if spec.kind in ("repeat", "if"):
            continue
        if spec.offset is None:
            continue
        size = spec.size
        if size is None and spec.kind in _INT_FORMATS:
            size = _INT_FORMATS[spec.kind][2]
        if size is None:
            size = 1
        cursor = max(cursor, start + spec.offset + size)
    return cursor


def _condition_holds(condition: Condition, fields: dict[str, Any]) -> bool:
    present = condition.field in fields and fields[condition.field] is not None
    if condition.operator == "exists":
        return present
    if not present:
        return False
    value = fields[condition.field]
    if isinstance(value, dict):
        raw = value.get("raw")
    else:
        raw = value
    if condition.operator == "equals":
        return _matches(raw, condition.value)
    if condition.operator == "not_equals":
        return not _matches(raw, condition.value)
    if condition.operator == "in":
        allowed = condition.value or []
        return any(_matches(raw, candidate) for candidate in allowed)
    if condition.operator == "greater_than":
        try:
            return float(raw) > float(condition.value)
        except (TypeError, ValueError):
            return False
    if condition.operator == "less_than":
        try:
            return float(raw) < float(condition.value)
        except (TypeError, ValueError):
            return False
    return False  # pragma: no cover - the schema restricts operators


def _matches(raw: Any, expected: Any) -> bool:
    """Compare an extracted scalar against a declared expectation.

    ``{"raw": 1}`` is accepted as a shorthand so a specification can address an
    enum field by its underlying byte value without depending on the label.
    """
    if isinstance(expected, dict):
        if "raw" in expected:
            return raw == expected["raw"]
        if "label" in expected:
            return False  # the label is carried by the caller, not here
    return raw == expected


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #


def parse_spec(payload: dict[str, Any] | str | bytes) -> InterpretationSpec:
    """Validate an untrusted specification document.

    ``payload`` may arrive from an upload, a project archive or the database, so
    every failure is converted into an explicit :class:`SpecError` rather than a
    partially-applied specification.
    """
    if isinstance(payload, bytes):
        if len(payload) > MAX_SPEC_BYTES:
            raise SpecError("specification document is too large")
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SpecError("specification document is not valid UTF-8") from exc
    if isinstance(payload, str):
        import json

        if len(payload.encode("utf-8")) > MAX_SPEC_BYTES:
            raise SpecError("specification document is too large")
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SpecError(f"specification document is not valid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise SpecError("specification document must be a JSON object")
    try:
        return InterpretationSpec.model_validate(payload)
    except ValidationError as exc:
        raise SpecError(_format_validation_error(exc)) from exc


def _format_validation_error(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors()[:12]:
        location = ".".join(str(item) for item in error.get("loc", ()))
        parts.append(f"{location or '<root>'}: {error.get('msg', 'invalid')}")
    suffix = "" if len(exc.errors()) <= 12 else f" (+{len(exc.errors()) - 12} more)"
    return "; ".join(parts) + suffix


def spec_checksum(spec: InterpretationSpec) -> str:
    return spec.compute_checksum()


def export_spec(spec: InterpretationSpec) -> dict[str, Any]:
    """Machine-readable export, including the version that produced it.

    The dump is fully normalised (no ``None`` elision) so that re-importing an
    exported document and re-exporting it yields byte-identical JSON and the
    same checksum.  Reproducibility depends on that property.
    """
    return {
        "schema_version": spec.schema_version,
        "protocol_name": spec.protocol_name,
        "description": spec.description,
        "direction": spec.direction,
        "framing": spec.framing.model_dump(mode="json"),
        "fields": [f.model_dump(mode="json") for f in spec.fields],
        "message_types": [m.model_dump(mode="json") for m in spec.message_types],
        "notes": spec.notes,
        "checksum": spec.compute_checksum(),
        "engine_version": ENGINE_VERSION,
    }


def describe_support() -> dict[str, Any]:
    """What the format can and cannot express - surfaced in the UI and docs."""
    return {
        "engine_version": ENGINE_VERSION,
        "schema_version": SPEC_SCHEMA_VERSION,
        "supported_framing": ["fixed_length", "length_prefix", "delimiter", "none"],
        "supported_field_kinds": sorted(_INT_FORMATS) + ["bytes", "ascii", "enum", "unknown", "if", "repeat"],
        "limits": {
            "max_fields": MAX_FIELDS,
            "max_nesting_depth": MAX_NESTING_DEPTH,
            "max_repeat_items": MAX_REPEAT_ITEMS,
            "max_document_bytes": MAX_SPEC_BYTES,
        },
        "explicitly_unsupported": [
            prose.UNSUPPORTED_BIT_FIELDS,
            prose.UNSUPPORTED_COMPUTED_FIELDS,
            prose.UNSUPPORTED_VARIABLE_NUMERIC,
            prose.UNSUPPORTED_CHECKSUM,
            prose.UNSUPPORTED_CONDITIONAL_FRAMING,
        ],
        "safety": prose.SPEC_SAFETY,
    }