"""Interpretation engine tests: strict schema, bounded evaluator, counterexamples."""

from __future__ import annotations

import json

import pytest

from app.interpretation.engine import (
    InterpretationEngine,
    SpecError,
    describe_support,
    export_spec,
    parse_spec,
)


def length_prefixed_spec(**overrides) -> dict:
    payload = {
        "schema_version": "1.0",
        "protocol_name": "TestProtocol",
        "framing": {
            "method": "length_prefix",
            "length_field": {"offset": 0, "size": 2, "endianness": "big", "includes_header": True},
        },
        "fields": [
            {"name": "length", "kind": "uint16", "offset": 0, "size": 2, "endianness": "big",
             "semantic_status": "observed"},
            {"name": "message_type", "kind": "enum", "offset": 2, "size": 1,
             "values": {"1": "read", "2": "set", "3": "measure"}},
            {"name": "request_id", "kind": "uint16", "offset": 3, "size": 2, "endianness": "big"},
        ],
    }
    payload.update(overrides)
    return payload


def test_valid_specification_parses_and_reports_its_checksum():
    spec = parse_spec(length_prefixed_spec())
    assert spec.protocol_name == "TestProtocol"
    assert len(spec.compute_checksum()) == 64


def test_unknown_key_is_rejected_instead_of_ignored():
    with pytest.raises(SpecError) as exc:
        parse_spec(length_prefixed_spec(surprise=1))
    assert "surprise" in str(exc.value)


def test_unknown_schema_version_refuses_to_be_reinterpreted():
    with pytest.raises(SpecError) as exc:
        parse_spec(length_prefixed_spec(schema_version="99.0"))
    assert "Refusing to silently reinterpret" in str(exc.value)


def test_missing_required_field_is_rejected():
    with pytest.raises(SpecError):
        parse_spec(length_prefixed_spec(protocol_name=""))


def test_bad_field_name_pattern_is_rejected():
    payload = length_prefixed_spec()
    payload["fields"][0]["name"] = "not a valid name!"
    with pytest.raises(SpecError):
        parse_spec(payload)


def test_length_prefix_framing_splits_messages():
    spec = parse_spec(length_prefixed_spec())
    engine = InterpretationEngine(spec)
    data = b"\x00\x05\x01\x00\x01" + b"\x00\x05\x02\x00\x02"
    spans, diagnostics = engine.split_messages(data)
    assert spans == [(0, 5), (5, 10)]
    assert diagnostics == []


def test_fields_are_extracted_from_a_message():
    spec = parse_spec(length_prefixed_spec())
    engine = InterpretationEngine(spec)
    result = engine.parse(b"\x00\x05\x01\x00\x2a")
    assert result.fields["length"] == 5
    assert result.fields["message_type"] == {"raw": 1, "label": "read"}
    assert result.fields["request_id"] == 42
    assert result.ok


def test_truncated_length_field_produces_a_diagnostic_not_a_crash():
    spec = parse_spec(length_prefixed_spec())
    engine = InterpretationEngine(spec)
    spans, diagnostics = engine.split_messages(b"\x00")
    assert spans == [(0, 1)]
    assert diagnostics[0]["code"] == "truncated_length_field"


def test_invalid_length_stops_framing_with_an_explicit_error():
    spec = parse_spec(length_prefixed_spec())
    engine = InterpretationEngine(spec)
    spans, diagnostics = engine.split_messages(b"\x00\x00\x01\x00\x01")
    assert diagnostics[0]["code"] == "invalid_length"


def test_field_out_of_bounds_is_reported_as_an_error():
    spec = parse_spec(length_prefixed_spec())
    engine = InterpretationEngine(spec)
    result = engine.parse(b"\x00\x05\x01\x00")
    assert not result.ok
    codes = {d["code"] for d in result.diagnostics}
    assert "field_out_of_bounds" in codes


def test_constraint_violation_is_detected():
    payload = length_prefixed_spec()
    payload["fields"][2]["constraint"] = {"kind": "range", "minimum": 100}
    engine = InterpretationEngine(parse_spec(payload))
    result = engine.parse(b"\x00\x05\x01\x00\x2a")
    assert not result.ok
    assert any(d["code"] == "constraint_violated" for d in result.diagnostics)


def test_constraint_satisfied_yields_a_clean_result():
    payload = length_prefixed_spec()
    payload["fields"][2]["constraint"] = {"kind": "range", "minimum": 1, "maximum": 100}
    engine = InterpretationEngine(parse_spec(payload))
    result = engine.parse(b"\x00\x05\x01\x00\x2a")
    assert result.ok


def test_constant_constraint_detects_a_changed_field():
    payload = length_prefixed_spec()
    payload["fields"][2]["constraint"] = {"kind": "constant", "value": 7}
    engine = InterpretationEngine(parse_spec(payload))
    assert not engine.parse(b"\x00\x05\x01\x00\x09").ok


def test_conditional_field_is_only_read_when_the_condition_holds():
    payload = length_prefixed_spec()
    payload["fields"].append(
        {
            "name": "parameter_id",
            "kind": "uint16",
            "offset": 5,
            "size": 2,
            "kind_if": None,
        }
    )
    payload["fields"][-1].pop("kind_if")
    engine = InterpretationEngine(parse_spec(length_prefixed_spec()))
    result = engine.parse(b"\x00\x05\x01\x00\x2a")
    assert result.ok


def test_if_group_is_evaluated_against_the_condition():
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Conditional",
        "framing": {"method": "none"},
        "fields": [
            {"name": "op", "kind": "uint8", "offset": 0},
            {
                "name": "read_payload",
                "kind": "if",
                "condition": {"field": "op", "operator": "equals", "value": 1},
                "items": [{"name": "param_id", "kind": "uint16", "offset": 1}],
            },
        ],
    }
    engine = InterpretationEngine(parse_spec(payload))
    applied = engine.parse(b"\x01\x00\x07")
    assert applied.fields["param_id"] == 7
    skipped = engine.parse(b"\x02\x00\x07")
    assert skipped.fields.get("param_id") is None


def test_repeat_group_needs_an_explicit_bound():
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Repeat",
        "framing": {"method": "none"},
        "fields": [
            {"name": "count", "kind": "uint8", "offset": 0},
            {
                "name": "samples",
                "kind": "repeat",
                "offset": 1,
                "count_from": "count",
                "items": [{"name": "value", "kind": "uint8", "offset": 0}],
            },
        ],
    }
    engine = InterpretationEngine(parse_spec(payload))
    result = engine.parse(b"\x03\x0a\x0b\x0c")
    assert result.fields["samples"] == [{"value": 10}, {"value": 11}, {"value": 12}]


def test_repeat_group_without_a_bound_is_rejected():
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Repeat",
        "framing": {"method": "none"},
        "fields": [
            {
                "name": "samples",
                "kind": "repeat",
                "offset": 0,
                "items": [{"name": "value", "kind": "uint8", "offset": 0}],
            }
        ],
    }
    with pytest.raises(SpecError) as exc:
        parse_spec(payload)
    assert "bound" in str(exc.value)


def test_reference_to_an_unknown_field_is_rejected():
    payload = length_prefixed_spec()
    payload["fields"].append(
        {"name": "payload", "kind": "repeat", "offset": 5, "count_from": "does_not_exist",
         "items": [{"name": "v", "kind": "uint8", "offset": 0}]}
    )
    with pytest.raises(SpecError) as exc:
        parse_spec(payload)
    assert "does_not_exist" in str(exc.value)


def test_unsupported_field_kind_is_rejected_explicitly():
    payload = length_prefixed_spec()
    payload["fields"][0]["kind"] = "bitfield"
    with pytest.raises(SpecError):
        parse_spec(payload)


def test_excessive_nesting_is_rejected():
    inner = {"name": "leaf", "kind": "uint8", "offset": 0}
    spec_field = inner
    for _ in range(6):
        spec_field = {
            "name": "g",
            "kind": "repeat",
            "offset": 0,
            "count_from": "n",
            "items": [spec_field],
        }
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Deep",
        "framing": {"method": "none"},
        "fields": [{"name": "n", "kind": "uint8", "offset": 0}, spec_field],
    }
    with pytest.raises(SpecError) as exc:
        parse_spec(payload)
    assert "nesting" in str(exc.value)


def test_oversized_document_is_rejected():
    payload = length_prefixed_spec(notes="x" * 300_000)
    with pytest.raises(SpecError) as exc:
        parse_spec(json.dumps(payload))
    assert "too large" in str(exc.value)


def test_non_utf8_document_is_rejected():
    with pytest.raises(SpecError):
        parse_spec(b"\xff\xfe\x00")


def test_delimiter_framing():
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Delimited",
        "framing": {"method": "delimiter", "delimiter": "\r\n", "include_delimiter": True},
        "fields": [{"name": "value", "kind": "bytes", "offset": 0, "size": 3}],
    }
    engine = InterpretationEngine(parse_spec(payload))
    spans, _ = engine.split_messages(b"abc\r\ndef\r\n")
    assert spans == [(0, 5), (5, 10)]


def test_fixed_length_framing():
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Fixed",
        "framing": {"method": "fixed_length", "fixed_length": 4},
        "fields": [{"name": "value", "kind": "uint32", "offset": 0}],
    }
    engine = InterpretationEngine(parse_spec(payload))
    spans, _ = engine.split_messages(b"aaaabbbbcccc")
    assert spans == [(0, 4), (4, 8), (8, 12)]


def test_message_type_rules_are_applied():
    payload = length_prefixed_spec()
    payload["message_types"] = [
        {"name": "read_request", "when": {"field": "message_type", "operator": "equals", "value": {"raw": 1}}}
    ]
    engine = InterpretationEngine(parse_spec(payload))
    assert engine.parse(b"\x00\x05\x01\x00\x01").message_type == "read_request"
    assert engine.parse(b"\x00\x05\x03\x00\x01").message_type is None


def test_unknown_ranges_are_recorded():
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Opaque",
        "framing": {"method": "none"},
        "fields": [{"name": "opaque", "kind": "unknown", "offset": 2, "size": 3}],
    }
    engine = InterpretationEngine(parse_spec(payload))
    result = engine.parse(b"\x00\x00\xaa\xbb\xcc")
    assert result.unknown_ranges == [{"start": 2, "end": 5}]


def test_endianness_is_respected():
    payload = {
        "schema_version": "1.0",
        "protocol_name": "Endian",
        "framing": {"method": "none"},
        "fields": [
            {"name": "be", "kind": "uint16", "offset": 0, "endianness": "big"},
            {"name": "le", "kind": "uint16", "offset": 0, "endianness": "little"},
        ],
    }
    engine = InterpretationEngine(parse_spec(payload))
    fields = engine.parse(b"\x01\x02").fields
    assert fields["be"] == 0x0102
    assert fields["le"] == 0x0201


def test_export_is_machine_readable_and_round_trips():
    spec = parse_spec(length_prefixed_spec())
    exported = export_spec(spec)
    assert exported["checksum"] == spec.compute_checksum()
    assert exported["engine_version"]
    reparsed = parse_spec(json.loads(json.dumps(exported)))
    assert reparsed.compute_checksum() == spec.compute_checksum()


def test_describe_support_lists_limits_and_gaps():
    support = describe_support()
    assert "checksum verification" in " ".join(support["explicitly_unsupported"])
    assert support["limits"]["max_fields"] > 0
    assert "ever imported" in support["safety"]


def test_no_execution_primitives_are_reachable_from_a_specification():
    payload = length_prefixed_spec()
    payload["notes"] = "__import__('os').system('whoami')"
    spec = parse_spec(payload)
    engine = InterpretationEngine(spec)
    # The string is inert data; nothing executes it.
    result = engine.parse(b"\x00\x05\x01\x00\x01")
    assert result.fields["request_id"] == 1