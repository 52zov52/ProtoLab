"""Byte-column classification for unknown binary protocols.

The classes describe the *shape* of a column (constant, counter, enum,
high_entropy, variable) and never the meaning of a field.  These tests pin the
boundaries so a rounded-off label cannot silently drift.
"""

from __future__ import annotations

from app.analyzers.byte_analysis import (
    COLUMN_CLASSES,
    classify_column,
    column_statistics,
)


def test_absent_when_the_offset_never_appears():
    name, rationale = classify_column(
        present_count=0,
        unique_values=0,
        entropy=0.0,
        change_rate=0.0,
        monotonic_ratio=0.0,
    )
    assert name == "absent"
    assert "not present" in rationale


def test_constant_column():
    stats = column_statistics([b"\x90\x00\x01" for _ in range(10)])
    assert [s.classification for s in stats] == ["constant", "constant", "constant"]
    assert "same value" in stats[0].classification_rationale


def test_counter_column_from_monotonic_bytes():
    stats = column_statistics([bytes([i & 0xFF]) for i in range(50)])
    column = stats[0]
    assert column.classification == "counter"
    assert column.monotonic_ratio >= 0.8
    assert "counter or running id" in column.classification_rationale


def test_small_enumeration_column():
    stats = column_statistics([bytes([value]) for value in [1, 2, 3, 4] * 10])
    assert stats[0].classification == "enum"
    assert "enumeration" in stats[0].classification_rationale


def test_high_entropy_column_never_claims_checksum():
    corpus = [bytes([(i * 73 + 11) % 256]) for i in range(200)]
    column = column_statistics(corpus)[0]
    assert column.classification == "high_entropy"
    assert column.entropy >= 6.5
    # A checksum, random, compressed and encrypted byte are indistinguishable
    # from this data, so none of those words may be asserted.
    assert "checksum" in column.classification_rationale
    assert "no single label" in column.classification_rationale


def test_variable_column_when_nothing_stronger_fits():
    corpus = [bytes([(i * 13) % 20]) for i in range(120)]
    column = column_statistics(corpus)[0]
    assert column.classification == "variable"
    assert column.unique_values > 16
    assert column.monotonic_ratio < 0.8


def test_every_classification_is_a_declared_class():
    corpora = [
        [b"\x01\x02"],
        [bytes([i & 0xFF]) for i in range(50)],
        [bytes([value]) for value in [1, 2, 3] * 10],
        [bytes([(i * 73) % 256]) for i in range(200)],
    ]
    for corpus in corpora:
        for stat in column_statistics(corpus):
            assert stat.classification in COLUMN_CLASSES


def test_rationale_and_classes_are_serialised():
    stat = column_statistics([b"\x01"])[0].to_dict()
    assert stat["classification"] == "constant"
    assert "classification_rationale" in stat
    assert "monotonic_ratio" in stat
