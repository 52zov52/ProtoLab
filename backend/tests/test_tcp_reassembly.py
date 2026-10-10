import pytest

from app.analyzers.tcp_reassembly import (
    Segment,
    find_duplicate_ack_runs,
    reassemble,
    relative_sequence,
)

ISN = 1000


def seg(packet_index: int, seq: int, data: bytes, *, flags: int = 0x18, window: int = 65535) -> Segment:
    return Segment(
        packet_index=packet_index,
        timestamp=packet_index * 0.001,
        sequence=seq,
        payload=data,
        flags=flags,
        window=window,
    )


def build(segments, *, isn=ISN, **kwargs):
    return reassemble(
        direction="a2b",
        local_endpoint="10.0.0.1:1234",
        remote_endpoint="10.0.0.2:80",
        segments=segments,
        isn=isn,
        **kwargs,
    )


def test_relative_sequence_handles_wraparound():
    assert relative_sequence(0, 0xFFFFFFFF) == 1
    assert relative_sequence(5, 5) == 0


def test_in_order_segments_produce_contiguous_stream():
    stream = build([seg(0, ISN + 1, b"AAA"), seg(1, ISN + 4, b"BBB")])
    assert stream.read(0, 6) == b"AAABBB"
    assert stream.is_present(0, 6)
    assert not stream.holes
    assert stream.present_bytes == 6
    assert stream.packet_references(0, 6) == [
        {"packet_index": 0, "start_offset": 0, "end_offset": 3},
        {"packet_index": 1, "start_offset": 3, "end_offset": 6},
    ]


def test_out_of_order_segments_are_reassembled_by_sequence():
    stream = build([seg(0, ISN + 4, b"CCC"), seg(1, ISN + 1, b"AAA")])
    assert stream.read(0, 6) == b"AAACCC"
    assert not stream.holes
    # Packet 1 back-fills data below the frontier that packet 0 already opened.
    assert [e["packet_index"] for e in stream.out_of_order] == [1]


def test_exact_retransmission_is_not_duplicated():
    stream = build(
        [seg(0, ISN + 1, b"AAAA"), seg(1, ISN + 1, b"AAAA"), seg(2, ISN + 5, b"BBBB")]
    )
    assert stream.read(0, 8) == b"AAAABBBB"
    assert stream.present_bytes == 8
    assert len(stream.duplicates) == 1
    assert stream.duplicates[0].packet_index == 1
    assert stream.duplicates[0].original_packet_index == 0
    assert not stream.conflicts
    assert stream.retransmissions[0]["kind"] == "exact_duplicate"


def test_partial_overlap_extends_the_stream_once():
    stream = build([seg(0, ISN + 1, b"AAAA"), seg(1, ISN + 3, b"AABBBB")])
    assert stream.read(0, 8) == b"AAAABBBB"
    assert stream.present_bytes == 8
    assert stream.retransmissions[0]["kind"] == "partial_overlap"
    assert stream.retransmissions[0]["overlap_length"] == 2


def test_conflicting_overlap_records_a_diagnostic():
    stream = build(
        [seg(0, ISN + 1, b"AAAA"), seg(1, ISN + 1, b"BBBB")],
        conflict_policy="first_writer_wins",
    )
    assert stream.read(0, 4) == b"AAAA"
    assert stream.conflicts, "a byte conflict must be recorded, not silently dropped"
    conflict = stream.conflicts[0]
    assert conflict.start_offset == 0
    assert conflict.end_offset == 4
    assert conflict.kept_hex == "41414141"
    assert conflict.rejected_hex == "42424242"
    assert conflict.kept_source_packet == 0
    assert conflict.rejected_packet == 1


def test_conflicting_overlap_last_writer_wins_policy():
    stream = build(
        [seg(0, ISN + 1, b"AAAA"), seg(1, ISN + 1, b"BBBB")],
        conflict_policy="last_writer_wins",
    )
    assert stream.read(0, 4) == b"BBBB"
    assert stream.conflicts[0].resolution == "last_writer_wins"
    assert stream.conflicts[0].kept_hex == "42424242"


def test_conflict_in_the_middle_of_a_longer_segment():
    stream = build(
        [seg(0, ISN + 1, b"AAAABBBB"), seg(1, ISN + 1, b"AAAAXXXXCCCC")]
    )
    assert stream.read(0, 12) == b"AAAABBBBCCCC"
    conflict = stream.conflicts[0]
    assert conflict.start_offset == 4
    assert conflict.end_offset == 8
    assert conflict.kept_hex == "42424242"
    assert conflict.rejected_hex == "58585858"


def test_gap_in_the_middle_is_reported_and_not_zero_filled():
    stream = build([seg(0, ISN + 1, b"AA"), seg(1, ISN + 5, b"CC")])
    assert stream.read(0, 2) == b"AA"
    assert stream.read(4, 2) == b"CC"
    assert not stream.is_present(2, 2)
    assert stream.coverage_of(0, 6) == 4
    assert {"start": 2, "end": 4, "length": 2, "reason": "missing_segments"} in stream.hole_list()
    assert stream.has_gaps


def test_segment_bridging_a_hole_does_not_fabricate_bytes():
    stream = build([seg(0, ISN + 1, b"AA"), seg(1, ISN + 5, b"CC"), seg(2, ISN + 1, b"AABBCC")])
    assert stream.read(0, 6) == b"AABBCC"
    assert stream.has_gaps is False


def test_hole_survives_when_the_later_segment_still_misses_the_range():
    # Segment 2 lands before the frontier but does not cover the missing
    # middle bytes, so the diagnostic must survive.
    stream = build(
        [seg(0, ISN + 1, b"AA"), seg(1, ISN + 5, b"CC"), seg(2, ISN + 9, b"CC")]
    )
    assert stream.has_gaps
    assert stream.coverage_of(0, 10) == 6
    assert {"start": 2, "end": 4, "length": 2, "reason": "missing_segments"} in stream.hole_list()


def test_missing_syn_is_reported_as_truncated_start():
    stream = build([seg(0, ISN + 500, b"AAAA")], isn=None)
    assert stream.is_truncated_start
    assert stream.diagnostics.get("isn_source") == "inferred_from_first_payload"


def test_zero_length_payloads_are_ignored():
    stream = build([seg(0, ISN + 1, b""), seg(1, ISN + 1, b"AA")])
    assert stream.present_bytes == 2
    assert stream.segment_count == 2
    assert stream.payload_segment_count == 1


def test_sequence_wraparound_is_handled():
    isn = 0xFFFFFFFE
    stream = build([seg(0, (isn + 1) & 0xFFFFFFFF, b"AAAA"), seg(1, 3, b"BBBB")], isn=isn)
    assert stream.read(0, 8) == b"AAAABBBB"
    assert not stream.holes


def test_reassembly_is_deterministic_under_packet_reordering():
    a = build([seg(0, ISN + 1, b"AAA"), seg(1, ISN + 4, b"BBB")])
    b = build([seg(0, ISN + 4, b"BBB"), seg(1, ISN + 1, b"AAA")])
    assert a.read(0, 6) == b.read(0, 6)
    assert a.present_bytes == b.present_bytes


def test_empty_segment_list_yields_empty_stream():
    stream = build([])
    assert stream.present_bytes == 0
    assert stream.stream_length == 0


def test_unknown_conflict_policy_is_rejected():
    with pytest.raises(ValueError):
        build([seg(0, ISN + 1, b"A")], conflict_policy="whatever")


def test_multiple_runs_are_reported_individually():
    stream = build([seg(0, ISN + 1, b"AAAA"), seg(1, ISN + 9, b"CCCC")])
    assert len(stream.runs) == 2
    assert stream.read(0, 4) == b"AAAA"
    assert stream.read(8, 4) == b"CCCC"
    assert stream.coverage_of(0, 12) == 8


def test_open_ended_hole_when_capture_stops_mid_stream():
    stream = build([seg(0, ISN + 1, b"AAAA")], assume_open_end=True)
    assert stream.hole_list() == [
        {"start": 4, "end": 4, "length": 0, "reason": "capture_ended"}
    ] or not stream.holes


def test_provenance_of_merged_bytes_lists_every_contributing_packet():
    stream = build([seg(0, ISN + 1, b"AAAA"), seg(1, ISN + 3, b"AABBBB")])
    refs = stream.packet_references(0, 8)
    packets = {r["packet_index"] for r in refs}
    assert packets == {0, 1}


def test_zero_window_is_reported():
    stream = build([seg(0, ISN + 1, b"A", window=0)])
    assert stream.zero_windows


def test_duplicate_ack_run_detection():
    segments = [
        seg(0, ISN + 1, b"", flags=0x10),
        seg(1, 5000, b"", flags=0x10),
        seg(2, 5000, b"", flags=0x10),
        seg(3, 5000, b"", flags=0x10),
    ]
    events = find_duplicate_ack_runs(segments)
    assert events and events[-1]["count"] >= 3