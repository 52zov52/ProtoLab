"""Regression tests for the bugs fixed on the way to the current baseline.

Each test pins a concrete failure that a plausible-looking implementation gets
wrong.  They are deliberately narrow: one property per bug, phrased as the
behaviour the product promises rather than as a snapshot of the current code.

* **Link-layer padding** — a short frame is padded to the 60-byte Ethernet
  minimum; the padding must not become protocol bytes.  When the network header
  is unusable (segmentation offload), the padding cannot be told apart from
  payload and the decoder says so instead of guessing.
* **Segment before the base** — a sequence number in the upper half of the
  32-bit space means "before the inferred ISN"; it is reported and excluded, not
  turned into a ~4 GiB hole.
* **Delimiter search across a hole** — the first delimiter at or after an offset
  must be found even when the search starts inside a gap.
* **A wide fixed header** — ``header_size`` lets a length prefix sit inside a
  header that is wider than the field itself.
"""

from __future__ import annotations

from app.analyzers.capture_reader import LINKTYPE_ETHERNET, decode_frame
from app.analyzers.framing import FramingConfig, frame_stream, _find_byte
from app.analyzers.tcp_reassembly import Segment, reassemble

ISN = 1000
BASE = ISN + 1


# --------------------------------------------------------------------------- #
# 1. Link-layer padding
# --------------------------------------------------------------------------- #


def _ethernet_ipv4_tcp_frame(payload: bytes, *, ip_total_length: int, pad_to: int = 0) -> bytes:
    eth = (
        b"\x02\x00\x00\x00\x00\x02"  # destination MAC
        b"\x02\x00\x00\x00\x00\x01"  # source MAC
        b"\x08\x00"  # IPv4
    )
    ip = bytearray(20)
    ip[0] = 0x45  # version 4, header length 5 words
    ip[2:4] = ip_total_length.to_bytes(2, "big")
    ip[8] = 64  # TTL
    ip[9] = 6  # TCP
    ip[12:16] = bytes([10, 0, 0, 1])
    ip[16:20] = bytes([10, 0, 0, 2])

    tcp = bytearray(20)
    tcp[0:2] = (4444).to_bytes(2, "big")
    tcp[2:4] = (80).to_bytes(2, "big")
    tcp[4:8] = BASE.to_bytes(4, "big")
    tcp[12] = 0x50  # data offset 5 words
    tcp[13] = 0x18  # PSH|ACK
    tcp[14:16] = (65535).to_bytes(2, "big")

    frame = bytes(eth) + bytes(ip) + bytes(tcp) + payload
    if pad_to > len(frame):
        frame += b"\x00" * (pad_to - len(frame))
    return frame


def test_ethernet_padding_is_not_part_of_the_payload():
    """A frame padded to the Ethernet minimum must not leak padding as data.

    The IPv4 total length declares 20 + 20 + 1 = 41 bytes, but the frame is
    padded to 60.  Six bytes are available after the TCP header; only one is
    real payload.
    """
    frame = _ethernet_ipv4_tcp_frame(b"A", ip_total_length=41, pad_to=60)
    decoded = decode_frame(LINKTYPE_ETHERNET, frame)

    assert decoded is not None
    assert decoded.payload_length == 1, "padding was counted as payload"
    assert decoded.truncated is False
    payload_start = decoded.payload_offset_in_frame
    assert frame[payload_start : payload_start + decoded.payload_length] == b"A"


def test_unknown_ip_total_length_falls_back_to_the_captured_bytes():
    """A zero total length (segmentation offload) cannot be trusted.

    The decoder uses everything the frame holds and does not invent a truncation
    it cannot justify.
    """
    frame = _ethernet_ipv4_tcp_frame(b"hello", ip_total_length=0)
    decoded = decode_frame(LINKTYPE_ETHERNET, frame)

    assert decoded is not None
    assert decoded.ip_total_length == 0
    assert decoded.payload_length == len(b"hello")
    assert decoded.truncated is False


# --------------------------------------------------------------------------- #
# 2. Segment before the base
# --------------------------------------------------------------------------- #


def _seg(packet_index: int, sequence: int, payload: bytes) -> Segment:
    return Segment(
        packet_index=packet_index,
        timestamp=packet_index * 0.001,
        sequence=sequence,
        payload=payload,
        flags=0x18,
        window=65535,
    )


def test_segment_before_the_base_is_reported_not_reassembled():
    stream = reassemble(
        direction="a2b",
        local_endpoint="10.0.0.1:4444",
        remote_endpoint="10.0.0.2:80",
        segments=[
            _seg(0, BASE, b"HELLO"),
            _seg(1, BASE - 20, b"XXXX"),  # precedes the inferred ISN
        ],
        isn=ISN,
    )

    assert stream.stream_length == 5, "a before-base segment blew up the stream length"
    assert stream.read(0, 5) == b"HELLO"
    assert stream.present_bytes == 5
    # The bytes were captured, so they are counted even though they are excluded.
    assert stream.byte_count == 9
    assert stream.diagnostics["segments_before_base_count"] == 1
    assert stream.diagnostics["segments_before_base"][0]["packet_index"] == 1


# --------------------------------------------------------------------------- #
# 3. Delimiter search across a hole
# --------------------------------------------------------------------------- #


def _stream_with_hole():
    return reassemble(
        direction="a2b",
        local_endpoint="10.0.0.1:4444",
        remote_endpoint="10.0.0.2:80",
        segments=[
            _seg(0, BASE, b"XY"),  # offsets 0..2
            # offsets 2..4 are missing
            _seg(1, BASE + 4, b"ab\ncd"),  # offsets 4..9
        ],
        isn=ISN,
    )


def test_delimiter_is_found_after_a_hole():
    stream = _stream_with_hole()
    assert stream.holes, "the fixture must contain a real gap"

    # The old search started inside the gap and skipped the delimiter at offset 6.
    assert _find_byte(stream, 2, 0x0A, 1 << 20) == 6


def test_delimiter_framing_across_a_hole():
    stream = _stream_with_hole()
    messages = frame_stream(
        stream,
        FramingConfig.parse(
            {
                "method": "delimiter",
                "config": {"delimiter": 0x0A, "max_length": 1 << 20, "keep_delimiter": True},
            }
        ),
    )
    assert [(m.start_offset, m.end_offset) for m in messages] == [(0, 7), (7, 9)]


# --------------------------------------------------------------------------- #
# 4. A wide fixed header
# --------------------------------------------------------------------------- #


def test_length_prefix_with_a_header_wider_than_the_field():
    payload = (
        b"\xA6\x5C\x00\x03\x00\x01\x00\x10abc"  # header 8, declared 3 -> total 11
        b"\xA6\x5C\x00\x00\x00\x02\x00\x20"  # header 8, declared 0 -> total 8
    )
    stream = reassemble(
        direction="a2b",
        local_endpoint="10.0.0.1:4444",
        remote_endpoint="10.0.0.2:80",
        segments=[_seg(0, BASE, payload)],
        isn=ISN,
    )
    messages = frame_stream(
        stream,
        FramingConfig.parse(
            {
                "method": "length_prefix",
                "config": {
                    "length_offset": 2,
                    "length_size": 2,
                    "endianness": "big",
                    "includes_header": "false",
                    "header_size": 8,
                    "max_length": 1 << 20,
                },
            }
        ),
    )
    assert [(m.start_offset, m.end_offset) for m in messages] == [(0, 11), (11, 19)]
