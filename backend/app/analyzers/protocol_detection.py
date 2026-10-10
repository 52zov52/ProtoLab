"""Application-protocol classification over reconstructed TCP streams.

Design constraints from the product brief:

* never classify by port alone;
* show the evidence *and* the failed checks for every candidate;
* if nothing is confirmed, say ``unknown_binary`` rather than guessing.

Each detector declares a :class:`ProtocolDetector`; the registry is open so new
protocols can be added without touching the engine.  A detector receives the
reassembled stream and answers with a score plus a list of fired signals and a
list of failed checks.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Sequence

from .byte_analysis import shannon_entropy
from .tcp_reassembly import ReassembledStream

DETECTOR_VERSION = "protocol-detection/1.1"

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
HTTP_VERSION = re.compile(rb"HTTP/1\.[01]\r\n")

_TLS_CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}


@dataclass
class Detection:
    protocol: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    evidence_offsets: list[int] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "confidence": round(self.confidence, 4),
            "signals": self.signals,
            "failed_checks": self.failed_checks,
            "evidence_offsets": self.evidence_offsets[:32],
            "details": self.details,
        }


@dataclass
class ProtocolDetector:
    name: str
    label: str
    check: Callable[[ReassembledStream], Detection | None]
    requires_port: int | None = None  # informational only, never used alone


def _head(stream: ReassembledStream, limit: int = 4096) -> bytes:
    return stream.read(0, min(stream.stream_length, limit))


def _all_present(stream: ReassembledStream, length: int = 8192) -> bool:
    return stream.is_present(0, min(stream.stream_length, length))


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #


def _detect_http(stream: ReassembledStream) -> Detection | None:
    head = _head(stream)
    if not head:
        return None
    signals: list[str] = []
    failed: list[str] = []
    offsets: list[int] = []
    method_hits = [m for m in HTTP_METHODS if head.startswith(m)]
    version = HTTP_VERSION.search(head[:2048])
    if not method_hits and not version:
        return None
    if method_hits:
        signals.append(f"stream starts with the HTTP method {method_hits[0]!r}")
        offsets.append(0)
    if version:
        signals.append(f"contains a status line matching {version.group(0)!r}")
        offsets.append(version.start())
    else:
        failed.append("no 'HTTP/1.x' status line found in the first 2 KiB")

    header_end = head.find(b"\r\n\r\n")
    if header_end < 0:
        failed.append("no CRLFCRLF header terminator in the first 4 KiB")
    else:
        signals.append(f"header block terminated at offset {header_end}")
        offsets.append(header_end)
        block = head[:header_end].decode("latin-1", "replace")
        if "\n" in block:
            lines = block.split("\r\n")
            names = {line.split(":", 1)[0].strip().lower() for line in lines if ":" in line}
            known = names & {
                "host", "content-length", "content-type", "user-agent",
                "accept", "connection", "authorization", "cookie",
            }
            if known:
                signals.append(f"recognised header names present: {sorted(known)}")
            else:
                failed.append("no well-known HTTP header names found")
    binary = head[max(0, head.find(b"\r\n\r\n") + 4):][:16] if header_end >= 0 else b""
    if binary and sum(1 for b in binary if b < 0x09 or (0x0E <= b < 0x20)) > len(binary) / 2:
        failed.append("body starts with bytes that are not typical HTTP content")
    return Detection(
        protocol="http1",
        confidence=0.85 if signals and not failed else 0.5,
        signals=signals,
        failed_checks=failed,
        evidence_offsets=offsets,
    )


def _detect_http2(stream: ReassembledStream) -> Detection | None:
    head = _head(stream, 64)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if len(head) < 3:
        return None
    if head[:3] != b"PRI":
        return None
    signals = ["client connection preface 'PRI * HTTP/2.0' observed"]
    failed: list[str] = []
    offsets = [0]
    if head == preface[: len(head)] and len(head) == len(preface):
        signals.append("full 24-byte HTTP/2 client preface present")
        server = stream.read(len(preface), 24)
        if server[:8] == b"HTTP/2.0":
            signals.append("server replied with the HTTP/2 SETTINGS status line")
        else:
            failed.append("no HTTP/2 server preface found after the client preface")
    return Detection(
        protocol="http2",
        confidence=0.9 if len(signals) > 1 else 0.6,
        signals=signals,
        failed_checks=failed,
        evidence_offsets=offsets,
    )


def _detect_grpc(stream: ReassembledStream) -> Detection | None:
    """gRPC over HTTP/2: HTTP/2 preface plus DATA frames with gRPC framing."""
    head = _head(stream, 64)
    if not head.startswith(b"PRI * HTTP/2.0"):
        return None
    signals = ["HTTP/2 connection preface present"]
    failed: list[str] = []
    offsets = [0]
    cursor = 24
    found_grpc = False
    while cursor + 9 <= len(head):
        length = int.from_bytes(head[cursor : cursor + 3], "big")
        frame_type = head[cursor + 3]
        if length > 16384 or cursor + 9 + length > len(head):
            break
        if frame_type == 0x00 and length >= 5:  # DATA
            compressed = head[cursor + 9]
            if compressed == 0 and b"grpc-" in head[cursor + 9 : cursor + 9 + length]:
                found_grpc = True
                offsets.append(cursor + 9)
        cursor += 9 + length
        if cursor > 8192:
            break
    if found_grpc:
        signals.append("uncompressed DATA frame carries gRPC content-type framing")
        failed.append("gRPC method names could not be read from the preface alone")
    else:
        failed.append("no gRPC-framed DATA frame observed in the first 8 KiB")
    return Detection(
        protocol="grpc",
        confidence=0.8 if found_grpc else 0.3,
        signals=signals,
        failed_checks=failed,
        evidence_offsets=offsets,
    )


def _detect_mqtt(stream: ReassembledStream) -> Detection | None:
    head = _head(stream)
    if not head:
        return None
    signals: list[str] = []
    failed: list[str] = []
    offsets: list[int] = []
    first = head[0]
    if first & 0xF0 != 0x10:
        return None
    signals.append(f"first byte 0x{first:02x} has the MQTT CONNECT control packet type")
    offsets.append(0)
    # Remaining length variable-byte integer must follow and stay in range.
    index = 1
    multiplier = 1
    remaining = 0
    while index < len(head) and index <= 4:
        byte = head[index]
        remaining += (byte & 0x7F) * multiplier
        multiplier *= 128
        index += 1
        if not byte & 0x80:
            break
    if index > 1:
        signals.append(f"remaining-length field decodes to {remaining}")
        if 1 <= remaining <= 1 << 20:
            signals.append("declared length is inside the plausible MQTT range")
        else:
            failed.append(f"declared remaining length {remaining} is implausible")
    else:
        failed.append("no remaining-length field after the fixed header")
    return Detection(
        protocol="mqtt",
        confidence=0.7 if len(signals) > 1 else 0.35,
        signals=signals,
        failed_checks=failed,
        evidence_offsets=offsets,
    )


def _detect_websocket(stream: ReassembledStream) -> Detection | None:
    head = _head(stream)
    if b"Upgrade: websocket" not in head and b"Upgrade: WebSocket" not in head:
        return None
    signals = ["HTTP upgrade request with 'Upgrade: websocket'"]
    failed: list[str] = []
    if b"Sec-WebSocket-Key:" in head:
        signals.append("Sec-WebSocket-Key header present")
    else:
        failed.append("no Sec-WebSocket-Key header found")
    if b"HTTP/1.1 101" in head:
        signals.append("server responded with 101 Switching Protocols")
    else:
        failed.append("no 101 response observed in this stream")
    return Detection(
        protocol="websocket",
        confidence=0.8 if len(signals) > 2 else 0.5,
        signals=signals,
        failed_checks=failed,
    )


def _detect_dns_tcp(stream: ReassembledStream) -> Detection | None:
    head = _head(stream)
    if len(head) < 12:
        return None
    txid = int.from_bytes(head[0:2], "big")
    flags = int.from_bytes(head[2:4], "big")
    if flags & 0x8000:
        return None  # response, not a query
    qdcount = int.from_bytes(head[4:6], "big")
    ancount = int.from_bytes(head[6:8], "big")
    if not (1 <= qdcount <= 8):
        # A real query carries a handful of questions at most; a larger count is
        # a coincidence of an arbitrary binary protocol, not a DNS header.
        return None
    if (flags & 0x7800) not in (0x0000, 0x0100, 0x0400, 0x0500):
        return None  # opcode outside the defined range
    qtype = None
    offset = 12
    labels = 0
    while offset < len(head) and head[offset] != 0 and labels < 64:
        labels += 1
        offset += 1 + head[offset]
    if offset + 4 <= len(head):
        qtype = int.from_bytes(head[offset : offset + 2], "big")
    if not _plausible_qname(head, 12):
        return None
    signals = [
        f"header parses as a DNS query (transaction id 0x{txid:04x})",
        f"QDCOUNT={qdcount} question section(s)",
        "question name decodes as a valid domain name",
    ]
    failed: list[str] = []
    if qtype in (1, 2, 5, 12, 15, 16, 28, 33):
        signals.append(f"QTYPE={qtype} is a recognised query type")
    else:
        failed.append(f"QTYPE={qtype} is not a standard DNS query type")
    return Detection(
        protocol="dns_tcp",
        confidence=0.85 if not failed else 0.45,
        signals=signals,
        failed_checks=failed,
        evidence_offsets=[0],
        details={"ancount": ancount},
    )


def _plausible_qname(head: bytes, offset: int) -> bool:
    cursor = offset
    for _ in range(64):
        if cursor >= len(head):
            return False
        length = head[cursor]
        if length == 0:
            return True
        if length & 0xC0:
            return False
        if cursor + 1 + length > len(head):
            return False
        for b in head[cursor + 1 : cursor + 1 + length]:
            if not (0x21 <= b <= 0x7E or b == 0x2E):
                return False
        cursor += 1 + length
    return False


def _detect_tls(stream: ReassembledStream) -> Detection | None:
    head = _head(stream, 8192)
    if not head or head[0] != 0x16 or len(head) < 6:
        return None
    version = f"{head[1]}.{head[2]}"
    record_type = _TLS_CONTENT_TYPES.get(head[0], "unknown")
    record_len = int.from_bytes(head[3:5], "big")
    signals = [
        f"first record has content type {record_type} (0x16 handshake)",
        f"record layer version field reads {version}",
        f"record length {record_len}",
    ]
    failed: list[str] = []
    offsets = [0]
    if head[5] == 0x01:
        signals.append("handshake message type 1 = ClientHello")
        if len(head) > 9 and head[9] == 0x03:
            signals.append(f"ClientHello TLS version reads 3.{head[10]}")
    else:
        failed.append(f"first handshake message is type {head[5]}, not ClientHello")
    return Detection(
        protocol="tls",
        confidence=0.9 if len(signals) > 2 else 0.5,
        signals=signals,
        failed_checks=failed,
        evidence_offsets=offsets,
        details={"record_version": version},
    )


def _detect_length_prefixed(stream: ReassembledStream) -> Detection | None:
    """Generic structural candidate: a self-describing length field.

    This is deliberately *not* a protocol identity.  It is reported separately
    as ``unknown_binary`` with a structural note, because recognising framing is
    not the same as recognising the protocol.
    """
    from .framing import suggest_framing

    suggestions = suggest_framing(stream, max_candidates=1)
    if not suggestions:
        return None
    top = suggestions[0]
    return Detection(
        protocol="unknown_binary",
        confidence=min(0.5, float(top["score"])),
        signals=[
            f"a length-prefix framing candidate (score {top['score']}) is consistent "
            "with the byte stream",
            str((top.get("evidence") or {}).get("messages_parsed", "")) + " messages parsed",
        ],
        failed_checks=[
            "no registered protocol analyser confirmed an application protocol",
        ],
        evidence_offsets=[0],
        details={
            "framing_candidate": top["config"],
            "entropy": round(shannon_entropy(_head(stream)), 4),
            "note": (
                "High entropy is not evidence of encryption; it also arises from "
                "compressed or high-cardinality payloads."
            ),
        },
    )


DETECTORS: tuple[ProtocolDetector, ...] = (
    ProtocolDetector("http2", "HTTP/2", _detect_http2),
    ProtocolDetector("http1", "HTTP/1.x", _detect_http),
    ProtocolDetector("grpc", "gRPC over HTTP/2", _detect_grpc),
    ProtocolDetector("websocket", "WebSocket", _detect_websocket),
    ProtocolDetector("mqtt", "MQTT", _detect_mqtt),
    ProtocolDetector("dns_tcp", "DNS over TCP", _detect_dns_tcp),
    ProtocolDetector("tls", "TLS", _detect_tls),
    ProtocolDetector("unknown_binary", "Unknown / binary stream", _detect_length_prefixed),
)

#: Protocols whose confirmation is strong enough to be reported as detected.
CONCLUSIVE = {"http1", "http2", "grpc", "websocket", "mqtt", "dns_tcp", "tls"}

MIN_CONFIDENCE = 0.5


def register_detector(detector: ProtocolDetector) -> None:
    """Extend the registry (used by plugins and tests)."""
    DETECTORS._tuple  # type: ignore[attr-defined]
    globals()["DETECTORS"] = tuple(
        d for d in globals()["DETECTORS"] if d.name != detector.name
    ) + (detector,)


def detect_protocol(stream: ReassembledStream) -> dict[str, object]:
    """Run every detector and return the full ranked candidate table."""
    candidates: list[Detection] = []
    for detector in DETECTORS:
        try:
            result = detector.check(stream)
        except Exception as exc:  # a broken detector must not break the run
            candidates.append(
                Detection(
                    protocol=detector.name,
                    confidence=0.0,
                    signals=[],
                    failed_checks=[f"detector raised {type(exc).__name__}; treated as no match"],
                )
            )
            continue
        if result is not None:
            candidates.append(result)

    conclusive = [c for c in candidates if c.protocol in CONCLUSIVE and c.confidence >= MIN_CONFIDENCE]
    conclusive.sort(key=lambda c: c.confidence, reverse=True)
    candidates.sort(key=lambda c: c.confidence, reverse=True)

    if conclusive:
        best = conclusive[0]
        label = best.protocol
        confidence = best.confidence
        verdict = "detected"
        ambiguity = len(conclusive) > 1 and conclusive[1].confidence >= best.confidence - 0.1
    else:
        structural = next((c for c in candidates if c.protocol == "unknown_binary"), None)
        best = structural
        label = "unknown_binary"
        confidence = structural.confidence if structural else 0.0
        verdict = "unclassified"
        ambiguity = False

    return {
        "analyzer_version": DETECTOR_VERSION,
        "verdict": verdict,
        "label": label,
        "confidence": round(confidence, 4),
        "ambiguous": ambiguity,
        "candidates": [c.to_dict() for c in candidates],
        "method_note": (
            "Classification uses structural signals, message length consistency, "
            "entropy and direction. The transport port number was not used."
        ),
    }


def detect_for_directions(
    a2b: ReassembledStream, b2a: ReassembledStream
) -> dict[str, object]:
    """Combine both directions, which matters for request/response protocols."""
    result_a = detect_protocol(a2b)
    result_b = detect_protocol(b2a)
    combined = str(result_a["label"])
    if result_a["label"] == result_b["label"]:
        confidence = max(float(result_a["confidence"]), float(result_b["confidence"]))
    elif result_a["label"] == "unknown_binary":
        combined = str(result_b["label"])
        confidence = float(result_b["confidence"])
    else:
        combined = "unknown_binary"
        confidence = 0.3
    return {
        "protocol": combined,
        "confidence": round(confidence, 4),
        "direction_a2b": result_a,
        "direction_b2a": result_b,
        "analyzer_version": DETECTOR_VERSION,
    }


_ = struct
_ = Sequence