"""Synthetic test bench: a real TCP device protocol and real PCAP writer.

The bench exists so the application can be exercised end to end on traffic it
has never seen.  The protocol *format* lives only here and in
``docs/TEST_BENCH.md``: the application is never handed this knowledge.  An
analyst has to recover it from the bytes, exactly as with a real device.

Protocol shape (the ground truth the analyst must rediscover)
--------------------------------------------------------------
Every message, in both directions::

    +--------+--------+---------+-------------+---------+----------+
    | LEN(2) | TYPE(1)|  REQ(2) |  BODY ...                |
    | big    |        |  big    |                            |
    +--------+--------+---------+-------------+---------+----------+

``LEN`` is the total message length *including* these two length bytes.

* ``TYPE``
    ``0x01`` read_parameter, ``0x02`` set_parameter, ``0x03`` measurements,
    ``0x04`` ack, ``0x05`` heartbeat.
* Request bodies: ``0x01`` = read(u16 param id), ``0x02`` = set(u16 id, u32 value).
* Response bodies: ``0x01`` = value(u32) + status(u8), ``0x03`` = N float samples.
* Responses echo the request id in bytes 3..4, which is what lets the analyst
  correlate request/response pairs.

This is intentionally *not* obvious: there is no magic, no checksum, and the
length field's convention (includes header or not) is discoverable only from the
data.
"""

from __future__ import annotations

import json
import math
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

BENCH_VERSION = "mplab-testbench/1.0"

TYPE_READ = 0x01
TYPE_SET = 0x02
TYPE_MEASURE = 0x03
TYPE_ACK = 0x04
TYPE_HEARTBEAT = 0x05

OP_READ = 0x01
OP_SET = 0x02
OP_VALUE = 0x01
OP_SAMPLES = 0x03

STATUS_OK = 0x00
STATUS_UNKNOWN_PARAM = 0x01
STATUS_REJECTED = 0x02


def msg(msg_type: int, req_id: int, body: bytes) -> bytes:
    """Build one frame.

    The header is LEN(2) + TYPE(1) + REQ(2) = 5 bytes and LEN counts itself, so
    ``total = 5 + len(body)``.
    """
    total = 5 + len(body)
    return struct.pack(">HBH", total, msg_type, req_id) + body


def read_request(req_id: int, param_id: int) -> bytes:
    return msg(TYPE_READ, req_id, struct.pack(">BH", OP_READ, param_id))


def set_request(req_id: int, param_id: int, value: int) -> bytes:
    return msg(TYPE_SET, req_id, struct.pack(">BHI", OP_SET, param_id, value))


def measure_request(req_id: int, count: int, interval: int) -> bytes:
    return msg(TYPE_MEASURE, req_id, struct.pack(">BHI", OP_SAMPLES, count, interval))


def value_response(req_id: int, value: int, status: int = STATUS_OK) -> bytes:
    return msg(TYPE_READ, req_id, struct.pack(">BIB", OP_VALUE, value, status))


def samples_response(req_id: int, samples: Sequence[float]) -> bytes:
    body = struct.pack(">BH", OP_SAMPLES, len(samples))
    for sample in samples:
        body += struct.pack(">f", sample)
    return msg(TYPE_MEASURE, req_id, body)


def ack_response(req_id: int, status: int = STATUS_OK) -> bytes:
    return msg(TYPE_ACK, req_id, struct.pack(">BB", 0x01, status))


def heartbeat() -> bytes:
    return msg(TYPE_HEARTBEAT, 0, b"")


# --------------------------------------------------------------------------- #
# PCAP writer
# --------------------------------------------------------------------------- #


@dataclass
class BenchHost:
    ip: str
    mac: bytes

    @property
    def ip_bytes(self) -> bytes:
        return bytes(int(p) for p in self.ip.split("."))


@dataclass
class TcpState:
    """Minimal TCP sender state: enough to emit believable segments.

    ``isn`` is the Initial Sequence Number.  Per RFC 793 the SYN carries the
    ISN itself and consumes one sequence number, so the first data byte is
    ``isn + 1``.
    """

    ip: str
    mac: bytes
    port: int
    isn: int = 1000
    next_seq: int = 0
    unacked: int = 0

    def __post_init__(self) -> None:
        self.next_seq = self.isn

    @property
    def ip_bytes(self) -> bytes:
        return bytes(int(part) for part in self.ip.split("."))


class PcapWriter:
    """Writes a classic libpcap file (little endian, microsecond)."""

    def __init__(self, *, snaplen: int = 262144, linktype: int = 1) -> None:
        self.snaplen = snaplen
        self.linktype = linktype
        self._records: list[tuple[float, bytes]] = []

    def add(self, timestamp: float, frame: bytes) -> None:
        self._records.append((timestamp, frame))

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            handle.write(
                struct.pack(
                    "<IHHiIII",
                    0xA1B2C3D4,
                    2,
                    4,
                    0,
                    0,
                    self.snaplen,
                    self.linktype,
                )
            )
            for timestamp, frame in self._records:
                sec = int(timestamp)
                usec = int(round((timestamp - sec) * 1_000_000))
                if usec >= 1_000_000:
                    sec += 1
                    usec -= 1_000_000
                handle.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                handle.write(frame)
        return path

    def write_pcapng(self, path: Path) -> Path:
        """Same records, pcapng container - exercises the other reader path."""
        path.parent.mkdir(parents=True, exist_ok=True)

        def block(block_type: int, body: bytes) -> bytes:
            total = 12 + len(body)
            pad = (-len(body)) % 4
            body_p = body + b"\x00" * pad
            total_p = total + pad
            return (
                struct.pack("<II", block_type, total_p)
                + body_p
                + struct.pack("<I", total_p)
            )

        out = bytearray()
        out += block(
            0x0A0D0D0A,
            struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
        )
        out += block(0x00000001, struct.pack("<HHI", self.linktype, 0, self.snaplen))
        for timestamp, frame in self._records:
            units = int(round(timestamp * 1_000_000))
            out += block(
                0x00000006,
                struct.pack("<IIIII", 0, units >> 32, units & 0xFFFFFFFF, len(frame), len(frame))
                + frame,
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(out))
        return path


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_frame(
    src: TcpState, dst: TcpState, *, flags: int, seq: int, ack: int, window: int = 65535,
    payload: bytes = b"", options: bytes = b"",
) -> bytes:
    src_port = src.port
    dst_port = dst.port
    tcp_offset = 5 + len(options) // 4
    tcp_header = (
        struct.pack(">HHIIBBHHH", src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                    tcp_offset << 4, flags, window, 0, 0)
        + options
    )
    pseudo = src.ip_bytes + dst.ip_bytes + struct.pack(">BBH", 0, 6, len(tcp_header) + len(payload))
    csum = _checksum(pseudo + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack(">H", csum) + tcp_header[18:]

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0x4000,
        64,
        6,
        0,
        src.ip_bytes,
        dst.ip_bytes,
    )
    ip_header = ip_header[:10] + struct.pack(">H", _checksum(ip_header)) + ip_header[12:]
    eth = src.mac + dst.mac + struct.pack(">H", 0x0800)
    return eth + ip_header + tcp_header + payload


MSS_OPTION = struct.pack(">BBH", 2, 4, 1460)
SACK_OPTION = b"\x04\x02"
TS_OPTION = struct.pack(">BBII", 8, 10, 0x0A0A0A0A, 0x0B0B0B0B)


@dataclass
class Conversation:
    """Emits a full TCP conversation into a :class:`PcapWriter`."""

    writer: PcapWriter
    client: TcpState
    server: TcpState
    clock: float = 1_767_225_600.0  # 2026-01-01T00:00:00Z, fixed for reproducibility

    def _tick(self, seconds: float = 0.001) -> None:
        self.clock += seconds

    def handshake(self) -> None:
        # SYN carries the ISN and consumes one sequence number.
        self.writer.add(self.clock, build_frame(
            self.client, self.server, flags=0x02, seq=self.client.isn, ack=0, options=MSS_OPTION))
        self.client.next_seq = self.client.isn + 1
        self._tick(0.0008)
        self.writer.add(self.clock, build_frame(
            self.server, self.client, flags=0x12, seq=self.server.isn, ack=self.client.next_seq,
            options=MSS_OPTION + SACK_OPTION + TS_OPTION))
        self.server.next_seq = self.server.isn + 1
        self.client.unacked = self.client.next_seq
        self.server.unacked = self.server.next_seq
        self._tick(0.0008)
        self.writer.add(self.clock, build_frame(
            self.client, self.server, flags=0x10, seq=self.client.next_seq, ack=self.server.next_seq))
        self._tick()

    def send(
        self,
        src: TcpState,
        dst: TcpState,
        data: bytes = b"",
        *,
        mss: int = 1400,
        force_retransmit: int | None = None,
        drop_segments: Sequence[int] = (),
        delay: float = 0.001,
    ) -> None:
        """Emit ``data`` as one or more segments, with optional impairments."""
        chunks = [data[i : i + mss] for i in range(0, len(data), mss)] or [b""]
        emitted = 0
        for index, chunk in enumerate(chunks):
            if index in drop_segments:
                # The sender still advances its sequence space; the receiver
                # never sees these bytes.
                src.next_seq += len(chunk)
                self._tick(delay)
                continue
            frame = build_frame(
                src, dst, flags=0x18, seq=src.next_seq, ack=dst.unacked, payload=chunk
            )
            self.writer.add(self.clock, frame)
            if force_retransmit is not None and emitted == force_retransmit:
                # Byte-identical retransmission after a short delay.
                self._tick(0.25)
                self.writer.add(self.clock, frame)
            src.next_seq += len(chunk)
            src.unacked = src.next_seq
            dst.unacked = src.next_seq
            emitted += 1
            self._tick(delay)

    def close(self) -> None:
        self.writer.add(self.clock, build_frame(
            self.client, self.server, flags=0x11, seq=self.client.next_seq, ack=self.server.next_seq))
        self.client.next_seq += 1
        self.server.unacked = self.client.next_seq
        self._tick(0.001)
        self.writer.add(self.clock, build_frame(
            self.server, self.client, flags=0x11, seq=self.server.next_seq, ack=self.client.next_seq))
        self.server.next_seq += 1
        self.client.unacked = self.server.next_seq
        self._tick(0.001)
        self.writer.add(self.clock, build_frame(
            self.client, self.server, flags=0x10, seq=self.client.next_seq, ack=self.server.next_seq))
        self._tick()


def reset_conversation(
    writer: PcapWriter, client: TcpState, server: TcpState, clock: float
) -> float:
    """A conversation that starts and ends with RST and carries no handshake."""
    client.next_seq = client.isn
    server.next_seq = server.isn
    writer.add(clock, build_frame(client, server, flags=0x18, seq=client.next_seq,
                                  ack=0, payload=read_request(1, 0x0001)))
    client.next_seq += len(read_request(1, 0x0001))
    clock += 0.002
    writer.add(clock, build_frame(server, client, flags=0x04, seq=server.next_seq,
                                  ack=client.next_seq))
    return clock + 0.002


@dataclass
class BenchResult:
    path: Path
    actions: list[dict[str, object]]
    ground_truth: dict[str, object]
    notes: str = ""


def _actions_from(base_time: float, entries: Iterable[tuple[str, dict]]) -> list[dict]:
    out = []
    for index, (action, params) in enumerate(entries):
        out.append(
            {
                "timestamp": _iso(base_time + index * 0.05),
                "action": action,
                "parameters": params,
                "observed_result": params.get("observed_result", "success"),
            }
        )
    return out


def _iso(epoch: float) -> str:
    import datetime as _dt

    return (
        _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


CLIENT_MAC = bytes.fromhex("021a3b4c5d6e")
SERVER_MAC = bytes.fromhex("021a7f8e9dab")


def _hosts(client_ip: str, server_ip: str, client_port: int, server_port: int) -> tuple[TcpState, TcpState]:
    client = TcpState(ip=client_ip, mac=CLIENT_MAC, port=client_port, isn=0x1F2E3D40)
    server = TcpState(ip=server_ip, mac=SERVER_MAC, port=server_port, isn=0x5A6B7C8D)
    return client, server


def scenario_basic(out_dir: Path, *, name: str = "basic") -> BenchResult:
    """Baseline: handshake, read, set, measure, close."""
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51422, 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()

    actions: list[tuple[str, dict]] = []
    req = 1
    conv.send(client, server, read_request(req, 0x0001))
    actions.append(("read_parameter", {"parameter": "device_serial", "parameter_id": 1}))
    req += 1
    conv.send(server, client, value_response(req - 1, 0x0000DEAD, STATUS_OK))

    conv.send(client, server, set_request(req, 0x0002, 20))
    actions.append(("set_parameter", {"parameter": "measurement_interval", "parameter_id": 2, "value": 20}))
    req += 1
    conv.send(server, client, ack_response(req - 1, STATUS_OK))

    conv.send(client, server, measure_request(req, 24, 20))
    actions.append(("get_measurements", {"parameter": "measurements", "count": 24, "interval": 20}))
    samples = [round(21.0 + 3.0 * math.sin(i / 3.0) + random.Random(i).uniform(-0.2, 0.2), 3)
               for i in range(24)]
    req += 1
    conv.send(server, client, samples_response(req - 1, samples))

    conv.send(client, server, heartbeat())
    actions.append(("heartbeat", {}))
    conv.close()

    path = writer.write(out_dir / f"{name}.pcap")
    truth = _truth_document()
    return BenchResult(
        path=path,
        actions=_actions_from(base, actions),
        ground_truth=truth,
        notes="Baseline conversation with a full handshake.",
    )


def scenario_read_parameters(out_dir: Path) -> BenchResult:
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51430, 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()
    actions = []
    values = [0x0000DEAD, 1234, 0, 65535, 250, 7]
    for index, value in enumerate(values):
        req = index + 1
        conv.send(client, server, read_request(req, 0x0001 + index))
        actions.append(("read_parameter", {"parameter": f"param_{index}", "parameter_id": index + 1}))
        conv.send(server, client, value_response(req, value, STATUS_OK))
    conv.close()
    return BenchResult(
        path=writer.write(out_dir / "read_parameters.pcap"),
        actions=_actions_from(base, actions),
        ground_truth=_truth_document(),
    )


def scenario_set_parameter(out_dir: Path, *, value: int, name: str) -> BenchResult:
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51440 + (value % 7), 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()
    req = 1
    conv.send(client, server, set_request(req, 0x0002, value))
    conv.send(server, client, ack_response(req, STATUS_OK))
    req += 1
    conv.send(client, server, read_request(req, 0x0002))
    conv.send(server, client, value_response(req, value, STATUS_OK))
    conv.close()
    return BenchResult(
        path=writer.write(out_dir / f"{name}.pcap"),
        actions=_actions_from(
            base,
            [
                ("set_parameter", {"parameter": "measurement_interval", "parameter_id": 2, "value": value}),
                ("read_parameter", {"parameter": "measurement_interval", "parameter_id": 2}),
            ],
        ),
        ground_truth=_truth_document(),
        notes=f"Corpus for value {value}: the analyst must show the parameter field tracks it.",
    )


def scenario_measurements(out_dir: Path, *, sample_count: int, name: str) -> BenchResult:
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51450 + (sample_count % 5), 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()
    req = 1
    conv.send(client, server, measure_request(req, sample_count, 15))
    samples = [round(20.0 + math.cos(i / 4.0) * 2.5, 3) for i in range(sample_count)]
    conv.send(server, client, samples_response(req, samples))
    conv.close()
    return BenchResult(
        path=writer.write(out_dir / f"{name}.pcap"),
        actions=_actions_from(
            base,
            [("get_measurements", {"parameter": "measurements", "count": sample_count})],
        ),
        ground_truth=_truth_document(),
        notes=f"Response length varies with the sample count ({sample_count}).",
    )


def scenario_with_losses(out_dir: Path) -> BenchResult:
    """A capture where a segment never made it to disk."""
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51460, 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()
    # One 60-byte read split into three segments; the middle one is dropped.
    body = read_request(1, 0x0001)
    padded = body + b"\x00" * 60
    conv.send(client, server, padded, mss=20, drop_segments=(1,))
    conv.send(server, client, value_response(1, 0x0000DEAD))
    conv.close()
    return BenchResult(
        path=writer.write(out_dir / "lossy_segments.pcap"),
        actions=_actions_from(base, [("read_parameter", {"parameter": "device_serial"})]),
        ground_truth=_truth_document(),
        notes="A 20-byte segment was lost: the analyst must see a hole, not zeros.",
    )


def scenario_with_retransmissions(out_dir: Path) -> BenchResult:
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51470, 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()
    conv.send(client, server, read_request(1, 0x0001), force_retransmit=0)
    conv.send(server, client, value_response(1, 0x0000DEAD))
    # A large response split over three segments with the middle one resent.
    samples = [round(19.0 + i * 0.125, 3) for i in range(120)]
    response = samples_response(2, samples)
    conv.send(client, server, measure_request(2, len(samples), 15))
    conv.send(server, client, response, mss=200, force_retransmit=1)
    conv.close()
    return BenchResult(
        path=writer.write(out_dir / "retransmissions.pcap"),
        actions=_actions_from(
            base,
            [
                ("read_parameter", {"parameter": "device_serial"}),
                ("get_measurements", {"parameter": "measurements", "count": len(samples)}),
            ],
        ),
        ground_truth=_truth_document(),
        notes="Byte-identical retransmissions must not duplicate bytes in the stream.",
    )


def scenario_mixed_lengths(out_dir: Path) -> BenchResult:
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51480, 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()
    rng = random.Random(0xC0FFEE)
    actions = []
    for index in range(1, 25):
        count = rng.choice([4, 8, 16, 32, 48, 64, 96])
        req = index
        conv.send(client, server, measure_request(req, count, 20))
        samples = [round(rng.uniform(-5, 40), 3) for _ in range(count)]
        conv.send(server, client, samples_response(req, samples))
        actions.append(("get_measurements", {"parameter": "measurements", "count": count}))
    conv.close()
    return BenchResult(
        path=writer.write(out_dir / "mixed_lengths.pcap"),
        actions=_actions_from(base, actions),
        ground_truth=_truth_document(),
        notes="Messages of strongly varying length in both directions.",
    )


def scenario_port_reuse(out_dir: Path) -> BenchResult:
    """Two independent conversations that share the same 4-tuple."""
    writer = PcapWriter()
    base = 1_767_225_600.0
    results = []
    all_actions = []
    for index in range(2):
        client = TcpState(ip="192.168.10.25", mac=CLIENT_MAC, port=51500, isn=0x1000 + index * 0x10000)
        server = TcpState(ip="192.168.10.5", mac=SERVER_MAC, port=9500, isn=0x9000 + index * 0x10000)
        conv = Conversation(writer, client, server)
        conv.clock = base + index * 300.0
        if index == 1:
            # No handshake at all on the second incarnation: starts mid-stream.
            # The sequence space continues from the ISN as if the handshake had
            # happened off-capture, so byte 0 of the stream is unknowable.
            client.next_seq = client.isn + 1
            server.next_seq = server.isn + 1
            conv.writer.add(conv.clock, build_frame(client, server, flags=0x18,
                                                    seq=client.next_seq, ack=0,
                                                    payload=read_request(1, 0x0001)))
            client.next_seq += len(read_request(1, 0x0001))
            conv.clock += 0.002
            conv.writer.add(conv.clock, build_frame(server, client, flags=0x18,
                                                    seq=server.next_seq,
                                                    ack=client.next_seq,
                                                    payload=value_response(1, 0x0000BEEF)))
            server.next_seq += len(value_response(1, 0x0000BEEF))
            conv.clock += 0.002
        else:
            conv.handshake()
            conv.send(client, server, read_request(1, 0x0001))
            conv.send(server, client, value_response(1, 0x0000DEAD))
            conv.close()
        all_actions.append(
            {
                "timestamp": _iso(conv.clock),
                "action": "read_parameter",
                "parameters": {"parameter": "device_serial", "connection_instance": index},
                "observed_result": "success",
            }
        )
        results.append(index)
    return BenchResult(
        path=writer.write(out_dir / "port_reuse.pcap"),
        actions=all_actions,
        ground_truth=_truth_document(),
        notes=(
            "Same 4-tuple reused 300s apart; the second incarnation has no SYN. "
            "A splitter that groups on the 5-tuple alone will merge them."
        ),
    )


def scenario_rst_and_no_syn(out_dir: Path) -> BenchResult:
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51510, 9500)
    clock = reset_conversation(writer, client, server, 1_767_225_600.0)
    client2, server2 = _hosts("192.168.10.26", "192.168.10.5", 51510, 9501)
    client2.next_seq = client2.isn
    server2.next_seq = server2.isn
    writer.add(clock + 1.0, build_frame(client2, server2, flags=0x18, seq=client2.next_seq,
                                        ack=0, payload=set_request(7, 0x0002, 35)))
    client2.next_seq += len(set_request(7, 0x0002, 35))
    clock += 1.002
    writer.add(clock, build_frame(server2, client2, flags=0x14, seq=server2.next_seq,
                                  ack=client2.next_seq, payload=ack_response(7, STATUS_REJECTED)))
    server2.next_seq += len(ack_response(7, STATUS_REJECTED))
    return BenchResult(
        path=writer.write(out_dir / "rst_no_syn.pcap"),
        actions=_actions_from(
            clock,
            [
                ("read_parameter", {"parameter": "device_serial", "note": "connection reset"}),
                ("set_parameter", {"parameter": "measurement_interval", "value": 35,
                                   "expected_result": "rejected"}),
            ],
        ),
        ground_truth=_truth_document(),
        notes="One connection is closed by RST; another starts without a SYN.",
    )


def scenario_unknown_status(out_dir: Path) -> BenchResult:
    writer = PcapWriter()
    client, server = _hosts("192.168.10.25", "192.168.10.5", 51520, 9500)
    conv = Conversation(writer, client, server)
    base = conv.clock
    conv.handshake()
    conv.send(client, server, read_request(1, 0x00FF))
    conv.send(server, client, value_response(1, 0, STATUS_UNKNOWN_PARAM))
    conv.send(client, server, read_request(2, 0x0002))
    conv.send(server, client, value_response(2, 0x000000FF, STATUS_OK))
    conv.close()
    return BenchResult(
        path=writer.write(out_dir / "unknown_status.pcap"),
        actions=_actions_from(
            base,
            [
                ("read_parameter", {"parameter": "unknown", "parameter_id": 255,
                                    "expected_result": "unknown_parameter"}),
                ("read_parameter", {"parameter": "flags", "parameter_id": 2}),
            ],
        ),
        ground_truth=_truth_document(),
        notes="Contains a status the analyst's first hypothesis will not account for.",
    )


def scenario_two_connections(out_dir: Path) -> BenchResult:
    """Parallel conversations with *different* 4-tuples."""
    writer = PcapWriter()
    base = 1_767_225_600.0
    actions = []
    for index, port in enumerate((9600, 9601)):
        client = TcpState(ip="192.168.10.25", mac=CLIENT_MAC, port=51600 + index,
                          isn=0x2000 + index * 0x8000)
        server = TcpState(ip="192.168.10.5", mac=SERVER_MAC, port=port, isn=0x7000 + index * 0x8000)
        conv = Conversation(writer, client, server)
        conv.clock = base + index * 0.5
        conv.handshake()
        conv.send(client, server, read_request(index + 1, 0x0001))
        conv.send(server, client, value_response(index + 1, 0x0000CAFE + index))
        conv.close()
        actions.append({
            "timestamp": _iso(conv.clock),
            "action": "read_parameter",
            "parameters": {"parameter": "device_serial", "server_port": port},
            "observed_result": "success",
        })
    return BenchResult(
        path=writer.write(out_dir / "two_connections.pcap"),
        actions=actions,
        ground_truth=_truth_document(),
    )


def scenario_pcapng(out_dir: Path) -> BenchResult:
    result = scenario_basic(out_dir, name="basic")
    ng = PcapWriter()
    # Re-encode the same conversation into a pcapng container.
    src = result.path.read_bytes()
    magic, _v1, _v2, _tz, _sf, _snap, _net = _read_pcap_global(src)
    offset = 24
    records = []
    while offset + 16 <= len(src):
        sec, usec, incl, _orig = struct.unpack_from("<IIII", src, offset)
        offset += 16
        frame = src[offset : offset + incl]
        offset += incl
        records.append((sec + usec / 1e6, frame))
    for ts, frame in records:
        ng.add(ts, frame)
    ng_path = ng.write_pcapng(out_dir / "basic.pcapng")
    return BenchResult(
        path=ng_path,
        actions=result.actions,
        ground_truth=result.ground_truth,
        notes="The same baseline exchange stored as pcapng.",
    )


def _read_pcap_global(blob: bytes) -> tuple:
    return struct.unpack_from("<IHHiIII", blob, 0)


def _truth_document() -> dict[str, object]:
    return {
        "generator": BENCH_VERSION,
        "framing": {
            "method": "length_prefix",
            "length_field": {"offset": 0, "size": 2, "endianness": "big", "includes_header": True},
            "note": "LEN counts the two length bytes themselves.",
        },
        "fields": [
            {"name": "length", "offset": 0, "size": 2, "type": "uint16", "endianness": "big"},
            {"name": "message_type", "offset": 2, "size": 1, "type": "uint8"},
            {"name": "request_id", "offset": 3, "size": 2, "type": "uint16", "endianness": "big"},
        ],
        "message_types": {
            str(TYPE_READ): "read_parameter",
            str(TYPE_SET): "set_parameter",
            str(TYPE_MEASURE): "measurements",
            str(TYPE_ACK): "ack",
            str(TYPE_HEARTBEAT): "heartbeat",
        },
        "request_bodies": {
            str(TYPE_READ): "01 + param_id(u16 BE)",
            str(TYPE_SET): "02 + param_id(u16 BE) + value(u32 BE)",
            str(TYPE_MEASURE): "03 + sample_count(u16 BE) + interval(u32 BE)",
        },
        "response_bodies": {
            str(TYPE_READ): "01 + value(u32 BE) + status(u8)",
            str(TYPE_MEASURE): "03 + sample_count(u16 BE) + count * float32 BE",
            str(TYPE_ACK): "01 + status(u8)",
        },
        "status_codes": {
            str(STATUS_OK): "ok",
            str(STATUS_UNKNOWN_PARAM): "unknown_parameter",
            str(STATUS_REJECTED): "rejected",
        },
        "endpoints": {
            "client": "192.168.10.25",
            "server": "192.168.10.5:9500",
        },
        "disclosure": (
            "This document is ground truth for the test bench only. It is never "
            "given to the application; the analyst is expected to recover the "
            "layout from the bytes."
        ),
    }


SCENARIOS = {
    "basic": scenario_basic,
    "read_parameters": scenario_read_parameters,
    "set_10": lambda out: scenario_set_parameter(out, value=10, name="set_parameter_10"),
    "set_20": lambda out: scenario_set_parameter(out, value=20, name="set_parameter_20"),
    "set_60": lambda out: scenario_set_parameter(out, value=60, name="set_parameter_60"),
    "measure_8": lambda out: scenario_measurements(out, sample_count=8, name="measurements_8"),
    "measure_64": lambda out: scenario_measurements(out, sample_count=64, name="measurements_64"),
    "measure_192": lambda out: scenario_measurements(out, sample_count=192, name="measurements_192"),
    "lossy": scenario_with_losses,
    "retransmissions": scenario_with_retransmissions,
    "mixed_lengths": scenario_mixed_lengths,
    "port_reuse": scenario_port_reuse,
    "rst_no_syn": scenario_rst_and_no_syn,
    "unknown_status": scenario_unknown_status,
    "two_connections": scenario_two_connections,
    "pcapng": scenario_pcapng,
}


def generate_all(out_dir: Path) -> dict[str, BenchResult]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, BenchResult] = {}
    for name, factory in SCENARIOS.items():
        results[name] = factory(out_dir)

    index = {
        "bench_version": BENCH_VERSION,
        "generated_by": "tools/testbench/generate.py",
        "captures": [
            {
                "key": key,
                "file": result.path.name,
                "notes": result.notes,
                "actions": result.actions,
            }
            for key, result in sorted(results.items())
        ],
    }
    (out_dir / "actions.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    per_capture = out_dir / "ground_truth.json"
    per_capture.write_text(
        json.dumps(results["basic"].ground_truth, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    for key, result in results.items():
        (out_dir / f"{key}.actions.json").write_text(
            json.dumps(result.actions, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return results


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate the synthetic protocol test bench.")
    parser.add_argument("--out", default="./data/testbench", help="output directory")
    args = parser.parse_args(list(argv) if argv is not None else None)
    out = Path(args.out).resolve()
    results = generate_all(out)
    print(f"Wrote {len(results)} captures to {out}")
    for key, result in sorted(results.items()):
        size = result.path.stat().st_size
        print(f"  {key:18s} {result.path.name:28s} {size:8d} bytes  {result.notes}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())