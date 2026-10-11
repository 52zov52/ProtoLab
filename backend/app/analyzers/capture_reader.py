"""Hardened, streaming reader for libpcap and pcapng capture files.

Why a hand-written reader instead of Scapy
------------------------------------------
Parsing an untrusted capture is the highest-risk operation in the product (see
docs/THREAT_MODEL.md).  A dedicated reader lets us enforce explicit, testable
ceilings on record counts, record sizes and nesting, and to fail with a precise
diagnostic instead of an arbitrary ``MemoryError``.  It also lets us stay
streaming: a 100 MiB capture never has to be materialised in memory.

Supported
---------
* classic libpcap, both endiannesses, microsecond and nanosecond resolution
* pcapng Section Header / Interface Description / Enhanced Packet / Simple
  Packet / obsolete Packet Block / Interface Statistics / Name Resolution
  (skipped) / custom (skipped) blocks
* truncated final records are reported, not silently ignored

Deliberately unsupported: writing pcapng with comments is handled separately by
:mod:`app.analyzers.pcapng_writer`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Iterator

from ..core.errors import LimitExceeded, UnsupportedFormat

# Link types we can decode to transport headers.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0
LINKTYPE_LOOP = 108
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

SUPPORTED_LINKTYPES = {
    LINKTYPE_NULL,
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    LINKTYPE_LOOP,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
}

# Magic numbers as they appear when read back in the file's own byte order.
# A little-endian pcap file literally starts with the bytes d4 c3 b2 a1.
PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

_SHB_TYPE = 0x0A0D0D0A
_SHB_MAGIC = 0x1A2B3C4D
_IDB_TYPE = 0x00000001
_PB_OBSOLETE = 0x00000002
_SPB_TYPE = 0x00000003
_NRB_TYPE = 0x00000004
_ISB_TYPE = 0x00000005
_EPB_TYPE = 0x00000006
_DSB_TYPE = 0x0000000A

#: A pcapng block is ``type(4) + total_length(4) + body + total_length(4)``.
#: The trailing 4-byte copy of ``total_length`` is the trailer.
BLOCK_HEADER_LEN = 8
BLOCK_TRAILER_LEN = 4
SHB_MIN_BODY = 16
EPB_MIN_BODY = 20
IDB_MIN_BODY = 8


class CaptureFormat(str):
    PCAP = "pcap"
    PCAPNG = "pcapng"
    UNKNOWN = "unknown"


class ReaderDiagnostics(dict):
    """Plain dict subclass so it serialises straight into JSON columns."""


#: ``endian`` values used across the reader mapped to ``struct`` byte-order
#: prefixes.  ``struct`` wants "<" / ">", never the word "little".
ENDIAN = {"little": "<", "big": ">"}


@dataclass(slots=True)
class RawPacket:
    """One capture record with its payload slice still inside the original file."""

    index: int
    timestamp: float
    captured_length: int
    original_length: int
    link_type: int
    interface_id: int
    file_offset: int  # offset of the record header inside the capture file
    data_offset: int  # offset of the packet bytes inside the capture file
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    comment: str | None = None


@dataclass(slots=True)
class CaptureHeader:
    format: str
    endianness: str  # "little" | "big"
    nanosecond: bool
    snaplen: int
    link_types: list[int]
    sections: int = 1
    version: tuple[int, int] = (0, 0)


def sniff_format(head: bytes) -> str:
    if len(head) < 4:
        return CaptureFormat.UNKNOWN
    le = struct.unpack_from("<I", head, 0)[0]
    be = struct.unpack_from(">I", head, 0)[0]
    if le in (PCAP_MAGIC_US, PCAP_MAGIC_NS) or be in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        return CaptureFormat.PCAP
    if le == _SHB_TYPE:
        return CaptureFormat.PCAPNG
    return CaptureFormat.UNKNOWN


class CaptureReader:
    """Streaming reader.  ``iter_packets`` is a generator: files are never
    fully buffered."""

    def __init__(
        self,
        path: Path,
        *,
        max_packets: int,
        max_packet_bytes: int,
        max_file_bytes: int | None = None,
    ) -> None:
        self.path = path
        self.max_packets = max_packets
        self.max_packet_bytes = max_packet_bytes
        self.max_file_bytes = max_file_bytes
        self.diagnostics: ReaderDiagnostics = {
            "warnings": [],
            "errors": [],
            "truncated_records": 0,
            "skipped_blocks": 0,
            "link_types": [],
        }
        self.header: CaptureHeader | None = None

    # -- helpers ---------------------------------------------------------- #

    def _warn(self, message: str) -> None:
        warnings = self.diagnostics["warnings"]
        if message not in warnings:
            warnings.append(message)

    def _error(self, message: str) -> None:
        errors = self.diagnostics["errors"]
        if message not in errors:
            errors.append(message)

    # -- public API ------------------------------------------------------- #

    def read_header(self, handle: BinaryIO) -> CaptureHeader:
        head = handle.read(8)
        fmt = sniff_format(head)
        if fmt == CaptureFormat.PCAP:
            handle.seek(0)
            header = self._read_pcap_header(handle)
        elif fmt == CaptureFormat.PCAPNG:
            handle.seek(0)
            header = self._read_pcapng_header(handle)
        else:
            raise UnsupportedFormat(
                "File is not a recognised libpcap or pcapng capture.",
                details={"detected": "unknown"},
            )
        self.header = header
        self.diagnostics["link_types"] = list(header.link_types)
        if header.link_types and any(lt not in SUPPORTED_LINKTYPES for lt in header.link_types):
            self._warn(
                "Capture contains link types that are not decoded for transport "
                f"analysis: {sorted(set(header.link_types) - SUPPORTED_LINKTYPES)}"
            )
        return header

    def iter_packets(self) -> Iterator[RawPacket]:
        size = self.path.stat().st_size
        if self.max_file_bytes is not None and size > self.max_file_bytes:
            raise LimitExceeded(
                "Capture file exceeds the configured maximum size.",
                details={"limit_bytes": self.max_file_bytes, "file_size": size},
            )
        with self.path.open("rb") as handle:
            # Always re-read the header on the fresh handle: that positions the
            # cursor past the container header.  Reusing a cached header would
            # silently start parsing at offset 0.
            header = self.read_header(handle)
            if header.format == CaptureFormat.PCAP:
                yield from self._iter_pcap(handle, header)
            else:
                yield from self._iter_pcapng(handle, header)

    # -- libpcap ---------------------------------------------------------- #

    def _read_pcap_header(self, handle: BinaryIO) -> CaptureHeader:
        raw = handle.read(24)
        if len(raw) < 24:
            raise UnsupportedFormat("Truncated libpcap global header.")
        magic_le = struct.unpack_from("<I", raw, 0)[0]
        magic_be = struct.unpack_from(">I", raw, 0)[0]
        if magic_le in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian = "little"
            nanosecond = magic_le == PCAP_MAGIC_NS
        elif magic_be in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian = "big"
            nanosecond = magic_be == PCAP_MAGIC_NS
        else:  # pragma: no cover - sniff_format already checked
            raise UnsupportedFormat("Unrecognised libpcap magic number.")
        fmt = "<" if endian == "little" else ">"
        major, minor, _tz, _sig, snaplen, network = struct.unpack_from(
            f"{fmt}HHiIII", raw, 4
        )
        link_type = network & 0x0FFFFFFF  # upper bits carry FCS info in some writers
        if snaplen <= 0:
            self._warn(f"Global header reports a non-positive snaplen ({snaplen}).")
            snaplen = 0
        return CaptureHeader(
            format=CaptureFormat.PCAP,
            endianness=endian,
            nanosecond=nanosecond,
            snaplen=snaplen,
            link_types=[link_type],
            version=(major, minor),
        )

    def _iter_pcap(self, handle: BinaryIO, header: CaptureHeader) -> Iterator[RawPacket]:
        fmt = ENDIAN[header.endianness]
        index = 0
        file_size = self.path.stat().st_size
        while True:
            record_offset = handle.tell()
            raw = handle.read(16)
            if not raw:
                return
            if len(raw) < 16:
                self._error(
                    "Capture ends with an incomplete packet record header "
                    f"(16 bytes expected at offset {record_offset}, got {len(raw)})."
                )
                return
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{fmt}IIII", raw)
            if incl_len > self.max_packet_bytes:
                raise LimitExceeded(
                    "A packet record exceeds the configured maximum record size.",
                    details={
                        "limit_bytes": self.max_packet_bytes,
                        "packet_index": index,
                        "captured_length": incl_len,
                    },
                )
            if incl_len > file_size - handle.tell():
                self._error(
                    f"Packet record at offset {record_offset} claims {incl_len} bytes but "
                    "the file ends first; the capture is truncated."
                )
                self.diagnostics["truncated_records"] = int(
                    self.diagnostics["truncated_records"]
                ) + 1
                yield RawPacket(
                    index=index,
                    timestamp=self._ts(ts_sec, ts_frac, header.nanosecond),
                    captured_length=incl_len,
                    original_length=orig_len,
                    link_type=header.link_types[0],
                    interface_id=0,
                    file_offset=record_offset,
                    data_offset=handle.tell(),
                    truncated=True,
                    warnings=["record truncated by end of file"],
                )
                return
            data_offset = handle.tell()
            if handle.seek(incl_len, 1) != data_offset + incl_len:  # pragma: no cover
                raise UnsupportedFormat("Seek past packet record failed.")
            index += 1
            if index > self.max_packets:
                raise LimitExceeded(
                    "Capture contains more packets than the configured maximum.",
                    details={"limit_packets": self.max_packets},
                )
            yield RawPacket(
                index=index - 1,
                timestamp=self._ts(ts_sec, ts_frac, header.nanosecond),
                captured_length=incl_len,
                original_length=orig_len,
                link_type=header.link_types[0],
                interface_id=0,
                file_offset=record_offset,
                data_offset=data_offset,
            )

    @staticmethod
    def _ts(ts_sec: int, ts_frac: int, nanosecond: bool) -> float:
        return ts_sec + (ts_frac / 1e9 if nanosecond else ts_frac / 1e6)

    # -- pcapng ----------------------------------------------------------- #

    def _read_pcapng_header(self, handle: BinaryIO) -> CaptureHeader:
        link_types: list[int] = []
        endian = "little"
        nanosecond = False
        sections = 0
        version = (0, 0)
        while True:
            block_type_raw = handle.read(4)
            if len(block_type_raw) < 4:
                break
            peek_len = handle.read(4)
            if len(peek_len) < 4:
                break
            little_type = struct.unpack("<I", block_type_raw)[0]
            if little_type == _SHB_TYPE:
                endian = "little"
            else:
                big_type = struct.unpack(">I", block_type_raw)[0]
                if big_type == _SHB_TYPE:
                    endian = "big"
            block_type = struct.unpack_from(f"{ENDIAN[endian]}I", block_type_raw, 0)[0]
            total_length = struct.unpack_from(f"{ENDIAN[endian]}I", peek_len, 0)[0]
            if block_type != _SHB_TYPE:
                break
            body = handle.read(max(0, total_length - BLOCK_HEADER_LEN - BLOCK_TRAILER_LEN))
            if len(body) < SHB_MIN_BODY:
                raise UnsupportedFormat("Truncated pcapng Section Header Block.")
            bom = struct.unpack_from(f"{ENDIAN[endian]}I", body, 0)[0]
            if bom != _SHB_MAGIC:
                raise UnsupportedFormat("Invalid pcapng byte-order magic.")
            major, minor = struct.unpack_from(f"{ENDIAN[endian]}HH", body, 4)
            if_tsunit_offset = 8
            (if_tsresol,) = struct.unpack_from(f"{ENDIAN[endian]}B", body, if_tsunit_offset)
            nanosecond = bool(if_tsresol & 0x80)
            version = (major, minor)
            sections += 1
            trailing = handle.read(4)
            if len(trailing) < 4:
                raise UnsupportedFormat("Truncated pcapng Section Header Block trailer.")
            handle.seek(0)
            return CaptureHeader(
                format=CaptureFormat.PCAPNG,
                endianness=endian,
                nanosecond=nanosecond,
                snaplen=0,
                link_types=[],
                sections=sections,
                version=version,
            )
        raise UnsupportedFormat("pcapng capture has no Section Header Block.")

    def _iter_pcapng(self, handle: BinaryIO, header: CaptureHeader) -> Iterator[RawPacket]:
        file_size = self.path.stat().st_size
        endian = header.endianness
        nanosecond = header.nanosecond
        interface_link_types: list[int] = []
        interface_tsresol: list[int] = []
        interface_snaplen: list[int] = []
        index = 0
        handle.seek(0)
        pending: tuple[int, bytes, int] | None = None

        while True:
            if pending is not None:
                block_type, block_body, block_offset = pending
                pending = None
            else:
                block_offset = handle.tell()
                head = handle.read(8)
                if not head:
                    return
                if len(head) < 8:
                    self._error(
                        f"pcapng file ends inside a block header at offset {block_offset}."
                    )
                    return
                block_type = struct.unpack_from(f"{ENDIAN[endian]}I", head, 0)[0]
                total_length = struct.unpack_from(f"{ENDIAN[endian]}I", head, 4)[0]
                if total_length < BLOCK_HEADER_LEN + BLOCK_TRAILER_LEN:
                    self._error(
                        f"pcapng block at offset {block_offset} declares an impossible "
                        f"length ({total_length}); stopping to avoid unbounded reads."
                    )
                    return
                if block_type == _SHB_TYPE and endian == "big":
                    big_type = struct.unpack(">I", head[0:4])[0]
                    if big_type != _SHB_TYPE:
                        # Endianness switch: restart parsing with the other order.
                        other = "little" if endian == "big" else "big"
                        if struct.unpack(f"{other}I", head[0:4])[0] != _SHB_TYPE:
                            self._error(
                                f"Unknown pcapng block type 0x{block_type:08x} at offset "
                                f"{block_offset}; stopping."
                            )
                            return
                        endian = other
                        block_type = struct.unpack_from(f"{ENDIAN[endian]}I", head, 0)[0]
                        total_length = struct.unpack_from(f"{ENDIAN[endian]}I", head, 4)[0]
                remaining = total_length - BLOCK_HEADER_LEN - BLOCK_TRAILER_LEN
                block_body = handle.read(remaining)
                if len(block_body) < remaining:
                    self._error(
                        f"pcapng block at offset {block_offset} is truncated "
                        f"({len(block_body)} of {remaining} body bytes)."
                    )
                    return
                trailer = handle.read(4)
                if len(trailer) < 4:
                    self._error("pcapng file ends inside a block trailer.")
                    return
                (declared_total,) = struct.unpack_from(f"{ENDIAN[endian]}I", trailer, 0)
                if declared_total != total_length:
                    self._error(
                        f"pcapng block at offset {block_offset} has mismatched trailer "
                        f"length ({declared_total} != {total_length})."
                    )
                    return

            if block_type == _SHB_TYPE:
                # (A section header may appear mid-file; the caller restarts
                # endianness detection via the loop below.)
                self.diagnostics["skipped_blocks"] = int(self.diagnostics["skipped_blocks"]) + 1
                continue

            if block_type == _IDB_TYPE:
                if len(block_body) < IDB_MIN_BODY:
                    self._error("pcapng Interface Description Block is too short.")
                    return
                link_type, _res, snaplen = struct.unpack_from(f"{ENDIAN[endian]}HHI", block_body, 0)
                tsresol = 6  # default: microseconds
                offset = IDB_MIN_BODY + 4
                while offset + 4 <= len(block_body):
                    code, length = struct.unpack_from(f"{ENDIAN[endian]}HH", block_body, offset)
                    if code == 0:
                        break
                    value = block_body[offset + 4 : offset + 4 + length]
                    if code == 9 and length >= 1:  # if_tsresol
                        tsresol = value[0]
                    offset += 4 + ((length + 3) // 4) * 4
                interface_link_types.append(link_type)
                interface_tsresol.append(tsresol)
                interface_snaplen.append(snaplen)
                continue

            if block_type == _EPB_TYPE:
                if len(block_body) < EPB_MIN_BODY:
                    self._error("pcapng Enhanced Packet Block is too short.")
                    return
                iface, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(
                    f"{ENDIAN[endian]}IIIII", block_body, 0
                )
                if cap_len > self.max_packet_bytes:
                    raise LimitExceeded(
                        "An Enhanced Packet Block exceeds the configured record size limit.",
                        details={
                            "limit_bytes": self.max_packet_bytes,
                            "packet_index": index,
                            "captured_length": cap_len,
                        },
                    )
                padded = ((cap_len + 3) // 4) * 4
                data_offset = block_offset + BLOCK_HEADER_LEN + EPB_MIN_BODY
                if data_offset + cap_len > file_size:
                    self._error(
                        f"pcapng packet block at offset {block_offset} extends past EOF."
                    )
                    self.diagnostics["truncated_records"] = int(
                        self.diagnostics["truncated_records"]
                    ) + 1
                    yield RawPacket(
                        index=index,
                        timestamp=0.0,
                        captured_length=cap_len,
                        original_length=orig_len,
                        link_type=_iface_type(interface_link_types, iface),
                        interface_id=iface,
                        file_offset=block_offset,
                        data_offset=data_offset,
                        truncated=True,
                        warnings=["packet data extends past end of file"],
                    )
                    return
                link_type = _iface_type(interface_link_types, iface)
                tsresol = (
                    interface_tsresol[iface]
                    if iface < len(interface_tsresol)
                    else interface_tsresol[-1] if interface_tsresol else 6
                )
                index += 1
                if index > self.max_packets:
                    raise LimitExceeded(
                        "Capture contains more packets than the configured maximum.",
                        details={"limit_packets": self.max_packets},
                    )
                yield RawPacket(
                    index=index - 1,
                    timestamp=_epb_timestamp(ts_high, ts_low, tsresol),
                    captured_length=cap_len,
                    original_length=orig_len,
                    link_type=link_type,
                    interface_id=iface,
                    file_offset=block_offset,
                    data_offset=data_offset,
                    comment=_extract_comment(
                        block_body, EPB_MIN_BODY + padded, endian
                    ),
                )
                _ = padded
                continue

            if block_type == _PB_OBSOLETE:
                if len(block_body) < 20:
                    self._error("pcapng obsolete Packet Block is too short.")
                    return
                iface, _drops, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(
                    f"{ENDIAN[endian]}HHIIII", block_body, 0
                )
                data_offset = block_offset + BLOCK_HEADER_LEN + 20
                if data_offset + cap_len > file_size or cap_len > self.max_packet_bytes:
                    self._error("pcapng obsolete Packet Block has an invalid length.")
                    return
                index += 1
                if index > self.max_packets:
                    raise LimitExceeded(
                        "Capture contains more packets than the configured maximum.",
                        details={"limit_packets": self.max_packets},
                    )
                tsresol = (
                    interface_tsresol[iface]
                    if iface < len(interface_tsresol)
                    else interface_tsresol[-1] if interface_tsresol else 6
                )
                yield RawPacket(
                    index=index - 1,
                    timestamp=_epb_timestamp(ts_high, ts_low, tsresol),
                    captured_length=cap_len,
                    original_length=orig_len,
                    link_type=_iface_type(interface_link_types, iface),
                    interface_id=iface,
                    file_offset=block_offset,
                    data_offset=data_offset,
                    comment=_extract_comment(
                        block_body, 20 + ((cap_len + 3) // 4) * 4, endian
                    ),
                )
                continue

            if block_type == _SPB_TYPE:
                if len(block_body) < 4:
                    self._error("pcapng Simple Packet Block is too short.")
                    return
                (orig_len,) = struct.unpack_from(f"{ENDIAN[endian]}I", block_body, 0)
                cap_len = min(orig_len, len(block_body) - 4)
                cap_len -= cap_len % 4
                data_offset = block_offset + BLOCK_HEADER_LEN + 4
                link_type = _iface_type(interface_link_types, 0)
                index += 1
                if index > self.max_packets:
                    raise LimitExceeded(
                        "Capture contains more packets than the configured maximum.",
                        details={"limit_packets": self.max_packets},
                    )
                yield RawPacket(
                    index=index - 1,
                    timestamp=0.0,
                    captured_length=cap_len,
                    original_length=orig_len,
                    link_type=link_type,
                    interface_id=0,
                    file_offset=block_offset,
                    data_offset=data_offset,
                    warnings=["Simple Packet Block has no timestamp"],
                )
                continue

            if block_type in (_ISB_TYPE, _NRB_TYPE, _DSB_TYPE):
                self.diagnostics["skipped_blocks"] = int(self.diagnostics["skipped_blocks"]) + 1
                continue

            self._warn(f"Skipped unknown pcapng block type 0x{block_type:08x}.")
            self.diagnostics["skipped_blocks"] = int(self.diagnostics["skipped_blocks"]) + 1


def _iface_type(link_types: list[int], iface: int) -> int:
    if iface < len(link_types):
        return link_types[iface]
    return link_types[0] if link_types else LINKTYPE_ETHERNET


def _extract_comment(body: bytes, options_offset: int, endian: str) -> str | None:
    """Read the pcapng ``comment`` (option 1) from a block's option list.

    Option lists are a sequence of ``code(2), length(2), value`` entries padded
    to 4 bytes, terminated by ``code=0``.  Anything malformed terminates the walk
    instead of raising: a broken comment must not make the capture unreadable.
    """
    prefix = ENDIAN[endian]
    offset = options_offset
    if offset < 0 or offset >= len(body):
        return None
    while offset + 4 <= len(body):
        try:
            code, length = struct.unpack_from(f"{prefix}HH", body, offset)
        except struct.error:
            return None
        if code == 0:
            return None
        offset += 4
        value = body[offset : offset + length]
        if len(value) < length:
            return None
        if code == 1:
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value.decode("latin-1", "replace")
        offset += length + ((-length) % 4)
    return None


_TSRESOL_DECIMAL = lambda raw: 10 ** (raw & 0x7F)


def _epb_timestamp(ts_high: int, ts_low: int, tsresol: int) -> float:
    units = (ts_high << 32) | ts_low
    decimal = tsresol & 0x7F
    if decimal & 0x40:
        # 2^(tsresol & 0x3F) seconds since epoch
        return float(units) / float(2 ** decimal)
    return float(units) / float(10 ** decimal)


@dataclass(slots=True)
class DecodedPacket:
    """Link/network/transport headers extracted from a raw record."""

    source_address: str
    destination_address: str
    ip_protocol: int
    ip_version: int
    transport_offset: int
    source_port: int | None = None
    destination_port: int | None = None
    transport_header_length: int = 0
    tcp_sequence: int | None = None
    tcp_acknowledgment: int | None = None
    tcp_flags: int | None = None
    tcp_window: int | None = None
    tcp_options: str | None = None
    payload_offset_in_frame: int | None = None
    payload_length: int = 0
    ip_total_length: int = 0
    truncated: bool = False
    anomalies: list[str] = field(default_factory=list)


def decode_frame(link_type: int, frame: bytes, *, expected_length: int | None = None) -> DecodedPacket | None:
    """Decode Ethernet/IP/TCP headers out of a captured frame.

    Returns ``None`` when the record carries no IPv4/IPv6 transport payload we
    can reason about (ARP, ICMP, truncated non-IP frame...).
    """
    if len(frame) > max(expected_length or 0, 0):
        pass  # truncation is judged against the declared length below

    ip_offset = _network_offset(link_type, frame)
    if ip_offset is None:
        return None
    if ip_offset >= len(frame):
        return None
    version = frame[ip_offset] >> 4
    if version == 4:
        return _decode_ipv4(frame, ip_offset)
    if version == 6:
        return _decode_ipv6(frame, ip_offset)
    return None


def _network_offset(link_type: int, frame: bytes) -> int | None:
    if link_type == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = (frame[12] << 8) | frame[13]
        offset = 14
        # Skip 802.1Q / QinQ tags.
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ethertype = (frame[offset + 2] << 8) | frame[offset + 3]
            offset += 4
        if ethertype == 0x0800 or ethertype == 0x86DD:
            return offset
        return None
    if link_type in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return 0
    if link_type in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(frame) < 4:
            return None
        return 4
    if link_type == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        return 16
    if link_type == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        return 20
    return None


def read_record_bytes(handle, raw_packet) -> bytes:
    """Read one packet's bytes by seeking in the original (immutable) file.

    The capture file is never rewritten, so seeking back into it is safe and is
    the cheapest way to avoid holding N payloads in memory at once.
    """
    handle.seek(raw_packet.data_offset)
    return handle.read(raw_packet.captured_length)


def _decode_ipv4(frame: bytes, off: int) -> DecodedPacket | None:
    if len(frame) < off + 20:
        return DecodedPacket(
            source_address="0.0.0.0",
            destination_address="0.0.0.0",
            ip_protocol=0,
            ip_version=4,
            transport_offset=off + 20,
            truncated=True,
            anomalies=["truncated IPv4 header"],
        )
    ihl = (frame[off] & 0x0F) * 4
    if ihl < 20:
        return None
    total_length = (frame[off + 2] << 8) | frame[off + 3]
    protocol = frame[off + 9]
    src = ".".join(str(b) for b in frame[off + 12 : off + 16])
    dst = ".".join(str(b) for b in frame[off + 16 : off + 20])
    transport_offset = off + ihl
    anomalies: list[str] = []
    # A zero total length is the classic signature of TCP segmentation offload
    # (the NIC fills the field after capture); anything smaller than the header
    # is malformed.  In both cases we must not trust the field, so the caller
    # falls back to the captured frame length.
    if total_length == 0 or total_length < ihl:
        ip_end: int | None = None
        if total_length != 0:
            anomalies.append("IPv4 total length field is smaller than the IPv4 header")
    else:
        ip_end = off + total_length
        if len(frame) < ip_end:
            anomalies.append("frame captured shorter than the IPv4 total length field")
    return _finish(frame, transport_offset, src, dst, protocol, 4, ip_end, anomalies)


def _decode_ipv6(frame: bytes, off: int) -> DecodedPacket | None:
    if len(frame) < off + 40:
        return None
    payload_len = (frame[off + 4] << 8) | frame[off + 5]
    next_header = frame[off + 6]
    src = _ipv6_str(frame[off + 8 : off + 24])
    dst = _ipv6_str(frame[off + 24 : off + 40])
    transport_offset = off + 40
    anomalies: list[str] = []
    # Walk the small set of extension headers we care about.
    guard = 0
    while next_header in (0, 43, 60) and guard < 8:
        if len(frame) < transport_offset + 8:
            return None
        ext_len = (frame[transport_offset + 1] + 1) * 8
        next_header = frame[transport_offset]
        transport_offset += ext_len
        guard += 1
    total = (off + 40 + payload_len)
    return _finish(
        frame, transport_offset, src, dst, next_header, 6, total, anomalies
    )


def _finish(
    frame: bytes,
    transport_offset: int,
    src: str,
    dst: str,
    protocol: int,
    version: int,
    ip_end: int | None,
    anomalies: list[str],
) -> DecodedPacket | None:
    decoded = DecodedPacket(
        source_address=src,
        destination_address=dst,
        ip_protocol=protocol,
        ip_version=version,
        transport_offset=transport_offset,
        ip_total_length=max(0, (ip_end - transport_offset)) if ip_end is not None else 0,
    )
    if protocol != 6:  # not TCP
        return decoded
    if len(frame) < transport_offset + 20:
        decoded.truncated = True
        decoded.anomalies.append("truncated TCP header")
        return decoded
    data_offset = (frame[transport_offset + 12] >> 4) * 4
    decoded.source_port = (frame[transport_offset] << 8) | frame[transport_offset + 1]
    decoded.destination_port = (frame[transport_offset + 2] << 8) | frame[
        transport_offset + 3
    ]
    decoded.tcp_sequence = int.from_bytes(frame[transport_offset + 4 : transport_offset + 8], "big")
    decoded.tcp_acknowledgment = int.from_bytes(
        frame[transport_offset + 8 : transport_offset + 12], "big"
    )
    decoded.tcp_flags = frame[transport_offset + 13]
    decoded.tcp_window = (frame[transport_offset + 14] << 8) | frame[transport_offset + 15]
    decoded.transport_header_length = data_offset
    options = _decode_tcp_options(frame, transport_offset + 20, transport_offset + data_offset)
    decoded.tcp_options = options
    payload_start = transport_offset + data_offset
    available = max(0, len(frame) - payload_start)
    if ip_end is None:
        # The network header carried no trustworthy length (e.g. segmentation
        # offload wrote zero).  We cannot tell real payload from link-layer
        # padding, so we use everything the frame holds and say so.
        length = available
    else:
        declared_payload = max(0, ip_end - payload_start)
        length = min(declared_payload, available)
        if available < declared_payload:
            decoded.truncated = True
            decoded.anomalies.append("TCP payload captured shorter than the IP total length")
    decoded.payload_offset_in_frame = payload_start
    decoded.payload_length = length
    if data_offset < 20:
        decoded.anomalies.append("TCP data offset below the 20-byte minimum")
    return decoded


def _decode_tcp_options(frame: bytes, start: int, end: int) -> str | None:
    if end <= start or end > len(frame):
        return None
    names: list[str] = []
    i = start
    while i < end:
        kind = frame[i]
        if kind == 0:
            break
        if kind == 1:
            names.append("NOP")
            i += 1
            continue
        if i + 1 >= end:
            break
        length = frame[i + 1]
        if length < 2 or i + length > end:
            names.append("MALFORMED")
            break
        names.append(_TCP_OPTION_NAMES.get(kind, f"OPT{kind}"))
        i += length
    return ",".join(names) if names else None


_TCP_OPTION_NAMES = {
    2: "MSS",
    3: "WS",
    4: "SACKOK",
    5: "SACK",
    8: "TIMESTAMP",
    19: "MSS",
    28: "USER-TIMEOUT",
    34: "TFO",
}


def _ipv6_str(raw: bytes) -> str:
    parts = [f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2)]
    return ":".join(parts)


class TcpFlags(IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


def describe_flags(flags: int) -> str:
    names = [f.name for f in TcpFlags if flags & f.value]
    return ",".join(names) if names else "NONE"


FLAG_SYN = TcpFlags.SYN
FLAG_FIN = TcpFlags.FIN
FLAG_RST = TcpFlags.RST
FLAG_ACK = TcpFlags.ACK
FLAG_PSH = TcpFlags.PSH