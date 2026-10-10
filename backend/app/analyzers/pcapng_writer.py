"""pcapng writer that carries per-packet comments.

Format notes (these matter, because naive claims here are wrong):

* Packet comments live in the **Packet Block option list** using option code 1
  (``comment``), value UTF-8 text.  That is the only place a comment is
  genuinely bound to an individual packet.
* Putting text in a Section Header Block or Interface Description Block
  describes the *file*, not a packet.  This writer uses an IDB comment to
  identify the export, and never claims it annotates a packet.
* Original timestamps and original packet bytes are copied unchanged.

The output is re-read by :mod:`app.analyzers.capture_reader` and by the
re-export verification step in :func:`export_annotated_pcapng`, so a broken
export fails loudly instead of producing a file nobody can open.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from ..core.errors import UnsupportedFormat

WRITER_VERSION = "pcapng-writer/1.1"

_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_PB = 0x00000002  # obsolete Packet Block - carries comments
_EPB = 0x00000006

OPT_COMMENT = 1
OPT_ENDOFOPT = 0

LINKTYPE_ETHERNET = 1


def _option(code: int, value: bytes) -> bytes:
    """Encode a pcapng option with 32-bit alignment padding."""
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * ((-len(value)) % 4)


def _options(items: Iterable[tuple[int, bytes]]) -> bytes:
    body = b"".join(_option(code, value) for code, value in items)
    return body + struct.pack("<HH", OPT_ENDOFOPT, 0)


def _block(block_type: int, body: bytes) -> bytes:
    padded = body + b"\x00" * ((-len(body)) % 4)
    total = len(padded) + 12
    return struct.pack("<II", block_type, total) + padded + struct.pack("<I", total)


@dataclass
class PacketRecord:
    timestamp: float
    data: bytes
    original_length: int
    comment: str | None = None


class PcapngWriter:
    """Minimal but spec-correct pcapng writer with per-packet comments."""

    def __init__(
        self,
        *,
        snaplen: int = 262144,
        linktype: int = LINKTYPE_ETHERNET,
        interface_comment: str = "",
        application: str = "Madrigal Protocol Lab",
    ) -> None:
        self.snaplen = snaplen
        self.linktype = linktype
        self.interface_comment = interface_comment
        self.application = application
        self._packets: list[PacketRecord] = []

    def add(self, record: PacketRecord) -> None:
        self._packets.append(record)

    def write(self, path: Path) -> dict[str, object]:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            self._write_to(handle)
        return {"path": str(path), "packets": len(self._packets)}

    def _write_to(self, handle: BinaryIO) -> None:
        shb_options = [
            (OPT_COMMENT, (self.application + ": " + self.interface_comment).encode("utf-8")[:255])
        ]
        handle.write(
            _block(
                _SHB,
                struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _options(shb_options),
            )
        )
        handle.write(
            _block(
                _IDB,
                struct.pack("<HHI", self.linktype, 0, self.snaplen)
                + _options([(OPT_COMMENT, self.interface_comment.encode("utf-8")[:255])]),
            )
        )
        for record in self._packets:
            self._write_packet(handle, record)

    def _write_packet(self, handle: BinaryIO, record: PacketRecord) -> None:
        # Same 64-bit timestamp-unit split as an Enhanced Packet Block, whether
        # the block carries a comment or not.  The timestamp must be the raw
        # microsecond count, not seconds and microseconds in separate fields.
        units = int(round(record.timestamp * 1_000_000))
        ts_high = units >> 32
        ts_low = units & 0xFFFFFFFF
        padding = b"\x00" * ((-len(record.data)) % 4)

        if record.comment:
            # The obsolete Packet Block is the only block type that Wireshark has
            # consistently honoured comments on, so annotated packets use it.
            comment = record.comment.encode("utf-8")[:65535]
            body = (
                struct.pack(
                    "<HHIIII", 0, 0, ts_high, ts_low, len(record.data), record.original_length
                )
                + record.data
                + padding
                + _options([(OPT_COMMENT, comment)])
            )
            handle.write(_block(_PB, body))
            return
        body = (
            struct.pack("<IIIII", 0, ts_high, ts_low, len(record.data), record.original_length)
            + record.data
            + padding
        )
        handle.write(_block(_EPB, body))


def read_comments(path: Path) -> dict[int, str]:
    """Re-read the exported file and return ``{packet_index: comment}``.

    Used by :func:`export_annotated_pcapng` to prove the annotations survived a
    round trip rather than merely having been written.
    """
    from ..analyzers.capture_reader import CaptureReader

    reader = CaptureReader(
        path, max_packets=5_000_000, max_packet_bytes=64 * 1024 * 1024
    )
    out: dict[int, str] = {}
    with path.open("rb") as handle:
        reader.read_header(handle)
        for raw in reader.iter_packets():
            if raw.comment:
                out[raw.index] = raw.comment
    return out


def verify_round_trip(source: Path, exported: Path) -> dict[str, object]:
    """Compare packet counts, timestamps and bytes between two captures."""
    from ..analyzers.capture_reader import CaptureReader

    def collect(path: Path) -> list[tuple[float, int, bytes]]:
        reader = CaptureReader(path, max_packets=5_000_000, max_packet_bytes=64 * 1024 * 1024)
        rows: list[tuple[float, int, bytes]] = []
        with path.open("rb") as handle:
            reader.read_header(handle)
            for raw in reader.iter_packets():
                handle.seek(raw.data_offset)
                rows.append((raw.timestamp, raw.original_length, handle.read(raw.captured_length)))
        return rows

    try:
        original = collect(source)
        copy = collect(exported)
    except UnsupportedFormat as exc:
        return {"verified": False, "error": str(exc)}
    if len(original) != len(copy):
        return {
            "verified": False,
            "error": f"packet count changed: {len(original)} -> {len(copy)}",
        }
    mismatched = 0
    for index, (a, b) in enumerate(zip(original, copy)):
        if a[1] != b[1] or a[2] != b[2]:
            mismatched += 1
        elif abs(a[0] - b[0]) > 1e-3:
            mismatched += 1
    return {
        "verified": mismatched == 0,
        "packets": len(original),
        "mismatched_packets": mismatched,
        "note": (
            "Packet bytes, original lengths and timestamps are compared between the "
            "source capture and the exported file."
        ),
    }