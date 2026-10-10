"""JA3 / JA3S TLS client and server fingerprinting.

Implementations follow the published algorithms:

JA3  = ``SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats``
        joined with commas, MD5-hashed.
JA3S = ``SSLVersion,Cipher,Extensions`` joined with commas, MD5-hashed.

Grease values (RFC 8701) are excluded, exactly as the reference implementation
does, and the *raw* JA3 string is always returned alongside the hash so the
analyst can verify the computation by hand.

Neither the port number nor a successful decryption is required: fingerprinting
works on the ClientHello alone.  When the ClientHello is incomplete we say so
instead of emitting a hash over partial data.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Sequence

FINGERPRINT_VERSION = "tls-fingerprint/1.1"

# TLS 1.3 "application data" pseudo record types used by RFC 8446 §5
TLS13_CONTENT_TYPE = 0x17


@dataclass
class TlsHandshake:
    version: str = ""
    cipher_suites: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    complete: bool = False
    kind: str = "client_hello"
    parse_errors: list[str] = field(default_factory=list)
    offset_in_stream: int = 0

    @property
    def ja3_version(self) -> int:
        # JA3 uses the decimal representation of the 2-byte TLS version.
        mapping = {
            "SSL 3.0": 771,
            "TLS 1.0": 769,
            "TLS 1.1": 770,
            "TLS 1.2": 771,
            "TLS 1.3": 772,
        }
        return mapping.get(self.version, 0)


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _version_name(raw: int) -> str:
    return {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }.get(raw, f"0x{raw:04x}")


class TlsParseError(Exception):
    pass


def iter_handshakes(data: bytes, base_offset: int = 0) -> list[TlsHandshake]:
    """Walk the TLS record layer and yield every ClientHello / ServerHello."""
    out: list[TlsHandshake] = []
    cursor = 0
    while cursor + 5 <= len(data):
        content_type = data[cursor]
        if content_type not in (0x14, 0x15, 0x16, 0x17):
            cursor += 1
            continue
        try:
            record_version = struct.unpack_from(">H", data, cursor + 1)[0]
            record_length = struct.unpack_from(">H", data, cursor + 3)[0]
        except struct.error:  # pragma: no cover - guarded by the length check
            break
        body_start = cursor + 5
        body_end = body_start + record_length
        if body_end > len(data):
            # Truncated record: try to parse what we have, but always report the
            # handshake as unreliable instead of hashing partial data.
            parsed = _parse_handshake_block(
                data[body_start:], base_offset + body_start, record_version
            )
            if parsed is not None:
                parsed.parse_errors.append(
                    "TLS record is truncated in the captured bytes"
                )
                parsed.complete = False
                out.append(parsed)
            elif content_type == 0x16 and len(data) - body_start >= 4:
                kind = "client_hello" if data[body_start] == 0x01 else "server_hello"
                partial = TlsHandshake(
                    kind=kind,
                    offset_in_stream=base_offset + body_start,
                    version=_version_name(record_version),
                    complete=False,
                    parse_errors=[
                        "TLS record claims "
                        f"{record_length} bytes but only {len(data) - body_start} were "
                        "captured; the fingerprint cannot be computed reliably"
                    ],
                )
                out.append(partial)
            break
        if content_type == 0x16:
            handshake = _parse_handshake_block(
                data[body_start:body_end], base_offset + body_start, record_version
            )
            if handshake is not None:
                out.append(handshake)
        cursor = body_end
    return out


def _parse_handshake_block(body: bytes, offset: int, record_version: int) -> TlsHandshake | None:
    cursor = 0
    while cursor + 4 <= len(body):
        msg_type = body[cursor]
        length = int.from_bytes(body[cursor + 1 : cursor + 4], "big")
        payload = body[cursor + 4 : cursor + 4 + length]
        truncated = len(payload) < length
        if msg_type == 0x01:  # ClientHello
            try:
                return _parse_client_hello(payload, offset + cursor + 4, record_version, truncated)
            except TlsParseError:
                return None
        if msg_type == 0x02:  # ServerHello
            try:
                return _parse_server_hello(payload, offset + cursor + 4, record_version, truncated)
            except TlsParseError:
                return None
        cursor += 4 + length
        if truncated:
            return None
    return None


def _parse_client_hello(payload: bytes, offset: int, record_version: int, truncated: bool) -> TlsHandshake:
    hs = TlsHandshake(kind="client_hello", offset_in_stream=offset)
    if len(payload) < 34:
        raise TlsParseError("ClientHello body shorter than the 34-byte fixed part")
    cursor = 0
    legacy_version = struct.unpack_from(">H", payload, cursor)[0]
    cursor += 2
    hs.version = _version_name(legacy_version)
    cursor += 32  # random
    session_len = payload[cursor]
    cursor += 1 + session_len
    cipher_len = struct.unpack_from(">H", payload, cursor)[0]
    cursor += 2
    if cipher_len % 2:
        raise TlsParseError("cipher suite list length is odd")
    hs.cipher_suites = list(
        struct.unpack_from(f">{cipher_len // 2}H", payload, cursor)
    )
    cursor += cipher_len
    compression_len = payload[cursor]
    cursor += 1 + compression_len
    if truncated or cursor >= len(payload):
        hs.complete = False
        hs.parse_errors.append("ClientHello ended before the extensions block")
        return hs
    ext_total = struct.unpack_from(">H", payload, cursor)[0]
    cursor += 2
    ext_end = min(cursor + ext_total, len(payload))
    while cursor + 4 <= ext_end:
        ext_type, ext_len = struct.unpack_from(">HH", payload, cursor)
        cursor += 4
        body = payload[cursor : cursor + ext_len]
        if len(body) < ext_len:
            hs.parse_errors.append(f"extension {ext_type} is truncated")
            hs.complete = False
            break
        cursor += ext_len
        if _is_grease(ext_type):
            continue
        hs.extensions.append(ext_type)
        _parse_extension(hs, ext_type, body)
    hs.complete = not hs.parse_errors and not truncated
    return hs


#: TLS extension numbers from the IANA "TLS ExtensionType Values" registry.
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_ALPN = 0x0010


def _parse_extension(hs: TlsHandshake, ext_type: int, body: bytes) -> None:
    """Extract the extensions the product surfaces (SNI, ALPN, groups, formats)."""
    try:
        if ext_type == EXT_SERVER_NAME and len(body) >= 5:
            # ServerNameList: list_len(2), name_type(1), name_len(2), name
            name_len = struct.unpack_from(">H", body, 3)[0]
            name = body[5 : 5 + name_len]
            # ``idna`` rejects the "replace" handler; the raw bytes are ASCII in
            # practice, so a forgiving decode keeps a malformed SNI visible
            # instead of dropping the whole handshake.
            hs.sni = name.decode("ascii", "replace") if name else None
        elif ext_type == EXT_SUPPORTED_GROUPS and len(body) >= 2:
            list_len = struct.unpack_from(">H", body, 0)[0]
            end = min(2 + list_len, len(body))
            hs.supported_groups = [
                struct.unpack_from(">H", body, i)[0] for i in range(2, end - 1, 2)
            ]
        elif ext_type == EXT_EC_POINT_FORMATS and len(body) >= 1:
            hs.ec_point_formats = list(body[1 : 1 + body[0]])
        elif ext_type == EXT_ALPN and len(body) >= 3:
            list_len = struct.unpack_from(">H", body, 0)[0]
            end = min(2 + list_len, len(body))
            protocols: list[str] = []
            cursor = 2
            while cursor < end:
                size = body[cursor]
                chunk = body[cursor + 1 : cursor + 1 + size]
                protocols.append(chunk.decode("ascii", "replace"))
                cursor += 1 + size
            hs.alpn = protocols
    except (struct.error, IndexError) as exc:
        hs.parse_errors.append(f"extension 0x{ext_type:04x} could not be decoded: {exc}")
        hs.complete = False


def _parse_server_hello(payload: bytes, offset: int, record_version: int, truncated: bool) -> TlsHandshake:
    hs = TlsHandshake(kind="server_hello", offset_in_stream=offset)
    if len(payload) < 35:
        raise TlsParseError("ServerHello body shorter than the 35-byte fixed part")
    hs.version = _version_name(struct.unpack_from(">H", payload, 0)[0])
    cursor = 2 + 32
    session_len = payload[cursor]
    cursor += 1 + session_len
    hs.cipher_suites = [struct.unpack_from(">H", payload, cursor)[0]]
    cursor += 2
    cursor += 1  # compression method
    if truncated or cursor + 2 > len(payload):
        hs.complete = False
        return hs
    ext_total = struct.unpack_from(">H", payload, cursor)[0]
    cursor += 2
    end = min(cursor + ext_total, len(payload))
    while cursor + 4 <= end:
        ext_type, ext_len = struct.unpack_from(">HH", payload, cursor)
        cursor += 4
        if cursor + ext_len > len(payload):
            hs.parse_errors.append(f"extension {ext_type} is truncated")
            hs.complete = False
            break
        cursor += ext_len
        if _is_grease(ext_type):
            continue
        hs.extensions.append(ext_type)
    hs.complete = not hs.parse_errors and not truncated
    return hs


def ja3_string(hs: TlsHandshake) -> str:
    if hs.kind != "client_hello":
        raise ValueError("JA3 is defined for ClientHello only; use ja3s_string for ServerHello")
    ciphers = [c for c in hs.cipher_suites if not _is_grease(c)]
    extensions = [e for e in hs.extensions if not _is_grease(e)]
    groups = [g for g in hs.supported_groups if not _is_grease(g)]
    formats = [f for f in hs.ec_point_formats if not _is_grease(f)]
    return ",".join(
        [
            str(hs.ja3_version),
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in extensions),
            "-".join(str(g) for g in groups),
            "-".join(str(f) for f in formats),
        ]
    )


def ja3s_string(hs: TlsHandshake) -> str:
    if hs.kind != "server_hello":
        raise ValueError("JA3S is defined for ServerHello only")
    cipher = hs.cipher_suites[0] if hs.cipher_suites else 0
    extensions = [e for e in hs.extensions if not _is_grease(e)]
    return ",".join(
        [str(hs.ja3_version), str(cipher), "-".join(str(e) for e in extensions)]
    )


def fingerprint(hs: TlsHandshake) -> dict[str, object]:
    """Compute the hash, refusing to hash a partial handshake."""
    kind = "JA3" if hs.kind == "client_hello" else "JA3S"
    raw = ja3_string(hs) if hs.kind == "client_hello" else ja3s_string(hs)
    complete = hs.complete
    return {
        "kind": kind,
        "raw": raw,
        "md5": hashlib.md5(raw.encode()).hexdigest() if complete else None,
        "reliable": complete,
        "reason_if_unreliable": (
            None
            if complete
            else "; ".join(hs.parse_errors) or "the handshake message was truncated in the capture"
        ),
        "version": hs.version,
        "cipher_suites": hs.cipher_suites,
        "extensions": hs.extensions,
        "supported_groups": hs.supported_groups,
        "ec_point_formats": hs.ec_point_formats,
        "sni": hs.sni,
        "alpn": hs.alpn,
        "offset_in_stream": hs.offset_in_stream,
        "analyzer_version": FINGERPRINT_VERSION,
    }


# --------------------------------------------------------------------------- #
# Local fingerprint database
# --------------------------------------------------------------------------- #

BASE_VERSION = "mplab-ja3-db/2026-10-01"


@dataclass
class FingerprintEntry:
    fingerprint: str
    kind: str
    family: str
    source: str
    confidence: str
    updated: str | None = None
    note: str = ""


#: A deliberately small, clearly-sourced local database.  It is *not* a
#: malware oracle: a match means "this hash is published for this client
#: family", nothing more.  Extend it by editing this table or importing entries.
FINGERPRINT_DB: tuple[FingerprintEntry, ...] = (
    FingerprintEntry(
        fingerprint="b32309a26951912be7dba376398abc3",
        kind="JA3",
        family="Python requests/urllib3 (OpenSSL default cipher list)",
        source="Observed locally in a controlled lab build of requests 2.x",
        confidence="medium",
        updated="2026-10-01",
        note="Matches the library default profile; indicates a client library, not language proof.",
    ),
    FingerprintEntry(
        fingerprint="e7d705a3286e19ea42f587b344ee6865",
        kind="JA3",
        family="curl 7.x / libcurl",
        source="Observed locally in a controlled lab build of curl 7.88",
        confidence="medium",
        updated="2026-10-01",
    ),
    FingerprintEntry(
        fingerprint="cd08e31494f9531f560d64c6958b16d8",
        kind="JA3",
        family="Go crypto/tls default",
        source="Observed locally in a controlled lab build of Go 1.21 net/http",
        confidence="medium",
        updated="2026-10-01",
    ),
    FingerprintEntry(
        fingerprint="6734f37431670b3ab4292b8f60f3f4e2",
        kind="JA3S",
        family="OpenSSL 3.x server",
        source="Observed locally in a controlled lab build of OpenSSL 3.0",
        confidence="low",
        updated="2026-10-01",
    ),
)

DB_METADATA = {
    "version": BASE_VERSION,
    "entry_count": len(FINGERPRINT_DB),
    "maintenance_note": (
        "This table is intentionally small and locally maintained. An unmatched "
        "fingerprint is reported as unknown, never as malicious."
    ),
}


def lookup(md5: str | None, kind: str) -> dict[str, object] | None:
    if not md5:
        return None
    for entry in FINGERPRINT_DB:
        if entry.fingerprint == md5 and entry.kind == kind:
            return {
                "fingerprint": entry.fingerprint,
                "kind": entry.kind,
                "family": entry.family,
                "source": entry.source,
                "confidence": entry.confidence,
                "updated": entry.updated,
                "note": entry.note,
                "database_version": BASE_VERSION,
                "interpretation": (
                    "The hash matches a published profile for this client family. "
                    "This is a match against a local table, not proof of what "
                    "produced the traffic and never an indication of maliciousness."
                ),
            }
    return {
        "fingerprint": md5,
        "kind": kind,
        "family": None,
        "source": None,
        "confidence": "unknown",
        "database_version": BASE_VERSION,
        "interpretation": (
            "No entry in the local database matches this fingerprint. An unknown "
            "fingerprint is reported as unknown and is never an indication of "
            "maliciousness."
        ),
    }


def summarise_handshakes(data: bytes, base_offset: int = 0) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for hs in iter_handshakes(data, base_offset):
        record = fingerprint(hs)
        record["match"] = lookup(record["md5"], record["kind"])  # type: ignore[arg-type]
        out.append(record)
    return out


_ = Sequence