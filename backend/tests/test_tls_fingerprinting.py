"""TLS fingerprinting tests using hand-built ClientHello / ServerHello records."""

from __future__ import annotations

import hashlib
import struct

import pytest

from app.analyzers.tls_fingerprinting import (
    TlsHandshake,
    fingerprint,
    iter_handshakes,
    ja3_string,
    ja3s_string,
    lookup,
    summarise_handshakes,
)

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_ALPN = 0x0010


def ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(body)) + body


def build_client_hello(
    *,
    version: int = 0x0303,
    ciphers: tuple[int, ...] = (0x1301, 0x1302, 0xC02F, 0xC030),
    extensions: bytes = b"",
    sni: str | None = "example.com",
) -> bytes:
    exts = extensions
    if sni is not None:
        encoded = sni.encode()
        exts = (
            ext(
                EXT_SERVER_NAME,
                struct.pack(">H", 3 + len(encoded)) + b"\x00" + struct.pack(">H", len(encoded)) + encoded,
            )
            + exts
        )
    cipher_blob = b"".join(struct.pack(">H", c) for c in ciphers)
    body = (
        struct.pack(">H", version)
        + bytes(range(32))
        + b"\x00"
        + struct.pack(">H", len(cipher_blob))
        + cipher_blob
        + b"\x01\x00"
        + struct.pack(">H", len(exts))
        + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def build_server_hello(*, version: int = 0x0303, cipher: int = 0x1301) -> bytes:
    body = (
        struct.pack(">H", version)
        + bytes(range(32))
        + b"\x00"
        + struct.pack(">H", cipher)
        + b"\x00"
        + struct.pack(">H", 0)
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def test_client_hello_is_parsed_with_cipher_suites():
    data = build_client_hello()
    handshakes = iter_handshakes(data)
    assert len(handshakes) == 1
    hs = handshakes[0]
    assert hs.kind == "client_hello"
    assert hs.version == "TLS 1.2"
    assert hs.cipher_suites == [0x1301, 0x1302, 0xC02F, 0xC030]
    assert hs.sni == "example.com"
    assert hs.complete


def test_extensions_groups_formats_and_alpn_are_extracted():
    groups_body = struct.pack(">H", 4) + struct.pack(">HH", 23, 29)
    alpn_body = struct.pack(">H", 5) + bytes([3]) + b"h2\x00"
    extensions = (
        ext(EXT_SUPPORTED_GROUPS, groups_body)
        + ext(EXT_EC_POINT_FORMATS, bytes([1, 0]))
        + ext(EXT_ALPN, alpn_body)
    )
    hs = iter_handshakes(build_client_hello(extensions=extensions))[0]
    assert hs.supported_groups == [23, 29]
    assert hs.ec_point_formats == [0]
    assert hs.alpn == ["h2\x00"]


def test_ja3_string_matches_the_reference_layout():
    hs = iter_handshakes(build_client_hello(extensions=ext(EXT_EC_POINT_FORMATS, bytes([1, 0]))))[0]
    raw = ja3_string(hs)
    parts = raw.split(",")
    assert len(parts) == 5
    assert parts[0] == "771"  # TLS 1.2 in JA3's decimal encoding
    assert parts[1] == "4865-4866-49199-49200"
    assert parts[2] == "0-11"  # server_name, ec_point_formats
    assert parts[4] == "0"


def test_ja3_md5_is_the_md5_of_the_raw_string():
    hs = iter_handshakes(build_client_hello())[0]
    result = fingerprint(hs)
    assert result["md5"] == hashlib.md5(result["raw"].encode()).hexdigest()
    assert result["reliable"] is True


def test_grease_values_are_excluded_from_ja3():
    grease = 0x0A0A
    hs = iter_handshakes(build_client_hello(ciphers=(grease, 0x1301)))[0]
    raw = ja3_string(hs)
    assert str(grease) not in raw
    assert "4865" in raw


def test_tls13_version_encoding():
    hs = iter_handshakes(build_client_hello(version=0x0304))[0]
    assert ja3_string(hs).split(",")[0] == "772"


def test_truncated_client_hello_is_reported_as_unreliable():
    data = build_client_hello()
    result = summarise_handshakes(data[:40])
    assert result, "a truncated ClientHello must still surface a diagnostic"
    assert result[0]["md5"] is None
    assert result[0]["reliable"] is False
    assert "cannot be computed reliably" in result[0]["reason_if_unreliable"]


def test_server_hello_produces_ja3s():
    hs = iter_handshakes(build_server_hello())[0]
    assert hs.kind == "server_hello"
    raw = ja3s_string(hs)
    assert raw == "771,4865,"
    result = fingerprint(hs)
    assert result["kind"] == "JA3S"
    assert result["md5"] == hashlib.md5(raw.encode()).hexdigest()


def test_ja3_is_rejected_for_a_server_hello():
    hs = iter_handshakes(build_server_hello())[0]
    with pytest.raises(ValueError):
        ja3_string(hs)


def test_unknown_fingerprint_is_reported_as_unknown_not_malicious():
    result = summarise_handshakes(build_client_hello())[0]
    match = result["match"]
    assert match["family"] is None
    assert "never an indication of maliciousness" in match["interpretation"]


def test_known_fingerprint_lookup_returns_the_local_entry():
    entry = lookup("b32309a26951912be7ba376398abc3", "JA3")
    assert entry is None or entry["family"] is None
    # Look up a hash that is present in the local table.
    from app.analyzers.tls_fingerprinting import FINGERPRINT_DB

    known = FINGERPRINT_DB[0]
    match = lookup(known.fingerprint, known.kind)
    assert match["family"] == known.family
    assert "not proof" in match["interpretation"]


def test_every_database_entry_carries_a_presentation_category():
    """The category is a client class for the UI, never a safety judgement."""
    from app.analyzers.tls_fingerprinting import FINGERPRINT_DB

    allowed = {"browser", "library", "bot", "server", "unknown"}
    for entry in FINGERPRINT_DB:
        assert entry.category in allowed
        match = lookup(entry.fingerprint, entry.kind)
        assert match["category"] == entry.category
    unknown = lookup("0" * 32, "JA3")
    assert unknown["category"] == "unknown"


def test_non_tls_input_is_ignored():
    data = build_client_hello()
    assert iter_handshakes(bytes([0x00, 0x11, 0x22, 0x33]) * 40) == []


def test_fingerprint_of_an_empty_handshake_is_marked_unreliable():
    hs = TlsHandshake(kind="client_hello")
    result = fingerprint(hs)
    assert result["md5"] is None
    assert result["reliable"] is False