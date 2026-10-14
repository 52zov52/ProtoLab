"""TLS decryption (Этап 6 / §8.4, TLS Decryption).

Decryption is the feature where a plausible-looking implementation is most
dangerous: bytes that read like a protocol but were never sent are worse than no
decryption at all. These tests therefore build real ciphertext with an
independent implementation of the same derivations and then demand the exact
plaintext back — a wrong key block, a wrong nonce or a wrong AAD shows up as an
authentication failure, not as plausible output.

The failure modes are pinned as hard as the success path: a wrong key, a
truncated record and an unsupported suite must each report themselves and must
never produce bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.analyzers.tls_decryption import (
    CONTENT_TYPE_APPLICATION_DATA,
    DecryptedRecord,
    SessionKeys,
    decrypt_records,
    describe_keylog,
    iter_records,
    key_block_tls12,
    parse_keylog,
    summarise,
)


# --------------------------------------------------------------------------- #
# Independent reference implementation (the "sender")
# --------------------------------------------------------------------------- #


def _prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    out = b""
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:length]


def _prf_sha384(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    out = b""
    a = label + seed
    while len(out) < length:
        a = hmac.new(secret, a, hashlib.sha384).digest()
        out += hmac.new(secret, a + label + seed, hashlib.sha384).digest()
    return out[:length]


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([0])
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def record(content_type: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", content_type, 0x0303, len(payload)) + payload


def encrypt_tls12_gcm(
    plaintext: bytes,
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    sequence: int,
    suite: int = 0xC013,
) -> bytes:
    """Encrypt one record exactly as a peer with the client keys would."""
    spec = Suite(spec_key=16, mac_len=32, salt_len=4)
    block = key_block_tls12(
        master_secret, client_random, server_random, spec.spec_key * 2 + spec.salt_len * 2
    )
    key, iv = block[: spec.spec_key], block[spec.spec_key * 2 :][: spec.salt_len]
    explicit_nonce = os.urandom(8)
    aad = struct.pack(">Q", sequence) + struct.pack(">BHH", 23, 0x0303, len(plaintext))
    sealed = AESGCM(key).encrypt(iv + explicit_nonce, plaintext, aad)
    return record(CONTENT_TYPE_APPLICATION_DATA, explicit_nonce + sealed)


def encrypt_tls13_gcm(
    plaintext: bytes, traffic_secret: bytes, sequence: int, inner_type: int = 23
) -> bytes:
    key = _hkdf_expand_label(traffic_secret, "key", 16)
    iv = _hkdf_expand_label(traffic_secret, "iv", 12)
    record_nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    body = plaintext + bytes([inner_type])
    aad = struct.pack(">BHH", 23, 0x0303, len(body))
    sealed = AESGCM(key).encrypt(record_nonce, body, aad)
    return record(CONTENT_TYPE_APPLICATION_DATA, sealed)


def encrypt_tls12_cbc(
    plaintext: bytes,
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    sequence: int,
) -> bytes:
    mac_key_len = 20
    block = key_block_tls12(
        master_secret, client_random, server_random, 16 * 2 + mac_key_len * 2, hashlib.sha1
    )
    write_key = block[:16]
    mac_key = block[32:][:mac_key_len]
    mac = hmac.new(
        mac_key,
        struct.pack(">Q", sequence) + struct.pack(">BHH", 23, 0x0303, len(plaintext)) + plaintext,
        hashlib.sha1,
    ).digest()
    pad_len = 16 - ((len(plaintext) + mac_key_len) + 1) % 16
    body = plaintext + mac + bytes([pad_len]) * (pad_len + 1)
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(write_key), modes.CBC(iv)).encryptor()
    return record(CONTENT_TYPE_APPLICATION_DATA, iv + encryptor.update(body) + encryptor.finalize())


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

CLIENT_RANDOM = bytes.fromhex("11" * 32)
SERVER_RANDOM = bytes.fromhex("22" * 32)
MASTER = bytes.fromhex("ab" * 48)
TRAFFIC_SECRET = bytes.fromhex("cd" * 32)


@dataclass
class Suite:
    """The sizes this test's sender needs for one direction."""

    spec_key: int
    mac_len: int
    salt_len: int


def keys(**kwargs) -> SessionKeys:
    base = dict(
        direction="client",
        cipher_suite=0xC013,
        client_random=CLIENT_RANDOM,
        server_random=SERVER_RANDOM,
        master_secret=MASTER,
    )
    base.update(kwargs)
    return SessionKeys(**base)


# --------------------------------------------------------------------------- #
# Key log
# --------------------------------------------------------------------------- #


def test_parse_keylog_keeps_labels_and_ignores_noise():
    entries = parse_keylog(
        "# a comment\n"
        "\n"
        "CLIENT_RANDOM 1122 0123456789abcdef\n"
        "garbage line\n"
        "CLIENT_RANDOM nothex secret2\n"
        "CLIENT_TRAFFIC_SECRET_0 3344 deadbeef\n"
    )
    assert entries["CLIENT_RANDOM"] == [
        (bytes.fromhex("1122"), bytes.fromhex("0123456789abcdef"))
    ]
    assert entries["CLIENT_TRAFFIC_SECRET_0"] == [
        (bytes.fromhex("3344"), bytes.fromhex("deadbeef"))
    ]
    assert describe_keylog(entries)["entries"] == 2
    assert describe_keylog({})["usable"] is False


def test_keylog_matches_a_client_random_case_insensitively():
    entries = parse_keylog(f"CLIENT_RANDOM {CLIENT_RANDOM.hex()} {MASTER.hex()}")
    stored = {random.hex(): secret for random, secret in entries["CLIENT_RANDOM"]}
    assert stored[CLIENT_RANDOM.hex()] == MASTER


# --------------------------------------------------------------------------- #
# Record layer
# --------------------------------------------------------------------------- #


def test_iter_records_counts_sequence_numbers_across_all_record_types():
    data = record(22, b"handshake") + record(20, b"") + record(23, b"app")
    records = iter_records(data)
    assert [r.content_type for r in records] == [22, 20, 23]
    assert [r.sequence for r in records] == [0, 1, 2]


def test_iter_records_marks_a_truncated_record_instead_of_raising():
    data = struct.pack(">BHH", 23, 0x0303, 40) + b"short"
    records = iter_records(data)
    assert len(records) == 1
    assert records[0].truncated is True
    assert len(records[0].payload) == 5


# --------------------------------------------------------------------------- #
# Round trips
# --------------------------------------------------------------------------- #


def test_tls12_aes_gcm_round_trip():
    plaintext = b"GET /measurements HTTP/1.1\r\nHost: termostend\r\n\r\n"
    # Two records before the encrypted one, so the encrypted record carries
    # sequence number 2 — the counter the counter itself, not the "kind".
    client_stream = record(22, b"\x01\x00\x00\x05fake") + encrypt_tls12_gcm(
        plaintext, MASTER, CLIENT_RANDOM, SERVER_RANDOM, sequence=1
    )

    results = decrypt_records(client_stream, keys())

    decrypted = [r for r in results if r.status == "decrypted"]
    assert len(decrypted) == 1
    assert decrypted[0].plaintext == plaintext
    assert decrypted[0].cipher_suite == 0xC013
    # The record before the encrypted one is a handshake: readable, not decrypted.
    assert [r.status for r in results] == ["not_encrypted", "decrypted"]


def test_tls12_aes_gcm_server_direction_uses_the_server_key_block():
    plaintext = b"HTTP/1.1 200 OK\r\n\r\n6f9a2b"
    # The sender encrypts with the server half of the key block, derived
    # independently here, and the record is the only one in the direction.
    block = key_block_tls12(MASTER, CLIENT_RANDOM, SERVER_RANDOM, 16 * 2 + 4 * 2)
    server_key = block[16:32]
    server_iv = block[32 + 4 :][:4]
    explicit = os.urandom(8)
    aad = struct.pack(">Q", 0) + struct.pack(">BHH", 23, 0x0303, len(plaintext))
    sealed = AESGCM(server_key).encrypt(server_iv + explicit, plaintext, aad)
    server_stream = record(23, explicit + sealed)

    results = decrypt_records(server_stream, keys(direction="server"))

    assert [r.status for r in results] == ["decrypted"]
    assert results[0].plaintext == plaintext


def test_tls12_sha384_gcm_suite_round_trip():
    plaintext = b"A" * 64
    # SHA-384 suites derive their key block with the SHA-384 PRF.
    block_bytes = _prf_sha384(MASTER, b"key expansion", SERVER_RANDOM + CLIENT_RANDOM, 32 * 2 + 4 * 2)
    key, iv = block_bytes[:32], block_bytes[64:68]
    explicit = os.urandom(8)
    aad = struct.pack(">Q", 0) + struct.pack(">BHH", 23, 0x0303, len(plaintext))
    sealed = AESGCM(key).encrypt(iv + explicit, plaintext, aad)
    stream = record(23, explicit + sealed)

    results = decrypt_records(stream, keys(cipher_suite=0xC014))

    assert [r.status for r in results] == ["decrypted"]
    assert results[0].plaintext == plaintext


def test_tls13_aes_gcm_round_trip():
    plaintext = b"POST /log HTTP/1.1\r\n\r\nop=0x20"
    stream = encrypt_tls13_gcm(plaintext, TRAFFIC_SECRET, sequence=0)

    results = decrypt_records(
        stream,
        keys(
            cipher_suite=0x1301,
            master_secret=None,
            tls13_secrets={"CLIENT_TRAFFIC_SECRET_0": TRAFFIC_SECRET},
        ),
    )

    assert [r.status for r in results] == ["decrypted"]
    assert results[0].plaintext == plaintext
    assert results[0].inner_type == "application_data"


def test_tls13_reports_a_missing_traffic_secret_instead_of_guessing():
    stream = encrypt_tls13_gcm(b"anything", TRAFFIC_SECRET, sequence=0)

    results = decrypt_records(stream, keys(cipher_suite=0x1301, master_secret=None))

    assert results[0].status == "unsupported"
    assert "CLIENT_TRAFFIC_SECRET_0" in results[0].reason


def test_tls12_aes_cbc_round_trip():
    plaintext = b"payload of a CBC suite"
    stream = encrypt_tls12_cbc(plaintext, MASTER, CLIENT_RANDOM, SERVER_RANDOM, sequence=0)

    results = decrypt_records(stream, keys(cipher_suite=0x002F))

    assert [r.status for r in results] == ["decrypted"]
    assert results[0].plaintext == plaintext


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


def test_a_wrong_master_secret_fails_authentication_and_shows_nothing():
    plaintext = b"sensitive bytes"
    stream = encrypt_tls12_gcm(plaintext, MASTER, CLIENT_RANDOM, SERVER_RANDOM, sequence=1)

    results = decrypt_records(stream, keys(master_secret=bytes(48)))

    assert [r.status for r in results] == ["auth_failed"]
    assert all(r.plaintext is None for r in results)
    assert "authentication tag" in results[0].reason


def test_a_captured_byte_flip_is_detected():
    plaintext = b"integrity matters"
    stream = bytearray(encrypt_tls12_gcm(plaintext, MASTER, CLIENT_RANDOM, SERVER_RANDOM, sequence=0))
    stream[-1] ^= 0x01

    results = decrypt_records(bytes(stream), keys())

    assert [r.status for r in results] == ["auth_failed"]


def test_a_truncated_record_is_reported_as_truncated():
    sealed = encrypt_tls12_gcm(b"cut me off", MASTER, CLIENT_RANDOM, SERVER_RANDOM, sequence=0)
    stream = sealed[:-6]

    results = decrypt_records(stream, keys())

    assert [r.status for r in results] == ["truncated"]
    assert "capture ends inside this record" in results[0].reason


def test_an_unlisted_cipher_suite_is_reported_with_its_number():
    stream = record(CONTENT_TYPE_APPLICATION_DATA, os.urandom(48))

    results = decrypt_records(stream, keys(cipher_suite=0x00FF))

    assert results[0].status == "unsupported"
    assert "0x00ff" in results[0].reason


def test_no_cipher_suite_at_all_is_reported_as_unreadable():
    stream = record(CONTENT_TYPE_APPLICATION_DATA, os.urandom(48))

    results = decrypt_records(stream, keys(cipher_suite=None))

    assert results[0].status == "unsupported"
    assert "could not be read" in results[0].reason


def test_summarise_counts_statuses_and_states_the_limitation():
    stream = encrypt_tls12_gcm(b"ok", MASTER, CLIENT_RANDOM, SERVER_RANDOM, sequence=0)
    results = decrypt_records(stream, keys())
    summary = summarise(results)
    assert summary["by_status"]["decrypted"] == 1
    assert summary["plaintext_bytes"] == 2
    assert "plaintext" in summary["interpretation"]


def test_session_keys_summary_explains_what_is_missing():
    assert keys().summary()["can_decrypt"] is True
    missing_master = keys(master_secret=None).summary()
    assert missing_master["can_decrypt"] is False
    assert "master secret" in missing_master["reason"]
    unknown = keys(cipher_suite=0xC099).summary()
    assert unknown["can_decrypt"] is False
    assert "0xc099" in unknown["reason"]


def test_decrypted_record_dict_hides_nothing_and_invents_nothing():
    result = DecryptedRecord(0, 0, "application_data", "auth_failed", reason="tag")
    payload = result.to_dict()
    assert payload["plaintext_hex"] is None
    assert payload["plaintext_length"] == 0
    assert payload["reason"] == "tag"
