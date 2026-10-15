"""TLS decryption from a key log (SSLKEYLOGFILE).

The product's promise is that a claim can always be traced to the bytes it came
from. Decryption is where that promise is *most* earnable and *most* often
broken, so every failure path here is explicit and named: a record that cannot
be opened is reported as such and no plaintext is invented for it.

What this module supports
-------------------------
* **TLS 1.2**, given ``CLIENT_RANDOM`` and the master secret: the key block is
  derived with the TLS 1.2 PRF (RFC 5246 §6.3); AES-GCM (RFC 5288) and
  AES-CBC + HMAC (RFC 5246 §6.2.3.2) records are opened.
* **TLS 1.3**, given the traffic secrets the key log already carries: the record
  key and IV are derived with HKDF-Expand-Label (RFC 8446 §7.1) and the
  per-record nonce is the IV XOR the sequence number (RFC 8446 §5.2.3).

What it refuses, on the record
------------------------------
* A suite outside the table above: ``unsupported`` with the suite and why.
* An authentication failure: ``auth_failed``. For AEAD, decryption *is*
  authentication, so a failed tag means these bytes were not produced by the
  session we think — nothing is rendered.
* A truncated record: ``truncated`` — the capture ended inside it.
* A non-application record: ``not_encrypted`` — handshakes and alerts are
  already readable and saying so keeps the caller from having to guess.

The key log is only ever read from a file the operator supplies. Nothing here
retrieves, derives or stores a private key.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from typing import Literal

Direction = Literal["client", "server"]

CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
CONTENT_TYPE_ALERT = 21
CONTENT_TYPE_HANDSHAKE = 22
CONTENT_TYPE_APPLICATION_DATA = 23

CONTENT_TYPE_NAMES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}

TAG_LENGTH = 16
NONCE_LENGTH = 12


class UnsupportedSuite(ValueError):
    """The suite is known but cannot be decrypted here."""

    def __init__(self, suite: int, reason: str) -> None:
        super().__init__(f"cipher suite 0x{suite:04x}: {reason}")
        self.suite = suite
        self.reason = reason


class CryptoUnavailable(RuntimeError):
    """This build has no AEAD backend, so nothing can be opened.

    Named separately from a per-record failure because it is not about the
    traffic: it is a missing dependency, and the caller has to say *that* rather
    than reporting every record as "auth_failed" (which would be a lie: nothing
    was even attempted).
    """


def require_crypto() -> None:
    """Fail loudly and specifically when the crypto backend is absent."""
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise CryptoUnavailable(
            "The 'cryptography' package is not installed, so TLS application "
            "records cannot be decrypted in this deployment."
        ) from exc


# --------------------------------------------------------------------------- #
# Record layer
# --------------------------------------------------------------------------- #


@dataclass
class TlsRecord:
    content_type: int
    legacy_version: int
    payload: bytes
    offset_in_stream: int
    length: int
    sequence: int
    truncated: bool


def iter_records(data: bytes, base_offset: int = 0) -> list[TlsRecord]:
    """Walk the record layer, counting the per-direction sequence number.

    The counter starts at 0 on the first record of the direction and counts
    *every* record — ClientHello, alerts and change-cipher-spec included —
    because that is the number the AEAD nonce and the CBC HMAC cover.
    """
    out: list[TlsRecord] = []
    cursor = 0
    sequence = 0
    while cursor + 5 <= len(data):
        content_type, legacy_version, length = struct.unpack_from(">BHH", data, cursor)
        end = cursor + 5 + length
        truncated = end > len(data)
        out.append(
            TlsRecord(
                content_type=content_type,
                legacy_version=legacy_version,
                payload=data[cursor + 5 : min(end, len(data))],
                offset_in_stream=base_offset + cursor,
                length=5 + min(length, max(0, len(data) - cursor - 5)),
                sequence=sequence,
                truncated=truncated,
            ),
        )
        sequence += 1
        if truncated:
            break
        cursor = end
    return out


# --------------------------------------------------------------------------- #
# Key log
# --------------------------------------------------------------------------- #


def parse_keylog(text: str) -> dict[str, list[tuple[bytes, bytes]]]:
    """Parse an SSLKEYLOGFILE into ``label -> [(client_random, secret)]``.

    The format is ``LABEL <client_random hex> <secret hex>``. Comments and blank
    lines are ignored, as in NSS' own parser, and a line that is not that shape
    is skipped rather than refusing the whole file: one odd line should not
    discard the keys that are usable.
    """
    entries: dict[str, list[tuple[bytes, bytes]]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, random_hex, secret_hex = parts
        try:
            client_random = bytes.fromhex(random_hex)
            secret = bytes.fromhex(secret_hex)
        except ValueError:
            continue
        if not client_random or not secret:
            continue
        entries.setdefault(label.strip(), []).append((client_random, secret))
    return entries


def describe_keylog(entries: dict[str, list[tuple[bytes, bytes]]]) -> dict[str, object]:
    """A non-secret summary of what a key log carries."""
    return {
        "labels": {label: len(values) for label, values in sorted(entries.items())},
        "entries": sum(len(values) for values in entries.values()),
        "usable": any(values for values in entries.values()),
    }


# --------------------------------------------------------------------------- #
# TLS 1.2 PRF and key block
# --------------------------------------------------------------------------- #


def _p_hash(secret: bytes, seed: bytes, digest, length: int) -> bytes:
    """P_hash (RFC 5246 section 5), truncated to `length` bytes.

    The loop bound is the requested length, not a fixed block count: a SHA-384
    key block for an AES-256-GCM suite is longer than the digest block, and
    stopping early silently truncated it.
    """
    out = b""
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, digest).digest()
        out += hmac.new(secret, a + seed, digest).digest()
    return out[:length]


def prf_12(secret: bytes, label: bytes, seed: bytes, length: int, digest) -> bytes:
    """The TLS 1.2 PRF (RFC 5246 §5) for the given hash."""
    return _p_hash(secret, label + seed, digest, length)


def _prf_sha256(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    return prf_12(secret, label, seed, length, hashlib.sha256)


def key_block_tls12(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    length: int,
    digest=hashlib.sha256,
) -> bytes:
    return prf_12(master_secret, b"key expansion", server_random + client_random, length, digest)


# --------------------------------------------------------------------------- #
# TLS 1.3 HKDF
# --------------------------------------------------------------------------- #


def _hkdf_expand_label(
    secret: bytes, label: str, context: bytes, length: int, digest=hashlib.sha256
) -> bytes:
    """HKDF-Expand-Label (RFC 8446 §7.1)."""
    full_label = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + bytes([len(full_label)]) + full_label
    info += bytes([len(context)]) + context
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), digest).digest()
        out += block
        counter += 1
    return out[:length]


# --------------------------------------------------------------------------- #
# Suites
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class TLS12Suite:
    """What a TLS 1.2 suite needs from the key block."""

    key_len: int
    mac_len: int
    bulk: str  # aes_gcm | aes_cbc
    hash: object  # the PRF/MAC hash
    salt_len: int  # implicit IV for AEAD; AES-CBC carries an explicit one


# suite -> TLS12Suite. The salt length is the implicit IV for AEAD; AES-CBC
# carries an explicit IV per record and therefore has none.
TLS12_SUITES: dict[int, "TLS12Suite"] = {
    0x002F: TLS12Suite(16, 20, "aes_cbc", hashlib.sha1, 0),
    0x0035: TLS12Suite(32, 20, "aes_cbc", hashlib.sha1, 0),
    0x003C: TLS12Suite(16, 32, "aes_cbc", hashlib.sha256, 0),
    0x009C: TLS12Suite(16, 32, "aes_gcm", hashlib.sha256, 4),
    0x009D: TLS12Suite(32, 48, "aes_gcm", hashlib.sha384, 4),
    0xC013: TLS12Suite(16, 32, "aes_gcm", hashlib.sha256, 4),
    0xC014: TLS12Suite(32, 48, "aes_gcm", hashlib.sha384, 4),
    0xC02B: TLS12Suite(16, 32, "aes_gcm", hashlib.sha256, 4),
    0xC02C: TLS12Suite(32, 48, "aes_gcm", hashlib.sha384, 4),
}

# suite -> (key_len, bulk_aead, hkdf hash)
TLS13_SUITES: dict[int, tuple[int, str, object]] = {
    0x1301: (16, "aes_gcm", hashlib.sha256),  # TLS_AES_128_GCM_SHA256
    0x1302: (32, "aes_gcm", hashlib.sha384),  # TLS_AES_256_GCM_SHA384
    0x1303: (32, "chacha20", hashlib.sha256),  # TLS_CHACHA20_POLY1305_SHA256
}

SUITE_NAMES = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

TLS13_SECRET_LABELS = {
    "client": "CLIENT_TRAFFIC_SECRET_0",
    "server": "SERVER_TRAFFIC_SECRET_0",
}

RecordStatus = Literal[
    "decrypted",
    "unsupported",
    "auth_failed",
    "truncated",
    "not_encrypted",
]


@dataclass
class DecryptedRecord:
    sequence: int
    offset_in_stream: int
    content_type: str
    status: RecordStatus
    plaintext: bytes | None = None
    inner_type: str | None = None
    cipher_suite: int | None = None
    cipher_suite_name: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "offset_in_stream": self.offset_in_stream,
            "content_type": self.content_type,
            "status": self.status,
            "plaintext_hex": self.plaintext.hex() if self.plaintext else None,
            "plaintext_length": len(self.plaintext) if self.plaintext else 0,
            "inner_type": self.inner_type,
            "cipher_suite": self.cipher_suite,
            "cipher_suite_name": self.cipher_suite_name,
            "reason": self.reason,
        }


@dataclass
class SessionKeys:
    """What is needed to open one direction of one session."""

    direction: Direction
    cipher_suite: int | None = None
    client_random: bytes | None = None
    master_secret: bytes | None = None
    server_random: bytes | None = None
    tls13_secrets: dict[str, bytes] = field(default_factory=dict)
    note: str | None = None

    def summary(self) -> dict[str, object]:
        """A non-secret view: what is available and what is missing."""
        suite = self.cipher_suite
        if suite is None:
            reason = "the negotiated cipher suite could not be read from the capture"
        elif suite in TLS12_SUITES:
            reason = None if self.master_secret else "no master secret in the key log"
        elif suite in TLS13_SUITES:
            reason = None if self._tls13_secret() else f"no {self._tls13_label()} in the key log"
        else:
            reason = f"cipher suite 0x{suite:04x} is not one this build decrypts"
        return {
            "direction": self.direction,
            "cipher_suite": suite,
            "cipher_suite_name": SUITE_NAMES.get(suite or 0),
            "algorithm": self.algorithm(),
            "can_decrypt": reason is None,
            "reason": reason,
            "note": self.note,
        }

    def algorithm(self) -> str:
        suite = self.cipher_suite or 0
        if suite in TLS12_SUITES:
            return f"tls1.2/{TLS12_SUITES[suite].bulk}"
        if suite in TLS13_SUITES:
            return f"tls1.3/{TLS13_SUITES[suite][1]}"
        return "unknown"

    def _tls13_label(self) -> str:
        return TLS13_SECRET_LABELS[self.direction]

    def _tls13_secret(self) -> bytes | None:
        return self.tls13_secrets.get(self._tls13_label())


# --------------------------------------------------------------------------- #
# Openers
# --------------------------------------------------------------------------- #


def _open_aead(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes, chacha: bool
) -> bytes | None:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        if chacha:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag:
        return None


def _decrypt_tls12_gcm(record: TlsRecord, keys: SessionKeys, key: bytes, iv: bytes) -> DecryptedRecord:
    suite = keys.cipher_suite or 0
    body = record.payload
    if len(body) < 8 + TAG_LENGTH:
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            "application_data",
            "truncated",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite),
            reason="the record is too short to hold an explicit nonce and a tag",
        )
    explicit_nonce, sealed = body[:8], body[8:]
    nonce = iv + explicit_nonce
    assert len(nonce) == NONCE_LENGTH
    aad = struct.pack(">Q", record.sequence) + struct.pack(">BHH", 23, 0x0303, len(sealed) - TAG_LENGTH)
    plaintext = _open_aead(
        key, nonce, sealed[:-TAG_LENGTH], sealed[-TAG_LENGTH:], aad, chacha=False
    )
    return _aead_outcome(record, keys, plaintext, inner_type="application_data")


def _decrypt_tls13(record: TlsRecord, keys: SessionKeys) -> DecryptedRecord:
    suite = keys.cipher_suite or 0
    key_len, aead, digest = TLS13_SUITES[suite]
    secret = keys._tls13_secret()
    if secret is None:
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            "application_data",
            "unsupported",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite),
            reason=f"the key log carries no {keys._tls13_label()} for this session",
        )
    body = record.payload
    if len(body) < TAG_LENGTH:
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            "application_data",
            "truncated",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite),
            reason="the record is too short to hold an authentication tag",
        )
    write_key = _hkdf_expand_label(secret, "key", b"", key_len, digest)
    write_iv = _hkdf_expand_label(secret, "iv", b"", NONCE_LENGTH, digest)
    nonce = bytes(a ^ b for a, b in zip(write_iv, record.sequence.to_bytes(12, "big")))
    aad = struct.pack(">BHH", 23, 0x0303, len(body) - TAG_LENGTH)
    plaintext = _open_aead(
        write_key,
        nonce,
        body[:-TAG_LENGTH],
        body[-TAG_LENGTH:],
        aad,
        chacha=aead == "chacha20",
    )
    if not plaintext:
        return _aead_outcome(record, keys, None)
    return DecryptedRecord(
        record.sequence,
        record.offset_in_stream,
        "application_data",
        "decrypted",
        plaintext=plaintext[:-1],
        inner_type=CONTENT_TYPE_NAMES.get(plaintext[-1], f"0x{plaintext[-1]:02x}"),
        cipher_suite=suite,
        cipher_suite_name=SUITE_NAMES.get(suite),
    )


def _decrypt_tls12_cbc(
    record: TlsRecord, keys: SessionKeys, mac_key: bytes, key: bytes
) -> DecryptedRecord:
    """AES-CBC + HMAC (RFC 5246 §6.2.3.2)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    suite = keys.cipher_suite or 0
    spec = TLS12_SUITES[suite]
    body = record.payload
    # The record carries an explicit 16-byte IV, so it must be at least a whole
    # number of 16-byte blocks and long enough for that IV plus one block.
    if not body or len(body) % 16 or len(body) < 32:
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            "application_data",
            "truncated",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite),
            reason="the record is not a whole number of cipher blocks plus an explicit IV",
        )
    iv, ciphertext = body[:16], body[16:]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # PKCS#7 padding is the last thing stripped, and a bad pad means these bytes
    # are not what they claim to be.
    pad_len = padded[-1] if padded else 0
    # The padding is `pad_len + 1` bytes: the pad bytes plus the length byte.
    if pad_len > 16 or len(padded) < pad_len + 1 + spec.mac_len:
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            "application_data",
            "auth_failed",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite),
            reason="the padding after decryption is invalid, so the bytes are not from this session",
        )
    fragment = padded[: len(padded) - (pad_len + 1)]
    mac, plaintext = fragment[-spec.mac_len :], fragment[: -spec.mac_len]
    expected = _cbc_mac(spec.hash, mac_key, record.sequence, plaintext)
    if not hmac.compare_digest(mac, expected):
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            "application_data",
            "auth_failed",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite),
            reason="the record MAC did not verify, so the bytes were modified or the keys are wrong",
        )
    return DecryptedRecord(
        record.sequence,
        record.offset_in_stream,
        "application_data",
        "decrypted",
        plaintext=plaintext,
        inner_type="application_data",
        cipher_suite=suite,
        cipher_suite_name=SUITE_NAMES.get(suite),
    )


def _cbc_mac(digest, mac_key: bytes, sequence: int, plaintext: bytes) -> bytes:
    """TLS 1.2 MAC over the record header and fragment (RFC 5246 §6.2.3.1)."""
    header = struct.pack(">Q", sequence) + struct.pack(">BHH", 23, 0x0303, len(plaintext))
    return hmac.new(mac_key, header + plaintext, digest).digest()


def _aead_outcome(
    record: TlsRecord, keys: SessionKeys, plaintext: bytes | None, inner_type: str | None = "application_data"
) -> DecryptedRecord:
    suite = keys.cipher_suite or 0
    if plaintext is None:
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            "application_data",
            "auth_failed",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite),
            reason="the authentication tag did not verify with these keys and this sequence number",
        )
    return DecryptedRecord(
        record.sequence,
        record.offset_in_stream,
        "application_data",
        "decrypted",
        plaintext=plaintext,
        inner_type=inner_type,
        cipher_suite=suite,
        cipher_suite_name=SUITE_NAMES.get(suite),
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def _direction_keys_tls12(keys: SessionKeys) -> tuple[bytes, bytes, bytes]:
    """(write key, write iv, mac key) for the session's direction."""
    suite = keys.cipher_suite or 0
    spec = TLS12_SUITES[suite]
    block = key_block_tls12(
        keys.master_secret or b"",
        keys.client_random or b"",
        keys.server_random or b"",
        spec.key_len * 2 + spec.salt_len * 2 + spec.mac_len * 2,
        spec.hash,
    )
    if keys.direction == "client":
        write_key = block[: spec.key_len]
        write_iv = block[spec.key_len * 2 : spec.key_len * 2 + spec.salt_len]
        mac_key = block[spec.key_len * 2 + spec.salt_len * 2 :][: spec.mac_len]
    else:
        write_key = block[spec.key_len : spec.key_len * 2]
        write_iv = block[
            spec.key_len * 2 + spec.salt_len : spec.key_len * 2 + spec.salt_len * 2
        ]
        mac_key = block[spec.key_len * 2 + spec.salt_len * 2 + spec.mac_len :][: spec.mac_len]
    return write_key, write_iv, mac_key


def decrypt_records(
    data: bytes,
    keys: SessionKeys,
    base_offset: int = 0,
) -> list[DecryptedRecord]:
    """Decrypt every application-data record of one direction, honestly."""
    require_crypto()
    suite = keys.cipher_suite
    records = iter_records(data, base_offset)
    if suite is None:
        return [_unsupported(record, suite, "the negotiated cipher suite could not be read from the capture") for record in records]
    if suite not in TLS12_SUITES and suite not in TLS13_SUITES:
        return [
            _unsupported(record, suite, f"cipher suite 0x{suite:04x} is not one this build decrypts")
            for record in records
        ]

    tls13 = suite in TLS13_SUITES
    write_key = write_iv = mac_key = b""
    if not tls13:
        write_key, write_iv, mac_key = _direction_keys_tls12(keys)

    out: list[DecryptedRecord] = []
    for record in records:
        if record.content_type != CONTENT_TYPE_APPLICATION_DATA:
            out.append(
                DecryptedRecord(
                    record.sequence,
                    record.offset_in_stream,
                    CONTENT_TYPE_NAMES.get(record.content_type, f"0x{record.content_type:02x}"),
                    "truncated" if record.truncated else "not_encrypted",
                    cipher_suite=suite,
                    cipher_suite_name=SUITE_NAMES.get(suite),
                    reason=(
                        "the capture ends inside this record" if record.truncated else None
                    ),
                ),
            )
            continue
        if record.truncated:
            out.append(
                DecryptedRecord(
                    record.sequence,
                    record.offset_in_stream,
                    "application_data",
                    "truncated",
                    cipher_suite=suite,
                    cipher_suite_name=SUITE_NAMES.get(suite),
                    reason="the capture ends inside this record",
                ),
            )
            continue
        if tls13:
            out.append(_decrypt_tls13(record, keys))
            continue
        if TLS12_SUITES[suite].bulk == "aes_cbc":
            out.append(_decrypt_tls12_cbc(record, keys, mac_key, write_key))
        else:
            out.append(_decrypt_tls12_gcm(record, keys, write_key, write_iv))
    return out


def _unsupported(record: TlsRecord, suite: int | None, reason: str) -> DecryptedRecord:
    if record.content_type != CONTENT_TYPE_APPLICATION_DATA:
        return DecryptedRecord(
            record.sequence,
            record.offset_in_stream,
            CONTENT_TYPE_NAMES.get(record.content_type, f"0x{record.content_type:02x}"),
            "truncated" if record.truncated else "not_encrypted",
            cipher_suite=suite,
            cipher_suite_name=SUITE_NAMES.get(suite or 0),
            reason=(
                "the capture ends inside this record" if record.truncated else None
            ),
        )
    return DecryptedRecord(
        record.sequence,
        record.offset_in_stream,
        "application_data",
        "truncated" if record.truncated else "unsupported",
        cipher_suite=suite,
        cipher_suite_name=SUITE_NAMES.get(suite or 0),
        reason="the capture ends inside this record" if record.truncated else reason,
    )


def summarise(results: list[DecryptedRecord]) -> dict[str, object]:
    """Counts by status, the plaintext total and the reasons recorded."""
    by_status: dict[str, int] = {}
    reasons: dict[str, int] = {}
    plaintext_bytes = 0
    for result in results:
        by_status[result.status] = by_status.get(result.status, 0) + 1
        if result.plaintext:
            plaintext_bytes += len(result.plaintext)
        if result.reason:
            reasons[result.reason] = reasons.get(result.reason, 0) + 1
    return {
        "records": len(results),
        "by_status": by_status,
        "plaintext_bytes": plaintext_bytes,
        "reasons": reasons,
        "interpretation": (
            "Decrypted bytes are exactly what the peer sent, proven by the "
            "authentication of the negotiated cipher suite. A record reported as "
            "auth_failed, unsupported or truncated has no plaintext shown, and "
            "nothing is ever rendered in its place."
        ),
    }

