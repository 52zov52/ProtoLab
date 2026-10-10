"""JWT inspection.

Decoding is not verification.  This module parses the structure, reports the
algorithm *name* it saw, and explicitly refuses to imply that a token is
authentic.  Signature verification is out of scope: it needs the issuer's key,
which the product deliberately does not assume it has.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from typing import Any

#: Header ``alg`` values that mean "the token carries no signature".
UNSIGNED_ALGORITHMS = {"none", "None", "NONE"}

MAX_TOKEN_LENGTH = 8192


def _b64url_decode(segment: str) -> bytes | None:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError):
        return None


def looks_like_jwt(value: str) -> bool:
    if not isinstance(value, str) or len(value) > MAX_TOKEN_LENGTH:
        return False
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return all(part and _is_b64url(part) for part in parts)


def _is_b64url(segment: str) -> bool:
    return all(ch.isalnum() or ch in "-_" for ch in segment)


def extract_jwt_claims(token: str) -> dict[str, Any] | None:
    """Return ``{header, payload, algorithm}`` or ``None`` if unparseable."""
    if not looks_like_jwt(token):
        return None
    raw_header, raw_payload, _signature = token.split(".", 2)
    header_bytes = _b64url_decode(raw_header)
    payload_bytes = _b64url_decode(raw_payload)
    if header_bytes is None or payload_bytes is None:
        return None
    try:
        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {
        "header": header,
        "payload": payload,
        "algorithm": header.get("alg"),
        "unsigned": header.get("alg") in UNSIGNED_ALGORITHMS,
    }


def scan_for_jwt(data: bytes, *, max_hits: int = 20) -> list[dict[str, Any]]:
    """Find JWT-shaped substrings in plaintext bytes.

    Only plaintext is scanned.  The caller is responsible for not pointing this
    at encrypted payloads and saying so.
    """
    if not data:
        return []
    try:
        text = data.decode("latin-1")
    except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
        return []
    hits: list[dict[str, Any]] = []
    tokens = re_findall_tokens(text)
    for token in tokens[:max_hits]:
        claims = extract_jwt_claims(token)
        if claims is None:
            continue
        payload = claims["payload"]
        expires = payload.get("exp")
        entry: dict[str, Any] = {
            "offset": text.index(token),
            "length": len(token),
            "algorithm": claims["algorithm"],
            "unsigned": claims["unsigned"],
            "claim_keys": sorted(payload)[:32],
            "signature_verified": False,
        }
        if isinstance(expires, (int, float)):
            entry["exp"] = expires
            entry["expired"] = time.time() >= float(expires)
        hits.append(entry)
    return hits


def re_findall_tokens(text: str) -> list[str]:
    import re

    return re.findall(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*", text)


def find_jwt_in_http(payload: bytes) -> dict[str, Any] | None:
    """Look for a bearer token in HTTP headers or a JSON body."""
    if not payload:
        return None
    try:
        text = payload.decode("latin-1")
    except UnicodeDecodeError:  # pragma: no cover
        return None
    lowered = text.lower()
    for marker in ("authorization:", "bearer ", '"access_token"', '"id_token"'):
        index = lowered.find(marker)
        if index < 0:
            continue
        window = text[index : index + 4096]
        tokens = re_findall_tokens(window)
        if tokens:
            return {"marker": marker, "offset": index, "token_length": len(tokens[0])}
    return None