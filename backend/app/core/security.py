"""Defensive helpers: request guards, path safety, rate limiting.

These controls live in the backend process because the browser UI is not a
trust boundary (see docs/THREAT_MODEL.md).
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import threading
import time
import unicodedata
from collections import deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .errors import PayloadTooLarge, RateLimited, SecurityViolation

# --------------------------------------------------------------------------- #
# Host / Origin / DNS-rebinding protection
# --------------------------------------------------------------------------- #

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _normalise_host(value: str) -> str:
    host = value.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        return host
    return host


def extract_host(authority: str) -> str:
    """Strip the port from a Host header value."""
    authority = authority.strip()
    if authority.startswith("["):
        # IPv6 literal, possibly with port.
        end = authority.find("]")
        if end != -1:
            return authority[: end + 1]
    if ":" in authority:
        return authority.rsplit(":", 1)[0]
    return authority


def is_loopback_host(host: str) -> bool:
    host = _normalise_host(host)
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_host_header(host_header: str | None, allowed: list[str]) -> None:
    """Reject requests whose Host header is not on the allowlist.

    Blocking unknown Host values defeats DNS-rebinding attacks, where an
    attacker-controlled name resolves to 127.0.0.1 and the browser then talks
    to the local API with a foreign Origin.
    """
    if not host_header:
        raise SecurityViolation("Missing Host header.")
    if _CONTROL_CHARS.search(host_header):
        raise SecurityViolation("Malformed Host header.")
    host = _normalise_host(extract_host(host_header))
    allowed_normalised = {_normalise_host(extract_host(a)) for a in allowed}
    if host in allowed_normalised:
        return
    raise SecurityViolation(f"Host header {host!r} is not allowed.")


def origin_matches(origin: str, allowed_origins: list[str]) -> bool:
    if not origin:
        return False
    parts = urlsplit(origin)
    if parts.scheme not in {"http", "https"}:
        return False
    normalised = f"{parts.scheme}://{parts.netloc}".lower()
    return normalised in {o.rstrip('/').lower() for o in allowed_origins}


def is_cross_origin(origin: str | None, referer: str | None, allowed_origins: list[str]) -> bool:
    """True when the request appears to originate from a page we do not serve."""
    candidates = [c for c in (origin, referer) if c]
    if not candidates:
        return False
    return any(not origin_matches(c, allowed_origins) for c in candidates)


def request_host_is_loopback(host_header: str | None) -> bool:
    if not host_header:
        return True
    return is_loopback_host(extract_host(host_header))


# --------------------------------------------------------------------------- #
# Filesystem safety
# --------------------------------------------------------------------------- #

_UNSAFE_NAME_CHARS = re.compile(r'[<>:"|?*\x00-\x1f\x7f]')
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def safe_display_filename(raw: str | None, *, fallback: str = "upload") -> str:
    """Turn an untrusted upload name into a display-safe string.

    The result is only ever used for display and for generating a *suggested*
    name; stored files always get random server-side names.
    """
    if not raw:
        return fallback
    # Unicode normalisation first so look-alike traversal names collapse.
    name = unicodedata.normalize("NFKC", raw)
    name = name.replace("\\", "/").split("/")[-1]
    name = _CONTROL_CHARS.sub("", name)
    name = _UNSAFE_NAME_CHARS.sub("_", name)
    name = name.strip().strip(".")
    name = name.lstrip("-")
    if not name or name in {".", ".."}:
        return fallback
    stem = name.split(".")[0].lower()
    if stem in _WINDOWS_RESERVED:
        name = f"_{name}"
    return name[:200]


def validate_relative_path(candidate: str) -> PurePosixPath:
    """Validate an archive member path before it is ever joined to a root.

    Rejects absolute paths, drive letters, UNC paths, ``..`` traversal, control
    characters and empty components.
    """
    if not candidate or not candidate.strip():
        raise SecurityViolation("Archive entry has an empty name.")
    if len(candidate) > 1024:
        raise SecurityViolation("Archive entry name is too long.")
    if _CONTROL_CHARS.search(candidate):
        raise SecurityViolation("Archive entry name contains control characters.")
    if candidate.startswith("/") or candidate.startswith("\\"):
        raise SecurityViolation("Archive entry uses an absolute path.")
    if re.match(r"^[A-Za-z]:", candidate):
        raise SecurityViolation("Archive entry uses a drive letter.")
    normalised = unicodedata.normalize("NFC", candidate.replace("\\", "/"))
    parts = [p for p in normalised.split("/") if p not in ("", ".")]
    if not parts:
        raise SecurityViolation("Archive entry resolves to an empty path.")
    if any(p == ".." for p in parts):
        raise SecurityViolation("Archive entry escapes the archive root.")
    safe = PurePosixPath(*parts)
    if safe.is_absolute():  # pragma: no cover - belt and braces
        raise SecurityViolation("Archive entry uses an absolute path.")
    return safe


def resolve_within(root: Path, *relative: str) -> Path:
    """Join ``relative`` under ``root`` and prove the result stays inside."""
    root_resolved = root.resolve()
    candidate = root_resolved
    for part in relative:
        part = part.replace("\\", "/")
        candidate = candidate / part
    # ``strict=False`` so we can also validate not-yet-created destinations.
    resolved = Path(os.path.normpath(str(candidate)))
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise SecurityViolation("Resolved path escapes the managed storage root.") from exc
    return resolved


def assert_no_symlink(path: Path, stop_at: Path) -> None:
    """Refuse to read/write through a symlink chain inside managed storage."""
    stop = stop_at.resolve()
    current = Path(os.path.normpath(str(path)))
    while True:
        if current.exists() and current.is_symlink():
            raise SecurityViolation("Symlinks are not permitted in managed storage.")
        if current == stop or current.parent == current:
            return
        current = current.parent


def random_storage_name(prefix: str, suffix: str = "") -> str:
    token = os.urandom(16).hex()
    return f"{prefix}{token}{suffix}"


def sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Rate limiting (in-process token bucket; documented as local-mode only)
# --------------------------------------------------------------------------- #


@dataclass
class _Bucket:
    window_start: float
    events: deque[float]


class SlidingWindowLimiter:
    """Simple in-memory sliding-window limiter keyed by client identity.

    Scope: single process, local mode.  Documented as *not* a distributed
    control; a remote deployment must front the API with a real limiter.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = max(1, limit)
        self.window = max(1, window_seconds)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def check(self, key: str, *, cost: int = 1) -> None:
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            bucket = self._buckets.get(key)
            if bucket is None or now - bucket.window_start >= self.window:
                bucket = _Bucket(window_start=now, events=deque())
                self._buckets[key] = bucket
            if len(bucket.events) + cost > self.limit:
                retry_after = max(1.0, self.window - (now - bucket.window_start))
                raise RateLimited(
                    "Too many requests for this client.",
                    details={"retry_after_seconds": round(retry_after, 2)},
                )
            for _ in range(cost):
                bucket.events.append(now)

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < max(5.0, self.window / 2):
            return
        self._last_sweep = now
        cutoff = now - self.window
        stale = [k for k, b in self._buckets.items() if b.window_start < cutoff]
        for key in stale:
            self._buckets.pop(key, None)


class ConcurrencyGate:
    """Bounds the number of simultaneously running analysis jobs."""

    def __init__(self, maximum: int) -> None:
        self.maximum = max(1, maximum)
        self._active = 0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            if self._active >= self.maximum:
                raise RateLimited(
                    "Too many analysis jobs are already running.",
                    details={"maximum": self.maximum},
                )
            self._active += 1

    def release(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)

    @property
    def active(self) -> int:
        return self._active


def enforce_body_size(content_length: str | None, maximum: int) -> None:
    if content_length is None:
        return
    try:
        length = int(content_length)
    except ValueError:
        raise SecurityViolation("Invalid Content-Length header.") from None
    if length < 0:
        raise SecurityViolation("Invalid Content-Length header.")
    if length > maximum:
        raise PayloadTooLarge(
            "Request body exceeds the configured limit.",
            details={"limit_bytes": maximum, "received_bytes": length},
        )


def clamp_page(size: int | None, *, default: int, maximum: int) -> int:
    if size is None:
        return default
    if size <= 0:
        raise SecurityViolation("Page size must be positive.")
    return min(size, maximum)