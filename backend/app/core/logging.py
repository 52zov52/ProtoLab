"""Logging with redaction plus the tamper-evident audit log.

Two separate sinks:

* ``logging`` - human/operational logs.  Payload bytes, key logs, tokens and
  secrets never reach it (see :func:`redact`).
* ``AuditLog`` - structured security events stored in SQLite with a hash chain
  so accidental or naive modification is detectable.

The hash chain is explicitly *not* tamper-proof against a local administrator
who can rewrite both the rows and the chain state; see docs/SECURITY.md.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|key[_ -]?log|authorization|cookie|credential|"
    r"client_secret|api[_-]?key|private[_-]?key|session[_ -]?id)",
    re.IGNORECASE,
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")
_KEYLOG_LINE = re.compile(
    r"\b(?:CLIENT_RANDOM|(?:CLIENT|SERVER)_(?:HANDSHAKE_)?TRAFFIC_SECRET_\d+|"
    r"(?:CLIENT|SERVER)_EARLY_TRAFFIC_SECRET_\d+|EXPORTER_SECRET|"
    r"(?:CLIENT_)?(?:RSA|ECDHE|DHE|PSK|MASTER)_[A-Z0-9_]*_[A-Z0-9_]+)"
    r"\s+[0-9a-fA-F]{32,}"
)

MASK = "***redacted***"


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively mask anything that looks like a secret.

    Best-effort by design: it protects against the common mistakes (logging a
    settings dict, a request body, a user-supplied note) rather than being a
    formal data-loss-prevention layer.
    """
    if _depth > 6:
        return MASK
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _SENSITIVE_KEY.search(key):
                out[key] = MASK
            else:
                out[key] = redact(item, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        return [redact(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        text = value
        text = _KEYLOG_LINE.sub("[keylog redacted]", text)
        text = _JWT.sub("[jwt redacted]", text)
        if len(text) > 256 and _HEX_BLOB.search(text):
            text = _HEX_BLOB.sub("[hex redacted]", text)
        return text
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D102
        try:
            record.msg = redact(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = redact(record.args)
                else:
                    record.args = tuple(redact(record.args))
        except Exception:  # pragma: no cover - logging must never explode
            record.msg = "[log redaction failed]"
            record.args = ()
        return True


_CONFIGURED = False


def configure_logging(level: str | None = None) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    resolved = (level or os.environ.get("MPLAB_LOG_LEVEL") or "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(resolved)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def hash_chain(prev_hash: str, payload: Any) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(canonical_json(payload).encode("utf-8"))
    return digest.hexdigest()


GENESIS_HASH = "0" * 64


class AuditEvent:
    __slots__ = (
        "action",
        "outcome",
        "project_id",
        "object_type",
        "object_id",
        "actor",
        "details",
        "risk",
    )

    def __init__(
        self,
        action: str,
        *,
        outcome: str = "success",
        project_id: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        actor: str | None = None,
        details: dict[str, Any] | None = None,
        risk: str = "info",
    ) -> None:
        self.action = action
        self.outcome = outcome
        self.project_id = project_id
        self.object_type = object_type
        self.object_id = object_id
        self.actor = actor or "local-user"
        self.details = redact(details or {})
        self.risk = risk

    def payload(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "outcome": self.outcome,
            "project_id": self.project_id,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "actor": self.actor,
            "risk": self.risk,
            "details": self.details,
        }


SENSITIVE_ACTIONS: dict[str, str] = {
    "capture.import": "info",
    "capture.analyze": "info",
    "capture.delete": "warning",
    "project.create": "info",
    "project.delete": "warning",
    "project.export": "info",
    "project.import": "info",
    "project.integrity_check": "info",
    "interpretation.create": "info",
    "interpretation.update": "info",
    "interpretation.validate": "info",
    "hypothesis.update": "info",
    "keylog.import": "warning",
    "keylog.delete": "warning",
    "export.pcapng": "info",
    "report.generate": "info",
    "ai.external_call": "warning",
    "assistant.query": "info",
    "auth.login": "info",
    "auth.login_failed": "warning",
    "auth.logout": "info",
    "security.denied": "warning",
    "security.config_check": "info",
    "job.start": "info",
    "job.cancel": "warning",
    "job.complete": "info",
    "job.failed": "error",
}


def audit_action_name(action: str) -> str:
    return action if action in SENSITIVE_ACTIONS else action


def iter_risk_levels() -> Iterable[str]:
    return ("info", "warning", "error")