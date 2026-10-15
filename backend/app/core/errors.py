"""Typed application errors.

Every failure the API can explain raises one of these instead of a bare
``Exception``, so the HTTP layer can return a stable machine-readable payload::

    {"error": {"code": "not_found", "message": "...", "details": {...}}}

The rules encoded here matter for the product claim "every conclusion is
traceable": a failure must never be swallowed into a partial result that looks
complete.  ``details`` carries the evidence an analyst needs to understand the
failure (which byte range, which packet, which limit).

Messages are written for the analyst reading the UI, not for a traceback
consumer: they never contain stack frames, filesystem paths outside managed
storage, or secret material.
"""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base class for every error the API reports deliberately.

    ``status_code`` is derived from ``code`` unless overridden.
    """

    code: str = "internal_error"
    status_code: int = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return {"error": payload}


class ValidationFailed(AppError):
    """The request or an imported document is structurally invalid."""

    code = "validation_failed"
    status_code = 400


class SemanticValidationFailed(AppError):
    """The request parses, but its contents are semantically invalid.

    Distinct from :class:`ValidationFailed` (400): here the request is
    well-formed HTTP/JSON but carries a value the domain rejects - an
    unparseable timestamp, a length field that cannot be satisfied.  FastAPI
    uses 422 for the same idea at the schema layer.
    """

    code = "semantic_validation_failed"
    status_code = 422


class NotFound(AppError):
    """The referenced object does not exist, or is not in this project.

    Also used for cross-project access attempts so an unauthorised lookup is
    indistinguishable from a missing object.
    """

    code = "not_found"
    status_code = 404


class Conflict(AppError):
    """The action contradicts current state (e.g. a duplicate capture)."""

    code = "conflict"
    status_code = 409


class LimitExceeded(AppError):
    """A configured ceiling was hit.

    Raised instead of truncating data, so the analyst is told the limit rather
    than silently shown a partial corpus.
    """

    code = "limit_exceeded"
    status_code = 413


class UnsupportedFormat(AppError):
    """The file or manifest is not a format this build can parse."""

    code = "unsupported_format"
    status_code = 415


class PayloadTooLarge(AppError):
    """A request or upload exceeded its size ceiling."""

    code = "payload_too_large"
    status_code = 413


class SecurityViolation(AppError):
    """A defensive control rejected the request.

    Covers Host/Origin policy, path traversal and archive-entry validation.
    """

    code = "security_violation"
    status_code = 403


class RateLimited(AppError):
    """Too many requests, or too many concurrent jobs."""

    code = "rate_limited"
    status_code = 429


class Canceled(AppError):
    """The operator cancelled a long-running job."""

    code = "canceled"
    status_code = 499


class DependencyUnavailable(AppError):
    """An optional dependency is not installed.

    Reported honestly rather than degrading silently: an anomaly model that
    cannot be trained must say so instead of returning invented scores.
    """

    code = "dependency_unavailable"
    status_code = 503


class AnalysisFailed(AppError):
    """Analysis could not complete; diagnostics are attached."""

    code = "analysis_failed"
    status_code = 422


class NotImplementedFeature(AppError):
    """A declared capability is deliberately absent in this build."""

    code = "not_implemented"
    status_code = 501


class InsufficientCorpus(ValidationFailed):
    """The request is well formed, but the corpus is too small to learn from.

    Its own type because the interface has to *react*, not just print: the
    numbers of what was needed and what was there belong in ``details`` so the
    message can be translated and paired with the action that would help.
    """

    code = "insufficient_corpus"
    status_code = 400


__all__ = [
    "AnalysisFailed",
    "AppError",
    "Canceled",
    "Conflict",
    "DependencyUnavailable",
    "InsufficientCorpus",
    "LimitExceeded",
    "NotFound",
    "NotImplementedFeature",
    "PayloadTooLarge",
    "RateLimited",
    "SemanticValidationFailed",
    "SecurityViolation",
    "UnsupportedFormat",
    "ValidationFailed",
]