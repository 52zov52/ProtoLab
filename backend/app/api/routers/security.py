"""Security Center endpoints.

These are thin HTTP wrappers over :mod:`app.api.security_center`, which owns
the checks.  The split keeps the verdict logic testable without a request and
avoids two implementations of the same security claims drifting apart.

Every check reports one of ``pass`` / ``fail`` / ``unknown`` / ``na``.  The API
never returns a green "secure" badge for a property that was not verified.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ...core.logging import AuditEvent, get_logger
from ...core.security import check_host_header, is_cross_origin
from ..context import ContextDep, SettingsDep, audit
from ..security_center import run_configuration_checks, runtime_report

router = APIRouter()
log = get_logger("mplab.api.security")


class HostHeaderRequest(BaseModel):
    host_header: str = Field(min_length=1, max_length=512)


class OriginRequest(BaseModel):
    origin: str = Field(min_length=1, max_length=512)
    referer: str | None = Field(default=None, max_length=512)


def _sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401
    except Exception:
        return False
    return True


@router.post("/security/check")
def security_check(context: ContextDep, settings: SettingsDep) -> dict[str, Any]:
    """Run the local configuration checks and report real verdicts.

    Not a penetration test: the response says so in ``security_checks.scope``.
    """
    from ...reporting.llm import status as llm_status

    context_session = context.open_session()
    try:
        audit(context_session).record(
            AuditEvent(
                "security.config_check",
                object_type="security",
                object_id="configuration",
                details={"scope": "local configuration checks"},
            )
        )
        context_session.commit()
    except Exception:  # pragma: no cover - auditing must not break the check
        context_session.rollback()
        log.exception("could not record the security configuration check")

    return runtime_report(
        settings,
        engine=context.engine,
        llm_status=llm_status(settings),
        sklearn=_sklearn_available(),
    )


@router.get("/security/report")
def security_report(context: ContextDep, settings: SettingsDep) -> dict[str, Any]:
    """The Security Center payload without running any mutation.

    Read-only counterpart of ``POST /security/check`` so the panel can render
    on load without recording an audit event every time it is opened.
    """
    from ...reporting.llm import status as llm_status

    return runtime_report(
        settings,
        engine=context.engine,
        llm_status=llm_status(settings),
        sklearn=_sklearn_available(),
    )


@router.get("/security/summary")
def security_summary(context: ContextDep, settings: SettingsDep) -> dict[str, Any]:
    """Just the verdicts, for a compact status panel."""
    report = run_configuration_checks(settings, engine=context.engine)
    return {"summary": report["summary"], "checked_at": report["checked_at"]}


@router.post("/security/host-header")
def validate_host_header(payload: HostHeaderRequest, settings: SettingsDep) -> dict[str, Any]:
    """Explain whether a given Host header would be accepted.

    Used by the Security Center so the analyst can see *why* a host is refused
    rather than guessing.
    """
    try:
        check_host_header(payload.host_header, list(settings.allowed_hosts))
    except Exception as exc:
        return {
            "valid": False,
            "host_header": payload.host_header,
            "code": "security_violation",
            "message": str(exc),
            "allowed_hosts": list(settings.allowed_hosts),
        }
    return {
        "valid": True,
        "host_header": payload.host_header,
        "code": "ok",
        "message": "Host header is on the allowlist.",
        "allowed_hosts": list(settings.allowed_hosts),
    }


@router.post("/security/origin")
def validate_origin(payload: OriginRequest, settings: SettingsDep) -> dict[str, Any]:
    """Explain whether a browser origin would be treated as cross-origin."""
    cross = is_cross_origin(payload.origin, payload.referer, list(settings.frontend_origins))
    return {
        "valid": not cross,
        "cross_origin": cross,
        "origin": payload.origin,
        "referer": payload.referer,
        "frontend_origins": list(settings.frontend_origins),
        "message": (
            "The origin is not on the allowlist, so a browser request from it would be "
            "rejected."
            if cross
            else "The origin matches an allowed frontend origin."
        ),
    }


__all__ = ["router"]