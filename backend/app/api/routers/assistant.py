"""Investigation Assistant endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select

from ...core.config import Settings
from ...core.logging import AuditEvent, get_logger
from ...models import Capture
from ...reporting.assistant import (
    ASSISTANT_VERSION,
    FIELD_SPECS,
    OPERATORS_ALLOWED,
    CompileError,
    compile_query,
    jwt_summary,
    summarise_plan,
    validate_plan,
)
from ...reporting.llm import LLMUnavailable, explain_findings, narrate
from ...reporting.query_executor import execute_plan
from ...schemas import AssistantQuery
from ..context import SessionDep, audit, get_settings_dep

router = APIRouter()
log = get_logger("mplab.assistant")

SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


@router.get("/assistant/capabilities")
def capabilities(settings: SettingsDep) -> dict[str, Any]:
    """Exactly what the assistant can and cannot do, stated plainly."""
    return {
        "version": ASSISTANT_VERSION,
        "entities": sorted(FIELD_SPECS),
        "fields": FIELD_SPECS,
        "operators": list(OPERATORS_ALLOWED),
        "execution_model": (
            "Requests are compiled into a typed query plan, schema-validated, "
            "checked against a field/operator allowlist, and executed through a "
            "fixed analytics API. No SQL, shell command or Python is ever "
            "generated from user text or from model output."
        ),
        "external_ai": {
            "enabled": settings.allow_external_ai,
            "provider": "ollama" if settings.allow_external_ai else None,
            "default": "disabled",
            "note": (
                "External AI is off by default. Even when enabled it may only "
                "narrate already-validated results; it cannot execute queries, "
                "write files, or alter the investigation."
            ),
        },
        "limitations": [
            "Searches run against plaintext payloads only; encrypted TLS content is "
            "not scanned unless a matching key log was supplied and decryption ran.",
            "Request/response pairing is inferred from ordering, not from a request "
            "identifier, unless the interpretation defines one.",
            "A JWT that decodes is not a JWT that is authentic; signatures are not "
            "verified here.",
        ],
    }


@router.post("/assistant/query")
def assistant_query(payload: AssistantQuery, session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    if len(payload.query) > 1000:
        from ...core.errors import ValidationFailed

        raise ValidationFailed("The query is too long (limit 1000 characters).")

    try:
        compiled = compile_query(payload.query, capture_ids=payload.capture_ids)
    except CompileError as exc:
        return {
            "status": "needs_clarification",
            "question": str(exc),
            "interpretation": None,
            "suggestions": _suggestions(),
            "note": (
                "The assistant refused to guess. Narrow the request to one of the "
                "supported patterns, or use the structured query API directly."
            ),
        }

    if payload.dry_run:
        return {
            "status": "planned",
            "interpretation": compiled.interpretation,
            "plan": compiled.plan.model_dump(),
            "plan_summary": summarise_plan(compiled.plan),
            "warnings": compiled.warnings,
            "executed": False,
            "note": "Dry run: the plan was compiled and validated but not executed.",
        }

    if settings.allow_external_ai:
        audit(session).record(
            AuditEvent(
                "assistant.query",
                project_id=None,
                object_type="query",
                object_id=None,
                risk="info",
                details={"query_length": len(payload.query), "entity": compiled.plan.entity},
            )
        )

    result = execute_plan(compiled.plan, session)
    response: dict[str, Any] = {
        "status": "executed",
        "interpretation": compiled.interpretation,
        "plan": compiled.plan.model_dump(),
        "plan_summary": summarise_plan(compiled.plan),
        "warnings": compiled.warnings,
        "executed": True,
        "result": result,
    }
    if payload.use_llm:
        if not settings.allow_external_ai:
            response["llm"] = {
                "used": False,
                "reason": (
                    "External AI is disabled. Enable MPLAB_ALLOW_EXTERNAL_AI to permit "
                    "an optional local Ollama narration pass."
                ),
            }
        else:
            try:
                response["llm"] = narrate(
                    question=payload.query,
                    plan=compiled.plan.model_dump(),
                    result_summary=_result_summary(result),
                    limits=settings.limits,
                )
            except LLMUnavailable as exc:
                response["llm"] = {"used": False, "reason": str(exc)}
    return response


@router.post("/assistant/jwt")
def inspect_jwt(payload: dict[str, Any]) -> dict[str, Any]:
    from ...core.errors import ValidationFailed

    token = payload.get("token")
    if not isinstance(token, str) or len(token) > 8192:
        raise ValidationFailed("Provide a 'token' string of at most 8192 characters.")
    return jwt_summary(token)


@router.post("/assistant/explain")
def explain(payload: dict[str, Any], session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    """Explain an existing finding from the stored evidence."""
    try:
        return explain_findings(payload, session, settings)
    except LLMUnavailable as exc:
        return {"used": False, "reason": str(exc)}


def _result_summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "entity": result.get("entity"),
        "count": result.get("count"),
        "sample": result.get("items", [])[:5],
    }


def _suggestions() -> list[str]:
    return [
        "Find TCP responses longer than 1000 bytes",
        "Show messages whose first two bytes match",
        "Find requests answered within 100 milliseconds",
        "Show streams with holes in the reconstructed bytes",
        "Find POST requests where HTTP content is visible",
    ]


_ = (select, Capture)