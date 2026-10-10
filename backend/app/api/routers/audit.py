"""Audit log browsing and export."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Response
from sqlalchemy import func, select

from ...core.errors import NotFound
from ...models import AuditEvent as AuditEventRow
from ..context import SessionDep

router = APIRouter(prefix="/audit")

DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


@router.get("/events")
def list_events(
    session: SessionDep,
    project_id: Annotated[str | None, Query(max_length=32)] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    outcome: Annotated[str | None, Query(max_length=24)] = None,
    risk: Annotated[str | None, Query(max_length=16)] = None,
    since: Annotated[str | None, Query(max_length=40)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    query = select(AuditEventRow)
    if project_id:
        query = query.where(AuditEventRow.project_id == project_id)
    if action:
        query = query.where(AuditEventRow.action == action)
    if outcome:
        query = query.where(AuditEventRow.outcome == outcome)
    if risk:
        query = query.where(AuditEventRow.risk == risk)
    if since:
        from datetime import datetime, timezone

        try:
            moment = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            from ...core.errors import ValidationFailed

            raise ValidationFailed(
                "'since' must be an ISO-8601 timestamp such as 2026-01-01T00:00:00Z."
            ) from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        query = query.where(AuditEventRow.created_at >= moment)

    total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = (
        session.execute(
            query.order_by(AuditEventRow.created_at.desc()).offset(offset).limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "timestamp": r.created_at,
                "action": r.action,
                "outcome": r.outcome,
                "risk": r.risk,
                "project_id": r.project_id,
                "object_type": r.object_type,
                "object_id": r.object_id,
                "actor": r.actor,
                "details": r.details,
                "entry_hash": r.entry_hash,
                "prev_hash": r.prev_hash,
            }
            for r in rows
        ],
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(rows) < total,
    }


@router.get("/verify")
def verify_chain(session: SessionDep, limit: Annotated[int, Query(ge=1, le=10_000)] = 1000) -> dict:
    from ...services.project_service import AuditLog

    return AuditLog(session).verify(limit=limit)


@router.get("/export")
def export_events(session: SessionDep, limit: Annotated[int, Query(ge=1, le=10_000)] = 1000) -> Response:
    import json

    rows = (
        session.execute(select(AuditEventRow).order_by(AuditEventRow.created_at.asc()).limit(limit))
        .scalars()
        .all()
    )
    payload = {
        "exported_at": None,
        "event_count": len(rows),
        "events": [
            {
                "timestamp": r.created_at.isoformat(),
                "action": r.action,
                "outcome": r.outcome,
                "risk": r.risk,
                "project_id": r.project_id,
                "object_type": r.object_type,
                "object_id": r.object_id,
                "actor": r.actor,
                "details": r.details,
                "entry_hash": r.entry_hash,
                "prev_hash": r.prev_hash,
            }
            for r in rows
        ],
        "caveat": (
            "This export does not include secrets. The audit log records that an event "
            "happened, not the data it processed."
        ),
    }
    return Response(
        content=json.dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="mplab-audit.json"'},
    )


@router.get("/actions")
def known_actions() -> dict[str, str]:
    from ...core.logging import SENSITIVE_ACTIONS

    return {
        "actions": SENSITIVE_ACTIONS,
        "note": (
            "These are the security-relevant event types the application records. "
            "Ordinary read operations are not audited."
        ),
    }


_ = NotFound