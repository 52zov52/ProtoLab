"""Report endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select

from ...core.config import Settings
from ...core.errors import NotFound
from ...core.logging import AuditEvent
from ...models import Report
from ...reporting.generator import (
    REPORT_VERSION,
    build_sections,
    collect_context,
    render_markdown,
    store_report,
)
from ...reporting.llm import LLMUnavailable, narrate
from ...schemas import ReportRequest
from ..context import SessionDep, StorageDep, audit, get_settings_dep, load_project

router = APIRouter()

SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


@router.post("/reports/generate")
def generate_report(
    payload: ReportRequest, session: SessionDep, storage: StorageDep, settings: SettingsDep
) -> dict[str, Any]:
    """Generate a report for a project named in the payload.

    ``POST /api/projects/{project_id}/reports`` is the preferred form; this alias
    exists for the documented flat path.
    """
    from ...core.errors import ValidationFailed

    project_id = _single_project(session)
    if not project_id:
        raise ValidationFailed(
            "This project has no reports to generate. Use "
            "POST /api/projects/{project_id}/reports."
        )
    return create_report(project_id, payload, session, storage, settings)


def _single_project(session: SessionDep) -> str | None:
    from ...models import Project

    rows = session.execute(select(Project.id).order_by(Project.updated_at.desc()).limit(2)).scalars().all()
    if len(rows) != 1:
        return None
    return rows[0]


@router.post("/projects/{project_id}/reports", response_model=dict)
def create_report(
    project_id: str, payload: ReportRequest, session: SessionDep, storage: StorageDep, settings: SettingsDep
) -> dict[str, Any]:
    project = load_project(session, project_id)
    ctx = collect_context(
        session,
        project,
        capture_ids=payload.capture_ids,
        interpretation_ids=payload.interpretation_ids,
        storage=storage,
        limits=settings.limits,
    )
    sections = build_sections(ctx)
    markdown = render_markdown(ctx, sections, payload.title)
    report = store_report(session, ctx, sections, markdown, payload.title)

    ai_used = False
    ai_warnings: list[str] = []
    if payload.use_llm:
        if not settings.allow_external_ai:
            ai_warnings.append(
                "External AI is disabled, so the report was produced entirely from "
                "stored facts. This is the expected offline behaviour."
            )
        else:
            try:
                result = narrate(
                    question="Summarise this protocol investigation for a reviewer.",
                    plan={"sections": [s.title for s in sections]},
                    result_summary=report.facts,
                    limits=settings.limits,
                    settings=settings,
                )
                report.ai_used = True
                report.ai_model = result["provider"]
                ai_warnings.append(result["disclaimer"])
            except LLMUnavailable as exc:
                ai_warnings.append(str(exc))
    report.ai_warnings = ai_warnings
    session.commit()

    audit(session).record(
        AuditEvent(
            "report.generate",
            project_id=project_id,
            object_type="report",
            object_id=report.id,
            details={"ai_used": report.ai_used, "sections": len(sections)},
        )
    )
    session.commit()
    return {
        "report_id": report.id,
        "title": report.title,
        "generator": REPORT_VERSION,
        "created_at": report.created_at,
        "sections": [s.to_dict() for s in sections],
        "facts": report.facts,
        "ai_used": report.ai_used,
        "ai_model": report.ai_model,
        "ai_warnings": ai_warnings,
    }


@router.get("/projects/{project_id}/reports")
def list_reports(project_id: str, session: SessionDep) -> list[dict[str, Any]]:
    load_project(session, project_id)
    rows = (
        session.execute(
            select(Report)
            .where(Report.project_id == project_id)
            .order_by(Report.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "title": r.title,
            "generator": r.generator,
            "created_at": r.created_at,
            "ai_used": r.ai_used,
            "facts": r.facts,
        }
        for r in rows
    ]


@router.get("/reports/{report_id}")
def get_report(report_id: str, session: SessionDep) -> dict[str, Any]:
    report = session.get(Report, report_id)
    if report is None:
        raise NotFound(f"Report {report_id!r} does not exist.")
    return {
        "id": report.id,
        "project_id": report.project_id,
        "title": report.title,
        "generator": report.generator,
        "created_at": report.created_at,
        "sections": report.sections,
        "facts": report.facts,
        "ai_used": report.ai_used,
        "ai_model": report.ai_model,
        "ai_warnings": report.ai_warnings,
    }


@router.get("/reports/{report_id}/markdown")
def report_markdown(report_id: str, session: SessionDep) -> Response:
    report = session.get(Report, report_id)
    if report is None:
        raise NotFound(f"Report {report_id!r} does not exist.")
    return Response(
        content=report.markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.md"'},
    )


@router.get("/reports/{report_id}/json")
def report_json(report_id: str, session: SessionDep) -> Response:
    import json

    report = session.get(Report, report_id)
    if report is None:
        raise NotFound(f"Report {report_id!r} does not exist.")
    payload = {
        "id": report.id,
        "project_id": report.project_id,
        "title": report.title,
        "generator": report.generator,
        "created_at": report.created_at.isoformat(),
        "sections": report.sections,
        "facts": report.facts,
        "ai_used": report.ai_used,
        "ai_model": report.ai_model,
        "ai_warnings": report.ai_warnings,
        "markdown": report.markdown,
    }
    return Response(
        content=json.dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.json"'},
    )