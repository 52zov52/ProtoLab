"""Background job endpoints.

Long-running analysis runs here.  Jobs are tracked in the database so progress,
cancellation and failures survive the request that started them.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Form, Query, UploadFile
from sqlalchemy import select

from ...core.errors import Conflict, NotFound, ValidationFailed
from ...core.logging import AuditEvent, get_logger
from ...models import Capture, ExperimentEvent, Hypothesis, Job, Project, Report, ValidationRun
from ...schemas import AnalyzeRequest, ExperimentImport
from ..context import SessionDep, StorageDep, audit, get_context, load_capture, load_project

router = APIRouter()
log = get_logger("mplab.jobs")


def _job_service(session, limits):
    from ..context import jobs

    return jobs(session, limits)


@router.get("/jobs")
def list_jobs(
    session: SessionDep,
    project_id: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict]:
    from ...core.config import get_settings

    service = _job_service(session, get_settings().limits)
    return [
        {
            "id": job.id,
            "kind": job.kind,
            "status": job.status,
            "progress": job.progress,
            "stage": job.stage,
            "project_id": job.project_id,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error_code": job.error_code,
            "error_message": job.error_message,
        }
        for job in service.list(project_id=project_id, limit=limit)
    ]


@router.get("/jobs/{job_id}")
def get_job(job_id: str, session: SessionDep) -> dict:
    from ...core.config import get_settings

    service = _job_service(session, get_settings().limits)
    job = service.get(job_id)
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "progress": job.progress,
        "stage": job.stage,
        "project_id": job.project_id,
        "params": job.params,
        "result": job.result,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error_code": job.error_code,
        "error_message": job.error_message,
        "cancel_requested": service.is_cancelled(job_id),
    }


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, session: SessionDep) -> dict:
    from ...core.config import get_settings

    service = _job_service(session, get_settings().limits)
    job = service.request_cancel(job_id)
    return {
        "id": job.id,
        "status": job.status,
        "stage": job.stage,
        "note": (
            "Cancellation is cooperative: the job stops at its next checkpoint and its "
            "temporary artefacts are removed."
        ),
    }


@router.post("/captures/{capture_id}/analyze-async")
def analyze_async(
    capture_id: str,
    background: BackgroundTasks,
    session: SessionDep,
    storage: StorageDep,
    framing: Annotated[str | None, Form()] = None,
) -> dict:
    """Queue a capture analysis and run it in the background."""
    from ...core.config import get_settings

    settings = get_settings()
    capture = load_capture(session, capture_id)
    service = _job_service(session, settings.limits)
    job = service.create(
        "capture.analyze",
        project_id=capture.project_id,
        params={"capture_id": capture_id},
    )
    payload = AnalyzeRequest()
    if framing:
        import json

        try:
            payload = AnalyzeRequest(framing=json.loads(framing))
        except Exception as exc:
            raise ValidationFailed(f"The framing configuration is not valid: {exc}") from exc

    def run() -> None:
        from ...services.jobs import run_analysis_job

        try:
            run_analysis_job(job.id, capture_id, payload, storage, settings)
        except Exception:  # already recorded on the job row
            log.exception("background analysis failed for capture %s", capture_id)

    background.add_task(run)
    audit(session).record(
        AuditEvent(
            "job.start",
            project_id=capture.project_id,
            object_type="job",
            object_id=job.id,
            details={"kind": "capture.analyze", "capture_id": capture_id},
        )
    )
    session.commit()
    return {"job_id": job.id, "status": "queued"}


@router.post("/projects/{project_id}/experiments")
def import_experiments(
    project_id: str, payload: ExperimentImport, session: SessionDep, storage: StorageDep
) -> dict:
    from ...core.config import get_settings

    project = load_project(session, project_id)
    service = _job_service(session, get_settings().limits)
    events = service_import_experiments(session, storage, project, payload)
    return {"imported": len(events), "project_id": project_id}


def service_import_experiments(session, storage, project, payload):
    from ...core.config import get_settings

    from ..context import project_service

    service = project_service(session, storage, get_settings().limits)
    events = service.add_experiment_events(project, payload.events)
    session.commit()
    return events


@router.get("/projects/{project_id}/experiments")
def list_experiments(
    project_id: str,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> list[dict]:
    load_project(session, project_id)
    rows = (
        session.execute(
            select(ExperimentEvent)
            .where(ExperimentEvent.project_id == project_id)
            .order_by(ExperimentEvent.timestamp)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "raw_timestamp": r.raw_timestamp,
            "action": r.action,
            "parameters": r.parameters,
            "observed_result": r.observed_result,
            "expected_result": r.expected_result,
            "linked_message_ids": r.linked_message_ids,
            "note": r.note,
        }
        for r in rows
    ]


_ = (
    Capture,
    Conflict,
    Hypothesis,
    Job,
    NotFound,
    Project,
    Report,
    ValidationRun,
    ValidationFailed,
    get_context,
)