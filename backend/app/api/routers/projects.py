"""Project lifecycle endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import func, select

from ...core.errors import NotFound
from ...models import (
    Capture,
    Hypothesis,
    Interpretation,
    Message,
    Packet,
    Stream,
    TcpSession,
    ValidationResult,
    ValidationRun,
)
from ...schemas import (
    ExportProjectRequest,
    HypothesisOut,
    InterpretationOut,
    ProjectCreate,
    ProjectMetrics,
    ProjectOut,
    ProjectSummaryOut,
    ValidationRunOut,
)
from ..context import SessionDep, StorageDep, load_project

router = APIRouter()


@router.get("/projects", response_model=list[ProjectSummaryOut])
def list_projects(session: SessionDep, storage: StorageDep) -> list[ProjectSummaryOut]:
    from ..context import project_service
    from ...core.config import get_settings

    service = project_service(session, storage, get_settings().limits)
    return [
        ProjectSummaryOut(**summary.__dict__) for summary in service.list()
    ]


@router.post("/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, session: SessionDep, storage: StorageDep) -> Project:
    from ..context import project_service
    from ...core.config import get_settings

    service = project_service(session, storage, get_settings().limits)
    project = service.create(
        name=payload.name, description=payload.description, settings=payload.settings
    )
    return project


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, session: SessionDep) -> Project:
    return load_project(session, project_id)


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, session: SessionDep, storage: StorageDep) -> Response:
    from ..context import project_service
    from ...core.config import get_settings

    service = project_service(session, storage, get_settings().limits)
    service.delete(project_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/projects/{project_id}/metrics", response_model=ProjectMetrics)
def project_metrics(project_id: str, session: SessionDep) -> ProjectMetrics:
    """Live counters.

    Every number here is computed from the current project state.  Nothing is
    cached, seeded or estimated, so an empty project honestly reports zeros.
    """
    project = load_project(session, project_id)
    captures = session.execute(
        select(Capture).where(Capture.project_id == project_id)
    ).scalars().all()
    capture_ids = [c.id for c in captures]

    def count(model, *filters):
        if not capture_ids:
            return 0
        return int(
            session.scalar(
                select(func.count()).select_from(model).where(*filters)
            )
            or 0
        )

    packets = count(Packet, Packet.capture_id.in_(capture_ids)) if capture_ids else 0
    sessions = count(TcpSession, TcpSession.project_id == project_id)
    streams = (
        int(
            session.scalar(
                select(func.count(Stream.id))
                .join(TcpSession, TcpSession.id == Stream.session_id)
                .where(TcpSession.project_id == project_id)
            )
            or 0
        )
    )
    messages = (
        int(
            session.scalar(
                select(func.count(Message.id))
                .join(Stream, Stream.id == Message.stream_id)
                .join(TcpSession, TcpSession.id == Stream.session_id)
                .where(TcpSession.project_id == project_id)
            )
            or 0
        )
    )
    hypotheses = count(Hypothesis, Hypothesis.project_id == project_id)
    interpretations = count(Interpretation, Interpretation.project_id == project_id)
    runs = count(ValidationRun, ValidationRun.project_id == project_id)
    counterexamples = (
        int(
            session.scalar(
                select(func.count(ValidationResult.id))
                .join(ValidationRun, ValidationRun.id == ValidationResult.validation_run_id)
                .where(
                    ValidationRun.project_id == project_id,
                    ValidationResult.outcome == "failed",
                )
            )
            or 0
        )
    )
    problem_sessions = (
        int(
            session.scalar(
                select(func.count(TcpSession.id)).where(
                    TcpSession.project_id == project_id,
                    TcpSession.completeness_status != "complete",
                )
            )
            or 0
        )
    )
    versions: dict[str, str] = {}
    for session_row in session.execute(
        select(TcpSession.analyzer_version).where(TcpSession.project_id == project_id).distinct()
    ).scalars():
        if session_row:
            versions.setdefault("tcp_reassembly", session_row)
    for run_version in session.execute(
        select(ValidationRun.analyzer_version)
        .where(ValidationRun.project_id == project_id)
        .distinct()
    ).scalars():
        if run_version:
            versions.setdefault("validation", run_version)

    return ProjectMetrics(
        project_id=project_id,
        captures=len(captures),
        packets=packets,
        tcp_sessions=sessions,
        streams=streams,
        messages=messages,
        hypotheses=hypotheses,
        interpretations=interpretations,
        validation_runs=runs,
        counterexamples=counterexamples,
        sessions_with_reconstruction_problems=problem_sessions,
        bytes_stored=sum(c.file_size for c in captures),
        analyst_versions=versions,
    )


@router.get("/projects/{project_id}/hypotheses", response_model=list[HypothesisOut])
def list_hypotheses(project_id: str, session: SessionDep) -> list[Hypothesis]:
    load_project(session, project_id)
    return list(
        session.execute(
            select(Hypothesis)
            .where(Hypothesis.project_id == project_id)
            .order_by(Hypothesis.updated_at.desc())
        )
        .scalars()
        .all()
    )


@router.get("/projects/{project_id}/interpretations", response_model=list[InterpretationOut])
def list_interpretations(project_id: str, session: SessionDep) -> list[Interpretation]:
    load_project(session, project_id)
    return list(
        session.execute(
            select(Interpretation)
            .where(Interpretation.project_id == project_id)
            .order_by(Interpretation.created_at.desc())
        )
        .scalars()
        .all()
    )


@router.get("/projects/{project_id}/validation-runs", response_model=list[ValidationRunOut])
def list_validation_runs(project_id: str, session: SessionDep) -> list[ValidationRun]:
    load_project(session, project_id)
    return list(
        session.execute(
            select(ValidationRun)
            .where(ValidationRun.project_id == project_id)
            .order_by(ValidationRun.started_at.desc())
        )
        .scalars()
        .all()
    )


@router.get("/projects/{project_id}/integrity")
def integrity(project_id: str, session: SessionDep, storage: StorageDep) -> dict:
    from ..context import project_service
    from ...core.config import get_settings

    service = project_service(session, storage, get_settings().limits)
    return service.verify_integrity(load_project(session, project_id))


@router.post("/projects/{project_id}/export")
def export_project(
    project_id: str,
    payload: ExportProjectRequest,
    session: SessionDep,
    storage: StorageDep,
) -> dict:
    from ...services.project_archive import build_project_archive

    project = load_project(session, project_id)
    result = build_project_archive(
        project=project,
        session=session,
        storage=storage,
        include_captures=payload.include_captures,
        include_reports=payload.include_reports,
    )
    return result


@router.get("/projects/{project_id}/hypotheses/{hypothesis_id}", response_model=HypothesisOut)
def get_hypothesis(project_id: str, hypothesis_id: str, session: SessionDep) -> Hypothesis:
    load_project(session, project_id)
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None or hypothesis.project_id != project_id:
        raise NotFound(f"Hypothesis {hypothesis_id!r} does not exist in project {project_id!r}.")
    return hypothesis


_ = Annotated