"""Request-scoped dependencies and object lookup.

Two responsibilities:

1. **Dependency injection** - a database session, managed storage and settings
   per request, declared as FastAPI dependencies.
2. **Object resolution** - :func:`load_project`, :func:`load_capture` and
   friends.  These are the enforcement point for object ownership: a path is
   never taken from the client, only an identifier, and an object that does not
   belong to the addressed project raises :class:`NotFound` rather than being
   returned.  The UI hides things it should not show, but this is the control
   that actually decides.
"""

from __future__ import annotations

from typing import Annotated, Any, Iterator

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings, get_settings as _load_settings
from ..core.errors import NotFound
from ..core.logging import AuditEvent
from ..core.security import ConcurrencyGate, SlidingWindowLimiter
from ..db.session import make_session_factory
from ..models import Capture, ExperimentEvent, Hypothesis, Interpretation, Packet, TcpSession
from ..services.project_service import ProjectService
from ..services.storage import ProjectStorage


class AppContext:
    """Process-level collaborators built once in :func:`create_app`."""

    def __init__(
        self,
        *,
        settings: Settings,
        engine: Any,
        limiter: SlidingWindowLimiter,
        job_gate: ConcurrencyGate,
    ) -> None:
        self.settings = settings
        self.engine = engine
        self.limiter = limiter
        self.job_gate = job_gate
        self.session_factory = make_session_factory(engine)
        self.storage = ProjectStorage(settings.storage_dir)

    def open_session(self) -> Session:
        return self.session_factory()


def get_context(request: Request) -> AppContext:
    context = getattr(request.app.state, "context", None)
    if context is None:  # pragma: no cover - only if create_app was bypassed
        raise NotFound("The application context is not initialised.")
    return context


def get_settings_dep(request: Request) -> Settings:
    """Prefer the instance handed to ``create_app`` over the process singleton.

    Tests construct ``Settings`` explicitly and pass it in; reading the global
    here would silently point the app at a different data directory.
    """
    context = getattr(request.app.state, "context", None)
    if context is not None:
        return context.settings
    return _load_settings()


def get_db(context: Annotated[AppContext, Depends(get_context)]) -> Iterator[Session]:
    """A session per request, always closed."""
    session = context.open_session()
    try:
        yield session
    finally:
        session.close()


def get_storage(context: Annotated[AppContext, Depends(get_context)]) -> ProjectStorage:
    return context.storage


def get_project_service(
    session: Annotated[Session, Depends(get_db)],
    storage: Annotated[ProjectStorage, Depends(get_storage)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> ProjectService:
    return ProjectService(session, storage, settings.limits)


SessionDep = Annotated[Session, Depends(get_db)]
StorageDep = Annotated[ProjectStorage, Depends(get_storage)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
ContextDep = Annotated[AppContext, Depends(get_context)]
ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]


# --------------------------------------------------------------------------- #
# Object resolution / ownership enforcement
# --------------------------------------------------------------------------- #


def load_project(session: Session, project_id: str) -> Any:
    from ..models import Project

    project = session.get(Project, project_id)
    if project is None:
        raise NotFound(f"Project {project_id!r} does not exist.")
    return project


def load_capture(session: Session, capture_id: str) -> Capture:
    capture = session.get(Capture, capture_id)
    if capture is None:
        raise NotFound(f"Capture {capture_id!r} does not exist.")
    return capture


def load_session_row(session: Session, session_id: str) -> TcpSession:
    row = session.get(TcpSession, session_id)
    if row is None:
        raise NotFound(f"TCP session {session_id!r} does not exist.")
    return row


def load_hypothesis(session: Session, hypothesis_id: str, project_id: str | None = None) -> Hypothesis:
    """Resolve a hypothesis, enforcing project ownership when given."""
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise NotFound(f"Hypothesis {hypothesis_id!r} does not exist.")
    if project_id is not None and hypothesis.project_id != project_id:
        # Do not confirm existence in a project the caller did not address.
        raise NotFound(
            f"Hypothesis {hypothesis_id!r} does not exist in project {project_id!r}."
        )
    return hypothesis


def load_interpretation(
    session: Session, interpretation_id: str, project_id: str | None = None
) -> Interpretation:
    interpretation = session.get(Interpretation, interpretation_id)
    if interpretation is None:
        raise NotFound(f"Interpretation {interpretation_id!r} does not exist.")
    if project_id is not None and interpretation.project_id != project_id:
        raise NotFound(
            f"Interpretation {interpretation_id!r} does not exist in project {project_id!r}."
        )
    return interpretation


def capture_in_project(session: Session, capture_id: str, project_id: str) -> Capture:
    """Resolve a capture only if it belongs to ``project_id``."""
    capture = load_capture(session, capture_id)
    if capture.project_id != project_id:
        raise NotFound(f"Capture {capture_id!r} does not exist in project {project_id!r}.")
    return capture


def packet_in_capture(session: Session, capture_id: str, packet_index: int) -> Packet:
    packet = (
        session.execute(
            select(Packet).where(
                Packet.capture_id == capture_id, Packet.packet_index == packet_index
            )
        )
        .scalars()
        .first()
    )
    if packet is None:
        raise NotFound(f"Packet {packet_index} is not present in capture {capture_id!r}.")
    return packet


def experiments_for_project(session: Session, project_id: str) -> list[ExperimentEvent]:
    return list(
        session.execute(
            select(ExperimentEvent)
            .where(ExperimentEvent.project_id == project_id)
            .order_by(ExperimentEvent.timestamp)
        )
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def project_service(session: Session, storage: ProjectStorage, limits: Any) -> ProjectService:
    """Build a :class:`ProjectService` from explicit collaborators.

    Routers call this directly instead of depending on ``ProjectServiceDep`` so
    the same construction is available inside locally-scoped helpers.
    """
    return ProjectService(session, storage, limits)


def jobs(session: Session, limits: Any) -> Any:
    """The job service bound to one request's session."""
    from ..services.project_service import JobService

    return JobService(session, limits)


def audit(session: Session) -> Any:
    """The project-scoped audit log, used by routers to record events."""
    from ..services.project_service import AuditLog

    return AuditLog(session)


def audit_event(
    action: str,
    *,
    project_id: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    details: dict[str, Any] | None = None,
    outcome: str = "success",
) -> AuditEvent:
    return AuditEvent(
        action,
        outcome=outcome,
        project_id=project_id,
        object_type=object_type,
        object_id=object_id,
        details=details,
    )


__all__ = [
    "AppContext",
    "ContextDep",
    "ProjectServiceDep",
    "SessionDep",
    "SettingsDep",
    "StorageDep",
    "audit",
    "audit_event",
    "capture_in_project",
    "experiments_for_project",
    "get_context",
    "get_db",
    "get_project_service",
    "get_settings_dep",
    "get_storage",
    "jobs",
    "load_capture",
    "load_hypothesis",
    "load_interpretation",
    "load_project",
    "load_session_row",
    "packet_in_capture",
    "project_service",
]