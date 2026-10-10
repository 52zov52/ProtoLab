"""Long-running job bodies.

Kept separate from the routers so the same function backs both the synchronous
``/analyze`` endpoint and the queued ``/analyze-async`` endpoint, and so the
optional subprocess isolation in ``docs/ARCHITECTURE.md`` has one place to hook
in.
"""

from __future__ import annotations

from typing import Any

from ..core.errors import AppError, Canceled
from ..core.logging import AuditEvent, get_logger
from ..models import Capture
from .project_service import AuditLog, JobService

log = get_logger("mplab.job")


def _session_factory(settings):
    from ..db.session import build_engine, make_session_factory

    return make_session_factory(build_engine(settings))


def run_analysis_job(
    job_id: str,
    capture_id: str,
    payload,
    storage,
    settings,
) -> dict[str, Any]:
    """Execute one capture analysis as a tracked job.

    Every exit path records a status and removes temporary artefacts, so a
    cancelled or failed job never leaves debris behind.
    """
    from ...services.capture_analysis import AnalysisOptions, CaptureAnalyzer
    from .project_service import JobService

    engine_session_factory = _session_factory(settings)
    session = engine_session_factory()
    service = JobService(session, settings.limits)
    audit = AuditLog(session)
    try:
        service.start(job_id)
        service.register_inflight(job_id)
        audit.record(
            AuditEvent(
                "job.start",
                object_type="job",
                object_id=job_id,
                details={"capture_id": capture_id},
            )
        )
        session.commit()
        capture = session.get(Capture, capture_id)
        if capture is None:
            raise AppError(f"Capture {capture_id!r} no longer exists.")
        capture.analysis_status = "running"
        session.commit()

        options = AnalysisOptions(
            flow_policy=payload.flow_policy,
            idle_timeout=payload.idle_timeout,
            conflict_policy=payload.conflict_policy,
            framing=payload.framing,
            detect_protocol=payload.detect_protocol,
            max_sessions=settings.limits.max_tcp_sessions_per_capture,
            max_messages_per_stream=settings.limits.max_messages_per_stream,
        )
        paths = storage.capture_paths(capture.project_id, capture.id, capture.format)

        def progress(fraction: float, stage: str) -> None:
            if service.is_cancelled(job_id):
                raise Canceled("The analysis was cancelled.")
            service.progress(job_id, fraction, stage)

        analyzer = CaptureAnalyzer(
            session, capture, paths.original, storage, options, settings.limits,
            progress=progress,
        )
        summary = analyzer.run()
        capture.analysis_status = "completed"
        capture.stats = summary
        session.commit()
        service.finish(job_id, status="succeeded", result=summary)
        audit.record(
            AuditEvent(
                "job.complete",
                project_id=capture.project_id,
                object_type="job",
                object_id=job_id,
                details={"capture_id": capture_id, "sessions": summary.get("sessions")},
            )
        )
        session.commit()
        return summary
    except Canceled:
        session.rollback()
        _mark_status(session, capture_id, "canceled")
        service.finish(job_id, status="canceled", error_code="canceled")
        audit.record(
            AuditEvent(
                "job.cancel",
                object_type="job",
                object_id=job_id,
                details={"capture_id": capture_id},
            )
        )
        session.commit()
        return {"status": "canceled"}
    except AppError as exc:
        session.rollback()
        _mark_status(session, capture_id, "failed")
        service.finish(job_id, status="failed", error_code=exc.code, error_message=exc.message)
        audit.record(
            AuditEvent(
                "job.failed",
                object_type="job",
                object_id=job_id,
                outcome="failure",
                risk="error",
                details={"capture_id": capture_id, "code": exc.code},
            )
        )
        session.commit()
        raise
    except Exception as exc:  # pragma: no cover - defensive
        session.rollback()
        _mark_status(session, capture_id, "failed")
        log.exception("job %s failed", job_id)
        service.finish(
            job_id,
            status="failed",
            error_code="internal_error",
            error_message=type(exc).__name__,
        )
        audit.record(
            AuditEvent(
                "job.failed",
                object_type="job",
                object_id=job_id,
                outcome="failure",
                risk="error",
                details={"capture_id": capture_id},
            )
        )
        session.commit()
        raise
    finally:
        service.cleanup(job_id)
        session.close()


def _mark_status(session, capture_id: str, status: str) -> None:
    from ..models import Capture as CaptureModel

    capture = session.get(CaptureModel, capture_id)
    if capture is not None:
        capture.analysis_status = status
    session.commit()