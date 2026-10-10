"""Project, capture and job services plus the audit log."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..core.errors import (
    Conflict,
    LimitExceeded,
    NotFound,
    SemanticValidationFailed,
    ValidationFailed,
)
from ..core.logging import GENESIS_HASH, AuditEvent, canonical_json, get_logger, hash_chain
from ..core.security import sha256_file
from ..models import (
    Annotation,
    AuditEvent as AuditEventRow,
    Capture,
    Evidence,
    ExperimentEvent,
    FramingRule,
    Hypothesis,
    Interpretation,
    Job,
    Message,
    Packet,
    Project,
    Report,
    Stream,
    TcpSession,
    ValidationRun,
)
from .storage import ProjectStorage, detect_capture_format

log = get_logger("mplab.projects")

PROJECT_SCHEMA_VERSION = 1
MAX_CAPTURE_NAME = 200


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def _audit_timestamp(value: datetime | None) -> str:
    """Canonical ISO-8601 UTC string for an audit row timestamp.

    SQLite hands naive datetimes back for ``DateTime(timezone=True)`` columns, so
    both the writer and the verifier must normalise to UTC before hashing or the
    chain would never validate.
    """
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class AuditLog:
    """Append-only audit trail with a hash chain.

    The chain detects casual modification; it is not tamper-proof against a
    local administrator who can rewrite both the rows and the chain head.  See
    docs/SECURITY.md for that limitation.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def record(self, event: AuditEvent) -> dict[str, Any]:
        last = self.session.execute(
            select(AuditEventRow.entry_hash).order_by(AuditEventRow.created_at.desc()).limit(1)
        ).scalar()
        prev = last or GENESIS_HASH
        row = AuditEventRow(
            action=event.action,
            outcome=event.outcome,
            risk=event.risk,
            project_id=event.project_id,
            object_type=event.object_type,
            object_id=event.object_id,
            actor=event.actor,
            details=event.details,
            prev_hash=prev,
            entry_hash="",
        )
        self.session.add(row)
        # Flush first so ``created_at`` is the exact value the verifier will
        # recompute from.  Hashing a separately-taken timestamp would make every
        # entry fail verification.
        self.session.flush()
        payload = event.payload()
        payload["timestamp"] = _audit_timestamp(row.created_at)
        row.entry_hash = hash_chain(prev, payload)
        self.session.flush()
        return {"id": row.id, "entry_hash": row.entry_hash, "prev_hash": prev}

    def verify(self, limit: int = 5000) -> dict[str, Any]:
        rows = (
            self.session.execute(
                select(AuditEventRow).order_by(AuditEventRow.created_at.asc()).limit(limit)
            )
            .scalars()
            .all()
        )
        prev = GENESIS_HASH
        for row in rows:
            if row.prev_hash != prev:
                return {
                    "valid": False,
                    "checked": len(rows),
                    "broken_at": row.id,
                    "explanation": "the previous-hash pointer does not match the preceding entry",
                }
            payload = {
                "action": row.action,
                "outcome": row.outcome,
                "project_id": row.project_id,
                "object_type": row.object_type,
                "object_id": row.object_id,
                "actor": row.actor,
                "risk": row.risk,
                "details": row.details,
            }
            payload["timestamp"] = _audit_timestamp(row.created_at)
            expected = hash_chain(prev, payload)
            if expected != row.entry_hash:
                return {
                    "valid": False,
                    "checked": len(rows),
                    "broken_at": row.id,
                    "explanation": "the entry hash does not match its contents",
                }
            prev = row.entry_hash
        return {
            "valid": True,
            "checked": len(rows),
            "explanation": (
                "Each entry hashes its own contents together with the previous entry's "
                "hash. This detects modification of the log file but does not protect "
                "against an administrator who can rewrite both the rows and the chain."
            ),
        }


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #


@dataclass
class ProjectSummary:
    id: str
    name: str
    created_at: datetime
    updated_at: datetime
    capture_count: int
    hypothesis_count: int
    interpretation_count: int
    message_count: int


class ProjectService:
    def __init__(self, session: Session, storage: ProjectStorage, limits) -> None:
        self.db = session
        self.storage = storage
        self.limits = limits
        self.audit = AuditLog(session)

    # -- projects ---------------------------------------------------------- #

    def create(self, *, name: str, description: str = "", settings: dict | None = None) -> Project:
        name = (name or "").strip()
        if not name:
            raise ValidationFailed("Project name must not be empty.")
        if len(name) > 200:
            raise ValidationFailed("Project name is too long (limit 200 characters).")
        project = Project(
            name=name,
            description=description or "",
            schema_version=PROJECT_SCHEMA_VERSION,
            settings=settings or {},
        )
        self.db.add(project)
        self.db.flush()
        self.storage.project_dir(project.id)
        self.audit.record(
            AuditEvent("project.create", project_id=project.id, object_type="project", object_id=project.id)
        )
        self.db.commit()
        return project

    def list(self) -> list[ProjectSummary]:
        rows = self.db.execute(select(Project).order_by(Project.updated_at.desc())).scalars().all()
        out: list[ProjectSummary] = []
        for project in rows:
            out.append(self.summary(project))
        return out

    def summary(self, project: Project) -> ProjectSummary:
        capture_count = self.db.scalar(
            select(func.count(Capture.id)).where(Capture.project_id == project.id)
        )
        hypothesis_count = self.db.scalar(
            select(func.count(Hypothesis.id)).where(Hypothesis.project_id == project.id)
        )
        interpretation_count = self.db.scalar(
            select(func.count(Interpretation.id)).where(Interpretation.project_id == project.id)
        )
        message_count = self.db.scalar(
            select(func.count(Message.id))
            .join(Stream, Stream.id == Message.stream_id)
            .join(TcpSession, TcpSession.id == Stream.session_id)
            .where(TcpSession.project_id == project.id)
        )
        return ProjectSummary(
            id=project.id,
            name=project.name,
            created_at=project.created_at,
            updated_at=project.updated_at,
            capture_count=int(capture_count or 0),
            hypothesis_count=int(hypothesis_count or 0),
            interpretation_count=int(interpretation_count or 0),
            message_count=int(message_count or 0),
        )

    def get(self, project_id: str) -> Project:
        project = self.db.get(Project, project_id)
        if project is None:
            raise NotFound(f"Project {project_id!r} does not exist.")
        return project

    def delete(self, project_id: str) -> None:
        project = self.get(project_id)
        # Delete managed storage for *this* project only.  Files are never
        # shared between projects (each has its own directory), so this cannot
        # damage another project.
        directory = self.storage.project_dir(project_id)
        self.audit.record(
            AuditEvent(
                "project.delete",
                project_id=project_id,
                object_type="project",
                object_id=project_id,
                risk="warning",
            )
        )
        self.db.delete(project)
        self.db.commit()
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)

    # -- captures ---------------------------------------------------------- #

    def import_capture(
        self,
        project: Project,
        *,
        name: str,
        source: Path,
        declared_format: str | None = None,
        source_kind: str = "user_upload",
    ) -> Capture:
        name = _validate_capture_name(name)
        fmt = declared_format or detect_capture_format(name)
        if fmt not in ("pcap", "pcapng"):
            raise ValidationFailed(
                "Only libpcap (.pcap/.cap) and pcapng (.pcapng) captures are supported.",
                details={"detected": fmt or "unknown"},
            )

        count = self.db.scalar(
            select(func.count(Capture.id)).where(Capture.project_id == project.id)
        )
        if int(count or 0) >= self.limits.max_project_files:
            raise LimitExceeded(
                "This project already holds the maximum number of captures.",
                details={"limit": self.limits.max_project_files},
            )
        total = self.db.scalar(
            select(func.coalesce(func.sum(Capture.file_size), 0)).where(
                Capture.project_id == project.id
            )
        )
        size = source.stat().st_size
        if size > self.limits.max_capture_bytes:
            raise LimitExceeded(
                "The capture exceeds the maximum file size accepted by this deployment.",
                details={"limit_bytes": self.limits.max_capture_bytes, "size_bytes": size},
            )
        if int(total or 0) + size > self.limits.max_project_total_bytes:
            raise LimitExceeded(
                "Importing this capture would exceed the project storage budget.",
                details={"limit_bytes": self.limits.max_project_total_bytes},
            )

        digest = sha256_file(source)
        duplicate = self.db.execute(
            select(Capture).where(
                Capture.project_id == project.id, Capture.sha256 == digest
            )
        ).scalars().first()
        if duplicate is not None:
            raise Conflict(
                "This exact capture is already imported in the project "
                f"(SHA-256 {digest[:16]}..., capture '{duplicate.name}'). "
                "Importing it again would duplicate the evidence.",
                details={"existing_capture_id": duplicate.id, "sha256": digest},
            )

        capture = Capture(
            project_id=project.id,
            name=name,
            relative_path="",
            sha256=digest,
            file_size=size,
            format=fmt,
            analysis_status="pending",
            source_kind=source_kind,
        )
        self.db.add(capture)
        self.db.flush()

        paths = self.storage.capture_paths(project.id, capture.id, fmt)
        destination = paths.original
        temporary = destination.with_suffix(destination.suffix + ".partial")
        shutil.copyfile(source, temporary)
        temporary.replace(destination)
        capture.relative_path = f"captures/{capture.id}/original.{fmt}"
        self.audit.record(
            AuditEvent(
                "capture.import",
                project_id=project.id,
                object_type="capture",
                object_id=capture.id,
                details={"name": name, "sha256": digest, "bytes": size, "format": fmt},
            )
        )
        self.db.commit()
        return capture

    def get_capture(self, capture_id: str) -> Capture:
        capture = self.db.get(Capture, capture_id)
        if capture is None:
            raise NotFound(f"Capture {capture_id!r} does not exist.")
        return capture

    def delete_capture(self, capture_id: str) -> None:
        capture = self.get_capture(capture_id)
        directory = self.storage.capture_dir(capture.project_id, capture.id)
        self.audit.record(
            AuditEvent(
                "capture.delete",
                project_id=capture.project_id,
                object_type="capture",
                object_id=capture.id,
                risk="warning",
                details={"name": capture.name},
            )
        )
        self.db.delete(capture)
        self.db.commit()
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)

    def verify_integrity(self, project: Project) -> dict[str, Any]:
        """Re-hash every stored capture and report drift."""
        captures = (
            self.db.execute(select(Capture).where(Capture.project_id == project.id))
            .scalars()
            .all()
        )
        results = []
        all_ok = True
        for capture in captures:
            paths = self.storage.capture_paths(project.id, capture.id, capture.format)
            if not paths.original.exists():
                all_ok = False
                results.append(
                    {
                        "capture_id": capture.id,
                        "name": capture.name,
                        "status": "missing",
                        "expected_sha256": capture.sha256,
                    }
                )
                continue
            actual = sha256_file(paths.original)
            ok = actual == capture.sha256
            all_ok = all_ok and ok
            results.append(
                {
                    "capture_id": capture.id,
                    "name": capture.name,
                    "status": "ok" if ok else "modified",
                    "expected_sha256": capture.sha256,
                    "actual_sha256": actual,
                }
            )
        self.audit.record(
            AuditEvent(
                "project.integrity_check",
                project_id=project.id,
                object_type="project",
                object_id=project.id,
                outcome="success" if all_ok else "failed",
                details={"captures": len(results), "all_match": all_ok},
            )
        )
        self.db.commit()
        return {
            "project_id": project.id,
            "all_match": all_ok,
            "captures": results,
            "note": (
                "SHA-256 detects unintended modification when a trusted reference "
                "exists. It does not prove provenance and provides no confidentiality."
            ),
        }

    # -- experiment log ---------------------------------------------------- #

    def add_experiment_events(
        self, project: Project, events: list[dict[str, Any]]
    ) -> list[ExperimentEvent]:
        created: list[ExperimentEvent] = []
        for item in events:
            timestamp = _coerce_timestamp(item.get("timestamp"))
            if timestamp is None:
                raise SemanticValidationFailed(
                    "Every experiment event needs a parseable 'timestamp'.",
                    details={"received": str(item.get("timestamp"))[:64]},
                )
            parameters = item.get("parameters") or item.get("parameter") or {}
            if not isinstance(parameters, dict):
                raise SemanticValidationFailed("'parameters' must be an object.")
            event = ExperimentEvent(
                project_id=project.id,
                timestamp=timestamp,
                raw_timestamp=str(item.get("timestamp"))[:64],
                action=str(item.get("action", ""))[:120] or "unspecified",
                parameters=parameters,
                observed_result=str(item.get("observed_result"))[:256] if item.get("observed_result") else None,
                expected_result=str(item.get("expected_result"))[:256] if item.get("expected_result") else None,
                metadata_json={
                    k: v for k, v in item.items()
                    if k not in {"timestamp", "action", "parameters", "parameter",
                                 "observed_result", "expected_result"}
                },
                note=str(item.get("note", ""))[:4000],
            )
            self.db.add(event)
            created.append(event)
        self.db.flush()
        return created


def _validate_capture_name(name: str) -> str:
    cleaned = " ".join((name or "").split())
    if not cleaned:
        raise ValidationFailed("Capture name must not be empty.")
    if len(cleaned) > MAX_CAPTURE_NAME:
        raise ValidationFailed(
            f"Capture name is too long (limit {MAX_CAPTURE_NAME} characters)."
        )
    return cleaned


def _coerce_timestamp(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    from datetime import datetime as _dt

    candidate = text.replace("Z", "+00:00")
    for parser in (_dt.fromisoformat,):
        try:
            parsed = parser(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return _dt.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #


class JobService:
    """In-process job registry with progress, cancellation and cleanup.

    Scope: single API process, local mode.  See docs/ARCHITECTURE.md for the
    subprocess isolation option used when parsing untrusted input.
    """

    def __init__(self, session: Session, limits) -> None:
        self.db = session
        self.limits = limits
        self._cancel: dict[str, bool] = {}
        self._temp_files: dict[str, list[Path]] = {}
        self._inflight: dict[str, str] = {}

    def create(self, kind: str, *, project_id: str | None, params: dict[str, Any]) -> Job:
        job = Job(
            kind=kind,
            project_id=project_id,
            params=params,
            status="queued",
            stage="queued",
        )
        self.db.add(job)
        self.db.commit()
        self._cancel[job.id] = False
        self._temp_files[job.id] = []
        return job

    def get(self, job_id: str) -> Job:
        job = self.db.get(Job, job_id)
        if job is None:
            raise NotFound(f"Job {job_id!r} does not exist.")
        return job

    def list(self, *, project_id: str | None = None, limit: int = 50) -> list[Job]:
        query = select(Job).order_by(Job.created_at.desc()).limit(limit)
        if project_id:
            query = query.where(Job.project_id == project_id)
        return list(self.db.execute(query).scalars().all())

    def request_cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        self._cancel[job_id] = True
        if job.status in ("queued", "running"):
            job.status = "canceling"
            job.stage = "cancel requested"
        self.db.commit()
        return job

    def is_cancelled(self, job_id: str) -> bool:
        return self._cancel.get(job_id, False)

    def check_cancelled(self, job_id: str) -> None:
        if self._cancel.get(job_id):
            raise _Cancelled()

    def start(self, job_id: str) -> None:
        job = self.get(job_id)
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        self.db.commit()

    def progress(self, job_id: str, fraction: float, stage: str) -> None:
        job = self.db.get(Job, job_id)
        if job is None:
            return
        job.progress = max(0.0, min(1.0, fraction))
        job.stage = stage[:120]
        self.db.commit()

    def finish(
        self,
        job_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        job = self.get(job_id)
        job.status = status
        job.result = result or {}
        job.error_code = error_code
        job.error_message = error_message
        job.finished_at = datetime.now(timezone.utc)
        job.progress = 1.0 if status == "succeeded" else job.progress
        self.db.commit()
        self.cleanup(job_id)

    def track_temp(self, job_id: str, path: Path) -> None:
        self._temp_files.setdefault(job_id, []).append(path)

    def cleanup(self, job_id: str) -> None:
        """Remove temporary artefacts after a job ends, however it ended."""
        for path in self._temp_files.pop(job_id, []):
            try:
                if path.exists() and path.is_file():
                    path.unlink()
            except OSError:  # pragma: no cover - best effort
                log.warning("could not remove temporary file %s", path)
        self._cancel.pop(job_id, None)
        self._inflight.pop(job_id, None)

    def active_count(self) -> int:
        return len(self._inflight)

    def register_inflight(self, job_id: str) -> None:
        self._inflight[job_id] = job_id


class _Cancelled(Exception):
    """Internal signal; translated into a 499 response at the API boundary."""


Cancelled = _Cancelled


def canonical_digest(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def iter_project_files(root: Path) -> Iterator[Path]:  # pragma: no cover - helper
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def new_temp_dir(prefix: str) -> Path:  # pragma: no cover - helper
    return Path(tempfile.mkdtemp(prefix=prefix))


def delete_rows(session: Session, model, **filters) -> int:  # pragma: no cover
    result = session.execute(delete(model).filter_by(**filters))
    session.commit()
    return result.rowcount or 0


def new_job_id() -> str:  # pragma: no cover - helper
    return uuid.uuid4().hex


_ = (Annotation, Evidence, FramingRule, Report, ValidationRun, json, time)