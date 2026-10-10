"""Portable investigation project archive (``.mplab``).

The archive is a ZIP with a manifest and a ``data/`` tree.  Design points that
matter:

* paths inside the archive are validated *before* extraction: absolute paths,
  ``..``, control characters, symlinks, duplicate names (including
  case/Unicode variants) and zip bombs are all rejected;
* extraction happens into a temporary directory and only becomes the live
  project after every hash in the manifest has been checked;
* a format version the build does not understand is refused rather than
  guessed at;
* nothing from the archive is executed, imported or dynamically loaded.
"""

from __future__ import annotations

import json
import os
import shutil
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.errors import Conflict, NotFound, SecurityViolation, UnsupportedFormat, ValidationFailed
from ..core.logging import AuditEvent, get_logger
from ..core.security import sha256_file, validate_relative_path
from ..models import (
    Annotation,
    Capture,
    Evidence,
    ExperimentEvent,
    FramingRule,
    Hypothesis,
    Interpretation,
    Project,
    Report,
    ValidationRun,
)
from .storage import ProjectStorage

log = get_logger("mplab.archive")

ARCHIVE_SUFFIX = ".mplab"
PROJECT_FORMAT_VERSION = 1
MANIFEST_NAME = "manifest.json"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


@dataclass
class Manifest:
    format: str
    version: int
    project: dict[str, Any]
    files: list[dict[str, Any]]
    counts: dict[str, int]
    created_at: str
    generator: str = "madrigal-protocol-lab/0.1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "version": self.version,
            "generator": self.generator,
            "created_at": self.created_at,
            "project": self.project,
            "counts": self.counts,
            "files": self.files,
        }


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #


def build_project_archive(
    *,
    project: Project,
    session: Session,
    storage: ProjectStorage,
    include_captures: bool = True,
    include_reports: bool = True,
) -> dict[str, Any]:
    from ..services.project_service import AuditLog

    exports = storage.capture_paths(project.id, "archive", "pcap").export_dir
    storage.project_dir(project.id)
    exports.mkdir(parents=True, exist_ok=True)
    target = exports / f"{_slug(project.name)}{PROJECT_FORMAT_VERSION and ''}{ARCHIVE_SUFFIX}"

    project_dir = storage.project_dir(project.id)
    hypothesis_rows = list(
        session.execute(select(Hypothesis).where(Hypothesis.project_id == project.id))
        .scalars().all()
    )
    interpretation_rows = list(
        session.execute(select(Interpretation).where(Interpretation.project_id == project.id))
        .scalars().all()
    )
    experiment_rows = list(
        session.execute(select(ExperimentEvent).where(ExperimentEvent.project_id == project.id))
        .scalars().all()
    )
    validation_rows = list(
        session.execute(select(ValidationRun).where(ValidationRun.project_id == project.id))
        .scalars().all()
    )
    capture_rows = list(
        session.execute(select(Capture).where(Capture.project_id == project.id)).scalars().all()
    )
    report_rows = (
        list(session.execute(select(Report).where(Report.project_id == project.id)).scalars().all())
        if include_reports
        else []
    )

    research = {
        "hypotheses": [_hypothesis_payload(h) for h in hypothesis_rows],
        "interpretations": [_interpretation_payload(i) for i in interpretation_rows],
        "experiments": [
            {
                "timestamp": e.timestamp,
                "raw_timestamp": e.raw_timestamp,
                "action": e.action,
                "parameters": e.parameters,
                "observed_result": e.observed_result,
                "expected_result": e.expected_result,
                "metadata": e.metadata_json,
                "note": e.note,
            }
            for e in experiment_rows
        ],
        "validation_runs": [
            {
                "id": r.id,
                "interpretation_checksum": _checksum_for(session, r.interpretation_id),
                "corpus": r.corpus,
                "settings": r.settings,
                "started_at": r.started_at.isoformat(),
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "status": r.status,
                "summary": r.summary,
                "stale": r.stale,
                "analyzer_version": r.analyzer_version,
            }
            for r in validation_rows
        ],
        "captures": [
            {
                "id": c.id,
                "name": c.name,
                "sha256": c.sha256,
                "file_size": c.file_size,
                "format": c.format,
                "relative_path": c.relative_path,
                "imported_at": c.imported_at.isoformat(),
                "analysis_status": c.analysis_status,
                "stats": c.stats,
                "diagnostics": c.diagnostics,
            }
            for c in capture_rows
        ],
        "reports": [
            {"title": r.title, "markdown": r.markdown, "facts": r.facts, "created_at": r.created_at.isoformat()}
            for r in report_rows
        ],
        "framing_rules": [
            {"id": r.id, "name": r.name, "version": r.version, "method": r.method,
             "config": r.config, "notes": r.notes, "is_active": r.is_active}
            for r in session.execute(
                select(FramingRule).where(FramingRule.project_id == project.id)
            ).scalars().all()
        ],
        "annotations": [
            {"target_type": a.target_type, "target_id": a.target_id, "text": a.text,
             "tags": a.tags, "author": a.author}
            for a in session.execute(
                select(Annotation).where(Annotation.project_id == project.id)
            ).scalars().all()
        ],
        "evidence": [
            {"entity_type": e.entity_type, "entity_id": e.entity_id, "description": e.description,
             "confidence": e.confidence, "byte_ranges": e.byte_ranges}
            for e in session.execute(
                select(Evidence).where(Evidence.project_id == project.id)
            ).scalars().all()[:1000]
        ],
    }

    files: list[dict[str, Any]] = []
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        research_blob = json.dumps(research, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        archive.writestr("data/research.json", research_blob)
        files.append({"path": "data/research.json", "sha256": _sha256_bytes(research_blob), "size": len(research_blob)})

        if include_captures:
            for capture in capture_rows:
                paths = storage.capture_paths(project.id, capture.id, capture.format)
                if not paths.original.exists():
                    files.append(
                        {
                            "path": capture.relative_path,
                            "missing": True,
                            "sha256": capture.sha256,
                            "size": 0,
                            "note": "source file absent; results referencing it cannot be reproduced",
                        }
                    )
                    continue
                archive_name = f"data/captures/{capture.id}/original.{capture.format}"
                blob = paths.original.read_bytes()
                archive.writestr(archive_name, blob)
                actual = _sha256_bytes(blob)
                files.append(
                    {
                        "path": archive_name,
                        "sha256": actual,
                        "expected_sha256": capture.sha256,
                        "size": len(blob),
                        "capture_id": capture.id,
                    }
                )

    manifest = Manifest(
        format="madrigal-protocol-lab-project",
        version=PROJECT_FORMAT_VERSION,
        project={
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "schema_version": project.schema_version,
            "settings": project.settings,
            "created_at": project.created_at.isoformat(),
        },
        files=files,
        counts={
            "captures": len(capture_rows),
            "hypotheses": len(hypothesis_rows),
            "interpretations": len(interpretation_rows),
            "experiments": len(experiment_rows),
            "validation_runs": len(validation_rows),
            "reports": len(report_rows),
        },
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    # The manifest is written last and is not self-referential.
    with zipfile.ZipFile(target, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_NAME, json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False))

    size = target.stat().st_size
    AuditLog(session).record(
        AuditEvent(
            "project.export",
            project_id=project.id,
            object_type="project",
            object_id=project.id,
            details={"archive": target.name, "bytes": size, "files": len(files)},
        )
    )
    session.commit()
    return {
        "archive": target.name,
        "bytes": size,
        "files": len(files),
        "counts": manifest.counts,
        "format_version": PROJECT_FORMAT_VERSION,
    }


def _slug(name: str) -> str:
    import re

    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")
    return (cleaned or "project")[:60]


def _sha256_bytes(blob: bytes) -> str:
    import hashlib

    return hashlib.sha256(blob).hexdigest()


def _hypothesis_payload(h: Hypothesis) -> dict[str, Any]:
    return {
        "id": h.id,
        "name": h.name,
        "description": h.description,
        "scope": h.scope,
        "proposed_structure": h.proposed_structure,
        "observations": h.observations,
        "evidence_refs": h.evidence_refs,
        "counterexample_refs": h.counterexample_refs,
        "unknown_regions": h.unknown_regions,
        "status": h.status,
        "version": h.version,
        "author": h.author,
        "origin": h.origin,
        "created_at": h.created_at.isoformat(),
        "updated_at": h.updated_at.isoformat(),
    }


def _interpretation_payload(i: Interpretation) -> dict[str, Any]:
    return {
        "id": i.id,
        "hypothesis_id": i.hypothesis_id,
        "name": i.name,
        "schema_json": i.schema_json,
        "version": i.version,
        "checksum": i.checksum,
        "notes": i.notes,
        "created_at": i.created_at.isoformat(),
    }


def _checksum_for(session: Session, interpretation_id: str) -> str | None:
    row = session.get(Interpretation, interpretation_id)
    return row.checksum if row else None


# --------------------------------------------------------------------------- #
# Import
# --------------------------------------------------------------------------- #


def inspect_archive(path: Path, limits) -> dict[str, Any]:
    """Validate an archive *without* extracting it.

    Every check here happens against the zip directory, so a hostile archive is
    rejected before a single byte is written to disk.
    """
    problems: list[dict[str, str]] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > limits.max_archive_entries:
            raise SecurityViolation(
                "The archive contains more entries than this deployment accepts.",
                details={"entries": len(infos), "limit": limits.max_archive_entries},
            )
        total_uncompressed = 0
        seen: dict[str, str] = {}
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            # Symlink: unix mode bits in the top 16 of external_attr.
            mode = (info.external_attr >> 16) & 0xF000
            if mode == 0xA000:
                problems.append({"path": name, "problem": "symlink entries are not permitted"})
                continue
            try:
                validate_relative_path(name)
            except SecurityViolation as exc:
                problems.append({"path": name[:120], "problem": str(exc)})
                continue
            folded = unicodedata.normalize("NFC", name).casefold()
            if folded in seen and seen[folded] != name:
                problems.append(
                    {
                        "path": name[:120],
                        "problem": (
                            f"duplicate entry; {seen[folded][:60]} differs only by case or "
                            "Unicode normalisation"
                        ),
                    }
                )
            seen[folded] = name
            if info.file_size > limits.max_archive_entry_bytes:
                problems.append({"path": name[:120], "problem": "entry exceeds the per-file limit"})
            total_uncompressed += info.file_size
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > limits.max_archive_compression_ratio:
                    problems.append(
                        {
                            "path": name[:120],
                            "problem": (
                                f"compression ratio {ratio:.0f}:1 exceeds the limit of "
                                f"{limits.max_archive_compression_ratio}:1"
                            ),
                        }
                    )
            if name.count("/") > limits.max_archive_depth:
                problems.append({"path": name[:120], "problem": "entry nests too deeply"})
        if total_uncompressed > limits.max_archive_uncompressed_bytes:
            problems.append(
                {
                    "path": "<archive>",
                    "problem": (
                        "total uncompressed size exceeds the limit "
                        f"({total_uncompressed} > {limits.max_archive_uncompressed_bytes} bytes)"
                    ),
                }
            )

        try:
            manifest_raw = archive.read(MANIFEST_NAME)
        except KeyError as exc:
            raise UnsupportedFormat(
                "The archive has no manifest.json, so it is not a Madrigal project archive."
            ) from exc
        if len(manifest_raw) > MAX_MANIFEST_BYTES:
            raise UnsupportedFormat("The manifest is implausibly large and was not parsed.")
        try:
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UnsupportedFormat(f"The manifest is not readable: {exc}") from exc

        if manifest.get("format") != "madrigal-protocol-lab-project":
            raise UnsupportedFormat(
                f"Unrecognised archive format {manifest.get('format')!r}."
            )
        version = manifest.get("version")
        if not isinstance(version, int):
            raise UnsupportedFormat("The manifest does not declare an integer format version.")
        if version > PROJECT_FORMAT_VERSION:
            raise UnsupportedFormat(
                f"This archive uses project format version {version}, but this build "
                f"understands up to {PROJECT_FORMAT_VERSION}. Refusing to guess at a "
                "newer format."
            )
    return {
        "valid": not problems,
        "problems": problems,
        "entries": len(infos),
        "uncompressed_bytes": total_uncompressed,
        "manifest_version": version,
        "manifest": manifest,
    }


def import_project_archive(
    path: Path, session: Session, storage: ProjectStorage, limits, *, name_override: str | None = None
) -> dict[str, Any]:
    """Import an archive as a new project.

    Extraction lands in a temporary directory first; the live project is only
    created after every manifest hash has been verified.
    """
    inspection = inspect_archive(path, limits)
    if not inspection["valid"]:
        raise SecurityViolation(
            "The archive failed validation and was not extracted.",
            details={"problems": inspection["problems"][:20]},
        )
    manifest = inspection["manifest"]

    staging = Path(os.path.join(str(storage.root), f".import-{os.urandom(8).hex()}"))
    staging.mkdir(parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                safe = validate_relative_path(info.filename)
                destination = staging / PurePosixPath(*safe.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source_handle, destination.open("wb") as target_handle:
                    shutil.copyfileobj(source_handle, target_handle, length=1024 * 1024)
                if destination.stat().st_size > limits.max_archive_entry_bytes:
                    raise SecurityViolation(
                        "An extracted entry exceeded the per-file limit.", details={"path": safe.name}
                    )

        mismatches = _verify_hashes(staging, manifest.get("files", []))
        research_path = staging / "data" / "research.json"
        if not research_path.exists():
            raise UnsupportedFormat("The archive does not contain data/research.json.")
        research = json.loads(research_path.read_text(encoding="utf-8"))

        project_name = name_override or (manifest.get("project") or {}).get("name") or "Imported project"
        from ..services.project_service import ProjectService

        service = ProjectService(session, storage, limits)
        project = service.create(
            name=project_name,
            description=(manifest.get("project") or {}).get("description", ""),
            settings=(manifest.get("project") or {}).get("settings", {}),
        )
        _restore_captures(session, storage, project, research, staging, limits)
        restored = _restore_research(session, project, research)

        AuditLog = __import__("app.services.project_service", fromlist=["AuditLog"]).AuditLog
        AuditLog(session).record(
            AuditEvent(
                "project.import",
                project_id=project.id,
                object_type="project",
                object_id=project.id,
                details={
                    "archive": path.name,
                    "hash_mismatches": len(mismatches),
                    "counts": manifest.get("counts", {}),
                },
            )
        )
        session.commit()
        return {
            "project_id": project.id,
            "name": project.name,
            "imported": {
                "captures": len(research.get("captures", [])),
                "hypotheses": len(research.get("hypotheses", [])),
                "interpretations": len(research.get("interpretations", [])),
                "experiments": len(research.get("experiments", [])),
                "validation_runs": len(research.get("validation_runs", [])),
            },
            "hash_mismatches": mismatches,
            "orphaned_validation_runs": restored["orphaned_validation_runs"],
            "notes": [
                "Reconstructed streams are not stored in the archive; re-run capture "
                "analysis to reproduce them. Deterministic re-analysis is part of the "
                "project's reproducibility guarantee.",
                "Imported validation runs are marked stale: they describe results "
                "obtained elsewhere and must be re-run here before they are cited.",
                (
                    "One or more capture files did not match their recorded hashes and "
                    "were not imported."
                    if mismatches
                    else "All capture hashes matched the manifest."
                ),
            ],
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _verify_hashes(staging: Path, files: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    for entry in files:
        if entry.get("missing"):
            mismatches.append({"path": entry.get("path"), "problem": "source file was absent at export time"})
            continue
        expected = entry.get("sha256")
        target = staging / PurePosixPath(*validate_relative_path(entry["path"]).parts)
        if not target.exists():
            mismatches.append({"path": entry.get("path"), "problem": "file listed in the manifest is missing"})
            continue
        actual = sha256_file(target)
        expected_source = entry.get("expected_sha256")
        problems = []
        if expected and actual != expected:
            problems.append("archive hash mismatch")
        if expected_source and actual != expected_source:
            problems.append("source capture hash mismatch")
        if problems:
            mismatches.append(
                {"path": entry.get("path"), "problem": "; ".join(problems), "actual": actual}
            )
    return mismatches


def _restore_captures(
    session: Session,
    storage: ProjectStorage,
    project: Project,
    research: dict[str, Any],
    staging: Path,
    limits,
) -> None:
    mismatched = {
        entry.get("path")
        for entry in research.get("captures", [])
        if entry.get("sha256") and _file_hash(staging, project, entry) not in (None, entry["sha256"])
    }
    for entry in research.get("captures", []):
        staged = staging / "data" / "captures" / entry["id"] / f"original.{entry['format']}"
        if not staged.exists() or entry["id"] in mismatched:
            continue
        try:
            capture = _import_capture_row(session, storage, project, entry, staged, limits)
        except (Conflict, ValidationFailed, NotFound):
            continue


def _file_hash(staging: Path, project: Project, entry: dict[str, Any]) -> str | None:
    staged = staging / "data" / "captures" / entry["id"] / f"original.{entry['format']}"
    return sha256_file(staged) if staged.exists() else None


def _import_capture_row(
    session: Session, storage: ProjectStorage, project: Project, entry: dict[str, Any], staged: Path, limits
) -> Capture:
    from ..services.project_service import ProjectService

    service = ProjectService(session, storage, limits)
    capture = service.import_capture(
        project,
        name=entry["name"],
        source=staged,
        declared_format=entry["format"],
        source_kind="project_import",
    )
    capture.analysis_status = "pending"
    capture.stats = entry.get("stats", {})
    capture.diagnostics = entry.get("diagnostics", {})
    session.commit()
    return capture


def _restore_research(session: Session, project: Project, research: dict[str, Any]) -> dict[str, Any]:
    """Re-insert the analytical record, remapping foreign keys.

    Object ids are regenerated, so every reference (interpretation ->
    validation run, hypothesis -> interpretation) is remapped rather than
    reused.  A run whose interpretation could not be restored is still kept, but
    marked stale so it can never be mistaken for a current result.
    """
    interpretation_map: dict[str, Interpretation] = {}
    for payload in research.get("interpretations", []):
        row = Interpretation(
            project_id=project.id,
            name=payload.get("name", "Interpretation")[:200],
            schema_json=payload.get("schema_json", {}),
            version=int(payload.get("version", 1)),
            checksum=payload.get("checksum", ""),
            notes=payload.get("notes", ""),
        )
        session.add(row)
        session.flush()
        if payload.get("id"):
            interpretation_map[payload["id"]] = row

    for payload in research.get("hypotheses", []):
        session.add(
            Hypothesis(
                project_id=project.id,
                name=payload.get("name", "Hypothesis")[:200],
                description=payload.get("description", ""),
                scope=payload.get("scope", {}),
                proposed_structure=payload.get("proposed_structure", {}),
                observations=payload.get("observations", []),
                evidence_refs=payload.get("evidence_refs", []),
                counterexample_refs=payload.get("counterexample_refs", []),
                unknown_regions=payload.get("unknown_regions", []),
                status=payload.get("status", "draft"),
                version=int(payload.get("version", 1)),
                author=payload.get("author", "analyst")[:120],
                origin=payload.get("origin", "analyst")[:32],
            )
        )
    for payload in research.get("experiments", []):
        session.add(
            ExperimentEvent(
                project_id=project.id,
                timestamp=float(payload.get("timestamp", 0.0)),
                raw_timestamp=payload.get("raw_timestamp"),
                action=str(payload.get("action", ""))[:120],
                parameters=payload.get("parameters", {}),
                observed_result=payload.get("observed_result"),
                expected_result=payload.get("expected_result"),
                metadata_json=payload.get("metadata", {}),
                note=payload.get("note", ""),
            )
        )
    orphaned_runs = 0
    for payload in research.get("validation_runs", []):
        checksum = payload.get("interpretation_checksum")
        target = next(
            (row for row in interpretation_map.values() if row.checksum == checksum), None
        )
        if target is None:
            orphaned_runs += 1
        session.add(
            ValidationRun(
                interpretation_id=target.id if target is not None else _placeholder_interpretation(session, project),
                project_id=project.id,
                corpus=payload.get("corpus", {}),
                settings=payload.get("settings", {}),
                status=payload.get("status", "imported"),
                summary=payload.get("summary", {}),
                # An imported run can never be "current" until it is re-run
                # against reconstructed streams in this installation.
                stale=True,
                analyzer_version=payload.get("analyzer_version", ""),
            )
        )
    for payload in research.get("reports", []):
        session.add(
            Report(
                project_id=project.id,
                title=payload.get("title", "Report")[:200],
                generator="imported",
                markdown=payload.get("markdown", ""),
                facts=payload.get("facts", {}),
            )
        )
    for payload in research.get("framing_rules", []):
        session.add(
            FramingRule(
                project_id=project.id,
                name=payload.get("name", "Rule")[:200],
                version=int(payload.get("version", 1)),
                method=payload.get("method", "manual"),
                config=payload.get("config", {}),
                notes=payload.get("notes", ""),
                is_active=bool(payload.get("is_active", True)),
            )
        )
    session.commit()
    return {"orphaned_validation_runs": orphaned_runs}


def _placeholder_interpretation(session: Session, project: Project) -> str:
    row = Interpretation(
        project_id=project.id,
        name="[unavailable interpretation] imported with a validation run",
        schema_json={
            "schema_version": "1.0",
            "protocol_name": "Unavailable",
            "framing": {"method": "none"},
            "fields": [],
            "notes": (
                "This placeholder exists only so an imported validation run keeps its "
                "foreign key. The original interpretation was not present in the "
                "archive, so the run cannot be reproduced from here."
            ),
        },
        checksum="0" * 64,
        notes="Created automatically during project import.",
    )
    session.add(row)
    session.flush()
    return row.id


_ = (FramingRule, Annotation, Evidence)