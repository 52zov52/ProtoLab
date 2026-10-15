"""Interpretation and validation endpoints mounted at the API root.

These are thin aliases of the project-scoped routes in ``hypotheses.py`` so the
documented flat paths (``/api/interpreters/{id}/validate``) work as specified.
"""

from __future__ import annotations

from fastapi import APIRouter

from ...schemas import InterpretationCreate, InterpretationOut, InterpretationUpdate, ValidationRequest
from ..context import SessionDep, StorageDep, load_project

router = APIRouter()


@router.post("/interpreters", response_model=InterpretationOut)
def create_interpretation_global(
    payload: InterpretationCreate,
    session: SessionDep,
    storage: StorageDep,
    project_id: str | None = None,
) -> object:
    if not payload.specification:
        from ...core.errors import ValidationFailed

        raise ValidationFailed("project_id is required when no payload.project_id is supplied.")
    target = project_id or payload.specification.get("__project_id__")
    if not target:
        from ...core.errors import ValidationFailed

        raise ValidationFailed(
            "A global interpretation must name its project. Use "
            "POST /api/projects/{project_id}/interpreters instead."
        )
    load_project(session, target)
    from .hypotheses import _service
    from ...services.interpretation_service import interpretation_payload

    row = _service(session, storage).create_interpretation(
        target,
        name=payload.name or "Interpretation",
        schema_json=payload.specification,
        hypothesis_id=payload.hypothesis_id,
        notes=payload.notes,
    )
    return interpretation_payload(row)


@router.get("/validation-runs/{run_id}")
def get_run_global(run_id: str, session: SessionDep) -> dict:
    """Flat alias of the project-scoped validation-run endpoint."""
    from ...core.errors import NotFound
    from ...models import Interpretation, ValidationRun

    run = session.get(ValidationRun, run_id)
    if run is None:
        raise NotFound(f"Validation run {run_id!r} does not exist.")
    interpretation = session.get(Interpretation, run.interpretation_id)
    return {
        "id": run.id,
        "interpretation_id": run.interpretation_id,
        "interpretation_name": interpretation.name if interpretation else None,
        "interpretation_version": interpretation.version if interpretation else None,
        "specification_checksum": (run.settings or {}).get("spec_checksum"),
        "project_id": run.project_id,
        "corpus": run.corpus,
        "settings": run.settings,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "status": run.status,
        "summary": run.summary,
        "stale": run.stale,
        "stale_reason": (
            "The specification changed after this run, so its results describe an "
            "older rule version."
            if run.stale
            else None
        ),
        "analyzer_version": run.analyzer_version,
    }


@router.get("/validation-runs/{run_id}/counterexamples")
def get_counterexamples_global(run_id: str, session: SessionDep, storage: StorageDep) -> dict:
    from ...core.errors import NotFound
    from ...models import ValidationRun

    from .hypotheses import _service

    run = session.get(ValidationRun, run_id)
    if run is None:
        raise NotFound(f"Validation run {run_id!r} does not exist.")
    examples = _service(session, storage).counterexamples(run_id)
    return {
        "run_id": run_id,
        "count": len(examples),
        "counterexamples": examples,
        "disclaimer": (
            "A counterexample shows where the rule did not hold on this corpus. "
            "It does not by itself prove the rule is wrong; a gap in the capture is "
            "an equally valid explanation until ruled out."
        ),
    }


@router.post("/interpreters/{interpretation_id}/validate")
def validate_global(
    interpretation_id: str, payload: ValidationRequest, session: SessionDep, storage: StorageDep
) -> dict:
    from ...models import Interpretation
    from .hypotheses import _service
    from ...services.interpretation_service import CorpusSelection

    row = session.get(Interpretation, interpretation_id)
    if row is None:
        from ...core.errors import NotFound

        raise NotFound(f"Interpretation {interpretation_id!r} does not exist.")
    load_project(session, row.project_id)
    corpus = CorpusSelection(
        capture_ids=payload.capture_ids,
        session_ids=payload.session_ids,
        directions=payload.directions,
        limit_per_stream=payload.limit_per_stream,
    )
    summary = _service(session, storage).validate(row, corpus)
    return {
        "interpretation_id": interpretation_id,
        "run_id": summary.run_id,
        "verdict": summary.verdict,
        "total": summary.total,
        "matched": summary.matched,
        "partial": summary.partial,
        "failed": summary.failed,
        "unparsed": summary.unparsed,
        "counterexamples": summary.counterexamples,
        "by_message_type": summary.by_message_type,
        "notes": summary.notes,
    }


@router.put("/interpreters/{interpretation_id}")
def update_global(
    interpretation_id: str,
    payload: InterpretationUpdate,
    session: SessionDep,
    storage: StorageDep,
) -> object:
    from ...core.errors import NotFound
    from ...models import Interpretation
    from .hypotheses import _service

    row = session.get(Interpretation, interpretation_id)
    if row is None:
        raise NotFound(f"Interpretation {interpretation_id!r} does not exist.")
    load_project(session, row.project_id)
    if payload.specification is None:
        return row
    return _service(session, storage).update_interpretation(
        interpretation_id, payload.specification, notes=payload.notes
    )