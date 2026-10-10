"""Hypotheses, interpretations, validation runs and counterexamples."""

from __future__ import annotations

from fastapi import APIRouter, status
from sqlalchemy import select

from ...core.errors import NotFound
from ...interpretation.engine import describe_support, export_spec, parse_spec
from ...models import Hypothesis, Interpretation, ValidationRun
from ...schemas import (
    HypothesisCreate,
    HypothesisOut,
    HypothesisUpdate,
    InterpretationCreate,
    InterpretationOut,
    InterpretationUpdate,
    ValidationRequest,
    ValidationRunOut,
)
from ..context import SessionDep, StorageDep, load_project

router = APIRouter(prefix="/projects/{project_id}")


def _service(session, storage):
    from ...services.interpretation_service import InterpretationService

    return InterpretationService(session, storage)


def _interpretation_payload(row: Interpretation) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "hypothesis_id": row.hypothesis_id,
        "name": row.name,
        "specification": row.schema_json,
        "version": row.version,
        "checksum": row.checksum,
        "created_at": row.created_at,
        "notes": row.notes,
    }


@router.post("/hypotheses", response_model=HypothesisOut, status_code=status.HTTP_201_CREATED)
def create_hypothesis(
    project_id: str, payload: HypothesisCreate, session: SessionDep, storage: StorageDep
) -> Hypothesis:
    load_project(session, project_id)
    return _service(session, storage).create_hypothesis(
        project_id,
        name=payload.name,
        description=payload.description,
        scope=payload.scope,
        proposed_structure=payload.proposed_structure,
        observations=payload.observations,
        evidence_refs=payload.evidence_refs,
        status=payload.status,
        author=payload.author,
        origin=payload.origin,
    )


@router.put("/hypotheses/{hypothesis_id}", response_model=HypothesisOut)
def update_hypothesis(
    project_id: str,
    hypothesis_id: str,
    payload: HypothesisUpdate,
    session: SessionDep,
    storage: StorageDep,
) -> Hypothesis:
    load_project(session, project_id)
    existing = session.get(Hypothesis, hypothesis_id)
    if existing is None or existing.project_id != project_id:
        raise NotFound(f"Hypothesis {hypothesis_id!r} does not exist in this project.")
    return _service(session, storage).update_hypothesis(
        hypothesis_id, payload.model_dump(exclude_unset=True)
    )


@router.get("/interpretation-support")
def interpretation_support() -> dict:
    """What the declarative format can and cannot express."""
    return describe_support()


@router.post("/interpreters", status_code=status.HTTP_201_CREATED)
def create_interpretation(
    project_id: str, payload: InterpretationCreate, session: SessionDep, storage: StorageDep
) -> dict:
    load_project(session, project_id)
    row = _service(session, storage).create_interpretation(
        project_id,
        name=payload.name or "Interpretation",
        schema_json=payload.specification,
        hypothesis_id=payload.hypothesis_id,
        notes=payload.notes,
    )
    return _interpretation_payload(row)


@router.get("/interpreters", response_model=list[InterpretationOut])
def list_interpretations(project_id: str, session: SessionDep) -> list[dict]:
    load_project(session, project_id)
    rows = (
        session.execute(
            select(Interpretation)
            .where(Interpretation.project_id == project_id)
            .order_by(Interpretation.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_interpretation_payload(r) for r in rows]


@router.put("/interpreters/{interpretation_id}")
@router.patch("/interpreters/{interpretation_id}")
def update_interpretation(
    project_id: str,
    interpretation_id: str,
    payload: InterpretationUpdate,
    session: SessionDep,
    storage: StorageDep,
) -> dict:
    load_project(session, project_id)
    row = session.get(Interpretation, interpretation_id)
    if row is None or row.project_id != project_id:
        raise NotFound(f"Interpretation {interpretation_id!r} does not exist in this project.")
    if payload.specification is None:
        return _interpretation_payload(row)
    updated = _service(session, storage).update_interpretation(
        interpretation_id, payload.specification, notes=payload.notes
    )
    return _interpretation_payload(updated)


@router.get("/interpreters/{interpretation_id}")
def get_interpretation(
    project_id: str, interpretation_id: str, session: SessionDep
) -> dict:
    load_project(session, project_id)
    row = session.get(Interpretation, interpretation_id)
    if row is None or row.project_id != project_id:
        raise NotFound(f"Interpretation {interpretation_id!r} does not exist in this project.")
    spec = parse_spec(row.schema_json)
    runs = (
        session.execute(
            select(ValidationRun)
            .where(ValidationRun.interpretation_id == interpretation_id)
            .order_by(ValidationRun.started_at.desc())
        )
        .scalars()
        .all()
    )
    return {
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "checksum": row.checksum,
        "notes": row.notes,
        "created_at": row.created_at,
        "specification": export_spec(spec),
        "validation_runs": [
            ValidationRunOut(
                id=r.id,
                interpretation_id=r.interpretation_id,
                project_id=r.project_id,
                corpus=r.corpus,
                settings=r.settings,
                started_at=r.started_at,
                completed_at=r.completed_at,
                status=r.status,
                summary=r.summary,
                stale=r.stale,
                analyzer_version=r.analyzer_version,
            ).model_dump()
            for r in runs
        ],
    }


@router.post("/interpreters/{interpretation_id}/validate")
def validate_interpretation(
    project_id: str,
    interpretation_id: str,
    payload: ValidationRequest,
    session: SessionDep,
    storage: StorageDep,
) -> dict:
    """Apply the specification to a corpus and report counterexamples."""
    from ...services.interpretation_service import CorpusSelection

    load_project(session, project_id)
    row = session.get(Interpretation, interpretation_id)
    if row is None or row.project_id != project_id:
        raise NotFound(f"Interpretation {interpretation_id!r} does not exist in this project.")
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
        "total": summary.total,
        "matched": summary.matched,
        "partial": summary.partial,
        "failed": summary.failed,
        "unparsed": summary.unparsed,
        "counterexamples": summary.counterexamples,
        "by_message_type": summary.by_message_type,
        "verdict": summary.verdict,
        "notes": summary.notes,
    }


@router.get("/validation-runs/{run_id}")
def get_validation_run(run_id: str, session: SessionDep) -> dict:
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
def get_counterexamples(run_id: str, session: SessionDep, storage: StorageDep) -> dict:
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