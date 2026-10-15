"""Anomaly detection endpoints: train a baseline, then score new captures."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import select

from ... import prose
from ...analyzers.anomaly_detection import (
    MIN_TRAINING_SAMPLES_FOREST,
    MIN_TRAINING_SAMPLES_PROFILE,
    FeatureSet,
    active_algorithm,
    build_matrix,
    explain,
    message_features,
    score,
    session_features,
    sklearn_available,
    train_baseline,
)
from ...core.errors import (
    DependencyUnavailable,
    InsufficientCorpus,
    NotFound,
    ValidationFailed,
)
from ...core.logging import AuditEvent
from ...models import AnomalyModel, Capture, Message, Stream, TcpSession
from ...schemas import AnomalyScoreRequest, AnomalyTrainRequest
from ..context import SessionDep

router = APIRouter()


@router.get("/anomalies/status")
def status() -> dict[str, Any]:
    """What this installation can actually train and score.

    Anomaly detection always works: with scikit-learn present the baseline is an
    Isolation Forest, and without it - or on a corpus too small for a forest - a
    robust per-feature profile. Which one applies is reported here rather than
    inferred from a disabled tab, and the sample floors are reported with it so
    the analyst can see why.
    """
    forest = sklearn_available()
    return {
        "available": True,
        "algorithm": active_algorithm(),
        "sklearn_installed": forest,
        "min_samples": {
            "isolation_forest": MIN_TRAINING_SAMPLES_FOREST,
            "robust_profile": MIN_TRAINING_SAMPLES_PROFILE,
        },
        "availability_note": prose.AVAILABILITY_FOREST
        if forest
        else prose.AVAILABILITY_PROFILE,
    }


@router.post("/anomalies/train")
def train(payload: AnomalyTrainRequest, session: SessionDep) -> dict[str, Any]:
    captures = []
    for capture_id in payload.capture_ids:
        capture = session.get(Capture, capture_id)
        if capture is None:
            raise NotFound(f"Capture {capture_id!r} does not exist.")
        captures.append(capture)

    if payload.scope == "messages":
        records = _message_records(session, [c.id for c in captures], payload.max_samples)
        extractor = message_features
    else:
        records = _session_records(session, [c.id for c in captures])
        extractor = session_features

    dataset = build_matrix(records, extractor, limit=payload.max_samples)
    try:
        model = train_baseline(
            dataset,
            contamination=payload.contamination,
            n_estimators=payload.n_estimators,
            seed=payload.seed,
            algorithm=payload.algorithm,
        )
    except ValueError as exc:
        # The refusal carries the numbers in `details`, not only in prose, so the
        # interface can say what is missing in the reader's language and offer the
        # next step instead of printing an English sentence with two digits in it.
        available = len(dataset)
        required = (
            MIN_TRAINING_SAMPLES_PROFILE
            if payload.algorithm != "isolation_forest"
            and active_algorithm() == "robust_profile"
            or (payload.algorithm == "auto" and active_algorithm(available) == "robust_profile")
            else MIN_TRAINING_SAMPLES_FOREST
        )
        raise InsufficientCorpus(
            str(exc),
            details={
                "available": available,
                "required": required,
                "scope": payload.scope,
                "detector": (
                    "isolation_forest"
                    if active_algorithm(available) == "isolation_forest"
                    else "robust_profile"
                ),
                "next_step": (
                    "Messages exist only where a framing rule has been applied to the "
                    "capture; a capture with no framing rule contributes no messages at "
                    "all. Derive or apply a framing rule in the Protocol Bench, add "
                    "captures to the corpus, or score the sessions of this project."
                ),
            },
        ) from exc

    row = AnomalyModel(
        project_id=captures[0].project_id,
        name=payload.name,
        # Recorded from the model itself rather than defaulted: a profile-trained
        # baseline must not be listed as a forest.
        algorithm=str(model.params.get("algorithm", "isolation_forest")),
        params=model.params,
        feature_names=model.feature_names,
        training_summary=model.summary,
        seed=model.seed,
        blob=model.blob,
    )
    session.add(row)
    session.commit()
    return {
        "model_id": row.id,
        "name": row.name,
        "project_id": row.project_id,
        "training_summary": model.summary,
        "analyzer_version": model.version,
    }


@router.post("/anomalies/score")
def score_captures(payload: AnomalyScoreRequest, session: SessionDep) -> dict[str, Any]:
    model_row = session.get(AnomalyModel, payload.model_id)
    if model_row is None:
        raise NotFound(f"Anomaly model {payload.model_id!r} does not exist.")
    if not model_row.blob:
        raise ValidationFailed("This model has no stored parameters and cannot be applied.")

    capture_ids = []
    for capture_id in payload.capture_ids:
        capture = session.get(Capture, capture_id)
        if capture is None:
            raise NotFound(f"Capture {capture_id!r} does not exist.")
        if capture.project_id != model_row.project_id:
            raise NotFound(
                f"Capture {capture_id!r} does not belong to the project this model was "
                "trained on."
            )
        capture_ids.append(capture_id)

    if payload.scope == "messages":
        records = _message_records(session, capture_ids, 200_000)
        extractor = message_features
    else:
        records = _session_records(session, capture_ids)
        extractor = session_features

    dataset = build_matrix(records, extractor, limit=200_000)
    missing = [name for name in (model_row.feature_names or []) if name not in dataset.names]
    if missing:
        raise ValidationFailed(
            "The selected captures do not contain every feature this model was trained "
            "on.",
            details={
                "missing_features": missing,
                "explanation": (
                    "Features are never imputed: scoring a capture that cannot supply a "
                    "feature would produce a meaningless score."
                ),
            },
        )
    # Reorder columns to match the trained model and keep only the trained set.
    trained = list(model_row.feature_names)
    index_of = {name: i for i, name in enumerate(dataset.names)}
    dataset.names = trained
    dataset.rows = [[row[index_of[name]] for name in trained] for row in dataset.rows]

    results = score(model_row.blob, dataset, limit=payload.limit)
    means = _means(dataset)
    for entry in results:
        record = next((r for r in records if r.get("id") == entry["entity_id"]), None)
        if record:
            entry["explanation"] = explain(extractor(record), means)
            entry["navigate_to"] = {
                "message_id": entry["entity_id"] if entry["entity_type"] == "message" else None,
                "stream_id": record.get("stream_id"),
                "capture_id": record.get("capture_id"),
            }
    return {
        "model_id": model_row.id,
        "model_name": model_row.name,
        "scope": payload.scope,
        "scored": len(results),
        "anomalies": results,
        "feature_names": model_row.feature_names,
        "training_summary": model_row.training_summary,
        "interpretation": (
            "Scores rank how unusual each entity is relative to the training corpus. "
            "They are not probabilities and carry no severity ordering."
        ),
    }


@router.get("/anomalies/models")
def list_models(project_id: str, session: SessionDep) -> list[dict[str, Any]]:
    rows = (
        session.execute(select(AnomalyModel).where(AnomalyModel.project_id == project_id))
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "project_id": r.project_id,
            "algorithm": r.algorithm,
            "params": r.params,
            "feature_names": r.feature_names,
            "training_summary": r.training_summary,
            "created_at": r.created_at,
        }
        for r in rows
    ]


# --------------------------------------------------------------------------- #


def _message_records(session, capture_ids: list[str], limit: int) -> list[dict[str, Any]]:
    rows = (
        session.execute(
            select(Message, Stream.direction, Stream.id)
            .join(Stream, Stream.id == Message.stream_id)
            .where(Message.capture_id.in_(capture_ids))
            .order_by(Stream.id, Message.index_in_stream)
            .limit(limit)
        )
        .all()
    )
    records: list[dict[str, Any]] = []
    previous: dict[str, tuple[int, float]] = {}
    for message, direction, stream_id in rows:
        gap = None
        last = previous.get(stream_id)
        if last is not None:
            gap = max(0.0, message.timestamp - last[1])
        previous[stream_id] = (message.index_in_stream, message.timestamp)
        records.append(
            {
                "id": message.id,
                "entity_type": "message",
                "stream_id": stream_id,
                "capture_id": message.capture_id,
                "direction": direction,
                "features": message.features,
                "inter_message_gap": gap,
                "diagnostic_count": len(message.diagnostics or {}),
            }
        )
    return records


def _session_records(session, capture_ids: list[str]) -> list[dict[str, Any]]:
    rows = (
        session.execute(select(TcpSession).where(TcpSession.capture_id.in_(capture_ids)))
        .scalars()
        .all()
    )
    records: list[dict[str, Any]] = []
    for row in rows:
        streams = (
            session.execute(select(Stream).where(Stream.session_id == row.id)).scalars().all()
        )
        lengths: list[int] = []
        retransmissions = 0
        for stream in streams:
            for message in session.execute(
                select(Message.present_length)
                .where(Message.stream_id == stream.id)
                .limit(500)
            ).scalars():
                lengths.append(int(message))
            retransmissions += len((stream.diagnostics or {}).get("retransmissions", []) or [])
        if not lengths:
            continue
        mean = sum(lengths) / len(lengths)
        variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
        duration = max(1e-6, row.end_time - row.start_time)
        records.append(
            {
                "id": row.id,
                "entity_type": "session",
                "capture_id": row.capture_id,
                "message_count": len(lengths),
                "bytes_total": stream_bytes(streams),
                "mean_message_length": mean,
                "stddev_message_length": variance**0.5,
                "requests_per_second": len(lengths) / duration,
                "unique_peers": 2,
                "retransmissions": retransmissions,
                "duration": duration,
            }
        )
    return records


def stream_bytes(streams) -> int:
    return sum(s.present_bytes or 0 for s in streams)


def _means(dataset: FeatureSet) -> dict[str, float]:
    if not dataset.rows:
        return {}
    count = len(dataset.rows)
    return {
        name: sum(row[index] for row in dataset.rows) / count
        for index, name in enumerate(dataset.names)
    }


_ = AuditEvent