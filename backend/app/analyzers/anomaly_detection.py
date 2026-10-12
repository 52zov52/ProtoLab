"""Anomaly detection with Isolation Forest.

Everything here is deliberately careful about wording:

* the score is a *relative* outlier measure, not a probability of compromise;
* features that cannot be computed from the current capture are excluded rather
  than imputed with zeros;
* the seed and parameters are stored so a score can be reproduced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

ANOMALY_VERSION = "anomaly-detection/1.1"
MIN_TRAINING_SAMPLES = 50


@dataclass
class FeatureSet:
    names: list[str]
    rows: list[list[float]]
    entity_ids: list[str]
    entity_types: list[str]
    skipped: dict[str, str] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.rows)


def message_features(record: dict[str, Any]) -> dict[str, float]:
    """Features for one message.

    Only values that are genuinely present are returned.  A missing feature is
    omitted so the model never learns from an imputed zero.
    """
    features = record.get("features") or {}
    out: dict[str, float] = {}
    if "length" in features:
        out["length"] = float(features["length"])
    if "entropy" in features:
        out["entropy"] = float(features["entropy"])
    if "unique_bytes" in features:
        out["unique_bytes"] = float(features["unique_bytes"])
    if "zero_ratio" in features:
        out["zero_ratio"] = float(features["zero_ratio"])
    if "printable_ratio" in features:
        out["printable_ratio"] = float(features["printable_ratio"])
    if "repeating_score" in features:
        out["repeating_score"] = float(features["repeating_score"])
    out["is_response"] = 1.0 if record.get("direction") == "b2a" else 0.0
    gap = record.get("inter_message_gap")
    if gap is not None:
        out["inter_message_gap"] = float(gap)
    if record.get("diagnostic_count") is not None:
        out["diagnostic_count"] = float(record["diagnostic_count"])
    return out


def session_features(record: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    for key in (
        "message_count",
        "bytes_total",
        "mean_message_length",
        "stddev_message_length",
        "requests_per_second",
        "unique_peers",
        "retransmissions",
        "duration",
    ):
        if key in record and record[key] is not None:
            out[key] = float(record[key])
    return out


def build_matrix(
    records: Sequence[dict[str, Any]], extractor, *, limit: int = 50_000
) -> FeatureSet:
    kept: list[dict[str, float]] = []
    ids: list[str] = []
    types: list[str] = []
    names: set[str] = set()
    for record in records[:limit]:
        features = extractor(record)
        if not features:
            continue
        kept.append(features)
        ids.append(str(record.get("id")))
        types.append(str(record.get("entity_type", "unknown")))
        names.update(features)
    ordered = sorted(names)
    # A feature that only some records carry cannot be compared across rows.
    # Those records are dropped rather than imputed with zeros, so the model
    # never learns a relationship from fabricated data.
    complete_mask = [
        all(name in features for name in ordered) for features in kept
    ]
    skipped: dict[str, str] = {}
    dropped = complete_mask.count(False)
    if dropped:
        skipped["incomplete_features"] = (
            f"{dropped} of {len(kept)} records lacked at least one of the {len(ordered)} "
            "features and were excluded rather than imputed"
        )
    matrix = [
        [float(row[name]) for name in ordered]
        for row, keep in zip(kept, complete_mask)
        if keep
    ]
    return FeatureSet(
        names=ordered,
        rows=matrix,
        entity_ids=[i for i, keep in zip(ids, complete_mask) if keep],
        entity_types=[t for t, keep in zip(types, complete_mask) if keep],
        skipped=skipped,
    )


@dataclass
class TrainedModel:
    blob: bytes
    feature_names: list[str]
    params: dict[str, Any]
    summary: dict[str, Any]
    seed: int
    version: str = ANOMALY_VERSION


def train_isolation_forest(
    dataset: FeatureSet, *, contamination: float, n_estimators: int, seed: int
) -> TrainedModel:
    import pickle

    import numpy as np
    from sklearn.ensemble import IsolationForest

    if len(dataset) < MIN_TRAINING_SAMPLES:
        raise ValueError(
            f"At least {MIN_TRAINING_SAMPLES} samples are needed to train a stable "
            f"model; only {len(dataset)} were available."
        )
    matrix = np.asarray(dataset.rows, dtype=float)
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=seed,
        n_jobs=1,
    )
    model.fit(matrix)
    inlier_scores = -model.score_samples(matrix)
    summary = {
        "sample_count": int(matrix.shape[0]),
        "feature_count": int(matrix.shape[1]),
        "feature_names": dataset.names,
        "contamination": contamination,
        "n_estimators": n_estimators,
        "seed": seed,
        "score_min": float(np.min(inlier_scores)),
        "score_max": float(np.max(inlier_scores)),
        "score_mean": float(np.mean(inlier_scores)),
        "score_std": float(np.std(inlier_scores)),
        "expected_outlier_fraction": float(contamination),
        "skipped": dataset.skipped,
        "interpretation": (
            "Scores are relative outlier measures within this baseline corpus. A "
            "higher score means 'less typical than the training data'. It is not a "
            "probability of compromise and carries no severity ranking."
        ),
        "warnings": _warnings(dataset, matrix),
    }
    return TrainedModel(
        blob=pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL),
        feature_names=dataset.names,
        params={
            "contamination": contamination,
            "n_estimators": n_estimators,
            "seed": seed,
            "algorithm": "isolation_forest",
            "sklearn_version": _sklearn_version(),
        },
        summary=summary,
        seed=seed,
    )


def score(model_blob: bytes, dataset: FeatureSet, *, limit: int = 2000) -> list[dict[str, Any]]:
    import pickle

    import numpy as np

    model = pickle.loads(model_blob)  # noqa: S301 - our own pickle, written by us
    if not dataset.rows:
        return []
    matrix = np.asarray(dataset.rows, dtype=float)
    scores = -model.score_samples(matrix)
    predictions = model.predict(matrix)
    rows: list[dict[str, Any]] = []
    for index, entity_id in enumerate(dataset.entity_ids[: len(matrix)]):
        rows.append(
            {
                "entity_id": entity_id,
                "entity_type": dataset.entity_types[index] if index < len(dataset.entity_types) else "unknown",
                "score": float(scores[index]),
                "classification": "outlier" if predictions[index] == -1 else "inlier",
            }
        )
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:limit]


def explain(entity_features: dict[str, float], dataset_mean: dict[str, float]) -> list[dict[str, Any]]:
    """Which features pushed an entity away from the baseline average."""
    out = []
    for name, value in entity_features.items():
        mean = dataset_mean.get(name)
        if mean is None:
            continue
        delta = float(value) - float(mean)
        scale = abs(float(mean)) or 1.0
        out.append(
            {
                "feature": name,
                "value": float(value),
                "baseline_mean": float(mean),
                "delta": round(delta, 4),
                "relative_delta": round(delta / scale, 4),
            }
        )
    out.sort(key=lambda r: abs(r["relative_delta"]), reverse=True)
    return out


def _warnings(dataset: FeatureSet, matrix) -> list[str]:
    import numpy as np

    warnings: list[str] = []
    if matrix.shape[0] < 500:
        warnings.append(
            f"Only {matrix.shape[0]} training samples were available. Isolation Forest "
            "is reliable from roughly 500 samples upward; treat these scores as noisy."
        )
    constant = [
        name
        for index, name in enumerate(dataset.names)
        if float(np.std(matrix[:, index])) == 0.0
    ]
    if constant:
        warnings.append(
            f"These features were constant across the baseline corpus and carry no "
            f"information: {constant}."
        )
    return warnings


def _sklearn_version() -> str:
    try:
        import sklearn

        return sklearn.__version__
    except Exception:  # pragma: no cover - defensive
        return "unknown"


def sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401

        return True
    except ImportError:
        return False