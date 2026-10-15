"""The reason the forest was not used must be the reason actually stated.

Found live on a 24-message corpus with scikit-learn installed: the summary
warned "This baseline was trained without scikit-learn", sending an analyst to
install a package the deployment already had. The corpus, not the installation,
was the reason.
"""

from __future__ import annotations

import numpy as np
import pytest

from app import prose
from app.analyzers import anomaly_detection as ad


def dataset(count: int = 28, *, planted: int = 2):
    rng = np.random.default_rng(11)
    rows = rng.normal(loc=[120.0, 4.0, 0.05], scale=[8.0, 0.6, 0.02], size=(count, 3))
    rows = rows.tolist()
    for index in range(planted):
        rows[index] = [900.0 + index, 7.8, 1.5]
    return ad.FeatureSet(
        names=["length", "entropy", "gap"],
        rows=rows,
        entity_ids=[f"m{index}" for index in range(count)],
        entity_types=["message"] * count,
    )


def test_a_small_corpus_does_not_blame_a_missing_package(monkeypatch):
    """The exact corpus an analyst hits, with scikit-learn present."""
    monkeypatch.setattr(ad, "sklearn_available", lambda: True)

    model = ad.train_baseline(
        dataset(24), contamination=0.1, n_estimators=100, seed=1, algorithm="auto"
    )

    warnings = model.summary["warnings"]
    assert model.summary["forest_unavailable_reason"] == "insufficient_samples"
    assert prose.NO_FOREST_WARNING not in warnings, (
        "scikit-learn is installed here; saying it is not would send the "
        "analyst to install a package the deployment already has"
    )
    # The real reason is stated, with the numbers that establish it.
    assert prose.SMALL_CORPUS_FALLBACK in warnings
    assert model.summary["sample_count"] == 24
    assert model.summary["forest_required_samples"] == ad.MIN_TRAINING_SAMPLES_FOREST


def test_a_genuinely_missing_package_still_says_so(monkeypatch):
    monkeypatch.setattr(ad, "sklearn_available", lambda: False)

    model = ad.train_baseline(
        dataset(60), contamination=0.1, n_estimators=100, seed=1, algorithm="auto"
    )

    assert model.summary["forest_unavailable_reason"] == "no_scikit_learn"
    assert prose.NO_FOREST_WARNING in model.summary["warnings"]


def test_the_two_small_corpus_warnings_do_not_repeat_each_other(monkeypatch):
    """One note about a small corpus, not two near-identical ones."""
    monkeypatch.setattr(ad, "sklearn_available", lambda: True)

    model = ad.train_baseline(
        dataset(24), contamination=0.1, n_estimators=100, seed=1, algorithm="auto"
    )

    corpus_warnings = [
        w for w in model.summary["warnings"] if "{count}" in w
    ]
    # The specific one (why the forest was skipped) replaces the generic one.
    assert prose.SMALL_CORPUS_FALLBACK in corpus_warnings
    assert len(corpus_warnings) == 1


@pytest.mark.parametrize("count", [24, 28, 49])
def test_every_corpus_under_the_forest_floor_still_trains_and_scores(count):
    """Whatever the corpus, the tool works and says which detector it used."""
    model = ad.train_baseline(
        dataset(count), contamination=0.1, n_estimators=100, seed=1, algorithm="auto"
    )
    ranked = ad.score(model.blob, dataset(count))

    assert model.params["algorithm"] == "robust_profile"
    assert len(ranked) == count
    # Ranked, not thresholded into nothing: the score orders the corpus, and the
    # two planted entities come out above every ordinary one.
    assert {row["entity_id"] for row in ranked[:2]} == {"m0", "m1"}