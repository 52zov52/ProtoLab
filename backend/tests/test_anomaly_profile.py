"""The baseline that works without scikit-learn.

Anomaly detection used to be gated on an optional dependency, which meant the tab
said "unavailable" in any install that skipped the extra. The numpy profile
removes that gate, so the properties worth pinning are that it *finds the outliers
it was given*, that it is reproducible, and that every awkward input degrades
into an honest report rather than an exception or a plausible wrong answer.

The scikit-learn path is exercised in ``test_anomaly_detection.py``; these tests
deliberately pretend sklearn is missing, because that is the deployment this
detector exists for. They do not import that module, because it skips itself
when sklearn is absent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

from app import prose
from app.analyzers import anomaly_detection as ad

MIN_SAMPLES = ad.MIN_TRAINING_SAMPLES_FOREST
MIN_SAMPLES_PROFILE = ad.MIN_TRAINING_SAMPLES_PROFILE


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture()
def without_sklearn(monkeypatch):
    """Pretend the analytics extra was never installed.

    Patched where the name is *used* as well as where it is defined: the router
    imported it by value, so patching only the analyser module would leave the
    endpoint reporting the real installation.
    """
    monkeypatch.setattr(ad, "sklearn_available", lambda: False)
    monkeypatch.setattr(
        "app.api.routers.anomalies.sklearn_available", lambda: False, raising=False
    )


def make_dataset(rows: list[list[float]]) -> ad.FeatureSet:
    return ad.FeatureSet(
        names=["length", "entropy", "gap"],
        rows=rows,
        entity_ids=[f"m{index}" for index in range(len(rows))],
        entity_types=["message"] * len(rows),
    )


def corpus(count: int = 200, *, planted: int = 3) -> ad.FeatureSet:
    """A normal corpus with a few entities far away from it."""
    rng = np.random.default_rng(7)
    rows = rng.normal(loc=[120.0, 4.0, 0.05], scale=[8.0, 0.6, 0.02], size=(count, 3))
    rows = rows.tolist()
    for index in range(planted):
        rows[index] = [900.0 + index, 7.8, 1.5]
    return make_dataset(rows)


def train(dataset: ad.FeatureSet, *, contamination: float = 0.05, **kwargs):
    return ad.train_baseline(
        dataset,
        contamination=contamination,
        n_estimators=100,
        seed=42,
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# The detector
# --------------------------------------------------------------------------- #


def test_the_profile_baseline_finds_the_entities_that_were_planted(without_sklearn):
    dataset = corpus()
    ranked = ad.score(train(dataset).blob, dataset)

    assert {row["entity_id"] for row in ranked[:3]} == {"m0", "m1", "m2"}
    assert all(row["classification"] == "outlier" for row in ranked[:3])
    # The normal corpus follows them: nothing routine outranks a planted one.
    assert max(row["score"] for row in ranked[3:]) < min(row["score"] for row in ranked[:3])


def test_the_requested_contamination_is_what_gets_flagged(without_sklearn):
    dataset = corpus(count=500)
    ranked = ad.score(
        train(dataset, contamination=0.1).blob, dataset, limit=500
    )
    flagged = sum(1 for row in ranked if row["classification"] == "outlier")
    # Three planted, plus roughly the requested tenth of the corpus.
    assert 40 <= flagged <= 70


def test_training_is_deterministic(without_sklearn):
    dataset = corpus()
    first = train(dataset)
    second = train(dataset)

    assert first.blob == second.blob
    assert ad.score(first.blob, dataset) == ad.score(second.blob, dataset)


def test_a_constant_feature_is_neutral_rather_than_infinite(without_sklearn):
    rows = [[10.0, 4.0, 0.05] for _ in range(120)]
    rows[0] = [900.0, 4.0, 0.05]
    dataset = make_dataset(rows)
    model = train(dataset)

    ranked = ad.score(model.blob, dataset)
    assert all(np.isfinite(row["score"]) for row in ranked)
    assert ranked[0]["entity_id"] == "m0"
    # A feature that never varies is reported as carrying no information.
    assert any("{features}" in warning for warning in model.summary["warnings"])


def test_too_few_samples_is_refused_with_both_numbers_in_the_message(without_sklearn):
    """Below the profile's own floor the request is still refused, with numbers."""
    dataset = corpus(count=10)
    with pytest.raises(ValueError) as excinfo:
        train(dataset)
    message = str(excinfo.value)
    assert str(MIN_SAMPLES_PROFILE) in message
    assert "10" in message


def test_asking_for_the_forest_explicitly_fails_instead_of_silently_switching(
    without_sklearn,
):
    with pytest.raises(ValueError) as excinfo:
        train(corpus(), algorithm="isolation_forest")
    assert "scikit-learn" in str(excinfo.value)


def test_auto_picks_the_forest_when_it_is_available(monkeypatch):
    monkeypatch.setattr(ad, "sklearn_available", lambda: True)
    model = ad.train_baseline(
        corpus(count=MIN_SAMPLES + 10),
        contamination=0.05,
        n_estimators=100,
        seed=42,
        algorithm="auto",
    )
    assert model.params["algorithm"] == "isolation_forest"


def test_a_corpus_too_small_for_a_forest_trains_the_profile_and_says_why(monkeypatch):
    """The case an analyst actually hits: scikit-learn present, corpus under 50.

    This used to be a dead end - "only 24 were available" and nothing to do
    about it. Now the corpus trains what it can honestly support, and the reason
    the better detector was skipped is stated rather than implied.
    """
    monkeypatch.setattr(ad, "sklearn_available", lambda: True)
    small = corpus(count=28, planted=2)

    model = ad.train_baseline(
        small, contamination=0.1, n_estimators=100, seed=42, algorithm="auto"
    )

    assert model.params["algorithm"] == "robust_profile"
    # A machine-readable reason plus the counts, not a sentence: the UI renders
    # it in the reader's language and supplies the numbers itself.
    assert model.summary["forest_unavailable_reason"] == "insufficient_samples"
    assert model.summary["sample_count"] == 28
    assert model.summary["forest_required_samples"] == MIN_SAMPLES
    assert any("{count}" in warning for warning in model.summary["warnings"])
    # ...and the fallback still does its job on that corpus.
    ranked = ad.score(model.blob, small)
    assert {row["entity_id"] for row in ranked[:2]} == {"m0", "m1"}


def test_the_status_endpoint_reports_the_floor_of_each_detector(
    without_sklearn, client
):
    payload = client.get("/api/anomalies/status").json()
    assert payload["min_samples"] == {
        "isolation_forest": MIN_SAMPLES,
        "robust_profile": MIN_SAMPLES_PROFILE,
    }
    # The note names the detector this deployment would use, so the reason a
    # score looks the way it does is readable without opening the code.
    note = payload["availability_note"]
    assert "robust per-feature profile" in note
    assert payload["sklearn_installed"] is False


def test_the_status_note_states_the_forest_floor_when_it_can_be_used(client):
    """With scikit-learn present the note says how big a corpus must be."""
    if not ad.sklearn_available():
        pytest.skip("this installation has no scikit-learn, so the branch is unreachable")
    payload = client.get("/api/anomalies/status").json()
    assert payload["sklearn_installed"] is True
    assert payload["algorithm"] == "isolation_forest"
    assert payload["availability_note"] == prose.AVAILABILITY_FOREST
    assert str(MIN_SAMPLES) in payload["availability_note"]


def test_the_summary_states_what_the_score_is_not(without_sklearn):
    summary = train(corpus()).summary
    assert summary["algorithm"] == "robust_profile"
    assert "not a probability of compromise" in summary["interpretation"]
    assert any("without scikit-learn" in warning for warning in summary["warnings"])


def test_a_model_trained_on_features_a_capture_lacks_is_refused(without_sklearn):
    model = train(corpus())
    narrower = ad.FeatureSet(
        names=["length"],
        rows=[[120.0] for _ in range(60)],
        entity_ids=[f"m{index}" for index in range(60)],
        entity_types=["message"] * 60,
    )
    with pytest.raises(ValueError) as excinfo:
        ad.score(model.blob, narrower)
    assert "entropy" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# Through the API
# --------------------------------------------------------------------------- #


def _write_many_message_capture(path: Path) -> Path:
    """A bench capture with ~120 framed messages, built by the bench generator."""
    import importlib.util

    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "bench_generate_profile", root / "tools" / "testbench" / "generate.py"
    )
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their module through sys.modules during class creation.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    writer = module.PcapWriter()
    client, server = module._hosts("192.168.10.25", "192.168.10.5", 51555, 9500)
    conversation = module.Conversation(writer, client, server)
    conversation.handshake()
    for request in range(1, 61):
        conversation.send(client, server, module.read_request(request, 0x0001))
        conversation.send(
            server,
            client,
            module.value_response(request, 1000 + request, module.STATUS_OK),
        )
    conversation.close()
    return writer.write(path)


def _capture_with_messages(client, project_id, tmp_path, bench_framing) -> dict:
    capture_file = _write_many_message_capture(tmp_path / "profile_messages.pcap")
    with capture_file.open("rb") as handle:
        capture = client.post(
            "/api/captures",
            data={"project_id": project_id, "name": "profile_messages.pcap"},
            files={"file": ("profile_messages.pcap", handle, "application/octet-stream")},
        ).json()
    analyzed = client.post(
        f"/api/captures/{capture['id']}/analyze", json={"framing": bench_framing}
    )
    assert analyzed.status_code == 200, analyzed.text
    return capture


def test_the_status_endpoint_reports_the_active_algorithm(without_sklearn, client):
    payload = client.get("/api/anomalies/status").json()
    assert payload["available"] is True
    assert payload["algorithm"] == "robust_profile"
    assert payload["sklearn_installed"] is False


def test_a_baseline_trained_without_sklearn_is_listed_as_a_profile(
    without_sklearn, client, project, bench_framing, tmp_path
):
    """A profile-trained baseline must not be advertised as a forest."""
    capture = _capture_with_messages(client, project["id"], tmp_path, bench_framing)

    trained = client.post(
        "/api/anomalies/train",
        json={
            "name": "Profile baseline",
            "capture_ids": [capture["id"]],
            "scope": "messages",
            "contamination": 0.1,
        },
    )
    assert trained.status_code == 200, trained.text
    assert trained.json()["training_summary"]["algorithm"] == "robust_profile"

    listed = client.get(f"/api/anomalies/models?project_id={project['id']}").json()
    assert [row["algorithm"] for row in listed] == ["robust_profile"]


def test_scoring_returns_ranked_rows_with_the_features_behind_each_score(
    without_sklearn, client, project, bench_framing, tmp_path
):
    capture = _capture_with_messages(client, project["id"], tmp_path, bench_framing)
    model_id = client.post(
        "/api/anomalies/train",
        json={
            "name": "Profile baseline",
            "capture_ids": [capture["id"]],
            "scope": "messages",
            "contamination": 0.1,
        },
    ).json()["model_id"]

    scored = client.post(
        "/api/anomalies/score",
        json={
            "model_id": model_id,
            "capture_ids": [capture["id"]],
            "scope": "messages",
            "limit": 10,
        },
    )
    assert scored.status_code == 200, scored.text
    body = scored.json()

    rows = body["anomalies"]
    assert rows, "scoring a trained corpus must return rows"
    assert [row["score"] for row in rows] == sorted(
        (row["score"] for row in rows), reverse=True
    )
    assert all(row["explanation"] for row in rows)
    # The wording that keeps a score from being read as a verdict.
    assert "not probabilities" in body["interpretation"]