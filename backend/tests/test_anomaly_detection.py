"""Anomaly detection: the model must be reproducible and rank real outliers.

Roadmap item 8.9 asks that training on a baseline ranks anomalies on a second
capture.  These tests use a synthetic but fully determined corpus so the ranking
claim is checkable, and they assert the wording stays honest: a score is a
relative "less typical" measure, never a probability of compromise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analyzers.anomaly_detection import (
    build_matrix,
    explain,
    message_features,
    score,
    train_isolation_forest,
)

pytest.importorskip("sklearn")


def _record(index: int, **overrides: float) -> dict:
    features = {
        "length": 64.0,
        "entropy": 3.0,
        "unique_bytes": 30.0,
        "zero_ratio": 0.2,
        "printable_ratio": 0.5,
        "repeating_score": 0.1,
    }
    features.update(overrides)
    return {
        "id": f"m{index}",
        "entity_type": "message",
        "direction": "a2b",
        "features": features,
    }


def _corpus() -> tuple[list[dict], list[dict]]:
    baseline = [_record(i) for i in range(120)]
    anomalies = [
        _record(
            1000 + i,
            length=4000.0,
            entropy=7.9,
            unique_bytes=250.0,
            zero_ratio=0.0,
            printable_ratio=0.0,
            repeating_score=0.9,
        )
        for i in range(3)
    ]
    return baseline, anomalies


def test_training_on_a_baseline_ranks_the_anomalies():
    baseline, anomalies = _corpus()
    dataset = build_matrix(baseline + anomalies, message_features)
    model = train_isolation_forest(
        dataset, contamination=0.05, n_estimators=100, seed=7
    )
    scored = score(model.blob, dataset, limit=200)

    top_three = {row["entity_id"] for row in scored[:3]}
    assert top_three == {a["id"] for a in anomalies}
    assert all(row["classification"] == "outlier" for row in scored[:3])
    # The score never claims compromise.
    assert "not a probability of compromise" in model.summary["interpretation"]


def test_the_same_seed_reproduces_the_same_model_and_ranking():
    baseline, anomalies = _corpus()
    dataset = build_matrix(baseline + anomalies, message_features)

    first = train_isolation_forest(dataset, contamination=0.05, n_estimators=100, seed=11)
    second = train_isolation_forest(dataset, contamination=0.05, n_estimators=100, seed=11)

    assert first.summary["score_mean"] == second.summary["score_mean"]
    assert first.summary["score_max"] == second.summary["score_max"]
    assert first.blob == second.blob

    order_a = [row["entity_id"] for row in score(first.blob, dataset, limit=200)]
    order_b = [row["entity_id"] for row in score(second.blob, dataset, limit=200)]
    assert order_a == order_b


def test_too_few_samples_is_refused_not_faked():
    dataset = build_matrix([_record(i) for i in range(10)], message_features)
    with pytest.raises(ValueError):
        train_isolation_forest(dataset, contamination=0.05, n_estimators=50, seed=1)


def test_incomplete_records_are_excluded_never_imputed():
    records = [
        _record(0),
        {"id": "sparse", "entity_type": "message", "direction": "a2b",
         "features": {"length": 12.0}},
    ]
    dataset = build_matrix(records, message_features)
    assert "sparse" not in dataset.entity_ids
    assert dataset.skipped.get("incomplete_features")


def test_explain_ranks_the_largest_relative_deviation_first():
    findings = explain({"length": 4000.0, "entropy": 3.1}, {"length": 64.0, "entropy": 3.0})
    assert findings[0]["feature"] == "length"
    assert findings[0]["delta"] == 3936.0


def _write_many_message_capture(path):
    """Build a real bench capture with ~120 messages using the bench generator."""
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "bench_generate", root / "tools" / "testbench" / "generate.py"
    )
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their module through sys.modules during class creation.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    writer = module.PcapWriter()
    client, server = module._hosts("192.168.10.25", "192.168.10.5", 51555, 9500)
    conversation = module.Conversation(writer, client, server)
    conversation.handshake()
    for req in range(1, 61):
        conversation.send(client, server, module.read_request(req, 0x0001))
        conversation.send(server, client, module.value_response(req, 1000 + req, module.STATUS_OK))
    conversation.close()
    return writer.write(path)


def test_train_and_score_round_trip_through_the_api(client, project, bench_framing, tmp_path):
    """The endpoint path must persist a model and score with it.

    This is the path that silently crashed before: ``train_isolation_forest``
    read a field name the dataset does not expose, so any deployment with
    scikit-learn installed failed the moment it had enough samples.
    """
    capture_file = _write_many_message_capture(tmp_path / "many_messages.pcap")
    with capture_file.open("rb") as handle:
        capture = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": "many_messages.pcap"},
            files={"file": ("many_messages.pcap", handle, "application/octet-stream")},
        ).json()
    analyzed = client.post(
        f"/api/captures/{capture['id']}/analyze", json={"framing": bench_framing}
    )
    assert analyzed.status_code == 200, analyzed.text

    trained = client.post(
        "/api/anomalies/train",
        json={"name": "baseline", "capture_ids": [capture["id"]], "scope": "messages", "seed": 3},
    )
    assert trained.status_code == 200, trained.text
    summary = trained.json()["training_summary"]
    assert summary["seed"] == 3
    assert summary["feature_names"], "the model must record the features it learned on"

    scored = client.post(
        "/api/anomalies/score",
        json={
            "model_id": trained.json()["model_id"],
            "capture_ids": [capture["id"]],
            "scope": "messages",
        },
    )
    assert scored.status_code == 200, scored.text
    body = scored.json()
    assert body["scored"] >= 50
    assert body["anomalies"]
    assert "not probabilities" in body["interpretation"]


def test_train_refuses_too_few_samples_instead_of_guessing(client, project, bench_dir, bench_framing):
    with (bench_dir / "basic.pcap").open("rb") as handle:
        capture = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": "basic.pcap"},
            files={"file": ("basic.pcap", handle, "application/octet-stream")},
        ).json()
    client.post(f"/api/captures/{capture['id']}/analyze", json={"framing": bench_framing})
    refused = client.post(
        "/api/anomalies/train",
        json={"name": "too-small", "capture_ids": [capture["id"]], "scope": "messages"},
    )
    assert refused.status_code == 400
    assert "At least 50 samples" in refused.json()["error"]["message"]


