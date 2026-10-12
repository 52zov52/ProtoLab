"""The ``examples/`` artefacts open in the app and reproduce the path (§31 п.9–14).

These tests never trust the files on their word: they import the archived
project, re-analyse the capture (an archive intentionally does not carry
reconstructed streams), then feed the published specification back through the
API and check the corpus verdict.  If ``examples/`` has not been generated, the
tests skip with the command that produces it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
ARCHIVE = EXAMPLES / "thermostand.mplab"
ACCEPTED = EXAMPLES / "thermostand_spec.json"
REJECTED = EXAMPLES / "thermostand_rejected_spec.json"


def _require_examples() -> None:
    if not ARCHIVE.exists():
        pytest.skip(
            "examples/ has not been generated. Run: python scripts/build_examples.py"
        )


def _framing_from_spec(spec: dict) -> dict:
    length_field = spec["framing"]["length_field"]
    config = {
        "length_offset": length_field["offset"],
        "length_size": length_field["size"],
        "endianness": length_field["endianness"],
        "includes_header": "true" if length_field["includes_header"] else "false",
        "max_length": (1 << (8 * length_field["size"])) - 1 if length_field["size"] < 4 else 1 << 31,
    }
    if length_field.get("header_size") is not None:
        config["header_size"] = length_field["header_size"]
    return {"method": "length_prefix", "config": config}


@pytest.fixture()
def imported_example(client):
    """Import the example archive as a new project, then re-analyse its capture."""
    _require_examples()
    with ARCHIVE.open("rb") as handle:
        response = client.post(
            "/api/projects/import",
            data={},
            files={"file": (ARCHIVE.name, handle, "application/octet-stream")},
        )
    assert response.status_code == 200, response.text
    imported = response.json()
    assert imported["hash_mismatches"] == [], imported
    assert imported["imported"]["captures"] >= 1
    assert imported["imported"]["interpretations"] >= 1
    assert imported["imported"]["hypotheses"] >= 1

    captures = client.get(f"/api/projects/{imported['project_id']}/captures").json()
    baseline = next((c for c in captures if c["name"].endswith(".pcap")), None)
    assert baseline is not None, captures

    spec = json.loads(ACCEPTED.read_text(encoding="utf-8"))
    analysis = client.post(
        f"/api/captures/{baseline['id']}/analyze",
        json={"framing": _framing_from_spec(spec)},
    )
    assert analysis.status_code == 200, analysis.text
    return {"project_id": imported["project_id"], "capture": baseline, "spec": spec}


def test_archive_carries_the_accepted_interpretation(client, imported_example):
    rows = client.get(
        f"/api/projects/{imported_example['project_id']}/interpretations"
    ).json()
    assert imported_example["spec"]["checksum"] in {row["checksum"] for row in rows}


def test_published_specification_reproduces_the_verdict(client, imported_example):
    spec = imported_example["spec"]
    project_id = imported_example["project_id"]
    capture = imported_example["capture"]

    interpretation = client.post(
        f"/api/projects/{project_id}/interpreters",
        json={"name": "Re-imported accepted specification", "specification": spec},
    )
    assert interpretation.status_code == 201, interpretation.text
    created = interpretation.json()
    assert created["checksum"] == spec["checksum"]

    run = client.post(
        f"/api/projects/{project_id}/interpreters/{created['id']}/validate",
        json={"capture_ids": [capture["id"]]},
    ).json()
    assert run["failed"] == 0, run
    assert run["matched"] > 0
    assert run["verdict"] == "consistent_with_corpus"


def test_rejected_specification_still_produces_counterexamples(client, imported_example):
    wrong = json.loads(REJECTED.read_text(encoding="utf-8"))
    project_id = imported_example["project_id"]
    capture = imported_example["capture"]

    interpretation = client.post(
        f"/api/projects/{project_id}/interpreters",
        json={"name": "Re-imported rejected specification", "specification": wrong},
    )
    assert interpretation.status_code == 201, interpretation.text
    created = interpretation.json()

    run = client.post(
        f"/api/projects/{project_id}/interpreters/{created['id']}/validate",
        json={"capture_ids": [capture["id"]]},
    ).json()
    assert run["failed"] > 0, run
    counterexamples = client.get(
        f"/api/validation-runs/{run['run_id']}/counterexamples"
    ).json()
    assert counterexamples["count"] > 0


def test_application_artifact_matches_a_new_record():
    _require_examples()
    application = json.loads(
        (EXAMPLES / "thermostand_application.json").read_text(encoding="utf-8")
    )
    assert application["failed"] == 0
    assert application["matched"] > 0


def test_report_artifacts_are_non_empty():
    _require_examples()
    report = json.loads(
        (EXAMPLES / "thermostand_report.json").read_text(encoding="utf-8")
    )
    assert report["sections"]
    assert report["markdown"].strip()
    markdown = (EXAMPLES / "thermostand_report.md").read_text(encoding="utf-8")
    assert markdown.strip()
