"""Shared pytest fixtures: an isolated app, database and storage per test."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "data" / "testbench"
sys.path.insert(0, str(ROOT / "backend"))


@pytest.fixture()
def settings(tmp_path: Path):
    """Isolated settings, also published through the environment.

    ``get_settings()`` is used in a few service paths, so the environment must
    agree with the object handed to ``create_app`` or tests would read a
    different data directory.
    """
    import os

    from app.core.config import Settings, reset_settings

    saved = {k: v for k, v in os.environ.items() if k.startswith("MPLAB_")}
    for key in list(saved):
        os.environ.pop(key, None)
    data_dir = tmp_path / "data"
    os.environ["MPLAB_DATA_DIR"] = str(data_dir)
    reset_settings()
    instance = Settings(data_dir=data_dir)
    yield instance
    for key in list(os.environ):
        if key.startswith("MPLAB_"):
            os.environ.pop(key, None)
    os.environ.update(saved)
    reset_settings()


@pytest.fixture()
def client(settings):
    from app.api.main import create_app

    app = create_app(settings)
    with TestClient(app, base_url="http://testserver") as test_client:
        test_client.app_instance = app  # type: ignore[attr-defined]
        yield test_client
    shutil.rmtree(settings.data_dir, ignore_errors=True)


@pytest.fixture()
def bench_dir() -> Path:
    if not BENCH.exists() or not any(BENCH.glob("*.pcap")):
        pytest.skip(
            "The synthetic test bench has not been generated. Run: "
            "python tools/testbench/generate.py --out data/testbench"
        )
    return BENCH


@pytest.fixture()
def project(client):
    response = client.post("/api/projects", json={"name": "Test project"})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture()
def bench_framing() -> dict:
    """The framing rule the analyst must *derive*; used to seed analyses."""
    return {
        "method": "length_prefix",
        "config": {
            "length_offset": 0,
            "length_size": 2,
            "endianness": "big",
            "includes_header": "true",
            "max_length": 65535,
        },
    }


@pytest.fixture()
def imported(client, project, bench_dir, bench_framing):
    """A project with the baseline capture imported and analysed and framed."""
    capture_file = bench_dir / "basic.pcap"
    with capture_file.open("rb") as handle:
        response = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": "basic.pcap"},
            files={"file": ("basic.pcap", handle, "application/octet-stream")},
        )
    assert response.status_code == 201, response.text
    capture = response.json()
    analysis = client.post(
        f"/api/captures/{capture['id']}/analyze", json={"framing": bench_framing}
    )
    assert analysis.status_code == 200, analysis.text
    return {"project": project, "capture": capture, "analysis": analysis.json(), "framing": bench_framing}


def make_spec(length_offset: int = 0, length_size: int = 2, endianness: str = "big") -> dict:
    """The bench protocol's real layout, expressed as an interpretation."""
    return {
        "schema_version": "1.0",
        "protocol_name": "MadrigalTestDevice",
        "description": "Recovered from the basic capture: 2-byte big-endian length that "
                       "counts itself, one type byte, a 2-byte request id.",
        "framing": {
            "method": "length_prefix",
            "length_field": {
                "offset": length_offset,
                "size": length_size,
                "endianness": endianness,
                "includes_header": True,
            },
        },
        "fields": [
            {
                "name": "length",
                "kind": "uint16",
                "offset": 0,
                "size": 2,
                "endianness": "big",
                "semantic_status": "observed",
                "description": "Total message length including these two bytes.",
            },
            {
                "name": "message_type",
                "kind": "enum",
                "offset": 2,
                "size": 1,
                "semantic_status": "hypothesis",
                "description": "1=read, 2=set, 3=measurements, 4=ack, 5=heartbeat",
                "values": {
                    "1": "read_parameter",
                    "2": "set_parameter",
                    "3": "measurements",
                    "4": "ack",
                    "5": "heartbeat",
                },
            },
            {
                "name": "request_id",
                "kind": "uint16",
                "offset": 3,
                "size": 2,
                "endianness": "big",
                "semantic_status": "hypothesis",
                "description": "Echoed by the response so pairs can be correlated.",
            },
        ],
        "message_types": [
            {
                "name": "read_request",
                "when": {"field": "message_type", "operator": "equals", "value": {"raw": 1}},
            },
            {
                "name": "set_request",
                "when": {"field": "message_type", "operator": "equals", "value": {"raw": 2}},
            },
        ],
    }