"""End-to-end check against the real "Термостенд" protocol sample.

The sample in ``sample_protocol/`` is a real TCP application exchange wrapped in
modelled packet headers.  Its true layout, per the accompanying materials, is::

    bytes 0..1   magic        0xA65C (big-endian u16)
    bytes 2..3   payload_len  big-endian u16
    bytes 4..5   request id   big-endian u16
    byte  6      flags
    byte  7      command
    bytes 8..    payload          total length = 8 + payload_len

Nothing here is allowed to use that knowledge: the test drives only the public
API and checks that the app *derives* this structure from the bytes.  The
assertions are the acceptance criteria of roadmap item 8.8 / stage 2.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sample_protocol"


@pytest.fixture()
def sample_capture_file() -> Path:
    path = SAMPLE / "research" / "01_configuration.pcap"
    if not path.exists():
        pytest.skip("sample_protocol/ is not present in this checkout")
    return path


def _streams(client, session_id: str) -> list[dict]:
    streams = client.get(f"/api/sessions/{session_id}/streams").json()
    return streams["items"] if isinstance(streams, dict) else streams


def _a2b_stream(client, capture_id: str) -> dict:
    sessions = client.get(f"/api/captures/{capture_id}/sessions").json()["items"]
    for stream in _streams(client, sessions[0]["id"]):
        if stream["direction"] == "a2b":
            return stream
    raise AssertionError("the first session has no a2b stream")


def test_the_app_derives_the_thermostand_protocol(
    client, project, sample_capture_file: Path
) -> None:
    with sample_capture_file.open("rb") as handle:
        capture = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": sample_capture_file.name},
            files={
                "file": (
                    sample_capture_file.name,
                    handle,
                    "application/octet-stream",
                )
            },
        ).json()
    client.post(f"/api/captures/{capture['id']}/analyze", json={})

    # 1. Framing is proposed, not seeded.  The true rule is a 2-byte
    #    big-endian length at offset 2 that counts only the payload, so the
    #    header is 8 bytes.
    stream = _a2b_stream(client, capture["id"])
    suggestions = client.get(
        f"/api/streams/{stream['id']}/framing-suggestions"
    ).json()["suggestions"]
    top = suggestions[0]
    assert top["method"] == "length_prefix"
    config = top["config"]
    assert config["length_offset"] == 2
    assert config["length_size"] == 2
    assert config["endianness"] == "big"
    assert str(config["includes_header"]).lower() == "false"
    assert config["header_size"] == 8

    # 2. Apply that rule and re-read the streams (re-analysis reassigns ids).
    client.post(
        f"/api/captures/{capture['id']}/analyze",
        json={"framing": {"method": top["method"], "config": config}},
    )
    stream = _a2b_stream(client, capture["id"])
    messages = client.get(f"/api/captures/{capture['id']}/messages?limit=5").json()
    assert messages["total"] >= 9

    # 3. Every message starts with the same big-endian magic and its declared
    #    length is the payload, i.e. total = declared + 8.
    for message in messages["items"][:5]:
        raw = client.get(
            f"/api/streams/{message['stream_id']}/messages/{message['id']}/hex"
        ).json()["hex"].replace(" ", "").lower()
        assert raw.startswith("a65c"), raw
        assert message["present_length"] == 8 + (message["declared_length"] or 0)

    # 4. The candidates are hypotheses and must say so.
    stats = client.get(f"/api/streams/{stream['id']}/field-statistics").json()
    assert any("hypothes" in note for note in stats["notes"])
    assert stats["constant_prefix_length"] >= 2
    assert any(c["role"] == "magic" for c in stats["candidates"])

    # 5. The request id at offset 4 is found as a big-endian 2-byte sequence.
    assert any(
        c["role"] == "sequence"
        and c["offset"] == 4
        and c["size"] == 2
        and c["endianness"] == "big"
        for c in stats["candidates"]
    )
    # 6. The command byte at offset 7 is found as a small enumeration.
    assert any(
        c["role"] == "message_type" and c["offset"] == 7
        for c in stats["candidates"]
    )

    # 7. Byte-column classes describe the shape: the magic is constant, the low
    #    byte of the request id rises, and the command is a small enumeration.
    classes = {col["offset"]: col["classification"] for col in stats["column_stats"]}
    assert classes[0] == "constant"
    assert classes[1] == "constant"
    assert classes[5] == "counter"
    assert classes[7] == "enum"
    # Every column carries a stated reason, never a bare label.
    assert all(col["classification_rationale"] for col in stats["column_stats"])
