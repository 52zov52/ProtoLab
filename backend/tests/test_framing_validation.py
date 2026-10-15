"""A framing rule the analyst supplied must be checked before anything is written.

Found live: posting a framing option with the wrong name (an easy mistake - the
field is ``length_offset``, not ``offset``) answered HTTP 500. The capture was
left marked "failed" and the response carried no indication of which option was
wrong, which is the opposite of the product's stated rule that a failure must
explain itself.

This checks both halves: the status code, and that nothing was written.
"""

from __future__ import annotations

import io

import pytest

from app.analyzers.framing import FramingConfig

#: Wrong rules in the shape the API actually accepts - a ``config`` object.
#: Flat dicts would be rejected for "no options at all", which is a different
#: refusal from the one an analyst hits when they misname an option.
BAD_RULES = [
    {"method": "length_prefix", "config": {"offset": 0, "length_size": 2}},
    {
        "method": "length_prefix",
        "config": {"length_offset": 0, "length_size": "two"},
    },
    {
        "method": "length_prefix",
        "config": {"length_offset": -1, "length_size": 2},
    },
    {"method": "not_a_framing_method", "config": {}},
    {"method": "delimiter", "config": {"delimiter": 123}},
]

GOOD_RULE = {
    "method": "length_prefix",
    "config": {
        "length_offset": 0,
        "length_size": 2,
        "endianness": "big",
        "includes_header": "true",
        "max_length": 65535,
    },
}


@pytest.mark.parametrize("rule", BAD_RULES, ids=lambda r: str(sorted(r))[:40])
def test_a_bad_framing_rule_is_refused_before_anything_is_written(client, project, rule):
    payload = b"\x00\x05hello"
    imported = client.post(
        "/api/captures",
        data={"project_id": project["id"], "name": "framing.pcap"},
        files={"file": ("framing.pcap", io.BytesIO(payload), "application/octet-stream")},
    ).json()

    response = client.post(
        f"/api/captures/{imported['id']}/analyze", json={"framing": rule}
    )

    assert response.status_code == 422, response.text
    body = response.json()["error"]
    assert body["code"] == "semantic_validation_failed"
    # The message names the offending option: an analyst can act on it.
    assert "framing rule rejected" in body["message"]
    # ...and the capture is untouched, not left marked failed.
    capture = client.get(f"/api/captures/{imported['id']}").json()
    assert capture["analysis_status"] != "failed"


def test_a_good_framing_rule_is_accepted(client, project, bench_dir, bench_framing):
    with (bench_dir / "basic.pcap").open("rb") as handle:
        imported = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": "ok.pcap"},
            files={"file": ("ok.pcap", handle, "application/octet-stream")},
        ).json()

    # The validation added here must not reject a rule the analyser accepts.
    FramingConfig.parse(GOOD_RULE)
    response = client.post(
        f"/api/captures/{imported['id']}/analyze", json={"framing": GOOD_RULE}
    )
    assert response.status_code == 200, response.text


def test_no_framing_rule_is_still_fine(client, project, bench_dir):
    with (bench_dir / "basic.pcap").open("rb") as handle:
        imported = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": "plain.pcap"},
            files={"file": ("plain.pcap", handle, "application/octet-stream")},
        ).json()

    response = client.post(f"/api/captures/{imported['id']}/analyze", json={})
    assert response.status_code == 200, response.text