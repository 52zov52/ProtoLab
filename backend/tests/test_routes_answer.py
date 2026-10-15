"""Every documented endpoint must actually answer.

Found by walking the OpenAPI document: `GET /api/audit/actions` returned 500 for
everyone, always. Its return annotation said `dict[str, str]` while the payload
nested a mapping under "actions", so FastAPI rejected the real response as a
validation failure before the router's own code had a chance to be wrong.

The endpoint has no caller in the interface, which is exactly why nothing
noticed: a route that is never exercised fails forever without complaint. So
this walks the document and asks every GET route - the ones nobody calls
included.
"""

from __future__ import annotations

import re

import pytest

PATH_PARAM = re.compile(r"\{([a-z_]+)\}")

#: Ids that exist nowhere. A 404 from these is the correct answer, and the check
#: below is that the server says so rather than crashing.
ABSENT = {
    "project_id": "00000000000000000000000000000000",
    "capture_id": "00000000000000000000000000000000",
    "session_id": "00000000000000000000000000000000",
    "stream_id": "00000000000000000000000000000000",
    "message_id": "00000000000000000000000000000000",
    "report_id": "00000000000000000000000000000000",
    "interpretation_id": "00000000000000000000000000000000",
    "hypothesis_id": "00000000000000000000000000000000",
    "keylog_id": "00000000000000000000000000000000",
    "model_id": "00000000000000000000000000000000",
}


def get_routes() -> list[str]:
    """Every GET path in the OpenAPI document, with ids filled in."""
    from app.api.main import create_app

    spec = create_app().openapi()
    routes: list[str] = []
    for path, operations in sorted(spec.get("paths", {}).items()):
        if "get" not in operations:
            continue
        concrete = path
        skip = False
        for name in PATH_PARAM.findall(path):
            if name in ABSENT:
                concrete = concrete.replace("{" + name + "}", ABSENT[name])
            else:
                skip = True
        if not skip and "{" not in concrete:
            routes.append(concrete)
    return routes


ROUTES = get_routes()


def test_the_document_was_actually_read():
    """A sweep that walked nothing would pass every case below."""
    assert len(ROUTES) > 30, f"only {len(ROUTES)} GET routes found"


@pytest.mark.parametrize("route", ROUTES)
def test_a_documented_get_route_never_answers_with_a_server_error(client, route):
    """
    A 404 is an answer: the id does not exist and the server says so.
    A 422 is an answer: a required parameter is missing and the server names it.
    A 500 is a fault, and a route nobody calls faults forever unnoticed.
    """
    response = client.get(route)
    assert response.status_code < 500, (
        f"{route} answered {response.status_code}: {response.text[:200]}"
    )
    if response.status_code >= 400:
        # The body must be the typed error payload, not a stack trace.
        body = response.json()
        assert "error" in body or "detail" in body, body


def test_the_audit_vocabulary_endpoint_returns_its_mapping(client):
    """The endpoint the sweep found: it used to answer 500 unconditionally."""
    response = client.get("/api/audit/actions")
    assert response.status_code == 200, response.text

    body = response.json()
    assert isinstance(body["actions"], dict), type(body["actions"])
    assert body["actions"], "the audit vocabulary is empty"
    # Every value is a severity, so the original dict[str, str] was only wrong
    # about the shape - not about what the mapping means.
    assert set(body["actions"].values()) <= {"info", "warning", "error"}
    assert body["note"]