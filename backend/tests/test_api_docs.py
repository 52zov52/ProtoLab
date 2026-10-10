"""The API documentation must match the routes the application exposes.

A doc that drifts from the code is worse than no doc: an analyst following
docs/API.md would call an endpoint that returns 404. This test compares the
Markdown tables against the generated OpenAPI schema in both directions, so an
undocumented *and* a non-existent endpoint both fail.
"""

from __future__ import annotations

import re
from pathlib import Path

DOC = Path(__file__).resolve().parents[2] / "docs" / "API.md"

# docs/API.md lists paths relative to the /api prefix, and some cells bundle
# several methods ("GET/POST"); expand those and drop any "?query" suffix.
_CELL = re.compile(
    r"\|\s*((?:GET|POST|PUT|PATCH|DELETE)(?:/(?:GET|POST|PUT|PATCH|DELETE))*)"
    r"\s*\|\s*`([^`]+)`"
)


def _documented_routes(text: str) -> set[tuple[str, str]]:
    return {
        (method, "/api" + re.sub(r"\?.*$", "", path))
        for methods, path in _CELL.findall(text)
        for method in methods.split("/")
    }


def test_api_documentation_matches_the_exposed_routes(client):
    assert DOC.exists(), f"{DOC} is missing"

    schema = client.get("/api/openapi.json").json()
    exposed = {
        (method.upper(), path)
        for path, methods in schema["paths"].items()
        for method in methods
    }
    documented = _documented_routes(DOC.read_text(encoding="utf-8"))

    missing = sorted(documented - exposed)
    undocumented = sorted(exposed - documented)

    assert not missing, f"documented but not exposed: {missing}"
    assert not undocumented, f"exposed but not documented: {undocumented}"