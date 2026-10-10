"""CORS behaviour.

The UI is served from port 3000 and the API from port 8010, so every API call
is cross-origin. The backend validates the Origin header, but validation alone
is not enough: without ``Access-Control-Allow-Origin`` the browser discards the
response body and the UI silently shows nothing.

These tests pin both halves, because either one alone is broken:

* allowed origins get the headers, so the app works;
* everything else still gets nothing, so the origin check is not cosmetic.
"""

from __future__ import annotations

import pytest

ALLOWED = "http://127.0.0.1:3000"
ATTACKER = "https://attacker.example"


def test_allowed_origin_receives_cors_headers(client):
    response = client.get("/api/health", headers={"Origin": ALLOWED})
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED
    assert "Origin" in response.headers.get("Vary", "")
    # Credentials must never be enabled: this API is token-less and must not
    # become a credential-bearing cross-origin surface.
    assert "Access-Control-Allow-Credentials" not in response.headers


def test_preflight_is_answered_for_an_allowed_origin(client):
    response = client.options(
        "/api/projects",
        headers={
            "Origin": ALLOWED,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code in (200, 204)
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED
    assert "POST" in response.headers["Access-Control-Allow-Methods"]


def test_foreign_origin_is_rejected_and_gets_no_cors_headers(client):
    response = client.get("/api/health", headers={"Origin": ATTACKER})
    assert response.status_code == 403
    assert "Access-Control-Allow-Origin" not in response.headers


def test_foreign_preflight_is_rejected(client):
    response = client.options(
        "/api/projects",
        headers={"Origin": ATTACKER, "Access-Control-Request-Method": "POST"},
    )
    assert response.status_code == 403
    assert "Access-Control-Allow-Origin" not in response.headers


def test_response_never_uses_a_wildcard_origin(client):
    """A wildcard would let any site read the API from the analyst's browser."""
    for origin in (ALLOWED, ATTACKER, None):
        headers = {"Origin": origin} if origin else {}
        response = client.get("/api/health", headers=headers)
        assert response.headers.get("Access-Control-Allow-Origin") != "*"


@pytest.mark.parametrize("path", ["/api/health", "/api/projects"])
def test_cors_headers_are_present_on_collecting_endpoints(client, path):
    response = client.get(path, headers={"Origin": ALLOWED})
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED