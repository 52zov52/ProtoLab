"""The narration providers, exercised over real HTTP.

The point of these tests is not that a mock was called. It is that a request
actually goes out in the OpenAI chat-completions shape, that the answer is read
out of it, and — the property that matters most here — that the API key is never
echoed back into a log line, an error message, the settings dump or the API.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.core.config import Settings
from app.core.logging import redact
from app.reporting.llm import (
    LLMUnavailable,
    NullProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    resolve_provider,
)

API_KEY = "sk-or-v1-secret-0123456789abcdef"


class StubHandler(BaseHTTPRequestHandler):
    """Records what it received and replies like a chat-completions endpoint."""

    seen: list[dict] = []
    reply: dict = {}
    status: int = 200

    def log_message(self, *args):  # keep the test output clean
        return

    def _send(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).seen.append({"path": self.path, "auth": self.headers.get("Authorization")})
        self._send(200, {"data": [{"id": "some-model"}]})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        type(self).seen.append(
            {
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "body": json.loads(raw),
            }
        )
        self._send(type(self).status, type(self).reply)


@pytest.fixture()
def stub():
    StubHandler.seen = []
    StubHandler.reply = {
        "choices": [{"message": {"role": "assistant", "content": "The evidence shows X."}}]
    }
    StubHandler.status = 200
    server = HTTPServer(("127.0.0.1", 0), StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()


def settings(tmp_path, **overrides) -> Settings:
    return Settings(data_dir=tmp_path / "d", **overrides)


# --------------------------------------------------------------------------- #
# The hosted path
# --------------------------------------------------------------------------- #


def test_a_completion_comes_back_from_the_endpoint_in_the_expected_shape(stub):
    provider = OpenAICompatibleProvider(
        base_url=stub + "/v1", api_key=API_KEY, model="free-model"
    )

    text = provider.complete("system rules", "the facts", max_chars=500)

    assert text == "The evidence shows X."
    call = StubHandler.seen[-1]
    assert call["path"] == "/v1/chat/completions"
    assert call["auth"] == f"Bearer {API_KEY}"
    assert call["body"]["model"] == "free-model"
    assert call["body"]["messages"] == [
        {"role": "system", "content": "system rules"},
        {"role": "user", "content": "the facts"},
    ]


def test_a_long_answer_is_capped_rather_than_trusted(stub):
    StubHandler.reply = {
        "choices": [{"message": {"content": "x" * 5000}}]
    }
    provider = OpenAICompatibleProvider(
        base_url=stub + "/v1", api_key=API_KEY, model="free-model"
    )
    assert len(provider.complete("s", "u", max_chars=120)) == 120


def test_an_unreadable_answer_is_reported_rather_than_returned_empty(stub):
    StubHandler.status = 500
    StubHandler.reply = {"error": "upstream exploded", "echoed_key": API_KEY}
    provider = OpenAICompatibleProvider(
        base_url=stub + "/v1", api_key=API_KEY, model="free-model"
    )

    with pytest.raises(LLMUnavailable) as excinfo:
        provider.complete("s", "u", max_chars=100)

    # Only the status is reported: some gateways echo the key back in the body.
    assert "500" in str(excinfo.value)
    assert API_KEY not in str(excinfo.value)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "API key"),
        (402, "credit"),
        (403, "403"),
        (404, "model id"),
        (429, "rate-limiting"),
    ],
)
def test_each_http_status_is_explained_rather_than_left_bare(stub, status, expected):
    """A free tier being busy is normal; a wrong key is a configuration error.

    Both are reported as themselves, because "HTTP 429" alone tells an operator
    nothing about whether to wait, change the key, or give up.
    """
    StubHandler.status = status
    StubHandler.reply = {"error": {"message": f"upstream said something about {API_KEY}"}}
    provider = OpenAICompatibleProvider(
        base_url=stub + "/v1", api_key=API_KEY, model="free-model"
    )

    with pytest.raises(LLMUnavailable) as excinfo:
        provider.complete("s", "u", max_chars=100)

    message = str(excinfo.value)
    assert expected in message
    assert str(status) in message
    assert API_KEY not in message


def test_an_unreachable_endpoint_reports_the_endpoint_not_a_key(stub):
    provider = OpenAICompatibleProvider(
        base_url="http://127.0.0.1:1/v1", api_key=API_KEY, model="free-model"
    )
    with pytest.raises(LLMUnavailable) as excinfo:
        provider.complete("s", "u", max_chars=100)
    assert API_KEY not in str(excinfo.value)


def test_availability_probes_models_without_spending_a_generation(stub):
    provider = OpenAICompatibleProvider(
        base_url=stub + "/v1", api_key=API_KEY, model="free-model"
    )
    assert provider.available() is True
    assert StubHandler.seen == [{"path": "/v1/models", "auth": f"Bearer {API_KEY}"}]


def test_a_refused_key_counts_as_a_reachable_but_misconfigured_endpoint(stub):
    StubHandler.reply = {"error": "no"}
    original = StubHandler.do_GET

    def unauthorized(self):
        self._send(401, {"error": {"message": "no credit"}})

    StubHandler.do_GET = unauthorized
    try:
        provider = OpenAICompatibleProvider(
            base_url=stub + "/v1", api_key=API_KEY, model="free-model"
        )
        assert provider.available() is True
    finally:
        StubHandler.do_GET = original


# --------------------------------------------------------------------------- #
# Provider selection
# --------------------------------------------------------------------------- #


def test_nothing_is_configured_by_default(tmp_path):
    assert isinstance(resolve_provider(settings(tmp_path)), NullProvider)


def test_external_ai_off_ignores_a_configured_key(tmp_path):
    """The master switch wins over configuration: that is what a switch is for."""
    configured = settings(
        tmp_path,
        llm_base_url="https://example.invalid/v1",
        llm_api_key=API_KEY,
        llm_model="free-model",
    )
    assert isinstance(resolve_provider(configured), NullProvider)
    assert isinstance(
        resolve_provider(settings(tmp_path, allow_external_ai=True, **{
            "llm_base_url": "https://example.invalid/v1",
            "llm_api_key": API_KEY,
            "llm_model": "free-model",
        })),
        OpenAICompatibleProvider,
    )


def test_auto_prefers_a_configured_hosted_endpoint_over_local_ollama(tmp_path):
    provider = resolve_provider(
        settings(
            tmp_path,
            allow_external_ai=True,
            llm_base_url="https://example.invalid/v1",
            llm_api_key=API_KEY,
            llm_model="free-model",
        )
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.name.endswith("/free-model")


def test_auto_falls_back_to_local_ollama_when_no_key_is_configured(tmp_path):
    provider = resolve_provider(settings(tmp_path, allow_external_ai=True))
    assert isinstance(provider, OllamaProvider)
    assert provider.model == "qwen2.5:7b-instruct"


def test_asking_for_none_disables_narration_even_with_a_key(tmp_path):
    provider = resolve_provider(
        settings(
            tmp_path,
            allow_external_ai=True,
            llm_provider="none",
            llm_base_url="https://example.invalid/v1",
            llm_api_key=API_KEY,
            llm_model="free-model",
        )
    )
    assert isinstance(provider, NullProvider)


def test_an_incomplete_hosted_configuration_is_not_silently_replaced(tmp_path):
    """A key without a model is a configuration error, not a reason to phone home."""
    provider = resolve_provider(
        settings(
            tmp_path,
            allow_external_ai=True,
            llm_provider="openai_compatible",
            llm_base_url="https://example.invalid/v1",
            llm_api_key=API_KEY,
        )
    )
    assert isinstance(provider, NullProvider)


# --------------------------------------------------------------------------- #
# The key must not leak
# --------------------------------------------------------------------------- #


def test_the_settings_dump_reports_the_key_without_revealing_it(tmp_path):
    described = settings(
        tmp_path,
        allow_external_ai=True,
        llm_base_url="https://example.invalid/v1",
        llm_api_key=API_KEY,
        llm_model="free-model",
    ).describe()

    assert described["llm_api_key_set"] is True
    assert described["llm_model"] == "free-model"
    assert API_KEY not in json.dumps(described)
    assert described["offline_first"] is True


def test_redaction_covers_a_key_that_appears_in_text():
    """Belt and braces: if a key ever reaches a payload, it must be masked."""
    scrubbed = json.dumps(redact({"note": f"used key {API_KEY}"}))
    assert API_KEY not in scrubbed


def test_the_capabilities_endpoint_reports_no_provider_by_default(client):
    payload = client.get("/api/assistant/capabilities").json()
    assert payload["external_ai"]["enabled"] is False
    assert payload["external_ai"]["provider"] is None
    assert payload["external_ai"]["configured"] is False


def test_a_configured_provider_is_named_without_its_key(tmp_path):
    from app.api.routers.assistant import _provider_configured, _provider_label

    configured = settings(
        tmp_path,
        allow_external_ai=True,
        llm_base_url="https://example.invalid/v1",
        llm_api_key=API_KEY,
        llm_model="free-model",
    )
    label = _provider_label(configured)
    assert label is not None
    assert label.endswith("/free-model")
    assert API_KEY not in label
    assert _provider_configured(configured) is True