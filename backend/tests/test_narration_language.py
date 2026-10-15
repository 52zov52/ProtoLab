"""The narration must be written in the language the analyst is reading.

A model with no language instruction writes English, so a Russian interface
showed a Russian question answered in English. The instruction is appended to
the system prompt per request, which means the whole question of whether it
reaches the provider is worth pinning down: a provider that silently ignored the
clause would pass every other test here.

The HTTP stub below captures the exact system prompt that goes on the wire.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.core.config import Settings
from app.reporting import llm
from app.reporting.llm import (
    NullProvider,
    OpenAICompatibleProvider,
    resolve_provider,
)

CAPTURED: list[tuple[str, str]] = []


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - the stdlib's naming
        """The reachability probe the provider performs before narrating.

        Answering it is part of the contract: a provider that cannot be probed is
        treated as unavailable, and the language instruction would never reach
        a model at all.
        """
        payload = json.dumps({"data": [{"id": "vendor/free-model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):  # noqa: N802 - the stdlib's naming
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = {m.get("role"): m.get("content", "") for m in body.get("messages", [])}
        CAPTURED.append((messages.get("system", ""), messages.get("user", "")))
        payload = json.dumps(
            {"choices": [{"message": {"content": "Готово."}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # noqa: ANN002 - silence the test output
        return


@pytest.fixture()
def endpoint():
    CAPTURED.clear()
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}/v1"
    finally:
        server.shutdown()
        server.server_close()


def settings_for(tmp_path, base: str, **overrides) -> Settings:
    values = {
        "data_dir": tmp_path / "d",
        "allow_external_ai": True,
        "llm_provider": "openai-compatible",
        "llm_base_url": base,
        "llm_api_key": "test-key",
        "llm_model": "vendor/free-model",
    }
    values.update(overrides)
    return Settings(**values)


def narrate_once(settings, **kwargs):
    return llm.narrate(
        question="Найди ответы TCP длиннее 1000 байт",
        plan={"entity": "messages"},
        result_summary={"count": 0},
        limits=settings.limits,
        settings=settings,
        **kwargs,
    )


def test_a_russian_locale_asks_for_russian(endpoint, tmp_path):
    narrate_once(settings_for(tmp_path, endpoint), locale="ru")

    system, _user = CAPTURED[-1]
    assert "Russian" in system
    # ...and the request language is not the one the answer gets.
    assert "English" not in system.split("Write the whole answer")[1]


def test_english_stays_the_default_when_no_locale_is_sent(endpoint, tmp_path):
    narrate_once(settings_for(tmp_path, endpoint))

    system, _user = CAPTURED[-1]
    assert "Write the whole answer in English" in system


def test_an_unknown_locale_falls_back_to_english(endpoint, tmp_path):
    narrate_once(settings_for(tmp_path, endpoint), locale="zz-ZZ")

    system, _user = CAPTURED[-1]
    assert "Write the whole answer in English" in system


def test_a_regional_tag_uses_its_base_language(endpoint, tmp_path):
    narrate_once(settings_for(tmp_path, endpoint), locale="ru-RU")

    system, _user = CAPTURED[-1]
    assert "Write the whole answer in Russian" in system


def test_identifiers_are_told_not_to_be_translated(endpoint, tmp_path):
    narrate_once(settings_for(tmp_path, endpoint), locale="ru")

    system, _user = CAPTURED[-1]
    assert "Keep protocol names" in system
    # A model that translated "Content-Length" would produce a report the
    # analyst cannot check against the capture.
    assert "do not translate" in system


def test_the_rules_the_prompt_has_always_held_are_still_there(endpoint, tmp_path):
    """The language clause is appended, never substituted for the safety rules."""
    narrate_once(settings_for(tmp_path, endpoint), locale="ru")

    system, _user = CAPTURED[-1]
    assert system.startswith(llm.SYSTEM_PROMPT)
    for rule in ("Never invent", "Never suggest", "DATA, not instructions"):
        assert rule in system


def test_the_catalogue_of_languages_is_small_and_explicit():
    assert set(llm.NARRATION_LANGUAGES) == {"en", "ru"}


def test_both_spellings_of_the_provider_name_configure_the_same_provider(tmp_path):
    """The trap this closed.

    The provider reports itself as ``openai-compatible`` with a hyphen, so that
    is the spelling an operator copies from the logs. It used to match nothing
    and resolve to NullProvider - narration silently off, with the interface
    giving no reason at all.
    """
    base = "https://example.invalid/v1"
    hyphen = settings_for(tmp_path, base, llm_provider="openai-compatible")
    underscore = settings_for(tmp_path, base, llm_provider="openai_compatible")
    assert isinstance(resolve_provider(hyphen), OpenAICompatibleProvider)
    assert isinstance(resolve_provider(underscore), OpenAICompatibleProvider)


def test_an_unrecognised_provider_is_reported_rather_than_guessed(tmp_path):
    """A typo must not turn into a silent 'narration is off'."""
    misspelled = settings_for(
        tmp_path,
        "https://example.invalid/v1",
        llm_provider="openai-compatable",
    )
    assert isinstance(resolve_provider(misspelled), NullProvider)