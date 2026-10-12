"""Optional LLM narration: redaction, context cap, consent and degradation.

These tests never touch a real model.  A fake provider records exactly what
would have left the process, which is the only way to prove that secrets do not.
The product rule under test is that narration is optional, labelled, and never
substitutes for the stored evidence.
"""

from __future__ import annotations

import pytest

from app.core.config import Limits
from app.reporting import llm


class FakeProvider:
    name = "fake:test"

    def __init__(self, *, available: bool = True) -> None:
        self._available = available
        self.calls: list[dict[str, object]] = []

    def available(self) -> bool:
        return self._available

    def complete(self, system: str, user: str, *, max_chars: int) -> str:
        self.calls.append({"system": system, "user": user, "max_chars": max_chars})
        return "a short narration"


def test_narrate_marks_its_output_as_narration_not_evidence(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(llm, "resolve_provider", lambda settings: provider)

    result = llm.narrate(
        question="summarise",
        plan={"sections": ["Project"]},
        result_summary={"messages": 3},
        limits=Limits(),
        settings=object(),
    )

    assert result["used"] is True
    assert result["provider"] == "fake:test"
    assert "narration, not evidence" in result["disclaimer"]
    assert provider.calls, "the provider must actually have been asked"


def test_narrate_degrades_cleanly_when_no_model_is_available(monkeypatch):
    monkeypatch.setattr(llm, "resolve_provider", lambda settings: llm.NullProvider())
    with pytest.raises(llm.LLMUnavailable):
        llm.narrate(
            question="summarise",
            plan={},
            result_summary={},
            limits=Limits(),
            settings=object(),
        )


def test_facts_block_masks_sensitive_keys():
    block = llm._facts_block(
        {"token": "supersecret-token-value", "password": "hunter2", "messages": 3},
        Limits(),
    )
    assert "supersecret-token-value" not in block
    assert "hunter2" not in block
    assert "messages" in block


def test_facts_block_redacts_keylog_and_jwt():
    block = llm._facts_block(
        {
            "line": "CLIENT_HANDSHAKE_TRAFFIC_SECRET_0 " + "ab" * 32,
            "header": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        },
        Limits(),
    )
    assert "abababab" not in block
    assert "[keylog redacted]" in block
    assert "[jwt redacted]" in block


def test_facts_block_caps_the_context_and_says_so():
    limits = Limits(max_ai_context_chars=200)
    block = llm._facts_block({"note": "z" * 500}, limits)
    assert "truncated at 200 characters" in block
    assert len(block) < 500


def test_narrate_sends_only_redacted_facts(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(llm, "resolve_provider", lambda settings: provider)
    llm.narrate(
        question="summarise",
        plan={},
        result_summary={"secret": "do-not-leak-this"},
        limits=Limits(),
        settings=object(),
    )
    sent = str(provider.calls[0]["user"])
    assert "do-not-leak-this" not in sent
    assert "FACTS" in sent


def test_project_consent_requires_the_explicit_key():
    class Project:
        settings: dict[str, object] = {}

    assert llm.project_consent(Project()) is False
    Project.settings = {"allow_external_ai": True}
    assert llm.project_consent(Project()) is True


def test_status_reports_disabled_without_a_provider():
    class Settings:
        allow_external_ai = False
        ollama_url = "http://127.0.0.1:11434"
        ollama_model = "qwen2.5:7b-instruct"

    out = llm.status(Settings())
    assert out["external_ai_enabled"] is False
    assert out["available"] is False
    assert out["provider"] == "none"


def test_report_with_use_llm_is_still_produced_when_ai_is_disabled(client, imported):
    """The honest degradation path: asking for narration must not break the report."""
    project_id = imported["project"]["id"]
    response = client.post(
        f"/api/projects/{project_id}/reports",
        json={"title": "With narration requested", "use_llm": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ai_used"] is False
    assert any("disabled" in warning for warning in body["ai_warnings"])
    assert {s["number"] for s in body["sections"]}, "sections must survive"
