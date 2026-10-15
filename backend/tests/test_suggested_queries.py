"""Every query the interface suggests must be one the compiler can run.

Two of the original five examples - "streams with holes in the reconstructed
bytes" and "POST requests where HTTP content is visible" - were never supported
in either language. Clicking one answered "The request could not be mapped to a
supported query", so the interface was advertising queries that could not run.

This lives on the backend side on purpose: it has to feed the real compiler, and
a frontend test cannot import Python. Reading the component's constants is the
only way to catch the two halves drifting apart, because neither side can see the
other's vocabulary.

The check is live data, not a regex: if the compiler stops understanding a
suggestion, this fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.reporting.assistant import compile_query

REPO = Path(__file__).resolve().parents[2]
PAGE = REPO / "frontend" / "app" / "assistant" / "page.tsx"

SUGGESTION_BLOCK = re.compile(r"const SUGGESTIONS = \[(.*?)\] as const;", re.S)
PAIR = re.compile(r'en:\s*"(?P<en>[^"]+)",\s*\n\s*ru:\s*"(?P<ru>[^"]+)"')


def suggestions() -> list[tuple[str, str]]:
    if not PAGE.exists():
        pytest.skip("the frontend page is not present in this checkout")
    block = SUGGESTION_BLOCK.search(PAGE.read_text(encoding="utf-8"))
    assert block, "SUGGESTIONS array not found in app/assistant/page.tsx"
    return [(m["en"], m["ru"]) for m in PAIR.finditer(block.group(1))]


ALL = suggestions()
QUERIES = [query for pair in ALL for query in pair]


def test_there_are_suggestions_to_check():
    assert len(ALL) >= 5, "the suggestions list shrank; is the check still meaningful?"


@pytest.mark.parametrize("query", QUERIES, ids=lambda q: q[:48])
def test_every_suggested_query_compiles(query):
    compiled = compile_query(query)
    assert compiled.plan.filters, f"compiled to a plan with no filter: {query}"


@pytest.mark.parametrize(("english", "russian"), ALL, ids=lambda v: v[:40])
def test_both_languages_of_a_suggestion_reach_the_same_plan(english, russian):
    """The label and the submitted text must mean the same thing.

    Before this, the button displayed a Russian sentence and put the English one
    in the query box. Both compiled, so nothing looked wrong - the two languages
    simply diverged silently.
    """
    left = compile_query(english).plan
    right = compile_query(russian).plan
    assert left.entity == right.entity
    assert [(f.field, f.operator, f.value) for f in left.filters] == [
        (f.field, f.operator, f.value) for f in right.filters
    ]


@pytest.mark.parametrize(("english", "russian"), ALL, ids=lambda v: v[:40])
def test_the_russian_text_is_russian_and_distinct_from_the_english(english, russian):
    assert re.search(r"[а-яА-ЯёЁ]", russian)
    assert russian != english


def test_the_dead_examples_are_gone():
    """The two that never worked, named so a reintroduction is deliberate."""
    dead = [
        "Show streams with holes in the reconstructed bytes",
        "Find POST requests where HTTP content is visible",
    ]
    assert not [query for query in QUERIES if query in dead]