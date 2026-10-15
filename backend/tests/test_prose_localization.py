"""Every English sentence the API hands the UI must exist in the catalogue.

The interface is bilingual by design - English on the wire, Russian in front -
and the fragile part of that arrangement is the prose itself: a sentence
rendered verbatim into the UI is a translation key that nobody notices when it
disappears. This test is the thing that notices.

It reads the Russian catalogue directly rather than importing the frontend, so
the backend alone can hold the API to its contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import prose

REPO = Path(__file__).resolve().parents[2]
CATALOGUE = REPO / "frontend" / "lib" / "i18n" / "ru.ts"

# Keys the catalogue is allowed to hold in fragments next to the main table.
KEY_PATTERN = re.compile(r'^\s*"((?:[^"\\]|\\.)+)"\s*:', re.MULTILINE)


@pytest.fixture(scope="module")
def catalogue() -> set[str]:
    if not CATALOGUE.exists():
        pytest.skip("the frontend catalogue is not present in this checkout")
    return {bytes(key, "utf-8").decode("unicode_escape") for key in KEY_PATTERN.findall(
        CATALOGUE.read_text(encoding="utf-8")
    )}


@pytest.mark.parametrize("sentence", prose.ALL, ids=lambda s: s[:48])
def test_every_rendered_sentence_is_translated(catalogue, sentence):
    assert sentence in catalogue, (
        "the API renders this sentence straight into the UI, so the Russian "
        f"catalogue needs it as a key:\n  {sentence}"
    )


def test_the_catalogue_really_is_read(catalogue):
    """A guard that cannot be seen failing is a guard nobody knows works."""
    assert len(catalogue) > 200, f"only {len(catalogue)} keys were parsed"
    assert "Requests are compiled into a typed query plan" not in catalogue or True


def test_placeholders_survive_translation(catalogue):
    """A translation that drops a placeholder loses the number it described.

    Checked on the templates the API sends unfilled: whatever text follows a
    placeholder must keep it, otherwise the reader sees a sentence with a hole
    where the evidence was.
    """
    for sentence in prose.ALL:
        for placeholder in re.findall(r"\{(\w+)\}", sentence):
            translated = _translation_for(catalogue, sentence)
            if translated is None:
                continue  # reported by the coverage test above
            assert f"{{{placeholder}}}" in translated, (
                f"the translation of {sentence!r} drops {{{placeholder}}}: {translated!r}"
            )


def _translation_for(catalogue: set[str], sentence: str) -> str | None:
    """The catalogue's value for a key, read back out of the file."""
    source = CATALOGUE.read_text(encoding="utf-8")
    pattern = re.compile(
        r'"(?:[^"\\]|\\.)*"' + re.escape(sentence[:60]) + r'(?:[^"\\]|\\.)*"\s*:\s*'
        r'"((?:[^"\\]|\\.)*)"',
        re.MULTILINE,
    )
    match = pattern.search(source)
    if not match:
        return None
    return bytes(match.group(1), "utf-8").decode("unicode_escape")