"""Frontend safety properties that must not regress.

These are asserted over the source rather than configured as a lint rule,
because a failing lint warning is easy to ignore and a failing test is not.

The product handles attacker-controlled text: capture filenames, packet
metadata, analyst notes and comments. None of it may reach the DOM as markup.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
SOURCE_DIRS = ("app", "components", "hooks", "lib")


def _source_files() -> list[Path]:
    files: list[Path] = []
    for directory in SOURCE_DIRS:
        root = FRONTEND / directory
        if root.exists():
            files.extend(root.rglob("*.tsx"))
            files.extend(root.rglob("*.ts"))
    return files


def _read(path: Path) -> str:
    # utf-8-sig: several files carry a byte-order mark from the original
    # authoring tool; it is not an error.
    return path.read_text(encoding="utf-8-sig")


def test_frontend_sources_exist():
    files = _source_files()
    assert files, "no frontend sources were found"


def test_untrusted_text_is_never_rendered_as_markup():
    """No dangerouslySetInnerHTML, and no innerHTML assignment."""
    offenders: list[str] = []
    for path in _source_files():
        text = _read(path)
        if "dangerouslySetInnerHTML" in text:
            offenders.append(f"{path.name}: dangerouslySetInnerHTML")
        if re.search(r"\.innerHTML\s*=", text):
            offenders.append(f"{path.name}: innerHTML assignment")
        if "document.write(" in text:
            offenders.append(f"{path.name}: document.write")
    assert not offenders, (
        "untrusted text must never be rendered as markup: " + ", ".join(offenders)
    )


def test_frontend_does_not_load_remote_scripts_or_fonts():
    """This tool is offline-first; nothing may be fetched from a third party."""
    offenders: list[str] = []
    for path in _source_files():
        text = _read(path)
        for needle in ("https://fonts.", "cdn.jsdelivr", "cdnjs.cloudflare", "unpkg.com"):
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert not offenders, "remote asset reference(s): " + ", ".join(offenders)


def test_api_client_does_not_use_eval_or_dynamic_import_of_user_input():
    offenders: list[str] = []
    for path in _source_files():
        text = _read(path)
        if re.search(r"\beval\s*\(", text):
            offenders.append(f"{path.name}: eval")
        if re.search(r"\bnew Function\s*\(", text):
            offenders.append(f"{path.name}: new Function")
    assert not offenders, ", ".join(offenders)


@pytest.mark.parametrize(
    "path",
    ["next.config.mjs"],
)
def test_security_headers_are_configured(path: str):
    """The browser-side defences documented in docs/SECURITY.md."""
    config = _read(FRONTEND / path)
    for header in (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
    ):
        assert header in config, f"{header} is not set in {path}"
    assert "nosniff" in config
    assert "frame-ancestors" in config, "CSP must forbid framing"