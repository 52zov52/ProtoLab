"""Every dependency the application imports must be declared.

CI caught this the hard way: `cryptography` was imported by the TLS decryption
module and declared nowhere, so the backend job failed at collection — and a
container built from the same declarations would have answered HTTP 500 on a
valid key log instead of naming the missing package.

The scan is on the *application* source, not on the tests, because a missing
dependency that only a test imports is a red CI run, while one the application
imports is a 500 in production that nobody sees until the feature is used.

`scripts/live_check.py` and the optional extras are excluded on purpose: the
analytics extra is exactly what makes scikit-learn optional, and the live check
only runs stdlib.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
APP = BACKEND / "app"

# Modules that are part of this project rather than third-party packages.
LOCAL = {"app", "alembic", "tests"}

# Imported by scripts, not by the application, and never by a request handler.
SCRIPT_ONLY = {"bandit"}


def _normalise(name: str) -> str:
    """Distribution names compare case- and separator-insensitively (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _declared() -> set[str]:
    """Every distribution pyproject declares, base and extras alike."""
    data = tomllib.loads((BACKEND / "pyproject.toml").read_text(encoding="utf-8"))
    names: set[str] = set()
    requirements = list(data["project"]["dependencies"])
    for extra in data["project"].get("optional-dependencies", {}).values():
        requirements.extend(extra)
    for requirement in requirements:
        name = re.split(r"[\[<>=!~;\s]", requirement, maxsplit=1)[0].strip()
        if name:
            names.add(_normalise(name))
    return names


def _distribution_for(import_name: str) -> str:
    """Map an import name to the distribution that provides it.

    Three of this project's dependencies import under a different name than they
    are distributed as: `sklearn` is scikit-learn, `multipart` is
    python-multipart, `yaml` would be PyYAML. Reading the installed metadata gets
    that right instead of hard-coding a list that drifts.
    """
    distributions = packages_distributions().get(import_name)
    if distributions:
        return _normalise(sorted(distributions)[0])
    return _normalise(import_name)


def _imported() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted(APP.rglob("*.py")):
        raw = path.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), (
            f"{path.relative_to(BACKEND)} starts with a UTF-8 BOM; strip it so the "
            "file parses the same way for every tool"
        )
        tree = ast.parse(raw.decode("utf-8-sig"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    found.setdefault(root, set()).add(str(path.relative_to(BACKEND)))
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                root = node.module.split(".")[0]
                found.setdefault(root, set()).add(str(path.relative_to(BACKEND)))
    return found


def _third_party() -> dict[str, set[str]]:
    stdlib = set(sys.stdlib_module_names)
    return {
        name: files
        for name, files in _imported().items()
        if name not in stdlib
        and name not in LOCAL
        and name not in SCRIPT_ONLY
        and not name.startswith("_")
    }


def test_every_third_party_import_is_declared_in_pyproject():
    declared = _declared()
    undeclared = {
        name: sorted(files)
        for name, files in _third_party().items()
        if _distribution_for(name) not in declared
    }
    assert not undeclared, (
        "the application imports packages that pyproject.toml does not declare; "
        f"add them or stop importing them: {undeclared}"
    )


def test_the_scan_actually_sees_the_imports_it_is_meant_to_check():
    """A scan that finds nothing is a scan that passes for the wrong reason."""
    third_party = _third_party()
    assert "fastapi" in third_party
    assert "sqlalchemy" in third_party
    assert third_party["fastapi"]


def test_a_source_file_never_carries_a_byte_order_mark():
    """BOMs survive `import` but break `ast.parse`, linters and diffs."""
    offenders = [
        str(path.relative_to(BACKEND))
        for path in sorted(APP.rglob("*.py"))
        if path.read_bytes().startswith(b"\xef\xbb\xbf")
    ]
    assert not offenders, f"strip the UTF-8 BOM from: {offenders}"


@pytest.mark.parametrize("package", ["cryptography"])
def test_the_crypto_backend_is_a_declared_dependency(package):
    """TLS decryption is a shipped feature, so its backend is not optional."""
    assert package in _declared()


@pytest.mark.parametrize(
    ("import_name", "distribution"),
    [("sklearn", "scikit-learn"), ("multipart", "python-multipart"), ("sqlalchemy", "SQLAlchemy")],
)
def test_the_name_mapping_covers_the_mismatched_dependencies(import_name, distribution):
    """The scan must not be defeated by a dependency whose names differ."""
    assert _normalise(_distribution_for(import_name)) == _normalise(distribution)