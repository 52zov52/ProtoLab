"""Project / capture storage layout.

Every artefact the analysis produces lives under a project-scoped directory::

    data/storage/<project_id>/
        captures/<capture_id>/original.<ext>   immutable upload
        captures/<capture_id>/streams.bin      reconstructed bytes per stream
        captures/<capture_id>/streams.json     run offsets + contributor packets
        exports/                                generated pcapng / spec / report
        projects/                               nothing - the project archive
                                                  is assembled on export

Two rules hold everywhere:

1. Stored names are **random server-side identifiers**, never user input.
2. Nothing is served from a directory the web tier can read.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from ..core.errors import SecurityViolation
from ..core.security import assert_no_symlink, random_storage_name, resolve_within

CAPTURE_EXTENSIONS = {".pcap": "pcap", ".pcapng": "pcapng", ".cap": "pcap", ".dmp": "pcap"}


@dataclass(frozen=True)
class CapturePaths:
    root: Path
    original: Path
    stream_blob: Path
    stream_index: Path
    export_dir: Path


class ProjectStorage:
    """Filesystem facade with containment guarantees."""

    def __init__(self, root: Path) -> None:
        self.root = root

    # -- directories ------------------------------------------------------ #

    def project_dir(self, project_id: str) -> Path:
        path = resolve_within(self.root, project_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def capture_dir(self, project_id: str, capture_id: str) -> Path:
        path = resolve_within(self.root, project_id, "captures", capture_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def capture_paths(self, project_id: str, capture_id: str, fmt: str) -> CapturePaths:
        base = self.capture_dir(project_id, capture_id)
        return CapturePaths(
            root=base,
            original=base / f"original.{fmt}",
            stream_blob=base / "streams.bin",
            stream_index=base / "streams.json",
            export_dir=base / "exports",
        )

    def exports_dir(self, project_id: str, capture_id: str) -> Path:
        path = resolve_within(self.root, project_id, "captures", capture_id, "exports")
        path.mkdir(parents=True, exist_ok=True)
        return path

    # -- writing ---------------------------------------------------------- #

    def store_upload(self, project_id: str, capture_id: str, source: Path, fmt: str) -> Path:
        """Copy an upload into managed storage under a fixed, random name."""
        paths = self.capture_paths(project_id, capture_id, fmt)
        destination = paths.original
        assert_no_symlink(destination, self.root)
        temporary = destination.with_suffix(destination.suffix + ".partial")
        temporary.write_bytes(source.read_bytes())
        os.replace(temporary, destination)
        _restrict(destination)
        return destination

    def new_temp_file(self, project_id: str, capture_id: str, suffix: str = "") -> Path:
        paths = self.capture_paths(project_id, capture_id, "pcap")
        name = random_storage_name("tmp-", suffix)
        path = resolve_within(paths.root, name)
        return path

    # -- reading ---------------------------------------------------------- #

    def resolve_original(self, project_id: str, capture_id: str, fmt: str) -> Path:
        paths = self.capture_paths(project_id, capture_id, fmt)
        if not paths.original.exists():
            raise SecurityViolation(
                "The original capture file is missing from managed storage; "
                "re-import it to restore the source of truth for this analysis."
            )
        return paths.original

    def contains(self, candidate: Path) -> bool:
        try:
            candidate.resolve().relative_to(self.root.resolve())
            return True
        except (ValueError, SecurityViolation):
            return False


def _restrict(path: Path) -> None:
    """Best-effort owner-only permissions (a no-op on Windows)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - platform dependent
        pass


def detect_capture_format(filename: str) -> str | None:
    suffix = Path(filename).suffix.lower()
    return CAPTURE_EXTENSIONS.get(suffix)