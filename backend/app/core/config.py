"""Application configuration.

Every knob is an environment variable so a deployment is reproducible from a
``.env`` file.  Defaults are the *Local Secure* profile: loopback bind, no
outbound network, no external AI, SQLite on local disk.

Two objects matter:

``Limits``
    Ceilings applied to untrusted input and to expensive analysis work.  They
    are checked in the API process, not only in the UI, because the browser is
    not a trust boundary.

``Settings``
    The resolved environment.  Constructed once per process via
    :func:`get_settings`; tests call :func:`reset_settings` between cases so a
    changed ``MPLAB_DATA_DIR`` takes effect.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

MODE_LOCAL_SECURE = "local_secure"
MODE_TEAM_REMOTE = "team_remote"
MODE_DEMO = "demo"
VALID_MODES = (MODE_LOCAL_SECURE, MODE_TEAM_REMOTE, MODE_DEMO)

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "localhost.localdomain"}

# Defaults chosen against the documented control profile (4 vCPU / 8 GiB,
# captures up to 100 MiB, up to 250k packets).  They are ceilings, not
# truncations: exceeding one produces an explicit error, never silent data loss.
DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_CAPTURE_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_PACKET_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_PACKETS_PER_CAPTURE = 250_000
DEFAULT_MAX_TCP_SESSIONS_PER_CAPTURE = 1_000
DEFAULT_MAX_MESSAGES_PER_STREAM = 100_000
DEFAULT_MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_ENTRIES = 20_000
DEFAULT_MAX_ARCHIVE_ENTRY_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_COMPRESSION_RATIO = 200
DEFAULT_MAX_ARCHIVE_DEPTH = 12


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        # A malformed limit must not silently disable the control it configures.
        return default
    return max(minimum, value)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Limits:
    """Ceilings enforced by the backend on untrusted input and heavy work."""

    # Request handling
    rate_limit_requests: int = 300
    rate_limit_window_seconds: int = 60
    max_json_body_bytes: int = DEFAULT_MAX_JSON_BODY_BYTES

    # Uploads and projects
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    max_project_files: int = 500
    max_project_total_bytes: int = 4 * 1024 * 1024 * 1024

    # Capture parsing
    max_packet_bytes: int = DEFAULT_MAX_PACKET_BYTES
    max_packets_per_capture: int = DEFAULT_MAX_PACKETS_PER_CAPTURE
    max_tcp_sessions_per_capture: int = DEFAULT_MAX_TCP_SESSIONS_PER_CAPTURE
    max_messages_per_stream: int = DEFAULT_MAX_MESSAGES_PER_STREAM

    # Project archives (.mplab) - untrusted input
    max_archive_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES
    max_archive_entry_bytes: int = DEFAULT_MAX_ARCHIVE_ENTRY_BYTES
    max_archive_uncompressed_bytes: int = DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES
    max_archive_compression_ratio: int = DEFAULT_MAX_ARCHIVE_COMPRESSION_RATIO
    max_archive_depth: int = DEFAULT_MAX_ARCHIVE_DEPTH

    # AI context - bounds what can ever leave the machine
    max_ai_context_chars: int = 24_000
    max_ai_output_chars: int = 8_000

    # Concurrency and pagination
    max_concurrent_jobs: int = 4
    max_page_size: int = 1000
    default_page_size: int = 50

    @classmethod
    def from_env(cls) -> "Limits":
        return cls(
            rate_limit_requests=_env_int("MPLAB_RATE_LIMIT_REQUESTS", cls.rate_limit_requests),
            rate_limit_window_seconds=_env_int("MPLAB_RATE_LIMIT_WINDOW_SECONDS", cls.rate_limit_window_seconds),
            max_json_body_bytes=_env_int("MPLAB_MAX_JSON_BODY_BYTES", cls.max_json_body_bytes),
            max_upload_bytes=_env_int("MPLAB_MAX_UPLOAD_BYTES", cls.max_upload_bytes),
            max_capture_bytes=_env_int("MPLAB_MAX_CAPTURE_BYTES", cls.max_capture_bytes),
            max_project_files=_env_int("MPLAB_MAX_PROJECT_FILES", cls.max_project_files),
            max_project_total_bytes=_env_int("MPLAB_MAX_PROJECT_TOTAL_BYTES", cls.max_project_total_bytes),
            max_packet_bytes=_env_int("MPLAB_MAX_PACKET_BYTES", cls.max_packet_bytes),
            max_packets_per_capture=_env_int("MPLAB_MAX_PACKETS_PER_CAPTURE", cls.max_packets_per_capture),
            max_tcp_sessions_per_capture=_env_int(
                "MPLAB_MAX_TCP_SESSIONS_PER_CAPTURE", cls.max_tcp_sessions_per_capture
            ),
            max_messages_per_stream=_env_int("MPLAB_MAX_MESSAGES_PER_STREAM", cls.max_messages_per_stream),
            max_archive_entries=_env_int("MPLAB_MAX_ARCHIVE_ENTRIES", cls.max_archive_entries),
            max_archive_entry_bytes=_env_int("MPLAB_MAX_ARCHIVE_ENTRY_BYTES", cls.max_archive_entry_bytes),
            max_archive_uncompressed_bytes=_env_int(
                "MPLAB_MAX_ARCHIVE_UNCOMPRESSED_BYTES", cls.max_archive_uncompressed_bytes
            ),
            max_archive_compression_ratio=_env_int(
                "MPLAB_MAX_ARCHIVE_COMPRESSION_RATIO", cls.max_archive_compression_ratio
            ),
            max_archive_depth=_env_int("MPLAB_MAX_ARCHIVE_DEPTH", cls.max_archive_depth),
            max_ai_context_chars=_env_int("MPLAB_MAX_AI_CONTEXT_CHARS", cls.max_ai_context_chars),
            max_ai_output_chars=_env_int("MPLAB_MAX_AI_OUTPUT_CHARS", cls.max_ai_output_chars),
            max_concurrent_jobs=_env_int("MPLAB_MAX_CONCURRENT_JOBS", cls.max_concurrent_jobs),
            max_page_size=_env_int("MPLAB_MAX_PAGE_SIZE", cls.max_page_size),
            default_page_size=_env_int("MPLAB_DEFAULT_PAGE_SIZE", cls.default_page_size),
        )


@dataclass(frozen=True)
class Settings:
    """Resolved runtime configuration for one process."""

    data_dir: Path
    limits: Limits = field(default_factory=Limits)
    mode: str = MODE_LOCAL_SECURE
    host: str = "127.0.0.1"
    port: int = 8010
    debug: bool = False
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1", "testserver")
    frontend_origins: tuple[str, ...] = (
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    )
    database_url: str = ""
    auto_create_schema: bool = True
    allow_external_ai: bool = False
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b-instruct"
    run_jobs_in_subprocess: bool = False
    allow_non_loopback_bind: bool = False
    log_level: str = "INFO"
    app_version: str = "0.1.0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "data_dir", Path(self.data_dir).expanduser().resolve())
        object.__setattr__(self, "limits", self.limits)
        object.__setattr__(self, "allowed_hosts", tuple(self.allowed_hosts))
        object.__setattr__(self, "frontend_origins", tuple(self.frontend_origins))
        if not self.database_url:
            object.__setattr__(
                self,
                "database_url",
                f"sqlite:///{(self.data_dir / 'mplab.db').as_posix()}",
            )

    # -- derived paths ----------------------------------------------------- #

    @property
    def storage_dir(self) -> Path:
        """Captures, stream artefacts and exports.  Never web-served."""
        return self.data_dir / "storage"

    @property
    def secrets_dir(self) -> Path:
        """TLS key logs and other sensitive material, owner-only."""
        return self.data_dir / "secrets"

    @property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    @property
    def temp_dir(self) -> Path:
        return self.data_dir / "temp"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def is_remote_mode(self) -> bool:
        return self.mode == MODE_TEAM_REMOTE

    @property
    def is_demo_mode(self) -> bool:
        return self.mode == MODE_DEMO

    # -- lifecycle --------------------------------------------------------- #

    def ensure_directories(self) -> "Settings":
        """Create the managed directories and tighten their permissions.

        Owner-only where the platform supports it.  On Windows this is a no-op
        beyond creation, which is documented in docs/SECURITY.md as a known
        limitation rather than a silent pass.
        """
        for path, mode in (
            (self.data_dir, 0o700),
            (self.storage_dir, 0o700),
            (self.secrets_dir, 0o700),
            (self.exports_dir, 0o700),
            (self.temp_dir, 0o700),
            (self.logs_dir, 0o700),
        ):
            path.mkdir(parents=True, exist_ok=True)
            _restrict(path, mode)
        return self

    def describe(self) -> dict[str, Any]:
        """A non-secret view of the configuration, for /api/health and logs."""
        return {
            "mode": self.mode,
            "bind": f"{self.host}:{self.port}",
            "debug": self.debug,
            "allowed_hosts": list(self.allowed_hosts),
            "frontend_origins": list(self.frontend_origins),
            "data_dir": str(self.data_dir),
            "allow_external_ai": self.allow_external_ai,
            "ollama_url": self.ollama_url if self.allow_external_ai else None,
            "offline_first": True,
        }

    @classmethod
    def from_env(cls, **overrides: Any) -> "Settings":
        """Build settings from the environment, honouring explicit overrides.

        ``overrides`` wins so tests can pin a data directory without mutating
        global state.
        """
        raw_data_dir = os.environ.get("MPLAB_DATA_DIR") or "data"
        data_dir = Path(overrides.pop("data_dir", raw_data_dir))
        if not data_dir.is_absolute():
            data_dir = Path.cwd() / data_dir

        mode = (overrides.pop("mode", None) or os.environ.get("MPLAB_MODE") or MODE_LOCAL_SECURE).strip()
        if mode not in VALID_MODES:
            mode = MODE_LOCAL_SECURE

        host = (overrides.pop("host", None) or os.environ.get("MPLAB_HOST") or "127.0.0.1").strip()

        limits = overrides.pop("limits", None) or Limits.from_env()

        settings = cls(
            data_dir=data_dir,
            limits=limits,
            mode=mode,
            host=host,
            port=int(overrides.pop("port", None) or _env_int("MPLAB_PORT", 8010)),
            debug=bool(overrides.pop("debug", _env_bool("MPLAB_DEBUG", False))),
            allowed_hosts=tuple(
                overrides.pop("allowed_hosts", None)
                or _env_list(
                    "MPLAB_ALLOWED_HOSTS", ["127.0.0.1", "localhost", "::1", "testserver"]
                )
            ),
            frontend_origins=tuple(
                overrides.pop("frontend_origins", None)
                or _env_list(
                    "MPLAB_FRONTEND_ORIGINS",
                    ["http://127.0.0.1:3000", "http://localhost:3000"],
                )
            ),
            database_url=str(overrides.pop("database_url", None) or os.environ.get("MPLAB_DATABASE_URL") or ""),
            auto_create_schema=bool(
                overrides.pop("auto_create_schema", _env_bool("MPLAB_AUTO_CREATE_SCHEMA", True))
            ),
            allow_external_ai=bool(
                overrides.pop("allow_external_ai", _env_bool("MPLAB_ALLOW_EXTERNAL_AI", False))
            ),
            ollama_url=str(overrides.pop("ollama_url", None) or os.environ.get("MPLAB_OLLAMA_URL") or "http://127.0.0.1:11434"),
            ollama_model=str(overrides.pop("ollama_model", None) or os.environ.get("MPLAB_OLLAMA_MODEL") or "qwen2.5:7b-instruct"),
            run_jobs_in_subprocess=bool(
                overrides.pop("run_jobs_in_subprocess", _env_bool("MPLAB_RUN_JOBS_IN_SUBPROCESS", False))
            ),
            # Containers must bind 0.0.0.0 inside their own network namespace
            # for a published port to reach them; the host-side port mapping
            # is what restricts reachability. This flag records that the
            # operator has made that trade-off deliberately.
            allow_non_loopback_bind=bool(
                overrides.pop("allow_non_loopback_bind", _env_bool("MPLAB_ALLOW_NON_LOOPBACK_BIND", False))
            ),
            log_level=str(overrides.pop("log_level", None) or os.environ.get("MPLAB_LOG_LEVEL") or "INFO"),
        )
        return settings


def _restrict(path: Path, mode: int) -> None:
    """Best-effort owner-only permissions; a documented no-op on Windows."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - platform dependent
        pass


_settings: Settings | None = None


def get_settings() -> Settings:
    """Process-wide settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings.from_env().ensure_directories()
    return _settings


def reset_settings() -> None:
    """Drop the cached instance (tests and config reloads)."""
    global _settings
    _settings = None


def is_loopback(host: str) -> bool:
    return host.strip().lower() in _LOOPBACK_HOSTS


__all__ = [
    "Limits",
    "Settings",
    "MODE_LOCAL_SECURE",
    "MODE_TEAM_REMOTE",
    "MODE_DEMO",
    "VALID_MODES",
    "get_settings",
    "reset_settings",
    "is_loopback",
]

_ = (stat, Mapping)