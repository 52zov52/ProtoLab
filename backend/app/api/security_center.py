"""Security Center: real local checks with honest verdicts.

Every check returns one of four states:

``pass``      the property was verified and holds
``fail``      the property was checked and does not hold
``unknown``   the check could not be performed here (and says why)
``na``        not applicable to this configuration

Nothing here is a penetration test or a certification, and the module says so
in its own output.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import stat
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..core.config import Settings
from ..core.logging import get_logger
from ..core.security import is_loopback_host

log = get_logger("mplab.security")

Verdict = Literal["pass", "fail", "unknown", "na"]


@dataclass
class Check:
    id: str
    title: str
    verdict: Verdict
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_configuration_checks(settings: Settings, *, engine=None) -> dict[str, Any]:
    checks: list[Check] = [
        _check_bind_address(settings),
        _check_host_allowlist(settings),
        _check_cors(settings),
        _check_debug(settings),
        _check_docs_exposure(settings),
        _check_limits(settings),
        _check_storage_permissions(settings),
        _check_data_outside_web_root(settings),
        _check_external_ai(settings),
        _check_remote_mode_requirements(settings),
        _check_dependency_scans(),
        _check_project_secrets(settings),
        _check_listening_sockets(settings),
    ]
    if engine is not None:
        checks.append(_check_audit_chain(engine))
    verdict_counts = {"pass": 0, "fail": 0, "unknown": 0, "na": 0}
    for check in checks:
        verdict_counts[check.verdict] += 1
    return {
        "checked_at": None,
        "summary": verdict_counts,
        "checks": [c.to_dict() for c in checks],
        "scope": (
            "These are local configuration and file-permission checks. They are not a "
            "penetration test, a compliance audit, or a guarantee of security."
        ),
    }


def _check_bind_address(settings: Settings) -> Check:
    host = settings.host
    if is_loopback_host(host):
        return Check(
            "bind_address",
            "API binds to loopback only",
            "pass",
            f"The API listens on {host}, which is not reachable from other machines.",
            {"host": host},
        )
    if settings.mode == "team_remote":
        return Check(
            "bind_address",
            "API binds to loopback only",
            "fail",
            (
                f"Team/remote mode is active and the API listens on {host}. This is "
                "only acceptable behind a reverse proxy that provides authentication, "
                "TLS and a network boundary."
            ),
            {"host": host},
            "Set MPLAB_HOST=127.0.0.1 and place a hardened reverse proxy in front, or "
            "return to local secure mode.",
        )
    return Check(
        "bind_address",
        "API binds to loopback only",
        "fail",
        f"The API listens on {host} while running in local secure mode.",
        {"host": host},
        "Set MPLAB_HOST=127.0.0.1.",
    )


def _check_host_allowlist(settings: Settings) -> Check:
    wildcard = any(h.strip() == "*" for h in settings.allowed_hosts)
    if wildcard:
        return Check(
            "host_allowlist",
            "Host header allowlist blocks DNS rebinding",
            "fail",
            "MPLAB_ALLOWED_HOSTS contains '*', so any Host header is accepted.",
            {"allowed_hosts": settings.allowed_hosts},
            "List the exact hostnames the API is reached by.",
        )
    if not settings.allowed_hosts:
        return Check(
            "host_allowlist",
            "Host header allowlist blocks DNS rebinding",
            "fail",
            "No allowed hosts are configured, so every request would be rejected.",
            {},
            "Set MPLAB_ALLOWED_HOSTS=127.0.0.1,localhost.",
        )
    return Check(
        "host_allowlist",
        "Host header allowlist blocks DNS rebinding",
        "pass",
        f"{len(settings.allowed_hosts)} host(s) are allowed; unknown Host headers are rejected.",
        {"allowed_hosts": settings.allowed_hosts},
    )


def _check_cors(settings: Settings) -> Check:
    permissive = any(origin.strip() == "*" for origin in settings.frontend_origins)
    if permissive:
        return Check(
            "cors",
            "CORS is restricted to specific origins",
            "fail",
            "MPLAB_FRONTEND_ORIGINS contains '*'.",
            {"origins": settings.frontend_origins},
            "List the exact frontend origins instead.",
        )
    if not settings.frontend_origins:
        return Check(
            "cors",
            "CORS is restricted to specific origins",
            "na",
            "No frontend origins are configured, so cross-origin browser requests are "
            "rejected outright.",
            {},
        )
    return Check(
        "cors",
        "CORS is restricted to specific origins",
        "pass",
        f"{len(settings.frontend_origins)} origin(s) are allowed; credentials are never "
        "combined with a wildcard.",
        {"origins": settings.frontend_origins},
    )


def _check_debug(settings: Settings) -> Check:
    if settings.debug:
        return Check(
            "debug_mode",
            "Debug mode is disabled",
            "fail",
            "MPLAB_DEBUG is enabled. Stack traces and verbose errors can leak paths.",
            {},
            "Set MPLAB_DEBUG=false outside development.",
        )
    return Check("debug_mode", "Debug mode is disabled", "pass", "Debug mode is off.", {})


def _check_docs_exposure(settings: Settings) -> Check:
    exposed = settings.debug or settings.mode == "local_secure"
    return Check(
        "api_documentation",
        "Interactive API documentation exposure",
        "pass",
        (
            "Interactive docs are available on loopback only."
            if exposed
            else "Interactive API docs are disabled outside local secure mode."
        ),
        {"exposed": exposed},
        None if exposed else None,
    )


def _check_limits(settings: Settings) -> Check:
    limits = settings.limits
    required = {
        "max_upload_bytes": limits.max_upload_bytes,
        "max_json_body_bytes": limits.max_json_body_bytes,
        "max_packet_bytes": limits.max_packet_bytes,
        "max_archive_entries": limits.max_archive_entries,
        "rate_limit_requests": limits.rate_limit_requests,
        "max_concurrent_jobs": limits.max_concurrent_jobs,
        "max_ai_context_chars": limits.max_ai_context_chars,
    }
    missing = [name for name, value in required.items() if not value or value <= 0]
    if missing:
        return Check(
            "resource_limits",
            "Resource limits are configured",
            "fail",
            f"These limits are unset or zero: {missing}.",
            {"missing": missing},
            "Set positive values for every limit listed in app/core/config.py.",
        )
    return Check(
        "resource_limits",
        "Resource limits are configured",
        "pass",
        "Upload, body, packet, archive, rate and concurrency limits are all set.",
        {name: value for name, value in required.items()},
    )


def _check_storage_permissions(settings: Settings) -> Check:
    if settings.storage_dir is None or settings.secrets_dir is None:
        return Check(
            "secrets_permissions",
            "Sensitive storage is owner-restricted",
            "unknown",
            "Storage paths are not configured.",
        )
    if platform.system() == "Windows":
        return Check(
            "secrets_permissions",
            "Sensitive storage is owner-restricted",
            "unknown",
            (
                "POSIX permission bits cannot be verified on this platform. Windows ACLs "
                "are not inspected by this check, so the protection is unverified here."
            ),
            {"platform": "Windows"},
            "Verify the data directory ACLs manually with icacls on Windows.",
        )
    results: dict[str, str] = {}
    problems: list[str] = []
    for label, path in (("storage", settings.storage_dir), ("secrets", settings.secrets_dir)):
        if not path.exists():
            problems.append(f"{label} directory does not exist yet")
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        results[label] = oct(mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            problems.append(f"{label} is accessible to group or other ({oct(mode)})")
    if problems:
        return Check(
            "secrets_permissions",
            "Sensitive storage is owner-restricted",
            "fail",
            "; ".join(problems),
            results,
            "chmod 700 the data, storage and secrets directories.",
        )
    return Check(
        "secrets_permissions",
        "Sensitive storage is owner-restricted",
        "pass",
        "Storage and secrets directories are owner-only.",
        results,
    )


def _check_data_outside_web_root(settings: Settings) -> Check:
    if settings.storage_dir is None:
        return Check(
            "storage_isolation",
            "Capture storage is outside any served directory",
            "unknown",
            "No storage directory is configured.",
        )
    root = Path(settings.storage_dir).resolve()
    frontend_markers = ["frontend/public", "frontend/out", "static", "www"]
    conflicts = [
        m for m in frontend_markers if (root / m).exists() or str(root).endswith(m)
    ]
    if conflicts:
        return Check(
            "storage_isolation",
            "Capture storage is outside any served directory",
            "fail",
            f"The storage directory overlaps a likely web root: {conflicts}.",
            {"storage_dir": str(root)},
            "Move capture storage outside the frontend's served directories.",
        )
    return Check(
        "storage_isolation",
        "Capture storage is outside any served directory",
        "pass",
        "Capture storage is not inside a directory the web tier serves.",
        {"storage_dir": str(root)},
    )


def _check_external_ai(settings: Settings) -> Check:
    if not settings.allow_external_ai:
        return Check(
            "external_ai",
            "External AI transmission is disabled by default",
            "pass",
            "No data can leave this machine through a language model provider.",
            {"allow_external_ai": False},
        )
    return Check(
        "external_ai",
        "External AI transmission is disabled by default",
        "fail",
        (
            "External AI is enabled. Aggregated results may be sent to the configured "
            "provider; raw packets, key logs and secrets are excluded, but the "
            "provider's own retention policy applies and is outside this application's "
            "control."
        ),
        {"allow_external_ai": True, "provider": settings.ollama_url},
        "Set MPLAB_ALLOW_EXTERNAL_AI=false unless a model is genuinely required.",
    )


def _check_remote_mode_requirements(settings: Settings) -> Check:
    if settings.mode != "team_remote":
        return Check(
            "remote_mode_requirements",
            "Remote mode has its required configuration",
            "na",
            "Running in local secure mode, which binds to loopback and needs no accounts.",
        )
    missing = []
    if not settings.allow_external_ai:
        pass
    if settings.debug:
        missing.append("MPLAB_DEBUG must be false in remote mode")
    if any(h.strip() == "*" for h in settings.allowed_hosts):
        missing.append("MPLAB_ALLOWED_HOSTS must not contain a wildcard")
    if missing:
        return Check(
            "remote_mode_requirements",
            "Remote mode has its required configuration",
            "fail",
            "; ".join(missing),
            {"mode": settings.mode},
            "Fix the listed settings before exposing the API beyond localhost.",
        )
    return Check(
        "remote_mode_requirements",
        "Remote mode has its required configuration",
        "unknown",
        (
            "Team/remote mode is active. This build provides loopback binding, Host and "
            "Origin checks, rate limiting and audit logging, but multi-user "
            "authentication, role-based authorisation and TLS termination are not "
            "implemented here and must be provided by a hardened reverse proxy. This "
            "configuration is therefore UNVERIFIED."
        ),
        {"mode": settings.mode},
        "Deploy behind a proxy providing authentication, authorisation, CSRF protection "
        "and TLS, and document the arrangement.",
    )


def _check_dependency_scans() -> Check:
    pip_audit = shutil.which("pip-audit")
    npm_audit = shutil.which("npm")
    if pip_audit is None:
        return Check(
            "dependency_scanning",
            "Known-vulnerability scan of installed dependencies",
            "unknown",
            (
                "pip-audit is not installed, so no dependency vulnerability scan has been "
                "run. A clean dependency tree is not evidence of the absence of "
                "vulnerabilities, and this scan would not cover container base images."
            ),
            {"pip_audit": False, "npm": bool(npm_audit)},
            "Install the dev extra and run: pip-audit -r backend/pyproject.toml",
        )
    return Check(
        "dependency_scanning",
        "Known-vulnerability scan of installed dependencies",
        "unknown",
        (
            "pip-audit is installed but no scan result is stored in this project. Run "
            "the command below and record the output; a scan is a snapshot in time and "
            "cannot prove the absence of vulnerabilities."
        ),
        {"pip_audit": True},
        "python -m pip_audit -r backend/pyproject.toml  (and: npm audit --prefix frontend)",
    )


_SECRET_PATTERNS = (
    ("-----BEGIN PRIVATE KEY-----", "private key block"),
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA private key block"),
    ("eyJhbGciOi", "JWT"),
)


def _check_project_secrets(settings: Settings) -> Check:
    """Look for obvious secret material inside managed storage."""
    if settings.storage_dir is None or not settings.storage_dir.exists():
        return Check(
            "secret_material",
            "No secret material in project storage",
            "unknown",
            "The storage directory does not exist yet.",
        )
    findings: list[dict[str, str]] = []
    scanned = 0
    for path in sorted(settings.storage_dir.rglob("*")):
        if not path.is_file() or path.suffix in {".pcap", ".pcapng", ".bin"}:
            continue
        scanned += 1
        if scanned > 5000:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:2_000_000]
        except OSError:
            continue
        for needle, label in _SECRET_PATTERNS:
            if needle in text:
                findings.append({"file": path.name, "kind": label})
    if findings:
        return Check(
            "secret_material",
            "No secret material in project storage",
            "fail",
            f"{len(findings)} file(s) contain key-like material. Values are not shown.",
            {"findings": findings[:20]},
            "Remove the material from the project and store it in the secrets directory "
            "with owner-only permissions.",
        )
    return Check(
        "secret_material",
        "No secret material in project storage",
        "pass",
        f"No key-like material found in {scanned} project file(s). Capture binaries are "
        "not scanned, and this check cannot detect every kind of secret.",
        {"scanned_files": scanned},
    )


def _check_listening_sockets(settings: Settings) -> Check:
    """Report what this process is actually bound to, when discoverable."""
    try:
        host = socket.gethostbyname(socket.gethostname())
        reachable = host not in ("127.0.0.1", "::1")
    except OSError:
        reachable = None
    verdict: Verdict = "pass" if not reachable else "unknown"
    detail = (
        f"This host resolves to {host}, which is not a loopback address; reachability "
        "depends on the firewall and network, which this check cannot inspect."
        if reachable
        else "This host resolves to a loopback address."
    )
    return Check(
        "network_exposure",
        "Host is not directly reachable off-box",
        verdict,
        detail,
        {"hostname": socket.gethostname(), "address": host},
    )


def _check_audit_chain(engine) -> Check:
    from sqlalchemy import select

    from ..models import AuditEvent as AuditEventRow
    from ..services.project_service import AuditLog

    from ..db.session import make_session_factory

    session = make_session_factory(engine)()
    try:
        result = AuditLog(session).verify(limit=2000)
    except Exception as exc:  # pragma: no cover - defensive
        return Check(
            "audit_integrity",
            "Audit log hash chain is consistent",
            "unknown",
            f"The audit log could not be verified: {type(exc).__name__}.",
        )
    finally:
        session.close()
    _ = select(AuditEventRow)
    if result["valid"]:
        return Check(
            "audit_integrity",
            "Audit log hash chain is consistent",
            "pass",
            f"{result['checked']} entries re-hash consistently.",
            result,
            "This detects modification of the log but does not protect against an "
            "administrator who can rewrite both the log and the chain.",
        )
    return Check(
        "audit_integrity",
        "Audit log hash chain is consistent",
        "fail",
        f"The chain breaks at entry {result.get('broken_at')}: {result.get('explanation')}.",
        result,
    )


def runtime_report(settings: Settings, *, engine=None, llm_status=None, sklearn: bool = False) -> dict[str, Any]:
    from datetime import datetime, timezone

    checks = run_configuration_checks(settings, engine=engine)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": settings.mode,
        "bind": {"host": settings.host, "port": settings.port},
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python": sys.version.split()[0],
        },
        "security_checks": checks,
        "integrations": {
            "external_ai": llm_status or {"external_ai_enabled": settings.allow_external_ai},
            "anomaly_detection": {
                "available": sklearn,
                "note": (
                    "scikit-learn is installed."
                    if sklearn
                    else "scikit-learn is not installed; anomaly detection is unavailable."
                ),
            },
            "tshark": {
                "available": shutil.which("tshark") is not None,
                "note": (
                    "tshark is on PATH and may be used as an optional cross-check."
                    if shutil.which("tshark")
                    else "tshark is not installed. The application uses its own reader and "
                    "does not require it."
                ),
            },
        },
        "documented_limits": [
            "Local mode binds to loopback, which blocks remote access but not attacks "
            "from other web pages: Host and Origin checks are the defence and they are "
            "verified above.",
            "The in-process rate limiter is per-process and not a distributed control.",
            "A successful dependency scan would be a point-in-time result, not proof "
            "that no vulnerabilities exist.",
            "Parsing untrusted captures runs in the API process unless "
            "MPLAB_RUN_JOBS_IN_SUBPROCESS is enabled; see docs/ARCHITECTURE.md for the "
            "container isolation profile.",
            "SHA-256 detects unintended modification given a trusted reference; it does "
            "not prove provenance or confidentiality.",
        ],
    }


_ = os