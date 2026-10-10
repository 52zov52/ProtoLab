"""FastAPI application factory with the local-security middleware stack."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..core.config import Settings, get_settings
from ..core.errors import AppError, PayloadTooLarge, RateLimited, SecurityViolation
from ..core.logging import configure_logging, get_logger, redact
from ..core.security import (
    ConcurrencyGate,
    SlidingWindowLimiter,
    check_host_header,
    enforce_body_size,
    is_cross_origin,
    is_loopback_host,
    origin_matches,
)
from ..db.base import Base
from ..db.session import build_engine, create_schema
from .context import AppContext
from .routers import (
    anomalies,
    assistant,
    audit,
    captures,
    diff,
    graph,
    hypotheses,
    interpret,
    jobs,
    projects,
    reports,
    security,
    sessions,
    streams,
)

log = get_logger("mplab.api")

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    settings.ensure_directories()
    if settings.auto_create_schema:
        Base.metadata.create_all(app.state.engine)
    log.info(
        "Madrigal Protocol Lab backend ready (mode=%s, bind=%s:%s)",
        settings.mode,
        settings.host,
        settings.port,
    )
    try:
        yield
    finally:
        app.state.engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    configure_logging()
    settings = settings or get_settings()
    engine = build_engine(settings)
    settings.ensure_directories()
    if settings.auto_create_schema:
        create_schema(engine)

    app = FastAPI(
        title="Madrigal Protocol Lab",
        version="0.1.0",
        description=(
            "Local protocol reverse-engineering platform. Every conclusion is "
            "traceable to capture bytes; nothing is asserted without evidence."
        ),
        lifespan=lifespan,
        docs_url="/api/docs" if settings.debug or settings.mode == "local_secure" else None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    _warn_on_remote_bind(settings)
    app.state.context = AppContext(
        settings=settings,
        engine=engine,
        limiter=SlidingWindowLimiter(
            settings.limits.rate_limit_requests, settings.limits.rate_limit_window_seconds
        ),
        job_gate=ConcurrencyGate(settings.limits.max_concurrent_jobs),
    )

    _install_middleware(app, settings)
    _install_error_handlers(app)

    app.include_router(projects.router, prefix="/api", tags=["projects"])
    app.include_router(captures.router, prefix="/api", tags=["captures"])
    app.include_router(sessions.router, prefix="/api", tags=["sessions"])
    app.include_router(streams.router, prefix="/api", tags=["streams"])
    app.include_router(hypotheses.router, prefix="/api", tags=["hypotheses"])
    app.include_router(interpret.router, prefix="/api", tags=["interpretations"])
    app.include_router(jobs.router, prefix="/api", tags=["jobs"])
    app.include_router(diff.router, prefix="/api", tags=["diff"])
    app.include_router(graph.router, prefix="/api", tags=["graph"])
    app.include_router(anomalies.router, prefix="/api", tags=["anomalies"])
    app.include_router(assistant.router, prefix="/api", tags=["assistant"])
    app.include_router(reports.router, prefix="/api", tags=["reports"])
    app.include_router(audit.router, prefix="/api", tags=["audit"])
    app.include_router(security.router, prefix="/api", tags=["security"])

    @app.get("/api/health", tags=["system"])
    def health() -> dict[str, object]:  # pragma: no cover - trivial
        return {
            "status": "ok",
            "version": "0.1.0",
            "mode": settings.mode,
            "bind": f"{settings.host}:{settings.port}",
            "offline_first": True,
        }

    return app


def _warn_on_remote_bind(settings: Settings) -> None:
    """Refuse to pretend that a LAN bind is a safe local deployment.

    In local secure mode a non-loopback bind is a configuration mistake, so it is
    surfaced loudly at startup and again in the Security Center, rather than
    being quietly accepted.
    """
    if is_loopback_host(settings.host):
        return
    message = (
        "SECURITY: the API is configured to listen on %s, which is reachable from "
        "other hosts. This deployment has no multi-user authentication, "
        "authorisation or TLS termination. Required before exposing it: set "
        "MPLAB_MODE=team_remote, terminate TLS in a reverse proxy, add "
        "authentication and CSRF protection, restrict MPLAB_ALLOWED_HOSTS, and "
        "restrict MPLAB_FRONTEND_ORIGINS."
    ) % settings.host
    if settings.is_remote_mode:
        log.warning(message)
    else:
        log.error(message)


def _install_middleware(app: FastAPI, settings: Settings) -> None:
    limiter = app.state.context.limiter
    allowed_origins = settings.frontend_origins
    allowed_hosts = settings.allowed_hosts

    @app.middleware("http")
    async def security_headers_and_guards(request: Request, call_next):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        try:
            check_host_header(request.headers.get("host"), allowed_hosts)

            # Note: the *bind address* is what limits network reachability, and it
            # is validated once at startup (see _warn_on_remote_bind).  Checking
            # the Host header for loopback-ness here would be useless: Host is
            # attacker-controlled, so it can never prove where the request went.
            # The Host allowlist above is what defeats DNS rebinding.

            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            is_browser = bool(origin or referer)

            if is_browser:
                if not (
                    origin_matches(origin, allowed_origins)
                    or origin_matches(referer, allowed_origins)
                ):
                    raise SecurityViolation(
                        "Cross-origin request rejected: the Origin header does not "
                        "match an allowed frontend origin."
                    )

            if request.method in MUTATING_METHODS and is_browser:
                # CSRF defence: a state-changing request from a page must carry
                # a same-origin Origin.  Non-browser clients (curl, the CLI)
                # send no Origin and are allowed; they are not driven by a
                # victim's ambient cookies in this deployment.
                if origin and not origin_matches(origin, allowed_origins):
                    raise SecurityViolation(
                        "State-changing request rejected by the origin check."
                    )

            enforce_body_size(
                request.headers.get("content-length"), settings.limits.max_json_body_bytes
            )
            limiter.check(_client_key(request))

            response = await call_next(request)
        except AppError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_payload(),
                headers={"Cache-Control": "no-store"},
            )
        except Exception:  # pragma: no cover - defensive
            log.exception("unhandled error while serving %s %s", request.method, request.url.path)
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "internal_error",
                        "message": "The request could not be completed.",
                        "details": {},
                    }
                },
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-Duration-Ms"] = f"{elapsed_ms:.1f}"
        if settings.is_remote_mode:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def _client_key(request: Request) -> str:
    """Rate-limit key.

    In local mode the peer address is the meaningful identity.  We deliberately
    do *not* trust ``X-Forwarded-For``: in local mode nothing sits in front of
    the API, and honouring a spoofable header would let a client evade its own
    limit.
    """
    client = request.client
    return client.host if client else "unknown"


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_request: Request, exc: AppError):  # pragma: no cover - thin
        return JSONResponse(status_code=exc.status_code, content=exc.to_payload())

    @app.exception_handler(429)
    async def _rate_limit(_request: Request, exc):  # pragma: no cover - thin
        return JSONResponse(
            status_code=429,
            content={"error": {"code": "rate_limited", "message": "Too many requests.", "details": {}}},
        )

    @app.exception_handler(413)
    async def _too_large(_request: Request, _exc):  # pragma: no cover - thin
        return JSONResponse(
            status_code=413,
            content={
                "error": {
                    "code": "payload_too_large",
                    "message": "The request body exceeds the configured limit.",
                    "details": {},
                }
            },
        )


_ = (PayloadTooLarge, RateLimited, redact)