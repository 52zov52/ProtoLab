"""Uvicorn entry point.

Run with::

    python -m app            # from the backend directory
    uvicorn app.api.main:create_app --factory --host 127.0.0.1 --port 8010
"""

from __future__ import annotations

from .core.config import get_settings


def main() -> int:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.api.main:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level="debug" if settings.debug else "info",
        access_log=settings.debug,
        server_header=False,
        date_header=True,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())