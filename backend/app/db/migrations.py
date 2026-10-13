"""Bring the database to the current schema.

The application still calls ``Base.metadata.create_all`` first, which keeps every
database an earlier build created working untouched. Alembic then runs to head,
so an operator who opts out of auto-creation
(``MPLAB_AUTO_CREATE_SCHEMA=false``) can rely on ``alembic upgrade head`` alone.

A database that has tables but no ``alembic_version`` row is **stamped** rather
than upgraded. Its tables already exist — created by ``create_all`` just above, or
by a build that predates Alembic — and replaying ``0001_initial`` against them
would fail on every table that is already there. Stamping records the fact that
the schema matches ``0001_initial``; ``tests/test_migrations.py`` compares the
migration's output against the models, which is what makes that claim a checked
one rather than an assumption.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine

log = logging.getLogger("mplab.migrations")

_ALEMBIC_INI = Path(__file__).resolve().parent.parent.parent / "alembic.ini"


def _config(database_url: str) -> Config:
    """An Alembic config pinned to this project's environment.

    `script_location` is resolved here rather than taken from the working
    directory: the API migrates itself from whatever directory it was started
    in, and a relative lookup would silently point somewhere else there.
    """
    scripts = _ALEMBIC_INI.parent / "alembic"
    if not _ALEMBIC_INI.exists() or not scripts.is_dir():
        # Plain Alembic reports this as "Path doesn't exist: …/alembic" from
        # inside its own machinery, which says nothing about how it happened.
        raise RuntimeError(
            f"Migration scripts are missing: expected {_ALEMBIC_INI} and {scripts}. "
            "An image that runs the backend must ship the alembic/ directory and "
            "alembic.ini (see backend/Dockerfile)."
        )
    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("script_location", str(scripts))
    if database_url:
        config.set_main_option("sqlalchemy.url", database_url)
    return config


def run_migrations(engine: Engine) -> None:
    """Apply every pending revision, or record that none are."""
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()

    config = _config(engine.url.render_as_string(hide_password=False))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        if current is None:
            log.info("mplab.migrations: no revision recorded; stamping at head")
            command.stamp(config, "head")
        else:
            log.info("mplab.migrations: upgrading from %s", current)
            command.upgrade(config, "head")
