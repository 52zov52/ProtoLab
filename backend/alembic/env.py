"""Alembic migration environment.

The URL comes from the application's own settings rather than from this file, so
``python -m alembic upgrade head`` and ``api.main`` always agree about which
database they are talking about. ``run_migrations`` in ``app.db.session`` passes
an open connection through ``config.attributes`` when the API migrates itself;
the CLI path opens its own.
"""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

from app.core.config import Settings

# Importing the model package registers every table on `Base.metadata`; without
# it the autogenerate diff sees an empty metadata and emits nothing.
import app.models  # noqa: F401  (side effect: table registration)
from app.db.base import Base

config = context.config

# `fileConfig` is intentionally skipped: the application configures its own
# logging, and re-reading an ini section at migration time would replace the
# handlers of loggers that are already in use.
target_metadata = Base.metadata

_settings = Settings.from_env()
# A migration is a mutating operation on the same directories the API uses, and
# SQLite will not create a missing parent; the CLI therefore has to do here what
# `create_app` does on startup.
_settings.ensure_directories()
# An explicit URL (passed by `app.db.migrations.run_migrations`, or by a test
# through `mp_database_url`) wins over the application default, so a migration
# can never target a different database than the caller asked for.
config.set_main_option(
    "sqlalchemy.url",
    config.get_main_option("sqlalchemy.url")
    or str(config.attributes.get("mp_database_url") or _settings.database_url),
)


def _configure(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Alembic compares names, so the same naming convention the ORM uses is
        # required for constraints to be recognised as unchanged.
        version_table="alembic_version",
        compare_type=True,
        compare_server_default=True,
    )


if context.is_offline_mode():

    def run_migrations() -> None:  # pragma: no cover - `--sql` only
        _configure(None)
        with context.begin_transaction():
            context.run_migrations()

else:

    def run_migrations() -> None:
        connectable = config.attributes.get("connection")
        if connectable is None:
            connectable = engine_from_config(
                config.get_section(config.config_ini_section, {}),
                prefix="sqlalchemy.",
                poolclass=pool.NullPool,
            )
            with connectable.connect() as connection:
                _configure(connection)
                with context.begin_transaction():
                    context.run_migrations()
        else:
            _configure(connectable)
            with context.begin_transaction():
                context.run_migrations()


run_migrations()
