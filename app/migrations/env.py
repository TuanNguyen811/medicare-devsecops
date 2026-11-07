import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

# Import every models module so autogenerate sees all tables.
import medicare.appointment.models
import medicare.audit.models
import medicare.auth.models
import medicare.billing.models
import medicare.department.models
import medicare.patient.models
import medicare.prescription.models
import medicare.record.models  # noqa: F401
from medicare.db import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError("Set sqlalchemy.url or the DATABASE_URL environment variable")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
