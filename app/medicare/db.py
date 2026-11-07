from collections.abc import Iterator
from enum import StrEnum

from fastapi import Request
from sqlalchemy import Engine, MetaData, create_engine
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )


def str_enum(enum_cls: type[StrEnum], name: str) -> SAEnum:
    """Store a StrEnum as a plain VARCHAR holding its value (e.g. REQUESTED) plus a CHECK."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=20,
        values_callable=lambda e: [m.value for m in e],
    )


def create_db(database_url: str) -> tuple[Engine, sessionmaker[Session]]:
    """Create the engine once (lazy: no connection until first use) and its session factory."""
    engine = create_engine(database_url, pool_pre_ping=True, hide_parameters=True)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def get_db(request: Request) -> Iterator[Session]:
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()
