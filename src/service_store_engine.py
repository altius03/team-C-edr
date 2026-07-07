from __future__ import annotations

from typing import Protocol

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import NullPool

EngineKwarg = bool | dict[str, bool] | type[NullPool]


class SqliteCursor(Protocol):
    def execute(self, statement: str) -> "SqliteCursor": ...

    def close(self) -> None: ...


class SqliteConnection(Protocol):
    def cursor(self) -> SqliteCursor: ...


def create_store_engine(database_url: str, storage_label: str) -> Engine:
    engine_kwargs: dict[str, EngineKwarg] = {"future": True, "pool_pre_ping": True}
    if storage_label == "sqlite":
        engine_kwargs["connect_args"] = {"check_same_thread": False}
        engine_kwargs["poolclass"] = NullPool
    engine = create_engine(database_url, **engine_kwargs)
    if storage_label == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def _enable_sqlite_foreign_keys(dbapi_connection: SqliteConnection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()
