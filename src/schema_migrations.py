from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.sqltypes import Integer, Text

from .service_models import Base


@dataclass(frozen=True, slots=True)
class SchemaIssue:
    table_name: str
    missing_columns: tuple[str, ...]


class SchemaDriftError(RuntimeError):
    def __init__(self, issues: list[SchemaIssue]) -> None:
        details = ", ".join(f"{issue.table_name}: {', '.join(issue.missing_columns)}" for issue in issues)
        super().__init__(f"database schema is missing required columns; run scripts/migrate_postgres.py first: {details}")
        self.issues = issues


def apply_additive_schema_migrations(engine: Engine) -> None:
    with engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
            _add_missing_columns(connection, table.name, tuple(table.columns))
    Base.metadata.create_all(engine)


def assert_service_schema(engine: Engine) -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    issues: list[SchemaIssue] = []
    for table in Base.metadata.sorted_tables:
        if table.name not in table_names:
            issues.append(SchemaIssue(table.name, tuple(column.name for column in table.columns)))
            continue
        column_names = {column["name"] for column in inspector.get_columns(table.name)}
        missing = tuple(column.name for column in table.columns if column.name not in column_names)
        if missing:
            issues.append(SchemaIssue(table.name, missing))
    if issues:
        raise SchemaDriftError(issues)


def _add_missing_columns(connection: Connection, table_name: str, columns: tuple[Column, ...]) -> None:
    inspector = inspect(connection)
    if table_name not in set(inspector.get_table_names()):
        return
    existing = {column["name"] for column in inspector.get_columns(table_name)}
    for column in columns:
        if column.name in existing:
            continue
        connection.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN {_column_sql(connection, column)}'))


def _column_sql(connection: Connection, column: Column) -> str:
    column_type = column.type.compile(dialect=connection.dialect)
    nullability = "" if column.nullable else " NOT NULL"
    return f'"{column.name}" {column_type}{nullability}{_default_sql(column)}'


def _default_sql(column: Column) -> str:
    if column.nullable:
        return ""
    if isinstance(column.type, Integer):
        return " DEFAULT 0"
    if isinstance(column.type, Text):
        return " DEFAULT '{}'"
    return " DEFAULT 'unknown'"
