"""Normalize JSON payload values before storing or reading database rows."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


class StoredPayloadError(TypeError):
    """Raised when persisted JSON does not decode to an object payload."""

    def __init__(self) -> None:
        """Build the fixed stored-payload validation message."""

        super().__init__("stored JSON payload is not an object")


def now_iso() -> str:
    """Return a seconds-precision timestamp for persisted rows."""

    return datetime.now().isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    """Create a compact prefixed identifier for persisted records."""

    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def dump_json(value: JsonValue) -> str:
    """Serialize JSON-compatible values in the compact stored format."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def load_json_object(value: str) -> JsonObject:
    """Deserialize a stored JSON payload and require an object at the top level."""

    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise StoredPayloadError()
    return parsed


def json_list(value: JsonValue) -> list[JsonObject]:
    """Extract object entries from a JSON list, dropping non-object items."""

    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def text_value(value: JsonValue) -> str:
    """Return string JSON values with an empty-string fallback."""

    return value if isinstance(value, str) else ""


def int_value(value: JsonValue) -> int:
    """Return integer JSON values with a zero fallback."""

    return value if isinstance(value, int) else 0
