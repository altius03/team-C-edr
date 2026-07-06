from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


class StoredPayloadError(TypeError):
    def __init__(self) -> None:
        super().__init__("stored JSON payload is not an object")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def dump_json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def load_json_object(value: str) -> JsonObject:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise StoredPayloadError()
    return parsed


def json_list(value: JsonValue) -> list[JsonObject]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def text_value(value: JsonValue) -> str:
    return value if isinstance(value, str) else ""


def int_value(value: JsonValue) -> int:
    return value if isinstance(value, int) else 0
