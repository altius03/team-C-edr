from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.config import DEFAULT_DATABASE_URL
from src.schema_migrations import apply_additive_schema_migrations, assert_service_schema
from src.service_store_engine import create_store_engine


def main() -> int:
    database_url = os.environ.get("DATABASE_URL") or os.environ.get("LAYERTRACE_DATABASE_URL") or DEFAULT_DATABASE_URL
    storage_label = "postgresql" if database_url.startswith("postgresql") else "sqlite"
    engine = create_store_engine(database_url, storage_label)
    try:
        apply_additive_schema_migrations(engine)
        assert_service_schema(engine)
    finally:
        engine.dispose()
    print(f"schema migration complete for {storage_label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
