from __future__ import annotations

from src.service_store import ServiceStore

_store: ServiceStore | None = None


def set_store(store: ServiceStore) -> None:
    global _store
    _store = store


def get_store() -> ServiceStore:
    global _store
    if _store is None:
        _store = ServiceStore()
        _store.initialize()
    return _store
