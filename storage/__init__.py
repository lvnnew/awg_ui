"""SQLite-backed panel storage (gradual migration from data.json)."""

from storage.store import Store, configure_store, get_store

__all__ = ["Store", "configure_store", "get_store"]
