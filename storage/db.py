"""Database engine / session helpers."""

from __future__ import annotations

import logging
import os
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    pass


def default_database_url(data_file: str | None = None) -> str:
    """sqlite:////data/panel.db next to DATA_FILE by default."""
    env = (os.environ.get("DATABASE_URL") or "").strip()
    if env:
        return env
    data_file = data_file or os.environ.get("DATA_FILE") or "data.json"
    base = os.path.dirname(os.path.abspath(data_file)) or "."
    path = os.path.join(base, "panel.db")
    return "sqlite:///" + path


@lru_cache(maxsize=1)
def get_engine(url: str | None = None):
    url = url or default_database_url()
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(url, future=True, connect_args=connect_args)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return engine


def get_session_factory(url: str | None = None):
    return sessionmaker(bind=get_engine(url), autoflush=False, autocommit=False, future=True)


def init_db(url: str | None = None):
    """Apply Alembic migrations (or create_all fallback). Safe on every startup."""
    from storage import models  # noqa: F401 — register mappers

    engine = get_engine(url)
    try:
        from alembic import command
        from alembic.config import Config

        ini = os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini")
        if os.path.exists(ini):
            cfg = Config(ini)
            cfg.set_main_option("sqlalchemy.url", str(engine.url))
            command.upgrade(cfg, "head")
            logger.info("SQLite storage ready via Alembic (%s)", engine.url)
            return engine
    except Exception as e:
        logger.warning("Alembic upgrade failed (%s); falling back to create_all", e)

    Base.metadata.create_all(engine)
    logger.info("SQLite storage ready via create_all (%s)", engine.url)
    return engine
