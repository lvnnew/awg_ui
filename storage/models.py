"""SQLAlchemy models for panel storage."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from storage.db import Base


class SchemaMeta(Base):
    __tablename__ = "schema_meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_ts", "ts"),
        Index("ix_audit_log_actor", "actor"),
        Index("ix_audit_log_action", "action"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.now)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    target_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        Index("ix_users_telegram_id", "telegram_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    telegram_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False, default="")
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class InviteCode(Base):
    __tablename__ = "invite_codes"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_api_tokens_hash"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, default="")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class Server(Base):
    __tablename__ = "servers"
    __table_args__ = (UniqueConstraint("legacy_index", name="uq_servers_legacy_index"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    legacy_index: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    host: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class UserConnection(Base):
    __tablename__ = "user_connections"
    __table_args__ = (
        Index("ix_user_connections_user_id", "user_id"),
        Index("ix_user_connections_server_id", "server_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    server_id: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    protocol: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    client_id: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
