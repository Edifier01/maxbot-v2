from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Callable

from .max_adapter import PyMaxAdapter
from .scheduling import assign_proxy


logger = logging.getLogger(__name__)


class WebCodeAuthFlow:
    """PyMax AuthFlow bridge to short-lived web OTP / 2FA queues."""
    def __init__(self, update: Callable[[str, str], None], *, account_id: int | None = None, proxy_id: int | None = None):
        self.update = update
        self.account_id = account_id
        self.proxy_id = proxy_id
        self.codes: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.passwords: asyncio.Queue[str] = asyncio.Queue(maxsize=1)

    def _stage(self, stage: str, started: float, error: Exception | None = None) -> None:
        fields = (self.account_id, self.proxy_id, stage, int((perf_counter() - started) * 1000))
        if error is None:
            logger.info("onboarding_stage account_id=%s proxy_id=%s stage=%s duration_ms=%d", *fields)
        else:
            logger.warning("onboarding_failed account_id=%s proxy_id=%s stage=%s duration_ms=%d error_class=%s", *fields, type(error).__name__)

    async def authenticate(self, app: Any):
        from pymax.auth.models import AuthResult
        self.update("requesting_code", "")
        stage = "request_code"
        started = perf_counter()
        try:
            start = await app.api.auth.request_code(str(app.config.phone))
        except Exception as exc:
            self._stage(stage, started, exc)
            raise
        self._stage(stage, started)
        self.update("waiting_code", "MAX принял запрос кода. Ожидайте сообщение с кодом.")
        code = await asyncio.wait_for(self.codes.get(), timeout=300)
        self.update("verifying_code", "")
        stage = "send_code"
        started = perf_counter()
        try:
            result = await app.api.auth.send_code(start.token, code)
        except Exception as exc:
            self._stage(stage, started, exc)
            raise
        self._stage(stage, started)
        login_token = result.login_token
        if result.password_challenge is not None:
            track_id = result.password_challenge.track_id
            for _ in range(5):
                self.update("waiting_password", str(result.password_challenge.hint or ""))
                password = await asyncio.wait_for(self.passwords.get(), timeout=300)
                stage = "check_password"
                started = perf_counter()
                try:
                    answer = await app.api.auth.check_password(track_id, password)
                except Exception:
                    answer = None
                self._stage(stage, started)
                if answer is not None and not answer.error and answer.login_token:
                    login_token = answer.login_token
                    break
                self.update("waiting_password", "Пароль MAX не подошёл. Попробуйте ещё раз.")
            if not login_token:
                raise RuntimeError("cloud_password_rejected")
        if result.register_token:
            raise RuntimeError("account_registration_required")
        if not login_token:
            raise RuntimeError("auth_token_missing")
        return AuthResult(token=login_token)


def member_proof(chat: Any, expected_chat_id: str) -> bool:
    try:
        actual_id = str(getattr(chat, "id", "") or getattr(chat, "chat_id", ""))
        status_value = getattr(chat, "status", "")
        status = str(getattr(status_value, "value", status_value)).casefold()
        joined = int(getattr(chat, "join_time", 0) or 0)
        return actual_id == str(expected_chat_id) and status in {"member", "active", "joined", "in"} and joined > 0
    except (TypeError, ValueError):
        return False


def prepare_account(connection: sqlite3.Connection, *, group_id: int, phone: str, full_name: str) -> tuple[int, int]:
    cursor = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'pending')", (group_id, phone, full_name))
    account_id = int(cursor.lastrowid)
    proxy_id = assign_proxy(connection, account_id, group_id)
    return account_id, proxy_id


def attach_group_on_first_account(connection: sqlite3.Connection, group_id: int, resolved_chat_id: str) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        row = connection.execute("SELECT chat_id FROM groups WHERE id=?", (group_id,)).fetchone()
        if row is None:
            raise ValueError("group_not_found")
        current = row["chat_id"]
        if current is None:
            connection.execute("UPDATE groups SET chat_id=? WHERE id=? AND chat_id IS NULL", (str(resolved_chat_id), group_id))
            current = connection.execute("SELECT chat_id FROM groups WHERE id=?", (group_id,)).fetchone()["chat_id"]
        if str(current) != str(resolved_chat_id):
            raise ValueError("group_destination_mismatch")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
