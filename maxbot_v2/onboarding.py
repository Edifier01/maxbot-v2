from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Awaitable, Callable

from .max_adapter import PyMaxAdapter
from .scheduling import assign_proxy


logger = logging.getLogger(__name__)


def normalize_russian_phone(value: str) -> str:
    raw = value.strip()
    if not re.fullmatch(r"\+?[0-9\s().-]+", raw):
        raise ValueError("invalid_russian_phone")
    digits = re.sub(r"[\s().-]", "", raw)
    if digits.startswith("+"):
        if not digits.startswith("+7"):
            raise ValueError("invalid_russian_phone")
        digits = digits[1:]
    if len(digits) == 11 and digits[0] in "78":
        digits = digits[1:]
    if len(digits) != 10 or not digits.isascii():
        raise ValueError("invalid_russian_phone")
    return "+7" + digits


class WebCodeAuthFlow:
    """PyMax AuthFlow bridge to short-lived web OTP / 2FA queues."""
    def __init__(self, update: Callable[[str, str], None], *, request_code: Callable[[str], Awaitable[Any]], validate_proxy: Callable[[], None], account_id: int | None = None, proxy_id: int | None = None, session_id: str | None = None):
        self.update = update
        self.request_code = request_code
        self.validate_proxy = validate_proxy
        self.account_id = account_id
        self.proxy_id = proxy_id
        self.session_id = session_id
        self.waiting_for: str | None = None
        self.current_stage: str | None = None
        self.request_count_left: int | None = None
        self.code_length: int | None = None
        self.codes: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.passwords: asyncio.Queue[str] = asyncio.Queue(maxsize=1)

    def _stage(self, stage: str, started: float, error: Exception | None = None) -> None:
        self.current_stage = stage
        fields = (self.session_id, self.account_id, self.proxy_id, stage, int((perf_counter() - started) * 1000))
        if error is None:
            logger.info("onboarding_stage session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d", *fields)
        else:
            logger.warning("onboarding_failed session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d error_class=%s", *fields, type(error).__name__)

    async def authenticate(self, app: Any):
        from pymax.auth.models import AuthResult
        self.current_stage = "request_code"
        self.update("requesting_code", "")
        stage = "request_code"
        started = perf_counter()
        try:
            self.validate_proxy()
            start = await self.request_code(str(app.config.phone))
        except Exception as exc:
            self._stage(stage, started, exc)
            raise
        self._stage(stage, started)
        self.code_length = getattr(start, "code_length", None)
        self.request_count_left = getattr(start, "request_count_left", None)
        logger.info(
            "onboarding_code_request session_id=%s account_id=%s proxy_id=%s route=direct auth_token_present=%s code_length=%s request_count_left=%s request_timeout=%s",
            self.session_id, self.account_id, self.proxy_id, bool(getattr(start, "token", None)),
            self.code_length, self.request_count_left, getattr(start, "request_max_duration", None),
        )
        self.waiting_for = "code"
        self.current_stage = "wait_code_input"
        self.update("waiting_code", "MAX принял запрос. Это ещё не подтверждает доставку SMS; проверьте приложение MAX и номер.")
        started = perf_counter()
        try:
            code = await asyncio.wait_for(self.codes.get(), timeout=300)
        except asyncio.TimeoutError:
            self._stage("wait_code_input", started, TimeoutError())
            raise
        self.waiting_for = None
        self.update("verifying_code", "")
        stage = "send_code"
        self.current_stage = stage
        started = perf_counter()
        try:
            self.validate_proxy()
            result = await app.api.auth.send_code(start.token, code)
        except Exception as exc:
            self._stage(stage, started, exc)
            raise
        self._stage(stage, started)
        login_token = result.login_token
        if result.password_challenge is not None:
            track_id = result.password_challenge.track_id
            for _ in range(5):
                self.waiting_for = "password"
                self.current_stage = "wait_password_input"
                self.update("waiting_password", "Введите облачный пароль MAX.")
                started = perf_counter()
                try:
                    password = await asyncio.wait_for(self.passwords.get(), timeout=300)
                except asyncio.TimeoutError:
                    self._stage("wait_password_input", started, TimeoutError())
                    raise
                self.waiting_for = None
                stage = "check_password"
                self.current_stage = stage
                started = perf_counter()
                try:
                    self.validate_proxy()
                    answer = await app.api.auth.check_password(track_id, password)
                except Exception as exc:
                    self._stage(stage, started, exc)
                    raise
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
        self.validate_proxy()
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


async def join_group_and_confirm_membership(
    adapter: Any,
    invite_link: str,
    chat_id: str,
    *,
    before_action: Callable[[], None] | None = None,
) -> tuple[bool, str | None]:
    def check() -> None:
        if before_action is not None:
            before_action()

    check()
    try:
        existing = await adapter.get_chat(int(chat_id))
    except Exception as exc:
        if type(exc).__name__ != "PyMaxError":
            raise
    else:
        if member_proof(existing, chat_id):
            return True, None

    check()
    join_error = None
    try:
        joined = await adapter.join_group(invite_link)
        returned_id = str(getattr(joined, "id", "") or getattr(joined, "chat_id", ""))
        if returned_id and returned_id != str(chat_id):
            raise ValueError("group_destination_mismatch")
    except ValueError as exc:
        if str(exc) == "group_destination_mismatch":
            raise
        join_error = "auto_join_failed"
    except Exception:
        join_error = "auto_join_failed"

    check()
    try:
        actual = await adapter.get_chat(int(chat_id))
    except Exception:
        return False, "membership_check_unavailable"
    if member_proof(actual, chat_id):
        return True, None
    return False, join_error or "membership_not_confirmed"


def prepare_account(connection: sqlite3.Connection, *, group_id: int, phone: str, full_name: str) -> tuple[int, int]:
    cursor = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'pending')", (group_id, phone, full_name))
    account_id = int(cursor.lastrowid)
    proxy_id = assign_proxy(connection, account_id, group_id)
    return account_id, proxy_id


def attach_group_on_first_account(connection: sqlite3.Connection, group_id: int, resolved_chat_id: str) -> None:
    owns_transaction = not connection.in_transaction
    if owns_transaction:
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
        if owns_transaction:
            connection.commit()
    except BaseException:
        if owns_transaction:
            connection.rollback()
        raise
