from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
from typing import Any, Callable

from .egress import assign_ip


logger = logging.getLogger(__name__)


class WebAuthProviders:
    """Web queue providers consumed by PyMax's standard SmsAuthFlow."""

    def __init__(self, update: Callable[[str, str], None], *, session_id: str, account_id: int, ip_id: int):
        self.update = update
        self.session_id = session_id
        self.account_id = account_id
        self.ip_id = ip_id
        self.codes: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.passwords: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.waiting_for: str | None = None
        self.current_stage = "request_code"
        self.hint = ""
        self.password_prompt_count = 0

    async def get_code(self, _phone: str) -> str:
        self.current_stage = "wait_code_input"
        self.waiting_for = "code"
        logger.info("onboarding_stage session_id=%s account_id=%s ip_id=%s stage=wait_code_input", self.session_id, self.account_id, self.ip_id)
        self.hint = "MAX принял запрос. Это ещё не подтверждает доставку SMS; проверьте приложение MAX и номер."
        self.update("waiting_code", self.hint)
        try:
            code = await asyncio.wait_for(self.codes.get(), timeout=300)
        finally:
            self.waiting_for = None
        self.current_stage = "send_code"
        self.update("verifying_code", "")
        return code

    async def get_password(self, _hint=None) -> str:
        self.current_stage = "wait_password_input"
        self.waiting_for = "password"
        if self.password_prompt_count:
            self.hint = "MAX не принял предыдущий облачный пароль. Введите пароль ещё раз."
        else:
            self.hint = "Введите пароль для входа MAX."
        self.password_prompt_count += 1
        self.update("waiting_password", self.hint)
        try:
            password = await asyncio.wait_for(self.passwords.get(), timeout=300)
        finally:
            self.waiting_for = None
        self.current_stage = "check_password"
        self.update("verifying_password", "")
        return password


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
    address = assign_ip(connection, account_id)
    ip_id = connection.execute("SELECT id FROM server_ips WHERE address=?", (address,)).fetchone()["id"]
    return account_id, int(ip_id)


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
