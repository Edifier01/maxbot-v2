from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from .action_gate import ActionGate
from .max_adapter import PyMaxAdapter
from .scheduling import assign_proxy


class WebCodeAuthFlow:
    """PyMax AuthFlow bridge to short-lived web OTP / 2FA queues."""
    def __init__(self, gate: ActionGate, update: Callable[[str, str], None]):
        self.gate = gate
        self.update = update
        self.codes: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.passwords: asyncio.Queue[str] = asyncio.Queue(maxsize=1)

    async def authenticate(self, app: Any):
        from pymax.auth.models import AuthResult
        self.gate.require("request_otp")
        self.update("requesting_code", "")
        start = await app.api.auth.request_code(str(app.config.phone))
        self.update("waiting_code", "")
        code = await asyncio.wait_for(self.codes.get(), timeout=300)
        self.gate.require("verify_auth")
        self.update("verifying_code", "")
        result = await app.api.auth.send_code(start.token, code)
        login_token = result.login_token
        if result.password_challenge is not None:
            track_id = result.password_challenge.track_id
            for _ in range(5):
                self.update("waiting_password", str(result.password_challenge.hint or ""))
                password = await asyncio.wait_for(self.passwords.get(), timeout=300)
                self.gate.require("verify_auth")
                try:
                    answer = await app.api.auth.check_password(track_id, password)
                except Exception:
                    answer = None
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
