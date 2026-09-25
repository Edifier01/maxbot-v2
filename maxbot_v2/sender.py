from __future__ import annotations

import asyncio
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


class Provider(Protocol):
    async def send_message(self, *, chat_id: int, text: str): ...


@dataclass(frozen=True)
class Ack:
    message_id: str


class KnownPreSendFailure(Exception):
    """The adapter can prove that MAX did not receive the message."""


class Sender:
    def __init__(self, connection: sqlite3.Connection, provider: Provider, *, delays=(5, 15), sleep=asyncio.sleep):
        self.db = connection
        self.provider = provider
        self.delays = delays
        self.sleep = sleep

    async def send_slot(self, slot_id: str, *, chat_id: int, now: datetime | None = None) -> str:
        stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        self.db.execute("BEGIN IMMEDIATE")
        slot = self.db.execute("SELECT * FROM weekly_slots WHERE slot_id=?", (slot_id,)).fetchone()
        if slot is None:
            self.db.rollback()
            raise ValueError("slot_not_found")
        if slot["status"] != "queued":
            self.db.rollback()
            return str(slot["status"])
        group = self.db.execute("SELECT chat_id,active FROM groups WHERE id=?", (slot["group_id"],)).fetchone()
        account = self.db.execute("SELECT status FROM accounts WHERE id=?", (slot["account_id"],)).fetchone()
        if group is None or not int(group["active"]):
            self.db.rollback()
            return "blocked"
        if not account or account["status"] != "active":
            self.db.execute("UPDATE weekly_slots SET status='blocked',error_code='account_not_active',updated_at=? WHERE slot_id=?", (stamp, slot_id))
            self.db.commit()
            return "blocked"
        if not group["chat_id"] or str(group["chat_id"]) != str(chat_id):
            self.db.execute("UPDATE weekly_slots SET status='blocked',error_code='destination_unverified',updated_at=? WHERE slot_id=?", (stamp, slot_id))
            self.db.commit()
            return "blocked"
        if self.db.execute("SELECT 1 FROM send_log WHERE account_id=? AND slot_id<>? AND sent_at>=?", (slot["account_id"], slot_id, slot["week_start"])).fetchone():
            self.db.execute("UPDATE weekly_slots SET status='blocked',error_code='weekly_limit_reached',updated_at=? WHERE slot_id=?", (stamp, slot_id))
            self.db.commit()
            return "blocked"
        operation_id = f"op-{uuid.uuid4().hex}"
        self.db.execute(
            "INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) VALUES(?,?,?,?,?,?)",
            (operation_id, slot_id, slot["account_id"], slot["group_id"], "in_flight", stamp),
        )
        self.db.execute("UPDATE weekly_slots SET status='in_flight',updated_at=? WHERE slot_id=?", (stamp, slot_id))
        self.db.commit()

        for attempt in range(3):
            try:
                result = await self.provider.send_message(chat_id=chat_id, text=slot["text"])
                message_id = str(getattr(result, "message_id", "") or getattr(result, "id", "") or "").strip()
                if not message_id:
                    raise RuntimeError("provider_ack_missing")
                accepted_at = datetime.now(timezone.utc).isoformat()
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute(
                    "UPDATE operations SET status='accepted',finished_at=?,provider_message_id=? WHERE operation_id=?",
                    (accepted_at, message_id, operation_id),
                )
                self.db.execute("UPDATE weekly_slots SET status='accepted',error_code=NULL,updated_at=? WHERE slot_id=?", (accepted_at, slot_id))
                self.db.execute(
                    "INSERT INTO send_log(account_id,group_id,slot_id,sent_at,provider_message_id,text) VALUES(?,?,?,?,?,?)",
                    (slot["account_id"], slot["group_id"], slot_id, accepted_at, message_id, slot["text"]),
                )
                self.db.commit()
                return "accepted"
            except KnownPreSendFailure as exc:
                code = _safe_code(exc)
                if attempt < 2:
                    self.db.execute("UPDATE weekly_slots SET retry_count=?,error_code=?,updated_at=? WHERE slot_id=?", (attempt + 1, code, stamp, slot_id))
                    await self.sleep(self.delays[attempt])
                    continue
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("UPDATE operations SET status='rejected',finished_at=?,error_code=? WHERE operation_id=?", (datetime.now(timezone.utc).isoformat(), code, operation_id))
                self.db.execute("UPDATE weekly_slots SET status='failed',retry_count=3,error_code=?,updated_at=? WHERE slot_id=?", (code, stamp, slot_id))
                self.db.commit()
                return "failed"
            except Exception as exc:
                # Once the request may have reached MAX, never repeat it automatically.
                code = _safe_code(exc)
                finished = datetime.now(timezone.utc).isoformat()
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("UPDATE operations SET status='unknown',finished_at=?,error_code=? WHERE operation_id=?", (finished, code, operation_id))
                self.db.execute("UPDATE weekly_slots SET status='unknown',error_code=?,updated_at=? WHERE slot_id=?", (code, finished, slot_id))
                self.db.commit()
                return "unknown"
        return "failed"


def recover_in_flight(connection: sqlite3.Connection) -> int:
    stamp = datetime.now(timezone.utc).isoformat()
    connection.execute("BEGIN IMMEDIATE")
    connection.execute("UPDATE operations SET status='unknown',finished_at=?,error_code='process_interrupted' WHERE status='in_flight'", (stamp,))
    cursor = connection.execute("UPDATE weekly_slots SET status='unknown',error_code='process_interrupted',updated_at=? WHERE status='in_flight'", (stamp,))
    connection.commit()
    return cursor.rowcount


def _safe_code(error: BaseException) -> str:
    # Provider exception text can contain phones, proxy credentials, or tokens.
    name = type(error).__name__.lower()
    return name[:64] if name.isidentifier() else "provider_error"
