from __future__ import annotations

import asyncio
import random
import sqlite3
import uuid
from datetime import date, datetime, time, timezone, timedelta
from typing import Callable, Any
from zoneinfo import ZoneInfo

from .db import connect
from .action_gate import ActionsClosed
from .planning import prepare_week
from .sender import KnownPreSendFailure, Sender


class GroupWorkerManager:
    """One asyncio worker task per active group, plus one central planner."""
    def __init__(self, db_path, provider_factory: Callable[[sqlite3.Row], Any], *, poll_seconds: float = 20, sleep=asyncio.sleep, rng=None):
        self.db_path = db_path
        self.provider_factory = provider_factory
        self.poll_seconds = poll_seconds
        self.sleep = sleep
        self.rng = rng or random.SystemRandom()
        self.tasks: dict[int, asyncio.Task] = {}
        self.worker_id = uuid.uuid4().hex
        self.planner: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        db = connect(self.db_path)
        try:
            self._prepare(db)
        finally:
            db.close()
        self._stopping.clear()
        self.planner = asyncio.create_task(self._plan_forever(), name="weekly-planner")
        await self._sync_group_workers()

    async def stop(self) -> None:
        self._stopping.set()
        tasks = list(self.tasks.values()) + ([self.planner] if self.planner else [])
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for group_id in list(self.tasks):
            self._release_lease(group_id)
        self.tasks.clear()
        self.planner = None

    async def _plan_forever(self) -> None:
        while not self._stopping.is_set():
            db = connect(self.db_path)
            try:
                self._prepare(db)
            finally:
                db.close()
            await self._sync_group_workers()
            await self.sleep(300)

    @staticmethod
    def _prepare(db: sqlite3.Connection) -> None:
        setting = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('timezone')").fetchall())
        tz = ZoneInfo(setting.get("timezone", "Europe/Moscow"))
        prepare_week(db, datetime.now(tz).date())

    async def _sync_group_workers(self) -> None:
        db = connect(self.db_path)
        try:
            active = {int(r[0]) for r in db.execute("SELECT id FROM groups WHERE active=1")}
        finally:
            db.close()
        for group_id in active - self.tasks.keys():
            self.tasks[group_id] = asyncio.create_task(self._group_forever(group_id), name=f"group-worker-{group_id}")
        for group_id in set(self.tasks) - active:
            self._release_lease(group_id)
            self.tasks.pop(group_id).cancel()
        for group_id, task in list(self.tasks.items()):
            if task.done():
                self._release_lease(group_id)
                del self.tasks[group_id]
                if group_id in active:
                    self.tasks[group_id] = asyncio.create_task(self._group_forever(group_id), name=f"group-worker-{group_id}")

    def _claim_lease(self, group_id: int) -> bool:
        now = datetime.now(timezone.utc)
        expiry = (now + timedelta(seconds=90)).isoformat()
        db = connect(self.db_path)
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT owner_id,expires_at FROM group_worker_leases WHERE group_id=?", (group_id,)).fetchone()
            if row is not None and row["owner_id"] != self.worker_id and row["expires_at"] > now.isoformat():
                db.rollback()
                return False
            db.execute("INSERT INTO group_worker_leases(group_id,owner_id,expires_at) VALUES(?,?,?) ON CONFLICT(group_id) DO UPDATE SET owner_id=excluded.owner_id,expires_at=excluded.expires_at", (group_id, self.worker_id, expiry))
            db.commit()
            return True
        finally:
            db.close()

    def _release_lease(self, group_id: int) -> None:
        db = connect(self.db_path)
        try:
            db.execute("DELETE FROM group_worker_leases WHERE group_id=? AND owner_id=?", (group_id, self.worker_id))
        finally:
            db.close()

    async def _group_forever(self, group_id: int) -> None:
        while not self._stopping.is_set():
            if not self._claim_lease(group_id):
                await self.sleep(self.poll_seconds)
                continue
            db = connect(self.db_path)
            try:
                setting = dict(db.execute("SELECT key,value FROM settings").fetchall())
                if setting.get("auto_run") != "1" or setting.get("global_stop") == "1":
                    await self.sleep(self.poll_seconds)
                    continue
                tz = ZoneInfo(setting.get("timezone", "Europe/Moscow"))
                now = datetime.now(tz)
                today = now.date()
                db.execute("UPDATE weekly_slots SET status='missed',updated_at=? WHERE group_id=? AND status='queued' AND scheduled_date<?", (datetime.now(timezone.utc).isoformat(), group_id, today.isoformat()))
                if not _inside_window(now, setting):
                    await self.sleep(self.poll_seconds)
                    continue
                slots = db.execute(
                    "SELECT s.*,a.phone,a.id AS account_id,g.chat_id FROM weekly_slots s JOIN accounts a ON a.id=s.account_id "
                    "JOIN groups g ON g.id=s.group_id WHERE s.group_id=? AND s.scheduled_date=? AND s.status='queued' "
                    "AND a.status='active' AND g.active=1 AND g.chat_id IS NOT NULL ORDER BY a.id",
                    (group_id, today.isoformat()),
                ).fetchall()
                for slot in slots:
                    if self._stopping.is_set():
                        return
                    if not self._claim_lease(group_id):
                        break
                    current = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('global_stop','auto_run')").fetchall())
                    if current.get("global_stop") == "1" or current.get("auto_run") != "1":
                        break
                    provider = None
                    try:
                        provider = await self.provider_factory(slot)
                        await Sender(db, provider, sleep=self.sleep).send_slot(slot["slot_id"], chat_id=int(slot["chat_id"]))
                    except ActionsClosed:
                        # Missing/expired authorization is a hard hold, not a send attempt.
                        break
                    except Exception:
                        class ConnectionFailure:
                            async def send_message(self, **kwargs):
                                raise KnownPreSendFailure("connect_failed")
                        await Sender(db, ConnectionFailure(), sleep=self.sleep).send_slot(slot["slot_id"], chat_id=int(slot["chat_id"]))
                    finally:
                        if provider is not None and hasattr(provider, "close"):
                            try:
                                await provider.close()
                            except Exception:
                                pass
                    delay_min = max(5, int(setting.get("delay_min_sec", 5)))
                    delay_max = max(delay_min, int(setting.get("delay_max_sec", 15)))
                    await self.sleep(self.rng.randint(delay_min, delay_max))
            finally:
                db.close()
            await self.sleep(self.poll_seconds)


def _inside_window(now: datetime, settings: dict[str, str]) -> bool:
    raw = settings["send_windows_weekday"] if now.weekday() < 5 else settings["send_windows_weekend"]
    current = now.time().replace(tzinfo=None)
    for interval in raw.split(","):
        try:
            start, end = (time.fromisoformat(part.strip()) for part in interval.split("-", maxsplit=1))
        except (ValueError, TypeError):
            return False
        if start <= current < end:
            return True
    return False
