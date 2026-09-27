from __future__ import annotations

import asyncio
import logging
import random
import sqlite3
import uuid
from datetime import date, datetime, time, timezone, timedelta
from typing import Callable, Any
from zoneinfo import ZoneInfo

from .db import connect
from .planning import prepare_week
from .sender import DispatchPaused, KnownPreSendFailure, Sender
from .egress import host_addresses, allowed_address


logger = logging.getLogger(__name__)


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
        planner = self.planner
        if planner is not None:
            planner.cancel()
            await asyncio.gather(planner, return_exceptions=True)
        workers = list(self.tasks.values())
        if workers:
            _done, pending = await asyncio.wait(workers, timeout=30)
            for task in pending:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
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
                if setting.get("global_stop") == "1":
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
                    "AND a.status='active' AND a.auth_state='authenticated' AND g.active=1 AND g.chat_id IS NOT NULL ORDER BY a.id",
                    (group_id, today.isoformat()),
                ).fetchall()
                for slot in slots:
                    if self._stopping.is_set():
                        return
                    if not self._claim_lease(group_id):
                        break
                    current = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('global_stop','timezone')").fetchall())
                    if current.get("global_stop") == "1":
                        break
                    provider = _RetriedConnectionProvider(
                        self.provider_factory,
                        slot,
                        lambda connected=None: DispatchPaused("app_stopping") if self._stopping.is_set() else _dispatch_block(
                            db, slot, expected_ip_id=getattr(connected, "ip_id", None),
                            expected_address=getattr(connected, "address", None),
                        ),
                    )
                    await Sender(db, provider, sleep=self.sleep).send_slot(slot["slot_id"], chat_id=int(slot["chat_id"]))
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


def _dispatch_block(
    db: sqlite3.Connection,
    slot: sqlite3.Row,
    *,
    expected_ip_id: int | None = None,
    expected_address: str | None = None,
) -> DispatchPaused | None:
    settings = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('global_stop','timezone','send_windows_weekday','send_windows_weekend')").fetchall())
    if settings.get("global_stop") == "1":
        return DispatchPaused("run_stopped")
    group = db.execute("SELECT active,chat_id FROM groups WHERE id=?", (slot["group_id"],)).fetchone()
    account = db.execute(
        "SELECT a.status,a.auth_state,ia.ip_id,p.address,p.enabled,p.available FROM accounts a LEFT JOIN ip_assignments ia ON ia.account_id=a.id "
        "LEFT JOIN server_ips p ON p.id=ia.ip_id WHERE a.id=?",
        (slot["account_id"],),
    ).fetchone()
    current_slot = db.execute("SELECT status,scheduled_date FROM weekly_slots WHERE slot_id=?", (slot["slot_id"],)).fetchone()
    if group is None or not group["active"] or str(group["chat_id"] or "") != str(slot["chat_id"]):
        return DispatchPaused("group_destination_changed")
    if account is None or account["status"] != "active":
        return DispatchPaused("account_not_active", blocked=True)
    if account["auth_state"] != "authenticated":
        return DispatchPaused("account_reauthentication_required", blocked=True)
    if account["enabled"] != 1 or account["available"] != 1 or not account["address"] or not allowed_address(account["address"]) or account["address"] not in host_addresses():
        return DispatchPaused("ip_assignment_unavailable", blocked=True)
    if expected_ip_id is not None and int(account["ip_id"] or 0) != int(expected_ip_id):
        return DispatchPaused("ip_assignment_changed")
    if expected_address is not None and account["address"] != expected_address:
        return DispatchPaused("ip_assignment_changed")
    if current_slot is None or current_slot["status"] != "in_flight":
        return DispatchPaused("slot_no_longer_queued")
    now = datetime.now(ZoneInfo(settings.get("timezone", "Europe/Moscow")))
    if current_slot["scheduled_date"] != now.date().isoformat() or not _inside_window(now, settings):
        return DispatchPaused("outside_send_window")
    return None


class _RetriedConnectionProvider:
    """Connect a fresh PyMax adapter for each proven pre-send retry."""

    def __init__(self, factory, slot, dispatch_check):
        self.factory = factory
        self.slot = slot
        self.dispatch_check = dispatch_check

    async def send_message(self, *, chat_id: int, text: str):
        blocked = self.dispatch_check()
        if blocked is not None:
            raise blocked
        try:
            provider = await self.factory(self.slot)
        except asyncio.CancelledError:
            raise
        except DispatchPaused:
            raise
        except Exception as exc:
            logger.warning(
                "scheduled_connect_failed group_id=%s account_id=%s error_class=%s",
                self.slot["group_id"], self.slot["account_id"], type(exc).__name__,
            )
            raise KnownPreSendFailure("connect_failed") from exc
        blocked = self.dispatch_check(provider)
        if blocked is not None:
            try:
                await self._close(provider)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("scheduled_session_close_failed account_id=%s error_class=%s", self.slot["account_id"], type(exc).__name__)
                raise DispatchPaused("session_save_failed", blocked=True) from exc
            raise blocked
        try:
            result = await provider.send_message(chat_id=chat_id, text=text)
        except BaseException:
            try:
                await self._close(provider)
            except BaseException as close_error:
                logger.error("scheduled_session_close_failed account_id=%s error_class=%s", self.slot["account_id"], type(close_error).__name__)
            raise
        await self._close(provider)
        return result

    async def _close(self, provider):
        close = getattr(provider, "close", None)
        if close is None:
            return
        try:
            await close()
        except BaseException as exc:
            logger.error("scheduled_session_close_failed account_id=%s error_class=%s", self.slot["account_id"], type(exc).__name__)
            raise
