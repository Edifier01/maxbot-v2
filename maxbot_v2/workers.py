from __future__ import annotations

import asyncio
import logging
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from typing import Callable, Any

from .db import connect
from .planning import prepare_week
from .sender import DispatchPaused, KnownPreSendFailure, Sender
from .egress import host_addresses, allowed_address
from .send_proxies import resume_proxy_blocked_slots
from .chat_queue import chat_dispatch_wait
from .scheduling import SCHEDULE_TZ, SEND_DAY_PAIRS, dispatch_quota_reason


logger = logging.getLogger(__name__)


class GroupWorkerManager:
    """One asyncio worker task per active group, plus one central planner."""
    def __init__(self, db_path, provider_factory: Callable[[sqlite3.Row], Any], *, poll_seconds: float = 20, sleep=asyncio.sleep):
        self.db_path = db_path
        self.provider_factory = provider_factory
        self.poll_seconds = poll_seconds
        self.sleep = sleep
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
        prepare_week(db, datetime.now(SCHEDULE_TZ).date())

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
                if _sending_stopped(db):
                    await self.sleep(self.poll_seconds)
                    continue
                today = datetime.now(SCHEDULE_TZ).date()
                resume_proxy_blocked_slots(db, group_id, today)
                db.execute("UPDATE weekly_slots SET status='missed',updated_at=? WHERE group_id=? AND status='queued' AND scheduled_date<?", (datetime.now(timezone.utc).isoformat(), group_id, today.isoformat()))
                if today.weekday() == 6:
                    await self.sleep(self.poll_seconds)
                    continue
                slots = db.execute(
                    "SELECT s.*,a.phone,a.id AS account_id,g.chat_id FROM weekly_slots s JOIN accounts a ON a.id=s.account_id "
                    "JOIN groups g ON g.id=s.group_id WHERE s.group_id=? AND s.scheduled_date=? AND s.status='queued' "
                    "AND a.lifecycle='active' AND a.status='active' AND a.auth_state='authenticated' "
                    "AND a.send_day_pair=? AND g.active=1 AND g.chat_id IS NOT NULL ORDER BY s.id",
                    (group_id, today.isoformat(), today.weekday() % len(SEND_DAY_PAIRS)),
                ).fetchall()
                for slot in slots:
                    if self._stopping.is_set():
                        return
                    if not self._claim_lease(group_id):
                        break
                    if _sending_stopped(db):
                        break
                    provider = _RetriedConnectionProvider(
                        self.provider_factory,
                        slot,
                        lambda connected=None: DispatchPaused("app_stopping") if self._stopping.is_set() else _dispatch_block(
                            db, slot, expected_ip_id=getattr(connected, "ip_id", None),
                            expected_address=getattr(connected, "address", None),
                        ),
                    )
                    result = await Sender(db, provider, sleep=self.sleep).send_slot(slot["slot_id"], chat_id=int(slot["chat_id"]))
                    if result in {"chat_waiting", "destination_changed"}:
                        break
            finally:
                db.close()
            await self.sleep(self.poll_seconds)


def _sending_stopped(db: sqlite3.Connection) -> bool:
    setting = db.execute("SELECT value FROM settings WHERE key='global_stop'").fetchone()
    return setting is None or setting[0] != "0"


def _dispatch_block(
    db: sqlite3.Connection,
    slot: sqlite3.Row,
    *,
    expected_ip_id: int | None = None,
    expected_address: str | None = None,
    available_hosts: set[str] | None = None,
) -> DispatchPaused | None:
    if _sending_stopped(db):
        return DispatchPaused("run_stopped")
    group = db.execute("SELECT active,chat_id FROM groups WHERE id=?", (slot["group_id"],)).fetchone()
    account = db.execute(
        "SELECT a.status,a.auth_state,a.lifecycle,a.send_day_pair,a.phone_fingerprint,ia.ip_id,p.address,p.enabled,p.available "
        "FROM accounts a LEFT JOIN ip_assignments ia ON ia.account_id=a.id "
        "LEFT JOIN server_ips p ON p.id=ia.ip_id WHERE a.id=?",
        (slot["account_id"],),
    ).fetchone()
    current_slot = db.execute(
        "SELECT slot_id,account_id,status,week_start,scheduled_date FROM weekly_slots WHERE slot_id=?", (slot["slot_id"],),
    ).fetchone()
    if group is None or not group["active"] or str(group["chat_id"] or "") != str(slot["chat_id"]):
        return DispatchPaused("group_destination_changed")
    if account is None or account["status"] != "active" or account["lifecycle"] != "active":
        return DispatchPaused("account_not_active", blocked=True)
    if account["auth_state"] != "authenticated":
        return DispatchPaused("account_reauthentication_required", blocked=True)
    addresses = host_addresses() if available_hosts is None else available_hosts
    if (account["enabled"] != 1 or account["available"] != 1 or not account["address"]
            or not allowed_address(account["address"]) or account["address"] not in addresses):
        return DispatchPaused("ip_assignment_unavailable", blocked=True)
    if expected_ip_id is not None and int(account["ip_id"] or 0) != int(expected_ip_id):
        return DispatchPaused("ip_assignment_changed")
    if expected_address is not None and account["address"] != expected_address:
        return DispatchPaused("ip_assignment_changed")
    if current_slot is None or current_slot["status"] != "in_flight":
        return DispatchPaused("slot_no_longer_queued")
    now = datetime.now(SCHEDULE_TZ)
    pair = account["send_day_pair"]
    if (current_slot["scheduled_date"] != now.date().isoformat()
            or pair is None or now.weekday() not in SEND_DAY_PAIRS[pair]):
        return DispatchPaused("outside_send_day")
    quota_reason = dispatch_quota_reason(db, current_slot, account["phone_fingerprint"])
    if quota_reason is not None:
        return DispatchPaused(quota_reason, blocked=True)
    wait_reason = chat_dispatch_wait(db, str(slot["chat_id"]), now, current_slot_id=slot["slot_id"])
    if wait_reason is not None:
        return DispatchPaused(wait_reason)
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
