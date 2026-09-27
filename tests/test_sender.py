import asyncio
import sqlite3
from datetime import date, datetime, timezone

import pytest

from maxbot_v2.db import initialize
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.planning import prepare_week
from maxbot_v2.scheduling import create_weekly_slot
from maxbot_v2.sender import Ack, KnownPreSendFailure, Sender, recover_in_flight
from maxbot_v2.workers import _RetriedConnectionProvider, _dispatch_block


def seeded_db():
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    initialize(db)
    db.execute("INSERT INTO groups(name,invite_link,chat_id) VALUES('group','https://max.ru/invite','10')")
    db.execute("INSERT INTO accounts(group_id,phone,full_name,status,auth_state) VALUES(1,'+70000000001','Name','active','authenticated')")
    replace_message_pool(db, ["one", "two"])
    return db


def test_prepare_week_freezes_slot_and_does_not_replace_text(tmp_path):
    db = seeded_db()
    created = prepare_week(db, date(2026, 9, 21))
    first = db.execute("SELECT * FROM weekly_slots").fetchone()
    assert created == 1
    assert first["scheduled_date"] == "2026-09-21"
    prepare_week(db, date(2026, 9, 21))
    assert db.execute("SELECT COUNT(*) FROM weekly_slots").fetchone()[0] == 1
    assert db.execute("SELECT text FROM weekly_slots").fetchone()[0] == first["text"]


def test_missed_assigned_day_is_never_caught_up():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 23))
    assert db.execute("SELECT status FROM weekly_slots").fetchone()[0] == "missed"


def test_unknown_send_result_is_not_retried():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))

    class UnknownProvider:
        calls = 0
        async def send_message(self, **kwargs):
            self.calls += 1
            raise TimeoutError("proxy secret and provider detail")

    provider = UnknownProvider()
    sender = Sender(db, provider, sleep=lambda _: asyncio.sleep(0))
    assert asyncio.run(sender.send_slot("slot-2026-09-21-1", chat_id=10)) == "unknown"
    assert asyncio.run(sender.send_slot("slot-2026-09-21-1", chat_id=10)) == "unknown"
    assert provider.calls == 1
    assert db.execute("SELECT status,error_code FROM operations").fetchone()["status"] == "unknown"
    assert "secret" not in db.execute("SELECT error_code FROM operations").fetchone()[0]


def test_only_provider_ack_counts_as_accepted():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))

    class AcceptedProvider:
        async def send_message(self, **kwargs):
            return Ack("max-message-123")

    sender = Sender(db, AcceptedProvider())
    assert asyncio.run(sender.send_slot("slot-2026-09-21-1", chat_id=10)) == "accepted"
    assert db.execute("SELECT provider_message_id FROM send_log").fetchone()[0] == "max-message-123"
    assert asyncio.run(sender.send_slot("slot-2026-09-21-1", chat_id=10)) == "accepted"
    assert db.execute("SELECT COUNT(*) FROM send_log").fetchone()[0] == 1


def test_process_interruption_marks_in_flight_unknown():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))
    db.execute("UPDATE weekly_slots SET status='in_flight'")
    db.execute("INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) VALUES('op','slot-2026-09-21-1',1,1,'in_flight','2026-09-21')")
    assert recover_in_flight(db) == 1
    assert db.execute("SELECT status FROM weekly_slots").fetchone()[0] == "unknown"


def test_concurrent_group_workers_cannot_send_same_queued_slot_twice():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))
    entered = asyncio.Event()
    release = asyncio.Event()

    class SlowProvider:
        calls = 0
        async def send_message(self, **kwargs):
            self.calls += 1
            entered.set()
            await release.wait()
            return Ack("once")

    provider = SlowProvider()
    sender = Sender(db, provider)

    async def scenario():
        first = asyncio.create_task(sender.send_slot("slot-2026-09-21-1", chat_id=10))
        await entered.wait()
        second = await sender.send_slot("slot-2026-09-21-1", chat_id=10)
        release.set()
        return second, await first

    second, first = asyncio.run(scenario())
    assert second == "in_flight"
    assert first == "accepted"
    assert provider.calls == 1


def test_cancelling_a_send_marks_the_slot_unknown_before_propagating():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))
    entered = asyncio.Event()

    class SlowProvider:
        async def send_message(self, **kwargs):
            entered.set()
            await asyncio.Event().wait()

    async def scenario():
        task = asyncio.create_task(Sender(db, SlowProvider()).send_slot("slot-2026-09-21-1", chat_id=10))
        await entered.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())
    assert db.execute("SELECT status FROM weekly_slots").fetchone()[0] == "unknown"
    assert db.execute("SELECT status FROM operations").fetchone()[0] == "unknown"


def test_connect_retry_creates_a_new_provider_for_each_proven_refusal():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))
    slot = db.execute("SELECT s.*,g.chat_id FROM weekly_slots s JOIN groups g ON g.id=s.group_id").fetchone()
    connections = []

    async def provider_factory(_slot):
        connections.append(len(connections) + 1)
        raise OSError("network refused")

    provider = _RetriedConnectionProvider(provider_factory, slot, lambda *_args: None)
    result = asyncio.run(Sender(db, provider, delays=(0, 0), sleep=lambda _delay: asyncio.sleep(0)).send_slot(slot["slot_id"], chat_id=10))
    assert result == "failed"
    assert len(connections) == 3
    assert db.execute("SELECT error_code FROM operations").fetchone()[0] == "connect_failed"


def test_session_close_failure_after_send_is_marked_unknown(caplog):
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))
    slot = db.execute("SELECT s.*,g.chat_id FROM weekly_slots s JOIN groups g ON g.id=s.group_id").fetchone()

    class Provider:
        async def send_message(self, **_kwargs):
            return Ack("accepted-before-close")

        async def close(self):
            raise OSError("private proxy detail")

    async def provider_factory(_slot):
        return Provider()

    result = asyncio.run(Sender(db, _RetriedConnectionProvider(provider_factory, slot, lambda *_args: None)).send_slot(slot["slot_id"], chat_id=10))

    assert result == "unknown"
    assert db.execute("SELECT status,error_code FROM operations").fetchone()["status"] == "unknown"
    assert "private proxy detail" not in caplog.text
    assert "error_class=OSError" in caplog.text


def test_manual_run_check_does_not_depend_on_autostart_setting(monkeypatch):
    db = seeded_db()
    monkeypatch.setattr("maxbot_v2.workers.host_addresses", lambda: {"62.109.20.186"})
    db.execute("INSERT INTO server_ips(id,address,enabled,available) VALUES(1,'62.109.20.186',1,1)")
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(1,1)")
    db.execute("UPDATE settings SET value='UTC' WHERE key='timezone'")
    db.execute("UPDATE settings SET value='00:00-23:59' WHERE key IN ('send_windows_weekday','send_windows_weekend')")
    db.execute("UPDATE settings SET value='0' WHERE key IN ('auto_run','global_stop')")
    scheduled = datetime.now(timezone.utc).date().isoformat()
    version = db.execute("SELECT id FROM message_versions ORDER BY id DESC LIMIT 1").fetchone()[0]
    create_weekly_slot(db, account_id=1, week_start=scheduled, scheduled_date=scheduled, text="hello", message_version_id=version)
    # Dispatch checks run after the sender has atomically claimed a queued slot.
    db.execute("UPDATE weekly_slots SET status='in_flight'")
    slot = db.execute("SELECT s.*,g.chat_id FROM weekly_slots s JOIN groups g ON g.id=s.group_id").fetchone()

    assert _dispatch_block(db, slot) is None
    db.execute("UPDATE accounts SET auth_state='reauth_required' WHERE id=1")
    reauth = _dispatch_block(db, slot)
    assert reauth.code == "account_reauthentication_required"
    assert reauth.blocked is True
    db.execute("UPDATE accounts SET auth_state='authenticated' WHERE id=1")
    changed = _dispatch_block(db, slot, expected_ip_id=999)
    assert changed.code == "ip_assignment_changed"
    assert changed.blocked is False
    db.execute("UPDATE server_ips SET enabled=0 WHERE id=1")
    rotated = _dispatch_block(db, slot, expected_ip_id=1, expected_address="62.109.20.186")
    assert rotated.code == "ip_assignment_unavailable"
    db.execute("UPDATE settings SET value='1' WHERE key='global_stop'")
    assert _dispatch_block(db, slot).code == "run_stopped"
