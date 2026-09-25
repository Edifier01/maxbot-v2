import asyncio
import sqlite3
from datetime import date, datetime, timezone

import pytest

from maxbot_v2.db import initialize
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.planning import prepare_week
from maxbot_v2.sender import Ack, KnownPreSendFailure, Sender, recover_in_flight


def seeded_db():
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    initialize(db)
    db.execute("INSERT INTO groups(name,invite_link,chat_id) VALUES('group','https://max.ru/invite','10')")
    db.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(1,'+70000000001','Name','active')")
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
