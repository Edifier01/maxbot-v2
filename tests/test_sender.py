import asyncio
import sqlite3
from datetime import date, datetime, timedelta, timezone

import pytest

from maxbot_v2.db import connect, initialize
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.planning import prepare_week
from maxbot_v2.scheduling import create_weekly_slot, monday_of
from maxbot_v2.sender import Ack, KnownPreSendFailure, Sender, recover_in_flight
from maxbot_v2.workers import _RetriedConnectionProvider, _dispatch_block


def seeded_db():
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    initialize(db)
    db.execute("INSERT INTO groups(name,invite_link,chat_id) VALUES('group','https://max.ru/invite','10')")
    db.execute("INSERT INTO accounts(group_id,phone,full_name,status,auth_state,send_day_pair) VALUES(1,'+70000000001','Name','active','authenticated',0)")
    replace_message_pool(db, ["one", "two"])
    return db


def seed_slot(db, *, account_id=1, day="2026-09-21", position=1):
    return create_weekly_slot(
        db, account_id=account_id, week_start=monday_of(date.fromisoformat(day)).isoformat(),
        scheduled_date=day, text="fixture", message_version_id=1, day_position=position,
    )


def test_prepare_week_freezes_slot_and_does_not_replace_text(tmp_path):
    db = seeded_db()
    created = prepare_week(db, date(2026, 9, 21))
    first = db.execute("SELECT * FROM weekly_slots").fetchone()
    assert created == 10
    assert first["scheduled_date"] == "2026-09-21"
    prepare_week(db, date(2026, 9, 21))
    assert db.execute("SELECT COUNT(*) FROM weekly_slots").fetchone()[0] == 10
    assert db.execute("SELECT text FROM weekly_slots").fetchone()[0] == first["text"]


def test_prepare_week_keeps_version_and_text_together_when_pool_changes(tmp_path):
    path = tmp_path / "planner.db"
    writer = sqlite3.connect(path, isolation_level=None)
    writer.row_factory = sqlite3.Row
    seed = seeded_db()
    seed.backup(writer)
    seed.close()
    new_version = None

    class PlannerConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            nonlocal new_version
            if sql == "BEGIN IMMEDIATE" and new_version is None:
                new_version = replace_message_pool(writer, ["updated text"])
            return super().execute(sql, parameters)

    planner = sqlite3.connect(path, isolation_level=None, factory=PlannerConnection)
    planner.row_factory = sqlite3.Row
    try:
        assert prepare_week(planner, date(2026, 9, 21)) == 10
        slot = planner.execute("SELECT message_version_id,text FROM weekly_slots").fetchone()
        assert new_version is not None
        assert tuple(slot) == (new_version, "updated text")
    finally:
        planner.close()
        writer.close()


def test_missed_assigned_day_is_never_caught_up():
    db = seeded_db()
    prepare_week(db, date(2026, 9, 23))
    assert [tuple(row) for row in db.execute(
        "SELECT scheduled_date,status,COUNT(*) FROM weekly_slots GROUP BY scheduled_date,status ORDER BY scheduled_date",
    )] == [("2026-09-21", "missed", 5), ("2026-09-24", "queued", 5)]


def test_unknown_send_result_is_not_retried():
    db = seeded_db()
    slot_id = seed_slot(db)["slot_id"]

    class UnknownProvider:
        calls = 0
        async def send_message(self, **kwargs):
            self.calls += 1
            raise TimeoutError("proxy secret and provider detail")

    provider = UnknownProvider()
    sender = Sender(db, provider, sleep=lambda _: asyncio.sleep(0))
    assert asyncio.run(sender.send_slot(slot_id, chat_id=10)) == "unknown"
    assert asyncio.run(sender.send_slot(slot_id, chat_id=10)) == "unknown"
    assert provider.calls == 1
    assert db.execute("SELECT status,error_code FROM operations").fetchone()["status"] == "unknown"
    assert "secret" not in db.execute("SELECT error_code FROM operations").fetchone()[0]


def test_only_provider_ack_counts_as_accepted():
    db = seeded_db()
    slot_id = seed_slot(db)["slot_id"]

    class AcceptedProvider:
        async def send_message(self, **kwargs):
            return Ack("max-message-123")

    sender = Sender(db, AcceptedProvider())
    assert asyncio.run(sender.send_slot(slot_id, chat_id=10)) == "accepted"
    assert db.execute("SELECT provider_message_id FROM send_log").fetchone()[0] == "max-message-123"
    assert asyncio.run(sender.send_slot(slot_id, chat_id=10)) == "accepted"
    assert db.execute("SELECT COUNT(*) FROM send_log").fetchone()[0] == 1


def test_process_interruption_marks_in_flight_unknown():
    db = seeded_db()
    slot_id = seed_slot(db)["slot_id"]
    db.execute("UPDATE weekly_slots SET status='in_flight'")
    db.execute("INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) VALUES('op',?,1,1,'in_flight','2026-09-21')", (slot_id,))
    assert recover_in_flight(db) == 1
    assert db.execute("SELECT status FROM weekly_slots").fetchone()[0] == "unknown"


def test_concurrent_group_workers_cannot_send_same_queued_slot_twice():
    db = seeded_db()
    slot_id = seed_slot(db)["slot_id"]
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
        first = asyncio.create_task(sender.send_slot(slot_id, chat_id=10))
        await entered.wait()
        second = await sender.send_slot(slot_id, chat_id=10)
        release.set()
        return second, await first

    second, first = asyncio.run(scenario())
    assert second == "in_flight"
    assert first == "accepted"
    assert provider.calls == 1


def add_group_slot(db, phone, chat_id, day="2026-09-21"):
    group_id = db.execute(
        "INSERT INTO groups(name,invite_link,chat_id) VALUES('other panel group','https://max.ru/invite',?)", (chat_id,),
    ).lastrowid
    account_id = db.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state,send_day_pair) VALUES(?,?,'Fixture','active','authenticated',?)",
        (group_id, phone, date.fromisoformat(day).weekday() % 3),
    ).lastrowid
    return seed_slot(db, account_id=account_id, day=day)


def test_shared_chat_serializes_due_slots_across_panel_groups(tmp_path):
    path = tmp_path / "queue.db"
    seed = seeded_db()
    first_db = connect(path)
    seed.backup(first_db)
    seed.close()
    first_slot = seed_slot(first_db)["slot_id"]
    after_other = seed_slot(first_db, position=2)["slot_id"]
    next_slot = add_group_slot(first_db, "+70000000002", "10")["slot_id"]
    separate_slot = add_group_slot(first_db, "+70000000003", "20")["slot_id"]
    second_db = connect(path)

    class SlowProvider:
        async def send_message(self, **_kwargs):
            entered.set()
            await release.wait()
            return Ack("first")

    class FastProvider:
        calls = 0

        async def send_message(self, **_kwargs):
            self.calls += 1
            return Ack("next")

    async def scenario():
        nonlocal entered, release
        entered, release = asyncio.Event(), asyncio.Event()
        fast = FastProvider()
        other = Sender(second_db, fast)
        assert await other.send_slot(next_slot, chat_id=10) == "chat_waiting"
        task = asyncio.create_task(Sender(first_db, SlowProvider()).send_slot(first_slot, chat_id=10))
        try:
            await entered.wait()
            assert await other.send_slot(next_slot, chat_id=10) == "chat_waiting"
            assert await other.send_slot(separate_slot, chat_id=20) == "accepted"
        finally:
            release.set()
            assert await task == "accepted"
        assert await other.send_slot(after_other, chat_id=10) == "chat_waiting"
        assert await other.send_slot(next_slot, chat_id=10) == "accepted"
        assert await other.send_slot(after_other, chat_id=10) == "accepted"
        assert fast.calls == 3

    entered = release = None
    try:
        asyncio.run(scenario())
        assert [row[0] for row in second_db.execute("SELECT destination_chat_id FROM operations ORDER BY id")] == ["10", "20", "10", "10"]
    finally:
        first_db.close()
        second_db.close()


def test_stale_worker_chat_does_not_block_a_slot_after_destination_verification():
    db = seeded_db()
    slot_id = seed_slot(db)["slot_id"]
    db.execute("UPDATE groups SET chat_id='20' WHERE id=1")

    class Provider:
        async def send_message(self, *, chat_id, **_kwargs):
            assert chat_id == 20
            return Ack("correct-destination")

    sender = Sender(db, Provider())
    assert asyncio.run(sender.send_slot(slot_id, chat_id=10)) == "destination_changed"
    assert db.execute("SELECT status FROM weekly_slots").fetchone()[0] == "queued"
    assert asyncio.run(sender.send_slot(slot_id, chat_id=20)) == "accepted"
    assert db.execute("SELECT destination_chat_id FROM operations").fetchone()[0] == "20"


def test_ack_write_failure_releases_chat_as_unknown_without_automatic_retry():
    db = seeded_db()
    slot_id = seed_slot(db)["slot_id"]
    db.execute("CREATE TEMP TRIGGER reject_ack BEFORE INSERT ON send_log BEGIN SELECT RAISE(ABORT,'fixture'); END")

    class Provider:
        calls = 0

        async def send_message(self, **_kwargs):
            self.calls += 1
            return Ack("confirmed")

    provider = Provider()
    sender = Sender(db, provider)
    assert asyncio.run(sender.send_slot(slot_id, chat_id=10)) == "unknown"
    assert asyncio.run(sender.send_slot(slot_id, chat_id=10)) == "unknown"
    assert provider.calls == 1
    assert db.execute("SELECT status FROM operations").fetchone()[0] == "unknown"
    assert db.execute("SELECT 1 FROM operations WHERE status='in_flight'").fetchone() is None


def test_cancelling_a_send_marks_the_slot_unknown_before_propagating():
    db = seeded_db()
    slot_id = seed_slot(db)["slot_id"]
    entered = asyncio.Event()

    class SlowProvider:
        async def send_message(self, **kwargs):
            entered.set()
            await asyncio.Event().wait()

    async def scenario():
        task = asyncio.create_task(Sender(db, SlowProvider()).send_slot(slot_id, chat_id=10))
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
    seed_slot(db)
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
    seed_slot(db)
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


def test_dispatch_rechecks_account_quota_after_connect(monkeypatch):
    db = seeded_db()
    clock = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)

    class FixedClock(datetime):
        @classmethod
        def now(cls, zone=None):
            return clock.astimezone(zone)

    monkeypatch.setattr("maxbot_v2.workers.datetime", FixedClock)
    monkeypatch.setattr("maxbot_v2.workers.host_addresses", lambda: {"62.109.20.186"})
    db.execute("INSERT INTO server_ips(id,address,enabled,available) VALUES(1,'62.109.20.186',1,1)")
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(1,1)")
    db.execute("UPDATE settings SET value='0' WHERE key='global_stop'")
    db.execute("UPDATE accounts SET phone_fingerprint='fixture-fingerprint' WHERE id=1")
    db.execute(
        "INSERT INTO accounts(id,group_id,phone,full_name,lifecycle,phone_fingerprint) "
        "VALUES(2,1,'deleted:2','','deleted','fixture-fingerprint')"
    )
    slot = seed_slot(db)
    slot = db.execute(
        "SELECT s.*,g.chat_id FROM weekly_slots s JOIN groups g ON g.id=s.group_id WHERE s.slot_id=?", (slot["slot_id"],),
    ).fetchone()
    prior = [seed_slot(db, account_id=2, position=position) for position in range(1, 6)]
    for previous in prior[:4]:
        db.execute(
            "INSERT INTO send_log(account_id,group_id,slot_id,sent_at,provider_message_id,text) VALUES(2,1,?,?,'prior','fixture')",
            (previous["slot_id"], clock.isoformat()),
        )

    class Provider:
        async def send_message(self, **kwargs):
            pytest.fail("The newly exhausted quota must be checked before sending")

        async def close(self):
            pass

    async def provider_factory(_slot):
        db.execute(
            "INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) "
            "VALUES('late-confirmation',?,2,1,'unknown',?)", (prior[-1]["slot_id"], clock.isoformat()),
        )
        return Provider()

    provider = _RetriedConnectionProvider(provider_factory, slot, lambda *_args: _dispatch_block(db, slot))
    assert asyncio.run(Sender(db, provider).send_slot(slot["slot_id"], chat_id=10, now=clock)) == "paused"
    assert tuple(db.execute("SELECT status,error_code FROM weekly_slots WHERE slot_id=?", (slot["slot_id"],)).fetchone()) == ("blocked", "daily_limit_reached")


def test_dispatch_rechecks_pair_sunday_and_manual_stop(monkeypatch):
    db = seeded_db()
    clock = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)

    class FixedClock(datetime):
        @classmethod
        def now(cls, zone=None):
            return clock.astimezone(zone)

    monkeypatch.setattr("maxbot_v2.workers.datetime", FixedClock)
    monkeypatch.setattr("maxbot_v2.workers.host_addresses", lambda: {"62.109.20.186"})
    db.execute("INSERT INTO server_ips(id,address,enabled,available) VALUES(1,'62.109.20.186',1,1)")
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(1,1)")
    db.execute("UPDATE settings SET value='0' WHERE key='global_stop'")
    seed_slot(db)
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
    assert _dispatch_block(db, slot, expected_ip_id=1, expected_address="62.109.20.186").code == "ip_assignment_unavailable"
    db.execute("UPDATE server_ips SET enabled=1 WHERE id=1")
    db.execute("UPDATE accounts SET send_day_pair=1 WHERE id=1")
    assert _dispatch_block(db, slot).code == "outside_send_day"
    db.execute("UPDATE accounts SET send_day_pair=0 WHERE id=1")
    clock += timedelta(days=6)
    db.execute("UPDATE weekly_slots SET scheduled_date='2026-09-27'")
    assert _dispatch_block(db, slot).code == "outside_send_day"
    db.execute("UPDATE settings SET value='1' WHERE key='global_stop'")
    assert _dispatch_block(db, slot).code == "run_stopped"
