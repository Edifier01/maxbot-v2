import asyncio
import sqlite3
from datetime import date, datetime, timedelta, timezone

import pytest

from maxbot_v2.db import connect, initialize
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
        assert prepare_week(planner, date(2026, 9, 21)) == 1
        slot = planner.execute("SELECT message_version_id,text FROM weekly_slots").fetchone()
        assert new_version is not None
        assert tuple(slot) == (new_version, "updated text")
    finally:
        planner.close()
        writer.close()


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


@pytest.mark.parametrize(
    ("prior_week", "logged_at", "expected"),
    [
        ("2026-09-21", "2026-09-21T10:00:00+00:00", "blocked"),
        # Monday 00:30 in Europe/Moscow is still Sunday in UTC.
        ("2026-09-21", "2026-09-20T21:30:00+00:00", "blocked"),
        # An operator can confirm last week's delivery during the new week.
        ("2026-09-14", "2026-09-21T10:00:00+00:00", "accepted"),
    ],
)
def test_weekly_limit_follows_phone_fingerprint_after_account_recreation(prior_week, logged_at, expected):
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0,phone_fingerprint='stable-private-fingerprint' WHERE id=1")
    week = "2026-09-21"
    prior = create_weekly_slot(db, account_id=1, week_start=prior_week, scheduled_date=prior_week, text="prior", message_version_id=1)
    db.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state,ever_authenticated,phone_fingerprint) "
        "VALUES(1,'+70000000002','Name','active','authenticated',1,'stable-private-fingerprint')"
    )
    current = create_weekly_slot(db, account_id=2, week_start=week, scheduled_date=week, text="new", message_version_id=1)
    db.execute(
        "INSERT INTO send_log(account_id,group_id,slot_id,sent_at,provider_message_id,text) "
        "VALUES(1,1,?,?,'accepted','prior')", (prior["slot_id"], logged_at),
    )
    db.execute("UPDATE weekly_slots SET status='accepted' WHERE slot_id=?", (prior["slot_id"],))

    class Provider:
        calls = 0
        async def send_message(self, **_kwargs):
            self.calls += 1
            return Ack("new-message")

    provider = Provider()
    assert asyncio.run(Sender(db, provider).send_slot(current["slot_id"], chat_id=10)) == expected
    assert provider.calls == int(expected == "accepted")
    assert db.execute("SELECT error_code FROM weekly_slots WHERE account_id=2").fetchone()[0] == (
        "weekly_limit_reached" if expected == "blocked" else None
    )


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


def add_group_slot(db, phone, chat_id, day="2026-09-21"):
    group_id = db.execute(
        "INSERT INTO groups(name,invite_link,chat_id) VALUES('other panel group','https://max.ru/invite',?)", (chat_id,),
    ).lastrowid
    account_id = db.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state) VALUES(?,?,'Fixture','active','authenticated')",
        (group_id, phone),
    ).lastrowid
    return create_weekly_slot(db, account_id=account_id, week_start="2026-09-21", scheduled_date=day, text="fixture", message_version_id=1)


def test_shared_chat_serializes_due_slots_across_panel_groups(tmp_path):
    path = tmp_path / "queue.db"
    seed = seeded_db()
    first_db = connect(path)
    seed.backup(first_db)
    seed.close()
    first_db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(first_db, date(2026, 9, 21))
    first_slot = first_db.execute("SELECT slot_id FROM weekly_slots").fetchone()[0]
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
        finished = datetime.fromisoformat(second_db.execute(
            "SELECT finished_at FROM operations WHERE slot_id=?", (first_slot,),
        ).fetchone()[0])
        assert await other.send_slot(next_slot, chat_id=10, now=finished + timedelta(seconds=14)) == "chat_waiting"
        assert await other.send_slot(next_slot, chat_id=10, now=finished + timedelta(seconds=15)) == "accepted"
        assert fast.calls == 2

    entered = release = None
    try:
        asyncio.run(scenario())
        assert [row[0] for row in second_db.execute("SELECT destination_chat_id FROM operations ORDER BY id")] == ["10", "20", "10"]
    finally:
        first_db.close()
        second_db.close()


def test_chat_daily_limit_charges_unknown_at_local_day_boundary():
    db = seeded_db()
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    prepare_week(db, date(2026, 9, 21))
    first_slot = db.execute("SELECT slot_id FROM weekly_slots").fetchone()[0]
    same_day = add_group_slot(db, "+70000000002", "10")["slot_id"]
    tomorrow = add_group_slot(db, "+70000000003", "10", "2026-09-22")["slot_id"]
    db.execute("INSERT INTO chat_dispatch_policies(chat_id,pause_seconds,daily_limit) VALUES('10',0,1)")

    class TimedOutProvider:
        async def send_message(self, **_kwargs):
            raise TimeoutError

    class AcceptingProvider:
        calls = 0

        async def send_message(self, **_kwargs):
            self.calls += 1
            return Ack("next-day")

    clock = datetime(2026, 9, 21, 20, 59, 30, tzinfo=timezone.utc)
    assert asyncio.run(Sender(db, TimedOutProvider()).send_slot(first_slot, chat_id=10, now=clock)) == "unknown"
    fast = AcceptingProvider()
    sender = Sender(db, fast)
    assert asyncio.run(sender.send_slot(same_day, chat_id=10, now=clock + timedelta(seconds=1))) == "chat_waiting"
    assert asyncio.run(sender.send_slot(tomorrow, chat_id=10, now=clock + timedelta(seconds=30))) == "accepted"
    assert fast.calls == 1


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


def test_dispatch_rechecks_chat_limit_after_connect(monkeypatch):
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
    db.execute("UPDATE settings SET value='UTC' WHERE key='timezone'")
    db.execute("UPDATE accounts SET send_weekday=0 WHERE id=1")
    day = clock.date().isoformat()
    prepare_week(db, clock.date())
    slot = db.execute("SELECT s.*,g.chat_id FROM weekly_slots s JOIN groups g ON g.id=s.group_id").fetchone()
    previous = add_group_slot(db, "+70000000002", "10", day)
    db.execute("UPDATE weekly_slots SET status='accepted' WHERE slot_id=?", (previous["slot_id"],))
    prior_timestamp = (clock - timedelta(minutes=1)).isoformat()
    db.execute(
        "INSERT INTO operations(operation_id,slot_id,account_id,group_id,destination_chat_id,status,started_at,finished_at) "
        "VALUES('previous',?,?,2,'10','accepted',?,?)", (previous["slot_id"], previous["account_id"], prior_timestamp, prior_timestamp),
    )

    class Provider:
        async def send_message(self, **kwargs):
            pytest.fail("The new chat limit must be checked before sending")

        async def close(self):
            pass

    async def provider_factory(_slot):
        db.execute("INSERT INTO chat_dispatch_policies(chat_id,pause_seconds,daily_limit) VALUES('10',0,1)")
        return Provider()

    provider = _RetriedConnectionProvider(provider_factory, slot, lambda *_args: _dispatch_block(db, slot))
    assert asyncio.run(Sender(db, provider).send_slot(slot["slot_id"], chat_id=10, now=clock)) == "paused"
    assert tuple(db.execute("SELECT status,error_code FROM weekly_slots WHERE slot_id=?", (slot["slot_id"],)).fetchone()) == ("queued", "chat_daily_limit_reached")


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
