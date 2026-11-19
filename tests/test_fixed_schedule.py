import asyncio
from contextlib import closing
from datetime import date, datetime, timezone

from maxbot_v2.db import connect, initialize
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.planning import prepare_week
from maxbot_v2.scheduling import create_weekly_slot
from maxbot_v2.sender import Ack, Sender


def test_week_uses_three_fixed_pairs_with_five_slots_per_day():
    with closing(connect(":memory:")) as db:
        initialize(db)
        db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'G','https://max.ru/join/fixture')")
        db.executemany(
            "INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state) VALUES(?,1,?,'Fixture','active','authenticated')",
            [(account_id, f"+7000000000{account_id}") for account_id in (1, 2, 3)],
        )
        replace_message_pool(db, ["first", "second"])
        monday = date(2026, 11, 16)
        assert prepare_week(db, monday) == 30
        for account_id, days in enumerate((
            ("2026-11-16", "2026-11-19"),
            ("2026-11-17", "2026-11-20"),
            ("2026-11-18", "2026-11-21"),
        ), start=1):
            actual = [tuple(row) for row in db.execute(
                "SELECT scheduled_date,day_position FROM weekly_slots WHERE account_id=? ORDER BY scheduled_date,day_position", (account_id,),
            )]
            assert actual == [(day, position) for day in days for position in range(1, 6)]
        assert prepare_week(db, date(2026, 11, 22)) == 0


def test_plan_reuses_existing_day_and_keeps_old_sunday_slot_as_history():
    with closing(connect(":memory:")) as db:
        initialize(db)
        db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'G','https://max.ru/join/fixture')")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state,send_weekday) VALUES(1,1,'+70000000001','Fixture','active','authenticated',4)")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state,send_weekday) VALUES(2,1,'+70000000002','Fixture 2','active','authenticated',6)")
        version = replace_message_pool(db, ["pool text"])
        existing = create_weekly_slot(db, account_id=1, week_start="2026-11-16", scheduled_date="2026-11-20", text="retained", message_version_id=version)
        sunday = create_weekly_slot(db, account_id=2, week_start="2026-11-16", scheduled_date="2026-11-22", text="old Sunday", message_version_id=version)

        assert prepare_week(db, date(2026, 11, 18)) == 19
        assert [tuple(row) for row in db.execute(
            "SELECT scheduled_date,status,COUNT(*) FROM weekly_slots WHERE account_id=1 GROUP BY scheduled_date,status ORDER BY scheduled_date",
        )] == [("2026-11-17", "missed", 5), ("2026-11-20", "queued", 5)]
        assert tuple(db.execute("SELECT text,day_position FROM weekly_slots WHERE slot_id=?", (existing["slot_id"],)).fetchone()) == ("retained", 1)
        assert tuple(db.execute("SELECT text,status,error_code FROM weekly_slots WHERE slot_id=?", (sunday["slot_id"],)).fetchone()) == ("old Sunday", "missed", "schedule_replaced")


def test_fingerprint_retains_five_daily_and_ten_weekly_quota_after_readdition():
    with closing(connect(":memory:")) as db:
        initialize(db)
        db.execute("INSERT INTO groups(id,name,invite_link,chat_id) VALUES(1,'G','https://max.ru/join/fixture','10')")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status,lifecycle,phone_fingerprint) VALUES(1,1,'deleted:1','','deleted','deleted','fixture-fingerprint')")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state,send_day_pair,phone_fingerprint) VALUES(2,1,'+70000000001','Fixture','active','authenticated',0,'fixture-fingerprint')")
        version = replace_message_pool(db, ["fixture"])
        for position in range(1, 6):
            prior = create_weekly_slot(db, account_id=1, week_start="2026-11-16", scheduled_date="2026-11-16", text="old", message_version_id=version, day_position=position)
            if position == 5:
                db.execute(
                    "INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) VALUES('uncertain',?,1,1,'unknown','2026-11-16T09:00:00+00:00')",
                    (prior["slot_id"],),
                )
            else:
                db.execute(
                    "INSERT INTO send_log(account_id,group_id,slot_id,sent_at,provider_message_id,text) VALUES(1,1,?,'2026-11-16T09:00:00+00:00','accepted','old')",
                    (prior["slot_id"],),
                )
        prepare_week(db, date(2026, 11, 16))

        class Provider:
            calls = 0

            async def send_message(self, **_kwargs):
                self.calls += 1
                return Ack(f"accepted-{self.calls}")

        provider = Provider()
        sender = Sender(db, provider)
        monday = datetime(2026, 11, 16, 10, tzinfo=timezone.utc)
        thursday = datetime(2026, 11, 19, 10, tzinfo=timezone.utc)
        assert asyncio.run(sender.send_slot("slot-2026-11-16-2-1", chat_id=10, now=monday)) == "blocked"
        assert db.execute("SELECT error_code FROM weekly_slots WHERE slot_id='slot-2026-11-16-2-1'").fetchone()[0] == "daily_limit_reached"
        for position in range(1, 6):
            assert asyncio.run(sender.send_slot(f"slot-2026-11-19-2-{position}", chat_id=10, now=thursday)) == "accepted"
        assert provider.calls == 5

        db.execute("UPDATE accounts SET lifecycle='deleted',phone='deleted:2' WHERE id=2")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state,send_day_pair,phone_fingerprint) VALUES(3,1,'+70000000001','Fixture','active','authenticated',2,'fixture-fingerprint')")
        prepare_week(db, date(2026, 11, 21))
        saturday = datetime(2026, 11, 21, 10, tzinfo=timezone.utc)
        assert asyncio.run(sender.send_slot("slot-2026-11-21-3-1", chat_id=10, now=saturday)) == "blocked"
        assert db.execute("SELECT error_code FROM weekly_slots WHERE slot_id='slot-2026-11-21-3-1'").fetchone()[0] == "weekly_limit_reached"
        assert provider.calls == 5
