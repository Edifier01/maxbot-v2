import asyncio
from contextlib import closing
from datetime import date, datetime, timezone

from maxbot_v2.db import SCHEMA, WEEKLY_SLOT_DEFINITION, connect, initialize
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.planning import prepare_week
from maxbot_v2.scheduling import create_weekly_slot
from maxbot_v2.sender import Ack, Sender


def test_migration_retains_slot_operation_and_receipt_keys(tmp_path):
    legacy_slot = WEEKLY_SLOT_DEFINITION.replace(
        "    day_position INTEGER NOT NULL DEFAULT 1 CHECK(day_position BETWEEN 1 AND 5),\n", "",
    ).replace("UNIQUE(account_id, week_start, scheduled_date, day_position)", "UNIQUE(account_id, week_start)")
    legacy_schema = SCHEMA.replace(WEEKLY_SLOT_DEFINITION, legacy_slot).replace(
        "    send_day_pair INTEGER CHECK(send_day_pair BETWEEN 0 AND 2),\n", "",
    )
    with closing(connect(tmp_path / "old.sqlite3")) as db:
        db.executescript(legacy_schema)
        db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'G','https://max.ru/join/fixture')")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,send_weekday) VALUES(1,1,'+70000000001','Fixture',4)")
        version = replace_message_pool(db, ["fixture"])
        db.execute(
            "INSERT INTO weekly_slots(id,slot_id,account_id,group_id,week_start,scheduled_date,message_version_id,text,status,updated_at) "
            "VALUES(7,'original',1,1,'2026-11-16','2026-11-20',?,'fixture','accepted','2026-11-20')", (version,),
        )
        db.execute("INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) VALUES('op','original',1,1,'accepted','2026-11-20')")
        db.execute("INSERT INTO send_log(account_id,group_id,slot_id,sent_at,provider_message_id,text) VALUES(1,1,'original','2026-11-20','message','fixture')")

        initialize(db)
        initialize(db)
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert tuple(db.execute("SELECT id,slot_id,status,day_position FROM weekly_slots").fetchone()) == (7, "original", "accepted", 1)
        assert db.execute("SELECT slot_id FROM operations").fetchone()[0] == "original"
        assert db.execute("SELECT slot_id FROM send_log").fetchone()[0] == "original"
        assert db.execute("SELECT send_day_pair FROM accounts").fetchone()[0] == 1
        seed = create_weekly_slot(db, account_id=1, week_start="2026-11-16", scheduled_date="2026-11-20", text="second", message_version_id=version, day_position=2)
        assert seed["slot_id"] != "original"


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


def test_days_can_be_assigned_before_the_text_pool_is_configured():
    with closing(connect(":memory:")) as db:
        initialize(db)
        db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'G','https://max.ru/join/fixture')")
        db.execute(
            "INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state) "
            "VALUES(1,1,'+70000000001','Fixture','active','authenticated')"
        )

        monday = date(2026, 11, 16)
        assert prepare_week(db, monday) == 0
        assert db.execute("SELECT send_day_pair FROM accounts WHERE id=1").fetchone()[0] == 0

        replace_message_pool(db, ["fixture"])
        assert prepare_week(db, monday) == 10
        assert [row[0] for row in db.execute(
            "SELECT DISTINCT scheduled_date FROM weekly_slots ORDER BY scheduled_date"
        )] == ["2026-11-16", "2026-11-19"]


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
    from maxbot_v2.scheduling import resume_quota_blocked_slots

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
        resume_quota_blocked_slots(db, 1, monday.date())
        assert db.execute("SELECT status FROM weekly_slots WHERE slot_id='slot-2026-11-16-2-1'").fetchone()[0] == "blocked"
        db.execute("UPDATE operations SET status='rejected' WHERE operation_id='uncertain'")
        resume_quota_blocked_slots(db, 1, monday.date())
        assert asyncio.run(sender.send_slot("slot-2026-11-16-2-1", chat_id=10, now=monday)) == "accepted"
        for position in range(1, 6):
            assert asyncio.run(sender.send_slot(f"slot-2026-11-19-2-{position}", chat_id=10, now=thursday)) == "accepted"
        assert provider.calls == 6

        db.execute("UPDATE accounts SET lifecycle='deleted',phone='deleted:2' WHERE id=2")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state,send_day_pair,phone_fingerprint) VALUES(3,1,'+70000000001','Fixture','active','authenticated',2,'fixture-fingerprint')")
        prepare_week(db, date(2026, 11, 21))
        saturday = datetime(2026, 11, 21, 10, tzinfo=timezone.utc)
        assert asyncio.run(sender.send_slot("slot-2026-11-21-3-1", chat_id=10, now=saturday)) == "blocked"
        assert db.execute("SELECT error_code FROM weekly_slots WHERE slot_id='slot-2026-11-21-3-1'").fetchone()[0] == "weekly_limit_reached"
        assert provider.calls == 6


def test_legacy_send_with_other_timezone_counts_against_moscow_monday():
    with closing(connect(":memory:")) as db:
        initialize(db)
        db.execute("INSERT INTO groups(id,name,invite_link,chat_id) VALUES(1,'G','https://max.ru/join/fixture','10')")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state,send_day_pair) VALUES(1,1,'+70000000001','Fixture','active','authenticated',0)")
        version = replace_message_pool(db, ["fixture"])
        sunday = create_weekly_slot(db, account_id=1, week_start="2026-11-09", scheduled_date="2026-11-15", text="legacy", message_version_id=version)
        db.execute("UPDATE weekly_slots SET status='accepted' WHERE slot_id=?", (sunday["slot_id"],))
        db.execute(
            "INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) "
            "VALUES('legacy',?,1,1,'accepted','2026-11-16T01:00:00+00:00')", (sunday["slot_id"],),
        )
        prepare_week(db, date(2026, 11, 16))

        class Provider:
            async def send_message(self, **_kwargs):
                return Ack("test")

        sender = Sender(db, Provider())
        monday = datetime(2026, 11, 16, 18, tzinfo=timezone.utc)
        for position in range(1, 5):
            assert asyncio.run(sender.send_slot(f"slot-2026-11-16-1-{position}", chat_id=10, now=monday)) == "accepted"
        assert asyncio.run(sender.send_slot("slot-2026-11-16-1-5", chat_id=10, now=monday)) == "blocked"
        assert db.execute("SELECT error_code FROM weekly_slots WHERE slot_id='slot-2026-11-16-1-5'").fetchone()[0] == "daily_limit_reached"
