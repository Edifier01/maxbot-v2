from __future__ import annotations

import sqlite3
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

DEFAULT_CHAT_PAUSE_SECONDS = 15


def chat_dispatch_policy(connection: sqlite3.Connection, chat_id: str) -> tuple[int, int]:
    row = connection.execute(
        "SELECT pause_seconds,daily_limit FROM chat_dispatch_policies WHERE chat_id=?", (chat_id,),
    ).fetchone()
    return (row[0], row[1]) if row else (DEFAULT_CHAT_PAUSE_SECONDS, 0)


def earlier_queued_slot(connection: sqlite3.Connection, slot: sqlite3.Row, chat_id: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM weekly_slots s JOIN groups g ON g.id=s.group_id JOIN accounts a ON a.id=s.account_id "
        "WHERE g.active=1 AND g.chat_id=? AND s.scheduled_date=? AND s.status='queued' AND s.id<? "
        "AND a.lifecycle='active' AND a.status='active' AND a.auth_state='authenticated' LIMIT 1",
        (chat_id, slot["scheduled_date"], slot["id"]),
    ).fetchone() is not None


def chat_dispatch_wait(
    connection: sqlite3.Connection, chat_id: str, now: datetime, *, current_slot_id: str | None = None,
) -> str | None:
    active = connection.execute(
        "SELECT slot_id FROM operations WHERE destination_chat_id=? AND status='in_flight' LIMIT 1", (chat_id,),
    ).fetchone()
    if active and active[0] != current_slot_id:
        return "chat_busy"

    pause_seconds, daily_limit = chat_dispatch_policy(connection, chat_id)
    if daily_limit:
        setting = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
        zone = ZoneInfo(setting[0] if setting else "Europe/Moscow")
        today = now.astimezone(zone).date()
        start = datetime.combine(today, time.min, zone).astimezone(timezone.utc)
        end = datetime.combine(today + timedelta(days=1), time.min, zone).astimezone(timezone.utc)
        charged = connection.execute(
            "SELECT COUNT(*) FROM operations WHERE destination_chat_id=? AND status IN ('accepted','unknown') "
            "AND started_at>=? AND started_at<?", (chat_id, start.isoformat(), end.isoformat()),
        ).fetchone()[0]
        if charged >= daily_limit:
            return "chat_daily_limit_reached"

    if pause_seconds:
        cutoff = (now.astimezone(timezone.utc) - timedelta(seconds=pause_seconds)).isoformat()
        if connection.execute(
            "SELECT 1 FROM operations WHERE destination_chat_id=? AND status IN ('accepted','unknown') "
            "AND finished_at>? LIMIT 1", (chat_id, cutoff),
        ).fetchone():
            return "chat_pause"
    return None
