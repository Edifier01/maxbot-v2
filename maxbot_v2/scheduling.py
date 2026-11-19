from __future__ import annotations

from datetime import date, timedelta
import sqlite3
import uuid
from zoneinfo import ZoneInfo


SCHEDULE_TZ = ZoneInfo("Europe/Moscow")
SEND_DAY_PAIRS = ((0, 3), (1, 4), (2, 5))
MESSAGES_PER_DAY = 5
MESSAGES_PER_WEEK = 2 * MESSAGES_PER_DAY


def monday_of(day: date) -> date:
    return day - timedelta(days=day.weekday())


def assign_day_pair(connection: sqlite3.Connection, account_id: int) -> int:
    row = connection.execute(
        "SELECT send_day_pair,send_weekday FROM accounts WHERE id=?", (int(account_id),)
    ).fetchone()
    if row is None:
        raise ValueError("account_not_found")
    if row["send_day_pair"] is not None:
        return row["send_day_pair"]
    previous = row["send_weekday"]
    if previous is not None and 0 <= previous <= 5:
        pair = previous % len(SEND_DAY_PAIRS)
    else:
        counts = dict(connection.execute(
            "SELECT send_day_pair,COUNT(*) FROM accounts WHERE lifecycle='active' "
            "AND send_day_pair IS NOT NULL GROUP BY send_day_pair"
        ).fetchall())
        pair = min(range(len(SEND_DAY_PAIRS)), key=lambda value: (counts.get(value, 0), value))
    connection.execute(
        "UPDATE accounts SET send_day_pair=? WHERE id=? AND send_day_pair IS NULL",
        (pair, int(account_id)),
    )
    return pair


def dispatch_quota_reason(connection: sqlite3.Connection, slot: sqlite3.Row, phone_fingerprint: str | None) -> str | None:
    day = slot["scheduled_date"]
    week_start = slot["week_start"]
    daily, weekly = connection.execute(
        "SELECT COUNT(CASE WHEN s.scheduled_date=? THEN 1 END), COUNT(CASE WHEN s.week_start=? THEN 1 END) "
        "FROM weekly_slots s JOIN accounts a ON a.id=s.account_id "
        "WHERE s.slot_id<>? AND (s.scheduled_date=? OR s.week_start=?) "
        "AND (a.id=? OR a.phone_fingerprint=?) "
        "AND (EXISTS(SELECT 1 FROM send_log l WHERE l.slot_id=s.slot_id) "
        "OR EXISTS(SELECT 1 FROM operations o WHERE o.slot_id=s.slot_id AND o.status IN ('accepted','unknown','in_flight')))",
        (day, week_start, slot["slot_id"], day, week_start, slot["account_id"], phone_fingerprint),
    ).fetchone()
    if daily >= MESSAGES_PER_DAY:
        return "daily_limit_reached"
    if weekly >= MESSAGES_PER_WEEK:
        return "weekly_limit_reached"
    return None


def create_weekly_slot(
    connection: sqlite3.Connection,
    *,
    account_id: int,
    week_start: str,
    scheduled_date: str,
    text: str,
    message_version_id: int = 1,
    day_position: int = 1,
) -> sqlite3.Row:
    account = connection.execute(
        "SELECT group_id FROM accounts WHERE id=?", (int(account_id),)
    ).fetchone()
    if account is None:
        raise ValueError("account_not_found")
    slot_id = f"weekly-{uuid.uuid4().hex}"
    connection.execute(
        "INSERT OR IGNORE INTO weekly_slots "
        "(slot_id, account_id, group_id, week_start, scheduled_date, day_position, "
        "message_version_id, text, status, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', CURRENT_TIMESTAMP)",
        (
            slot_id,
            int(account_id),
            int(account["group_id"]),
            week_start,
            scheduled_date,
            day_position,
            int(message_version_id),
            text,
        ),
    )
    return connection.execute(
        "SELECT * FROM weekly_slots WHERE account_id=? AND week_start=? AND scheduled_date=? AND day_position=?",
        (int(account_id), week_start, scheduled_date, day_position),
    ).fetchone()
