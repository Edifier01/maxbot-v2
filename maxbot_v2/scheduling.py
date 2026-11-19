from __future__ import annotations

from datetime import date, datetime, time, timedelta
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
    day = date.fromisoformat(slot["scheduled_date"])
    week_start = monday_of(day)
    week_end = week_start + timedelta(days=7)
    day_start_time = datetime.combine(day, time.min, SCHEDULE_TZ)
    day_end_time = day_start_time + timedelta(days=1)
    # An older schedule could place an operation in a neighboring local week.
    # The operation's start anchors both limits, even after late reconciliation.
    daily, weekly = connection.execute(
        """
        WITH matching_accounts(id) AS (
            SELECT ?
            UNION
            SELECT id FROM accounts WHERE phone_fingerprint=?
        ),
        completed_or_reserved(sent_at) AS (
            SELECT COALESCE(
                (SELECT COALESCE(julianday(o.started_at), julianday(s.scheduled_date || 'T12:00:00+03:00'))
                 FROM operations o WHERE o.slot_id=s.slot_id AND o.status IN ('accepted','unknown','in_flight')
                 ORDER BY o.id DESC LIMIT 1),
                (SELECT COALESCE(julianday(l.sent_at), julianday(s.scheduled_date || 'T12:00:00+03:00'))
                 FROM send_log l WHERE l.slot_id=s.slot_id)
            )
            FROM matching_accounts a
            JOIN weekly_slots s ON s.account_id=a.id AND s.week_start BETWEEN ? AND ?
            WHERE s.slot_id<>?
        )
        SELECT COUNT(CASE WHEN sent_at>=julianday(?) AND sent_at<julianday(?) THEN 1 END), COUNT(*)
        FROM completed_or_reserved WHERE sent_at>=julianday(?) AND sent_at<julianday(?)
        """,
        (
            slot["account_id"], phone_fingerprint, (week_start - timedelta(days=7)).isoformat(), week_end.isoformat(),
            slot["slot_id"], day_start_time.isoformat(), day_end_time.isoformat(),
            datetime.combine(week_start, time.min, SCHEDULE_TZ).isoformat(),
            datetime.combine(week_end, time.min, SCHEDULE_TZ).isoformat(),
        ),
    ).fetchone()
    if daily >= MESSAGES_PER_DAY:
        return "daily_limit_reached"
    if weekly >= MESSAGES_PER_WEEK:
        return "weekly_limit_reached"
    return None


def resume_quota_blocked_slots(connection: sqlite3.Connection, group_id: int, today: date) -> None:
    day = today.isoformat()
    slots = connection.execute(
        "SELECT a.phone_fingerprint,s.account_id,s.scheduled_date,MIN(s.slot_id) AS slot_id "
        "FROM weekly_slots s JOIN accounts a ON a.id=s.account_id "
        "WHERE s.group_id=? AND s.scheduled_date=? AND s.status='blocked' "
        "AND s.error_code IN ('daily_limit_reached','weekly_limit_reached') "
        "AND a.lifecycle='active' AND a.status='active' AND a.auth_state='authenticated' GROUP BY s.account_id",
        (group_id, day),
    ).fetchall()
    for slot in slots:
        if dispatch_quota_reason(connection, slot, slot["phone_fingerprint"]) is None:
            connection.execute(
                "UPDATE weekly_slots SET status='queued',error_code=NULL,updated_at=CURRENT_TIMESTAMP "
                "WHERE account_id=? AND group_id=? AND scheduled_date=? AND status='blocked' "
                "AND error_code IN ('daily_limit_reached','weekly_limit_reached')",
                (slot["account_id"], group_id, day),
            )


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
