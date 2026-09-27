from __future__ import annotations

from datetime import date, timedelta
import sqlite3
import uuid


def monday_of(day: date) -> date:
    return day - timedelta(days=day.weekday())


def assign_weekday(connection: sqlite3.Connection, account_id: int) -> int:
    row = connection.execute(
        "SELECT send_weekday FROM accounts WHERE id=?", (int(account_id),)
    ).fetchone()
    if row is None:
        raise ValueError("account_not_found")
    if row["send_weekday"] is not None:
        return int(row["send_weekday"])
    counts = [0] * 7
    for item in connection.execute(
        "SELECT send_weekday, COUNT(*) AS n FROM accounts "
        "WHERE send_weekday IS NOT NULL GROUP BY send_weekday"
    ):
        counts[int(item["send_weekday"])] = int(item["n"])
    weekday = min(range(7), key=lambda value: (counts[value], value))
    connection.execute(
        "UPDATE accounts SET send_weekday=? WHERE id=? AND send_weekday IS NULL",
        (weekday, int(account_id)),
    )
    return weekday


def create_weekly_slot(
    connection: sqlite3.Connection,
    *,
    account_id: int,
    week_start: str,
    scheduled_date: str,
    text: str,
    message_version_id: int = 1,
) -> sqlite3.Row:
    account = connection.execute(
        "SELECT group_id FROM accounts WHERE id=?", (int(account_id),)
    ).fetchone()
    if account is None:
        raise ValueError("account_not_found")
    slot_id = f"weekly-{uuid.uuid4().hex}"
    connection.execute(
        "INSERT OR IGNORE INTO weekly_slots "
        "(slot_id, account_id, group_id, week_start, scheduled_date, "
        "message_version_id, text, status, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', CURRENT_TIMESTAMP)",
        (
            slot_id,
            int(account_id),
            int(account["group_id"]),
            week_start,
            scheduled_date,
            int(message_version_id),
            text,
        ),
    )
    return connection.execute(
        "SELECT * FROM weekly_slots WHERE account_id=? AND week_start=?",
        (int(account_id), week_start),
    ).fetchone()
