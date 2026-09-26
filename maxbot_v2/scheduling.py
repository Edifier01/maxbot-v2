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


def assign_proxy(connection: sqlite3.Connection, account_id: int, group_id: int) -> int:
    current = connection.execute(
        "SELECT a.proxy_id, p.group_id, p.enabled, p.check_status FROM proxy_assignments a "
        "JOIN proxies p ON p.id=a.proxy_id WHERE a.account_id=?",
        (int(account_id),),
    ).fetchone()
    if current is not None:
        if int(current["group_id"]) != int(group_id):
            raise ValueError("proxy_assignment_group_mismatch")
        if int(current["enabled"]) and current["check_status"] != "failed":
            return int(current["proxy_id"])
        raise ValueError("proxy_reassignment_required")
    candidates = connection.execute(
        "SELECT p.id, COUNT(a.account_id) AS load FROM proxies p "
        "LEFT JOIN proxy_assignments a ON a.proxy_id=p.id "
        "WHERE p.group_id=? AND p.enabled=1 AND p.check_status='healthy' GROUP BY p.id ORDER BY load, p.position, p.id",
        (int(group_id),),
    ).fetchall()
    if not candidates:
        raise ValueError("proxy_assignment_required")
    proxy_id = int(candidates[0]["id"])
    connection.execute(
        "INSERT INTO proxy_assignments(account_id, proxy_id) VALUES (?, ?)",
        (int(account_id), proxy_id),
    )
    return proxy_id


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
