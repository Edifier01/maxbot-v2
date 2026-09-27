from __future__ import annotations

import sqlite3
from datetime import date

from .message_pool import MessagePool
from .scheduling import assign_weekday, monday_of


def prepare_week(connection: sqlite3.Connection, today: date) -> int:
    """Create one immutable slot/account/week; missed days stay missed."""
    week_start = monday_of(today)
    version_row = connection.execute("SELECT value FROM settings WHERE key='message_version_id'").fetchone()
    if version_row is None:
        return 0
    version_id = int(version_row["value"])
    count = 0
    connection.execute("BEGIN IMMEDIATE")
    try:
        pool = MessagePool(connection)
        accounts = connection.execute(
            "SELECT a.id FROM accounts a JOIN groups g ON g.id=a.group_id WHERE a.status='active' AND a.auth_state='authenticated' AND g.active=1 ORDER BY a.group_id,a.id"
        ).fetchall()
        for row in accounts:
            account_id = int(row["id"])
            weekday = assign_weekday(connection, account_id)
            target = week_start.fromordinal(week_start.toordinal() + weekday)
            exists = connection.execute("SELECT 1 FROM weekly_slots WHERE account_id=? AND week_start=?", (account_id, week_start.isoformat())).fetchone()
            if exists:
                continue
            text = pool.draw()
            status = "missed" if target < today else "queued"
            connection.execute(
                "INSERT INTO weekly_slots(slot_id,account_id,group_id,week_start,scheduled_date,message_version_id,text,status,updated_at) "
                "SELECT ?,a.id,a.group_id,?,?,?,?,?,CURRENT_TIMESTAMP FROM accounts a WHERE a.id=?",
                (f"slot-{week_start.isoformat()}-{account_id}", week_start.isoformat(), target.isoformat(), version_id, text, status, account_id),
            )
            count += 1
        connection.commit()
        return count
    except BaseException:
        connection.rollback()
        raise
