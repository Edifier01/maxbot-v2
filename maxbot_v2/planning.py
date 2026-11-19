from __future__ import annotations

import sqlite3
from datetime import date, timedelta

from .message_pool import MessagePool
from .scheduling import MESSAGES_PER_DAY, SEND_DAY_PAIRS, assign_day_pair, monday_of


def prepare_week(connection: sqlite3.Connection, today: date) -> int:
    """Prepare five fixed slots on each of the account's two sending days."""
    week_start = monday_of(today)
    week_key = week_start.isoformat()
    count = 0
    connection.execute("BEGIN IMMEDIATE")
    try:
        version_row = connection.execute("SELECT value FROM settings WHERE key='message_version_id'").fetchone()
        if version_row is None:
            connection.commit()
            return 0
        version_id = int(version_row["value"])
        pool = MessagePool(connection)
        accounts = connection.execute(
            "SELECT a.id,a.group_id FROM accounts a JOIN groups g ON g.id=a.group_id "
            "WHERE a.lifecycle='active' AND a.status='active' AND a.auth_state='authenticated' AND g.active=1 ORDER BY a.group_id,a.id"
        ).fetchall()
        for row in accounts:
            account_id = int(row["id"])
            pair = assign_day_pair(connection, account_id)
            days = [(week_start + timedelta(days=weekday)).isoformat() for weekday in SEND_DAY_PAIRS[pair]]
            connection.execute(
                "UPDATE weekly_slots SET status='missed',error_code='schedule_replaced',updated_at=CURRENT_TIMESTAMP "
                "WHERE account_id=? AND week_start=? AND scheduled_date NOT IN (?,?) AND status IN ('queued','blocked')",
                (account_id, week_key, *days),
            )
            saved = {tuple(slot) for slot in connection.execute(
                "SELECT scheduled_date,day_position FROM weekly_slots WHERE account_id=? AND week_start=?", (account_id, week_key),
            )}
            for scheduled_date in days:
                status = "missed" if scheduled_date < today.isoformat() else "queued"
                for day_position in range(1, MESSAGES_PER_DAY + 1):
                    if (scheduled_date, day_position) in saved:
                        continue
                    connection.execute(
                        "INSERT INTO weekly_slots(slot_id,account_id,group_id,week_start,scheduled_date,day_position,message_version_id,text,status,updated_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                        (f"slot-{scheduled_date}-{account_id}-{day_position}", account_id, row["group_id"], week_key,
                         scheduled_date, day_position, version_id, pool.draw(), status),
                    )
                    count += 1
        connection.commit()
        return count
    except BaseException:
        connection.rollback()
        raise
