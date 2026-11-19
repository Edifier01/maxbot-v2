from __future__ import annotations

import sqlite3
from datetime import date, datetime

from .scheduling import SCHEDULE_TZ, SEND_DAY_PAIRS


def other_slot_has_priority(connection: sqlite3.Connection, slot: sqlite3.Row, chat_id: str) -> bool:
    pair = date.fromisoformat(slot["scheduled_date"]).weekday() % len(SEND_DAY_PAIRS)
    first = connection.execute(
        "SELECT MIN(s.id) FROM weekly_slots s JOIN groups g ON g.id=s.group_id JOIN accounts a ON a.id=s.account_id "
        "WHERE g.active=1 AND g.chat_id=? AND s.scheduled_date=? AND s.status='queued' "
        "AND a.lifecycle='active' AND a.status='active' AND a.auth_state='authenticated' AND a.send_day_pair=? GROUP BY s.group_id "
        "ORDER BY COALESCE((SELECT MAX(o.id) FROM operations o WHERE o.destination_chat_id=? "
        "AND o.group_id=s.group_id AND o.status IN ('accepted','unknown')),0), MIN(s.id) LIMIT 1",
        (chat_id, slot["scheduled_date"], pair, chat_id),
    ).fetchone()
    return first is not None and first[0] != slot["id"]


def chat_dispatch_wait(
    connection: sqlite3.Connection, chat_id: str, now: datetime, *, current_slot_id: str | None = None,
) -> str | None:
    active = connection.execute(
        "SELECT slot_id,started_at FROM operations WHERE destination_chat_id=? AND status='in_flight' LIMIT 1", (chat_id,),
    ).fetchone()
    if active:
        if active[0] != current_slot_id:
            return "chat_busy"
        if datetime.fromisoformat(active[1]).astimezone(SCHEDULE_TZ).date() != now.astimezone(SCHEDULE_TZ).date():
            return "outside_send_day"
    return None
