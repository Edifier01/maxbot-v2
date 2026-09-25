from __future__ import annotations

import hashlib
import random
import sqlite3
from datetime import datetime, timezone


class MessagePool:
    def __init__(self, connection: sqlite3.Connection, *, rng: random.Random | None = None):
        self.connection = connection
        self.rng = rng or random.SystemRandom()

    def replace(self, raw_messages: list[str]) -> int:
        messages = [str(item).strip() for item in raw_messages if str(item).strip()]
        if not messages:
            raise ValueError("empty_message_pool")
        if len(set(messages)) != len(messages):
            raise ValueError("duplicate_message")
        digest = hashlib.sha256("\n".join(messages).encode("utf-8")).hexdigest()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.connection.execute(
                "INSERT INTO message_versions(created_at, checksum) VALUES (?, ?)",
                (datetime.now(timezone.utc).isoformat(), digest),
            )
            version_id = int(cursor.lastrowid)
            rows = []
            for position, message in enumerate(messages):
                item = self.connection.execute(
                    "INSERT INTO messages(version_id, ordinal, text) VALUES (?, ?, ?)",
                    (version_id, position, message),
                )
                rows.append((version_id, int(item.lastrowid)))
            order = list(rows)
            self.rng.shuffle(order)
            self.connection.executemany(
                "INSERT INTO message_bag(version_id, message_id, position) VALUES (?, ?, ?)",
                [(version_id, message_id, position) for position, (_, message_id) in enumerate(order)],
            )
            self.connection.execute(
                "INSERT INTO settings(key, value) VALUES ('message_version_id', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(version_id),),
            )
            self.connection.commit()
            return version_id
        except BaseException:
            self.connection.rollback()
            raise
    def draw(self) -> str:
        owns_transaction = not self.connection.in_transaction
        if owns_transaction:
            self.connection.execute("BEGIN IMMEDIATE")
        try:
            setting = self.connection.execute(
                "SELECT value FROM settings WHERE key='message_version_id'"
            ).fetchone()
            if setting is None:
                raise ValueError("empty_message_pool")
            version_id = int(setting["value"])
            row = self.connection.execute(
                "SELECT b.id, m.text FROM message_bag b JOIN messages m "
                "ON m.id=b.message_id WHERE b.version_id=? ORDER BY b.position LIMIT 1",
                (version_id,),
            ).fetchone()
            if row is None:
                messages = self.connection.execute(
                    "SELECT id FROM messages WHERE version_id=? ORDER BY ordinal",
                    (version_id,),
                ).fetchall()
                if not messages:
                    raise ValueError("empty_message_pool")
                order = [int(item["id"]) for item in messages]
                self.rng.shuffle(order)
                self.connection.executemany(
                    "INSERT INTO message_bag(version_id, message_id, position) VALUES (?, ?, ?)",
                    [(version_id, item_id, position) for position, item_id in enumerate(order)],
                )
                row = self.connection.execute(
                    "SELECT b.id, m.text FROM message_bag b JOIN messages m "
                    "ON m.id=b.message_id WHERE b.version_id=? ORDER BY b.position LIMIT 1",
                    (version_id,),
                ).fetchone()
            self.connection.execute("DELETE FROM message_bag WHERE id=?", (int(row["id"]),))
            if owns_transaction:
                self.connection.commit()
            return str(row["text"])
        except BaseException:
            if owns_transaction:
                self.connection.rollback()
            raise


def replace_message_pool(connection: sqlite3.Connection, raw_messages: list[str]) -> int:
    return MessagePool(connection).replace(raw_messages)
