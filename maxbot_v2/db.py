from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    invite_link TEXT NOT NULL,
    chat_id TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    url_ciphertext TEXT NOT NULL,
    label TEXT NOT NULL,
    position INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(group_id, position)
);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    phone TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    max_user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    send_weekday INTEGER CHECK(send_weekday BETWEEN 0 AND 6),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proxy_assignments (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    proxy_id INTEGER NOT NULL REFERENCES proxies(id),
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS owner_sessions (
    token_hash TEXT PRIMARY KEY,
    csrf_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_attempts (
    attempt_key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    window_start INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS onboarding_invites (
    id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL UNIQUE REFERENCES groups(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER,
    uses_count INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS onboarding_sessions (
    id TEXT PRIMARY KEY,
    invite_id INTEGER NOT NULL REFERENCES onboarding_invites(id),
    token_hash TEXT NOT NULL,
    csrf_hash TEXT NOT NULL,
    phone TEXT,
    full_name TEXT,
    state TEXT NOT NULL,
    max_user_id TEXT,
    account_id INTEGER REFERENCES accounts(id),
    proxy_id INTEGER REFERENCES proxies(id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error_code TEXT
);
CREATE TABLE IF NOT EXISTS message_versions (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    checksum TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    version_id INTEGER NOT NULL REFERENCES message_versions(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    text TEXT NOT NULL,
    UNIQUE(version_id, ordinal),
    UNIQUE(version_id, text)
);
CREATE TABLE IF NOT EXISTS message_bag (
    id INTEGER PRIMARY KEY,
    version_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    UNIQUE(version_id, position),
    UNIQUE(version_id, message_id)
);
CREATE TABLE IF NOT EXISTS weekly_slots (
    id INTEGER PRIMARY KEY,
    slot_id TEXT NOT NULL UNIQUE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    week_start TEXT NOT NULL,
    scheduled_date TEXT NOT NULL,
    message_version_id INTEGER NOT NULL REFERENCES message_versions(id),
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    retry_count INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(account_id, week_start)
);
CREATE INDEX IF NOT EXISTS idx_weekly_due ON weekly_slots(group_id, scheduled_date, status);
CREATE TABLE IF NOT EXISTS group_worker_leases (
    group_id INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    slot_id TEXT NOT NULL REFERENCES weekly_slots(slot_id),
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    group_id INTEGER NOT NULL REFERENCES groups(id),
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    provider_message_id TEXT,
    error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_operations_slot ON operations(slot_id, id);
CREATE TABLE IF NOT EXISTS send_log (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    group_id INTEGER NOT NULL REFERENCES groups(id),
    slot_id TEXT NOT NULL UNIQUE REFERENCES weekly_slots(slot_id),
    sent_at TEXT NOT NULL,
    provider_message_id TEXT NOT NULL,
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    group_id INTEGER,
    account_id INTEGER,
    detail TEXT NOT NULL
);
"""

DEFAULTS = {
    "timezone": "Europe/Moscow",
    "send_windows_weekday": "09:00-13:00,16:00-21:00",
    "send_windows_weekend": "11:00-14:00,17:00-20:00",
    "delay_min_sec": "5",
    "delay_max_sec": "15",
    "auto_run": "1",
    "global_stop": "0",
    "max_actions_enabled": "0",
}


def connect(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    if str(path) != ":memory:":
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.executemany(
        "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", DEFAULTS.items()
    )
