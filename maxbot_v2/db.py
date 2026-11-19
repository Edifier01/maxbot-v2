from __future__ import annotations

import sqlite3
from pathlib import Path


WEEKLY_SLOT_DEFINITION = """(
    id INTEGER PRIMARY KEY,
    slot_id TEXT NOT NULL UNIQUE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    week_start TEXT NOT NULL,
    scheduled_date TEXT NOT NULL,
    day_position INTEGER NOT NULL DEFAULT 1 CHECK(day_position BETWEEN 1 AND 5),
    message_version_id INTEGER NOT NULL REFERENCES message_versions(id),
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    retry_count INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(account_id, week_start, scheduled_date, day_position)
)"""


SCHEMA = f"""
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
    auth_state TEXT NOT NULL DEFAULT 'unverified',
    lifecycle TEXT NOT NULL DEFAULT 'active',
    deletion_reason TEXT,
    ever_authenticated INTEGER NOT NULL DEFAULT 0,
    phone_fingerprint TEXT,
    send_weekday INTEGER CHECK(send_weekday BETWEEN 0 AND 6),
    send_day_pair INTEGER CHECK(send_day_pair BETWEEN 0 AND 2),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proxy_assignments (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    proxy_id INTEGER NOT NULL REFERENCES proxies(id),
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS server_ips (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 0,
    available INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT,
    last_assigned_at TEXT
);
CREATE TABLE IF NOT EXISTS ip_assignments (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    ip_id INTEGER NOT NULL REFERENCES server_ips(id),
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS send_proxies (
    id INTEGER PRIMARY KEY,
    ip_id INTEGER NOT NULL REFERENCES server_ips(id),
    url_ciphertext TEXT NOT NULL,
    url_fingerprint TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
    check_status TEXT NOT NULL DEFAULT 'unchecked',
    last_checked_at TEXT,
    UNIQUE(ip_id, url_fingerprint)
);
CREATE TABLE IF NOT EXISTS send_proxy_assignments (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    proxy_id INTEGER NOT NULL REFERENCES send_proxies(id),
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_send_proxy_assignments_proxy ON send_proxy_assignments(proxy_id);
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
CREATE TABLE IF NOT EXISTS weekly_slots {WEEKLY_SLOT_DEFINITION};
CREATE TABLE IF NOT EXISTS chat_dispatch_policies (
    chat_id TEXT PRIMARY KEY,
    pause_seconds INTEGER NOT NULL CHECK(pause_seconds >= 0),
    daily_limit INTEGER NOT NULL CHECK(daily_limit >= 0)
);
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
    destination_chat_id TEXT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    dispatch_finished_at TEXT,
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
CREATE TABLE IF NOT EXISTS onboarding_events (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES groups(id),
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    ip_id INTEGER REFERENCES server_ips(id),
    stage TEXT NOT NULL,
    result TEXT NOT NULL,
    duration_ms INTEGER,
    response_received INTEGER NOT NULL DEFAULT 0,
    error_class TEXT
);
"""

DEFAULTS = {
    "global_stop": "1",
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
    _migrate_weekly_slots(connection)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_weekly_due ON weekly_slots(group_id, scheduled_date, status)")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(accounts)")}
    if "send_day_pair" not in columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN send_day_pair INTEGER CHECK(send_day_pair BETWEEN 0 AND 2)")
    connection.execute("UPDATE accounts SET send_day_pair=send_weekday % 3 WHERE send_day_pair IS NULL AND send_weekday BETWEEN 0 AND 5")
    if "session_generation" not in columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN session_generation INTEGER NOT NULL DEFAULT 0")
    if "auth_state" not in columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN auth_state TEXT NOT NULL DEFAULT 'unverified'")
        connection.execute(
            "UPDATE accounts SET auth_state='authenticated' WHERE status IN ('active','needs_membership')"
        )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(accounts)")}
    if "lifecycle" not in columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'active'")
    if "deletion_reason" not in columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN deletion_reason TEXT")
    if "ever_authenticated" not in columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN ever_authenticated INTEGER NOT NULL DEFAULT 0")
        connection.execute(
            "UPDATE accounts SET ever_authenticated=1 WHERE auth_state IN ('authenticated','reauth_required') "
            "OR status IN ('active','needs_membership') OR max_user_id IS NOT NULL"
        )
    if "phone_fingerprint" not in columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN phone_fingerprint TEXT")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(onboarding_sessions)")}
    if "ip_id" not in columns:
        connection.execute("ALTER TABLE onboarding_sessions ADD COLUMN ip_id INTEGER REFERENCES server_ips(id)")
    ip_columns = {row[1] for row in connection.execute("PRAGMA table_info(server_ips)")}
    if "last_assigned_at" not in ip_columns:
        connection.execute("ALTER TABLE server_ips ADD COLUMN last_assigned_at TEXT")
    send_proxy_columns = {row[1] for row in connection.execute("PRAGMA table_info(send_proxies)")}
    if "check_status" not in send_proxy_columns:
        connection.execute("ALTER TABLE send_proxies ADD COLUMN check_status TEXT NOT NULL DEFAULT 'unchecked'")
    if "last_checked_at" not in send_proxy_columns:
        connection.execute("ALTER TABLE send_proxies ADD COLUMN last_checked_at TEXT")
    operation_columns = {row[1] for row in connection.execute("PRAGMA table_info(operations)")}
    if "destination_chat_id" not in operation_columns:
        connection.execute("ALTER TABLE operations ADD COLUMN destination_chat_id TEXT")
    if "dispatch_finished_at" not in operation_columns:
        connection.execute("ALTER TABLE operations ADD COLUMN dispatch_finished_at TEXT")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_in_flight ON operations(destination_chat_id) "
        "WHERE destination_chat_id IS NOT NULL AND status='in_flight'"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chat_daily_operations ON operations(destination_chat_id,status,started_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chat_dispatch_finishes ON operations(destination_chat_id,status,dispatch_finished_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chat_group_turn ON operations(destination_chat_id,group_id,id) "
        "WHERE status IN ('accepted','unknown')"
    )
    connection.execute(
        "UPDATE onboarding_sessions SET phone=NULL,full_name=NULL WHERE state IN "
        "('completed','failed','expired','cancelled')"
    )
    connection.executemany(
        "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", DEFAULTS.items()
    )


def _migrate_weekly_slots(connection: sqlite3.Connection) -> None:
    actual_columns = {row[1] for row in connection.execute("PRAGMA table_info(weekly_slots)")}
    if "day_position" in actual_columns:
        return
    columns = (
        "id", "slot_id", "account_id", "group_id", "week_start", "scheduled_date",
        "message_version_id", "text", "status", "retry_count", "error_code", "updated_at",
    )
    if actual_columns != set(columns):
        raise sqlite3.DatabaseError("unexpected_weekly_slots_schema")

    # SQLite needs a transactional table swap to replace the old inline UNIQUE constraint.
    # Existing slot keys stay the same for both operations and send_log.
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(f"CREATE TABLE weekly_slots_upgrade {WEEKLY_SLOT_DEFINITION}")
        names = ",".join(columns)
        connection.execute(f"INSERT INTO weekly_slots_upgrade({names}) SELECT {names} FROM weekly_slots")
        connection.execute("DROP TABLE weekly_slots")
        connection.execute("ALTER TABLE weekly_slots_upgrade RENAME TO weekly_slots")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise sqlite3.IntegrityError("weekly_slot_references_invalid")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.execute(f"PRAGMA foreign_keys={foreign_keys}")
