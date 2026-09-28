"""Review and optionally remove legacy accounts that never completed MAX login.

Dry-run is the default. The apply mode is intentionally conservative: accounts
with active/ambiguous attempts, any send/slot/operation history, auth markers,
or unreadable/token-backed session generations are skipped.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from maxbot_v2.db import connect
from maxbot_v2.lifecycle import phone_fingerprint
from maxbot_v2.onboarding import normalize_russian_phone
from maxbot_v2.session_vault import EncryptedSessionFile, SessionDeletionError, SessionSnapshotUnavailable


TERMINAL_STATES = ("completed", "failed", "expired", "cancelled")


def candidate_reason(connection, account, vault: EncryptedSessionFile, runtime_dir: str | Path) -> str | None:
    if account["lifecycle"] != "active":
        return "lifecycle_not_active"
    if account["ever_authenticated"] or account["auth_state"] in {"authenticated", "reauth_required"}:
        return "authentication_history"
    if account["status"] in {"active", "needs_membership"} or account["max_user_id"]:
        return "authentication_marker"
    if connection.execute(
        "SELECT 1 FROM onboarding_sessions WHERE account_id=? AND state='completed' LIMIT 1",
        (account["id"],),
    ).fetchone():
        return "completed_attempt"
    if connection.execute(
        "SELECT 1 FROM onboarding_sessions WHERE account_id=? AND state NOT IN ('completed','failed','expired','cancelled') LIMIT 1",
        (account["id"],),
    ).fetchone():
        return "attempt_not_terminal"
    for table in ("weekly_slots", "operations", "send_log"):
        if connection.execute(f"SELECT 1 FROM {table} WHERE account_id=? LIMIT 1", (account["id"],)).fetchone():
            return "send_history"
    try:
        if vault.has_saved_session_token_any_generation():
            return "saved_session_token"
    except SessionSnapshotUnavailable:
        return "session_unreadable"
    runtime_pattern = re.compile(rf"account-{int(account['id'])}(?:-generation-[0-9]+)?\Z")
    try:
        if Path(runtime_dir).exists() and any(
            runtime_pattern.fullmatch(path.name) for path in Path(runtime_dir).iterdir()
        ):
            return "runtime_session_present"
    except OSError:
        return "session_unreadable"
    return None


def inspect_database(db_path: str | Path, data_dir: str | Path, runtime_dir: str | Path) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []
    connection = connect(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM accounts WHERE lifecycle='active' AND ever_authenticated=0 ORDER BY id"
        ).fetchall()
        for row in rows:
            account_id = int(row["id"])
            try:
                vault = EncryptedSessionFile(
                    account_id, generation=int(row["session_generation"]),
                    durable_dir=Path(data_dir) / "sessions", runtime_dir=runtime_dir,
                )
                reason = candidate_reason(connection, row, vault, runtime_dir)
            except Exception:
                reason = "session_unreadable"
            results.append((account_id, reason or "eligible"))
    finally:
        connection.close()
    return results


def apply_cleanup(db_path: str | Path, data_dir: str | Path, runtime_dir: str | Path, account_ids: list[int]) -> list[tuple[int, str]]:
    outcomes: list[tuple[int, str]] = []
    connection = connect(db_path)
    try:
        for account_id in account_ids:
            connection.execute("BEGIN IMMEDIATE")
            account = connection.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
            if account is None:
                connection.rollback()
                outcomes.append((account_id, "account_missing"))
                continue
            try:
                vault = EncryptedSessionFile(
                    account_id, generation=int(account["session_generation"]),
                    durable_dir=Path(data_dir) / "sessions", runtime_dir=runtime_dir,
                )
                reason = candidate_reason(connection, account, vault, runtime_dir)
            except Exception:
                connection.rollback()
                outcomes.append((account_id, "session_unreadable"))
                continue
            if reason is not None:
                connection.rollback()
                outcomes.append((account_id, reason))
                continue
            raw_phone = str(account["phone"] or "").strip()
            try:
                canonical_phone = normalize_russian_phone(
                    raw_phone.removeprefix("+8") if raw_phone.startswith("+8") else raw_phone
                )
            except ValueError:
                # candidate_reason already ruled out all send history, so an old
                # unparseable phone needs no retained weekly-limit fingerprint.
                canonical_phone = None
            try:
                fingerprint = account["phone_fingerprint"] or (
                    phone_fingerprint(canonical_phone, os.getenv("DATA_ENCRYPTION_KEY", ""))
                    if canonical_phone else None
                )
            except ValueError:
                connection.rollback()
                outcomes.append((account_id, "fingerprint_key_unavailable"))
                continue
            connection.execute(
                "UPDATE accounts SET lifecycle='delete_pending',deletion_reason='legacy_cleanup',phone_fingerprint=? WHERE id=?",
                (fingerprint, account_id),
            )
            assignment = connection.execute(
                "SELECT ip_id FROM ip_assignments WHERE account_id=?", (account_id,),
            ).fetchone()
            ip_id = int(assignment[0]) if assignment is not None else None
            if ip_id is None:
                prior = connection.execute(
                    "SELECT ip_id FROM onboarding_events WHERE account_id=? AND ip_id IS NOT NULL ORDER BY id DESC LIMIT 1",
                    (account_id,),
                ).fetchone()
                ip_id = int(prior[0]) if prior is not None else None
            connection.execute(
                "INSERT INTO onboarding_events(created_at,attempt_id,group_id,account_id,ip_id,stage,result) "
                "VALUES(CURRENT_TIMESTAMP,?,?,?,?, 'deletion','started')",
                (f"account-{account_id}", account["group_id"], account_id, ip_id),
            )
            connection.execute("DELETE FROM ip_assignments WHERE account_id=?", (account_id,))
            connection.execute(
                "UPDATE weekly_slots SET status='blocked',error_code='account_deleted',updated_at=CURRENT_TIMESTAMP WHERE account_id=? AND status='queued'",
                (account_id,),
            )
            connection.commit()
            try:
                vault.delete_all_generations()
            except (SessionDeletionError, OSError):
                connection.execute(
                    "INSERT INTO onboarding_events(created_at,attempt_id,group_id,account_id,ip_id,stage,result,error_class) "
                    "VALUES(CURRENT_TIMESTAMP,?,?,?,?,'session_cleanup','failed','SessionDeletionError')",
                    (f"account-{account_id}", account["group_id"], account_id, ip_id),
                )
                connection.commit()
                outcomes.append((account_id, "cleanup_incomplete"))
                continue
            connection.execute("BEGIN IMMEDIATE")
            unresolved = connection.execute(
                "SELECT 1 FROM operations WHERE account_id=? AND status IN ('in_flight','unknown') LIMIT 1",
                (account_id,),
            ).fetchone()
            if unresolved:
                connection.rollback()
                outcomes.append((account_id, "operation_reconciliation_required"))
                continue
            connection.execute("UPDATE onboarding_sessions SET phone=NULL,full_name=NULL WHERE account_id=?", (account_id,))
            connection.execute(
                "UPDATE accounts SET lifecycle='deleted',phone=?,full_name='',max_user_id=NULL,auth_state='unverified',status='pending' WHERE id=?",
                (f"deleted:{account_id}", account_id),
            )
            connection.execute(
                "INSERT INTO audit_log(created_at,kind,group_id,account_id,detail) VALUES(CURRENT_TIMESTAMP,'account_deleted',?,?,'{}')",
                (account["group_id"], account_id),
            )
            connection.execute(
                "INSERT INTO onboarding_events(created_at,attempt_id,group_id,account_id,ip_id,stage,result) "
                "VALUES(CURRENT_TIMESTAMP,?,?,?,?, 'session_cleanup','deleted')",
                (f"account-{account_id}", account["group_id"], account_id, ip_id),
            )
            connection.commit()
            outcomes.append((account_id, "deleted"))
    finally:
        connection.close()
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", default=os.getenv("DATABASE_PATH", "/data/maxbot.sqlite3"))
    parser.add_argument("--data-dir", default=os.getenv("DATA_DIR", "/data"))
    parser.add_argument("--runtime-dir", default=os.getenv("SESSION_RUNTIME_DIR", "/run/maxbot-sessions"))
    parser.add_argument("--apply", action="store_true", help="apply only after reviewing the dry-run account-ID report")
    parser.add_argument("--account-ids", nargs="+", type=int, help="exact reviewed account IDs to apply")
    args = parser.parse_args()
    if args.apply and not args.account_ids:
        parser.error("--apply requires --account-ids with the exact reviewed IDs")
    report = inspect_database(args.db_path, args.data_dir, args.runtime_dir)
    print("mode=apply" if args.apply else "mode=dry-run")
    for account_id, reason in report:
        print(f"account_id={account_id} result={reason}")
    if args.apply:
        eligible = {account_id for account_id, reason in report if reason == "eligible"}
        requested = list(dict.fromkeys(args.account_ids))
        selected = [account_id for account_id in requested if account_id in eligible]
        incomplete = False
        for account_id in requested:
            if account_id not in eligible:
                print(f"account_id={account_id} result=not_eligible")
                incomplete = True
        for account_id, result in apply_cleanup(args.db_path, args.data_dir, args.runtime_dir, selected):
            print(f"account_id={account_id} result={result}")
            if result != "deleted":
                incomplete = True
        return int(incomplete)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
