import sqlite3
import sys
from unittest.mock import patch

import pytest

from maxbot_v2.db import connect, initialize
from maxbot_v2.crypto import SecretBox
from maxbot_v2.lifecycle import phone_fingerprint
from maxbot_v2.session_vault import EncryptedSessionFile
from scripts.cleanup_unverified_accounts import apply_cleanup, inspect_database, main


def prepare_database(tmp_path):
    db_path = tmp_path / "accounts.sqlite3"
    connection = connect(db_path)
    initialize(connection)
    group_id = connection.execute(
        "INSERT INTO groups(name,invite_link) VALUES('group','https://max.ru/join/test')"
    ).lastrowid
    eligible = connection.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?, '+79990000001','Guest','pending')",
        (group_id,),
    ).lastrowid
    connected = connection.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state,ever_authenticated) "
        "VALUES(?, '+79990000002','Member','needs_membership','authenticated',1)",
        (group_id,),
    ).lastrowid
    pending_ip = connection.execute(
        "INSERT INTO server_ips(address,enabled,available) VALUES('62.109.20.186',1,1)"
    ).lastrowid
    connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (eligible, pending_ip))
    connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (connected, pending_ip))
    connection.close()
    return db_path, eligible, connected, group_id


def test_legacy_cleanup_dry_run_lists_only_safe_ids_without_mutating(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, connected, _group = prepare_database(tmp_path)
    data_dir = tmp_path / "data"

    report = inspect_database(db_path, data_dir, tmp_path / "runtime")

    assert report == [(eligible, "eligible")]
    db = connect(db_path)
    assert db.execute("SELECT lifecycle FROM accounts WHERE id=?", (eligible,)).fetchone()[0] == "active"
    assert db.execute("SELECT lifecycle FROM accounts WHERE id=?", (connected,)).fetchone()[0] == "active"
    db.close()


def test_legacy_cleanup_skips_live_runtime_session_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, _connected, _group = prepare_database(tmp_path)
    runtime_dir = tmp_path / "runtime"
    (runtime_dir / f"account-{eligible}").mkdir(parents=True)

    report = inspect_database(db_path, tmp_path / "data", runtime_dir)

    assert report == [(eligible, "runtime_session_present")]


def test_legacy_cleanup_skips_completed_attempt_without_auth_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, _connected, group_id = prepare_database(tmp_path)
    db = connect(db_path)
    invite_id = db.execute(
        "INSERT INTO onboarding_invites(group_id,token_hash,token_ciphertext,created_at,expires_at) "
        "VALUES(?, 'token-hash', 'ciphertext', '2026-09-27', '2099-01-01')",
        (group_id,),
    ).lastrowid
    db.execute(
        "INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,state,account_id,expires_at,created_at,updated_at) "
        "VALUES('completed-attempt',?,'token-hash','csrf-hash','completed',?,'2099-01-01','2026-09-27','2026-09-27')",
        (invite_id, eligible),
    )
    db.close()

    report = inspect_database(db_path, tmp_path / "data", tmp_path / "runtime")

    assert report == [(eligible, "completed_attempt")]


def test_legacy_cleanup_apply_anonymizes_only_unverified_account_and_keeps_neighbor(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, connected, _group = prepare_database(tmp_path)
    data_dir = tmp_path / "data"
    runtime_dir = tmp_path / "runtime"

    report = apply_cleanup(db_path, data_dir, runtime_dir, [eligible])

    assert report == [(eligible, "deleted")]
    db = connect(db_path)
    deleted = db.execute("SELECT lifecycle,phone,full_name,phone_fingerprint FROM accounts WHERE id=?", (eligible,)).fetchone()
    assert deleted["lifecycle"] == "deleted"
    assert deleted["phone"] == f"deleted:{eligible}"
    assert deleted["full_name"] == ""
    assert len(deleted["phone_fingerprint"]) == 64
    assert db.execute("SELECT lifecycle,phone FROM accounts WHERE id=?", (connected,)).fetchone()["lifecycle"] == "active"
    assert db.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (eligible,)).fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (connected,)).fetchone()[0] == 1
    events = db.execute(
        "SELECT stage,result FROM onboarding_events WHERE account_id=? ORDER BY id",
        (eligible,),
    ).fetchall()
    assert [tuple(event) for event in events] == [("deletion", "started"), ("session_cleanup", "deleted")]
    db.close()


def test_legacy_cleanup_skips_accounts_with_any_saved_token_generation(tmp_path, monkeypatch):
    key = SecretBox.generate_key()
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", key)
    db_path, eligible, _connected, group_id = prepare_database(tmp_path)
    db = connect(db_path)
    token_account = db.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?, '+79990000003','Guest','pending')",
        (group_id,),
    ).lastrowid
    db.close()
    data_dir = tmp_path / "data"
    vault = EncryptedSessionFile(token_account, generation=2, durable_dir=data_dir / "sessions", runtime_dir=tmp_path / "runtime", box=SecretBox(key))
    vault.open()
    session_db = sqlite3.connect(vault.work_path)
    session_db.execute("CREATE TABLE sessions(token TEXT NOT NULL PRIMARY KEY)")
    session_db.execute("INSERT INTO sessions(token) VALUES('synthetic-token')")
    session_db.commit()
    session_db.close()
    vault.snapshot()

    report = inspect_database(db_path, data_dir, tmp_path / "runtime")

    assert report == [(eligible, "eligible"), (token_account, "saved_session_token")]


@pytest.mark.parametrize("legacy_phone", ["+89990000001", " +89990000001 "])
def test_legacy_cleanup_normalizes_plus8_before_retaining_fingerprint(tmp_path, monkeypatch, legacy_phone):
    key = SecretBox.generate_key()
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", key)
    db_path, eligible, _connected, _group = prepare_database(tmp_path)
    db = connect(db_path)
    db.execute("UPDATE accounts SET phone=? WHERE id=?", (legacy_phone, eligible))
    db.close()

    result = apply_cleanup(db_path, tmp_path / "data", tmp_path / "runtime", [eligible])

    assert result == [(eligible, "deleted")]
    db = connect(db_path)
    row = db.execute("SELECT lifecycle,phone_fingerprint FROM accounts WHERE id=?", (eligible,)).fetchone()
    assert row["lifecycle"] == "deleted"
    assert row["phone_fingerprint"] == phone_fingerprint("+79990000001", key)
    db.close()


def test_legacy_cleanup_anonymizes_unparseable_phone_without_send_history(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, _connected, _group = prepare_database(tmp_path)
    db = connect(db_path)
    db.execute("UPDATE accounts SET phone='legacy-invalid' WHERE id=?", (eligible,))
    db.close()

    result = apply_cleanup(db_path, tmp_path / "data", tmp_path / "runtime", [eligible])

    assert result == [(eligible, "deleted")]
    db = connect(db_path)
    row = db.execute("SELECT lifecycle,phone,full_name,phone_fingerprint FROM accounts WHERE id=?", (eligible,)).fetchone()
    assert tuple(row) == ("deleted", f"deleted:{eligible}", "", None)
    db.close()


def test_legacy_cleanup_preserves_unparseable_phone_with_slot_history(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, _connected, group_id = prepare_database(tmp_path)
    db = connect(db_path)
    db.execute("UPDATE accounts SET phone='legacy-invalid' WHERE id=?", (eligible,))
    version_id = db.execute(
        "INSERT INTO message_versions(created_at,checksum) VALUES('2026-09-28','test-checksum')"
    ).lastrowid
    db.execute(
        "INSERT INTO weekly_slots(slot_id,account_id,group_id,week_start,scheduled_date,message_version_id,text,updated_at) "
        "VALUES('old-slot',?,?,'2026-09-28','2026-09-28',?,'test message','2026-09-28')",
        (eligible, group_id, version_id),
    )
    db.close()

    result = apply_cleanup(db_path, tmp_path / "data", tmp_path / "runtime", [eligible])

    assert result == [(eligible, "send_history")]
    db = connect(db_path)
    row = db.execute("SELECT lifecycle,phone FROM accounts WHERE id=?", (eligible,)).fetchone()
    assert tuple(row) == ("active", "legacy-invalid")
    db.close()


def test_legacy_cleanup_apply_returns_failure_when_any_reviewed_id_is_skipped(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, connected, _group = prepare_database(tmp_path)
    monkeypatch.setattr(sys, "argv", [
        "cleanup_unverified_accounts", "--db-path", str(db_path),
        "--data-dir", str(tmp_path / "data"), "--runtime-dir", str(tmp_path / "runtime"),
        "--apply", "--account-ids", str(eligible), str(connected),
    ])

    result = main()

    assert result == 1
    output = capsys.readouterr().out
    assert f"account_id={eligible} result=deleted" in output
    assert f"account_id={connected} result=not_eligible" in output


def test_legacy_cleanup_apply_returns_failure_when_selected_cleanup_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    db_path, eligible, _connected, _group = prepare_database(tmp_path)
    monkeypatch.setattr(sys, "argv", [
        "cleanup_unverified_accounts", "--db-path", str(db_path),
        "--data-dir", str(tmp_path / "data"), "--runtime-dir", str(tmp_path / "runtime"),
        "--apply", "--account-ids", str(eligible),
    ])

    with patch("scripts.cleanup_unverified_accounts.apply_cleanup", return_value=[(eligible, "cleanup_incomplete")]):
        result = main()

    assert result == 1
    assert f"account_id={eligible} result=cleanup_incomplete" in capsys.readouterr().out
