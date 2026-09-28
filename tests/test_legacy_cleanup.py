import sqlite3

from maxbot_v2.db import connect, initialize
from maxbot_v2.crypto import SecretBox
from maxbot_v2.session_vault import EncryptedSessionFile
from scripts.cleanup_unverified_accounts import apply_cleanup, inspect_database


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
