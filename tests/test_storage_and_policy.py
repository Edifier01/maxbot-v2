import sqlite3
import asyncio
import logging
from types import SimpleNamespace

from maxbot_v2.crypto import SecretBox
from maxbot_v2.db import connect, initialize
from maxbot_v2.egress import assign_ip
from maxbot_v2.session_vault import EncryptedSessionFile
from maxbot_v2.max_adapter import PyMaxAdapter
from maxbot_v2.onboarding import join_group_and_confirm_membership, member_proof, normalize_russian_phone
from scripts.backup import create_backup
from scripts.restore import restore_backup


def test_pymax_adapter_calls_provider_without_local_authorization_file():
    class FakeClient:
        def __init__(self):
            self.calls = []
        async def connect(self):
            self.calls.append("connect")
        async def send_message(self, **kwargs):
            self.calls.append(kwargs)
            return SimpleNamespace(id="msg-1")
        async def close(self):
            self.calls.append("close")

    client = FakeClient()
    adapter = PyMaxAdapter(client)
    asyncio.run(adapter.connect())
    accepted = asyncio.run(adapter.send_message(chat_id=12, text="hello"))
    assert accepted.message_id == "msg-1"
    assert client.calls == ["connect", {"chat_id": 12, "text": "hello"}]
    assert len(client.calls) == 2


def test_pymax_adapter_joins_and_refreshes_membership_from_provider():
    class Chats:
        def __init__(self):
            self.cached = True

        def _remove_cached_chat(self, _chat_id):
            self.cached = False

    class Client:
        def __init__(self):
            self.chats_api = Chats()
            self._app = SimpleNamespace(api=SimpleNamespace(chats=self.chats_api))

        async def join_group(self, link):
            assert link == "https://max.ru/join/test"
            return SimpleNamespace(id=7001)

        async def get_chat(self, _chat_id):
            return SimpleNamespace(id=7001, status="none" if self.chats_api.cached else "member", join_time=0 if self.chats_api.cached else 1)

    adapter = PyMaxAdapter(Client())
    assert asyncio.run(adapter.join_group("https://max.ru/join/test")).id == 7001
    assert member_proof(asyncio.run(adapter.get_chat(7001)), "7001")


def test_pinned_pymax_client_constructs_with_bound_ip_and_encrypted_session_vault(tmp_path):
    from importlib.metadata import version
    assert version("maxapi-python") == "2.4.1"
    vault = EncryptedSessionFile(10, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    adapter = PyMaxAdapter.create(phone="+70000000000", source_ip="62.109.20.186", session_vault=vault)
    assert adapter.client is not None
    assert adapter.client.extra_config.proxy is None
    assert not (tmp_path / "encrypted" / "account-10.session.enc").exists()


def test_failed_pymax_constructor_removes_decrypted_session(tmp_path, monkeypatch):
    import pymax

    vault = EncryptedSessionFile(10, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    vault.open()
    connection = sqlite3.connect(vault.work_path)
    connection.execute("CREATE TABLE sessions (token TEXT NOT NULL PRIMARY KEY)")
    connection.execute("INSERT INTO sessions(token) VALUES('previously-saved-token')")
    connection.commit()
    connection.close()
    vault.seal()

    def fail_constructor(**_kwargs):
        raise RuntimeError("synthetic constructor failure")

    monkeypatch.setattr(pymax, "Client", fail_constructor)
    try:
        PyMaxAdapter.create(phone="+79990000000", source_ip="62.109.20.186", session_vault=vault)
    except Exception:
        pass
    else:
        raise AssertionError("PyMax construction should fail")
    assert vault.encrypted_path.exists()
    assert not vault.work_path.exists()


def test_pymax_error_text_is_not_emitted_to_ordinary_logs(tmp_path, caplog):
    vault = EncryptedSessionFile(10, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    PyMaxAdapter.create(phone="+79990000000", source_ip="62.109.20.186", session_vault=vault)
    with caplog.at_level(logging.ERROR, logger="pymax.audit"):
        logging.getLogger("pymax.audit").error("synthetic-private-provider-response")
    assert "synthetic-private-provider-response" not in caplog.text


def test_membership_proof_rejects_wrong_group_and_missing_join_time():
    member = SimpleNamespace(id=12, status=SimpleNamespace(value="member"), join_time=123)
    assert member_proof(member, "12")
    assert not member_proof(member, "13")
    assert not member_proof(SimpleNamespace(id=12, status="member", join_time=0), "12")


def test_russian_phone_normalization_and_rejection():
    for raw in ("89991234567", "79991234567", "+79991234567", "9991234567", "8 (999) 123-45-67"):
        assert normalize_russian_phone(raw) == "+79991234567"
    for raw in ("+89991234567", "+19991234567", "89abc123456", "899912345"):
        try:
            normalize_russian_phone(raw)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid phone form: {raw!r}")


def test_auto_join_skips_join_when_already_a_member():
    class Adapter:
        async def get_chat(self, _chat_id):
            return SimpleNamespace(id=7001, status="member", join_time=1)

        async def join_group(self, _link):
            raise AssertionError("already a member")

    assert asyncio.run(join_group_and_confirm_membership(Adapter(), "https://max.ru/join/test", "7001")) == (True, None)


def test_auto_join_checks_membership_after_unknown_result_without_retry():
    class Adapter:
        def __init__(self):
            self.checks = 0
            self.joins = 0

        async def get_chat(self, _chat_id):
            self.checks += 1
            return SimpleNamespace(id=7001, status="member" if self.checks > 1 else "none", join_time=1 if self.checks > 1 else 0)

        async def join_group(self, _link):
            self.joins += 1
            raise TimeoutError("uncertain response")

    adapter = Adapter()
    assert asyncio.run(join_group_and_confirm_membership(adapter, "https://max.ru/join/test", "7001")) == (True, None)
    assert adapter.joins == 1


def test_auto_join_refuses_a_different_chat():
    class Adapter:
        async def get_chat(self, _chat_id):
            return SimpleNamespace(id=7001, status="none", join_time=0)

        async def join_group(self, _link):
            return SimpleNamespace(id=7002, status="member", join_time=1)

    try:
        asyncio.run(join_group_and_confirm_membership(Adapter(), "https://max.ru/join/test", "7001"))
    except ValueError as exc:
        assert str(exc) == "group_destination_mismatch"
    else:
        raise AssertionError("joined a different chat")


def test_session_snapshot_is_encrypted_and_restorable(tmp_path):
    box = SecretBox(SecretBox.generate_key())
    vault = EncryptedSessionFile(7, durable_dir=tmp_path / "durable", runtime_dir=tmp_path / "runtime", box=box)
    vault.open()
    session = vault.work_path
    connection = sqlite3.connect(session)
    connection.execute("CREATE TABLE sessions (token TEXT NOT NULL PRIMARY KEY)")
    connection.execute("INSERT INTO sessions(token) VALUES('session-token-secret')")
    connection.commit()
    connection.close()
    vault.seal()
    encrypted = (tmp_path / "durable" / "account-7.session.enc").read_bytes()
    assert b"session-token-secret" not in encrypted
    assert not session.exists()
    vault.open()
    restored = sqlite3.connect(session)
    assert restored.execute("SELECT token FROM sessions").fetchone() == ("session-token-secret",)
    restored.close()


def test_existing_session_generation_schema_and_file_survive_restart(tmp_path):
    connection = connect(tmp_path / "existing.sqlite3")
    initialize(connection)
    group_id = connection.execute("INSERT INTO groups(name,invite_link) VALUES('group','https://max.ru/join/test')").lastrowid
    account_id = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,'+79990000000','test','active')", (group_id,)).lastrowid
    connection.execute("UPDATE accounts SET session_generation=2 WHERE id=?", (account_id,))
    initialize(connection)
    assert connection.execute("SELECT session_generation FROM accounts WHERE id=?", (account_id,)).fetchone()[0] == 2
    connection.close()
    box = SecretBox(SecretBox.generate_key())
    old = EncryptedSessionFile(account_id, generation=2, durable_dir=tmp_path / "sessions", runtime_dir=tmp_path / "runtime", box=box)
    old.open()
    session_db = sqlite3.connect(old.work_path)
    session_db.execute("CREATE TABLE sessions (token TEXT NOT NULL PRIMARY KEY)")
    session_db.execute("INSERT INTO sessions(token) VALUES('generation-token')")
    session_db.commit()
    session_db.close()
    old.seal()
    assert old.encrypted_path.name == f"account-{account_id}-generation-2.session.enc"
    restored = EncryptedSessionFile(account_id, generation=2, durable_dir=tmp_path / "sessions", runtime_dir=tmp_path / "runtime", box=box)
    restored.open()
    restored_db = sqlite3.connect(restored.work_path)
    assert restored_db.execute("SELECT token FROM sessions").fetchone() == ("generation-token",)
    restored_db.close()


def test_backup_and_restore_verify_database_and_encrypted_sessions(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    data = source / "data"
    (data / "sessions").mkdir(parents=True)
    db_path = data / "maxbot.sqlite3"
    connection = sqlite3.connect(db_path)
    initialize(connection)
    connection.execute("INSERT INTO groups(name,invite_link) VALUES('group','https://max.ru/invite')")
    connection.commit()
    connection.close()
    (data / "sessions" / "account-1.session.enc").write_bytes(b"encrypted-content")
    archive = create_backup(db_path, data, tmp_path / "backup.zip")
    restored = tmp_path / "restored"
    restore_backup(archive, restored)
    connection = sqlite3.connect(restored / "maxbot.sqlite3")
    assert connection.execute("SELECT name FROM groups").fetchone()[0] == "group"
    connection.close()
    assert (restored / "sessions" / "account-1.session.enc").read_bytes() == b"encrypted-content"


def test_seal_does_not_persist_a_pymax_database_without_a_session_token(tmp_path):
    from maxbot_v2.crypto import SecretBox
    from maxbot_v2.session_vault import EncryptedSessionFile

    vault = EncryptedSessionFile(31, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    vault.open()
    connection = sqlite3.connect(vault.work_path)
    connection.execute("CREATE TABLE sessions (token TEXT NOT NULL PRIMARY KEY)")
    connection.close()

    vault.seal()

    assert not vault.encrypted_path.exists()


def test_tokenless_attempt_does_not_replace_an_existing_session_generation(tmp_path):
    box = SecretBox(SecretBox.generate_key())
    vault = EncryptedSessionFile(35, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=box)
    vault.open()
    connection = sqlite3.connect(vault.work_path)
    connection.execute("CREATE TABLE sessions (token TEXT NOT NULL PRIMARY KEY)")
    connection.execute("INSERT INTO sessions(token) VALUES('valid-old-token')")
    connection.commit()
    connection.close()
    vault.seal()
    previous = vault.encrypted_path.read_bytes()

    vault.open()
    connection = sqlite3.connect(vault.work_path)
    connection.execute("DELETE FROM sessions")
    connection.commit()
    connection.close()
    vault.seal()

    assert vault.encrypted_path.read_bytes() == previous


def test_snapshot_encrypts_a_live_session_without_removing_the_working_database(tmp_path):
    from maxbot_v2.crypto import SecretBox
    from maxbot_v2.session_vault import EncryptedSessionFile

    box = SecretBox(SecretBox.generate_key())
    vault = EncryptedSessionFile(32, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=box)
    vault.open()
    connection = sqlite3.connect(vault.work_path)
    connection.execute("CREATE TABLE sessions (token TEXT NOT NULL PRIMARY KEY)")
    connection.execute("INSERT INTO sessions(token) VALUES('synthetic-token')")
    connection.commit()
    connection.close()

    vault.snapshot()

    assert vault.encrypted_path.exists()
    assert vault.work_path.exists()
    decrypted = box.decrypt_bytes(vault.encrypted_path.read_bytes())
    assert b"synthetic-token" not in vault.encrypted_path.read_bytes()
    restored = sqlite3.connect(":memory:")
    restored.deserialize(decrypted)
    assert restored.execute("SELECT token FROM sessions").fetchone() == ("synthetic-token",)


def test_initialize_conservatively_backfills_authentication_once(tmp_path):
    connection = sqlite3.connect(tmp_path / "legacy.db")
    connection.execute("CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL, invite_link TEXT NOT NULL, chat_id TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    connection.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES groups(id), phone TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL, max_user_id TEXT, status TEXT NOT NULL DEFAULT 'pending', send_weekday INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    connection.execute("INSERT INTO groups(name,invite_link) VALUES('group','https://max.ru/join/test')")
    connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(1,'+79990000001','active','active')")
    connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(1,'+79990000002','membership','needs_membership')")
    connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(1,'+79990000003','pending','pending')")

    initialize(connection)
    connection.execute("UPDATE accounts SET auth_state='reauth_required' WHERE id=1")
    initialize(connection)

    states = [row[0] for row in connection.execute("SELECT auth_state FROM accounts ORDER BY id")]
    connection.close()
    assert states == ["reauth_required", "authenticated", "unverified"]


def test_allocator_ignores_old_failed_ip_assignments(tmp_path):
    connection = connect(tmp_path / "allocator.db")
    initialize(connection)
    group_id = connection.execute("INSERT INTO groups(name,invite_link) VALUES('group','https://max.ru/join/test')").lastrowid
    ip_a = connection.execute("INSERT INTO server_ips(address,enabled,available) VALUES('62.109.20.186',1,1)").lastrowid
    connection.execute("INSERT INTO server_ips(address,enabled,available) VALUES('62.109.20.187',1,1)")
    accounts = []
    for index in range(4):
        account_id = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'pending')", (group_id, f'+7999000000{index}', 'guest')).lastrowid
        connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_a))
        accounts.append(account_id)
    connection.execute("UPDATE accounts SET auth_state='authenticated' WHERE id=?", (accounts[0],))
    connection.execute("INSERT INTO onboarding_invites(group_id,token_hash,token_ciphertext,created_at,expires_at) VALUES(1,'hash','cipher','2026-09-27','2099-01-01')")
    invite_id = connection.execute("SELECT id FROM onboarding_invites").fetchone()[0]
    connection.execute(
        "INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,state,account_id,expires_at,created_at,updated_at) "
        "VALUES('active-attempt',?,'hash','csrf','waiting_code',?,'2099-01-01','2026-09-27','2026-09-27')",
        (invite_id, accounts[1]),
    )
    new_id = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'pending')", (group_id, '+799900000099', 'new')).lastrowid

    selected = assign_ip(connection, new_id)

    assert selected == '62.109.20.187'
    connection.close()
