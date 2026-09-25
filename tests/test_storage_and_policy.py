import json
import sqlite3
import asyncio
from types import SimpleNamespace

import pytest

from maxbot_v2.action_gate import ActionGate, ActionsClosed
from maxbot_v2.crypto import SecretBox
from maxbot_v2.db import initialize
from maxbot_v2.session_vault import EncryptedSessionFile
from maxbot_v2.max_adapter import PyMaxAdapter
from maxbot_v2.onboarding import member_proof
from scripts.backup import create_backup
from scripts.restore import restore_backup


def test_action_gate_fails_closed_then_checks_scope_and_expiry(tmp_path):
    gate = ActionGate(tmp_path / "missing.json")
    with pytest.raises(ActionsClosed):
        gate.require("send")
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps({"status": "authorized", "contract_reference": "ref-1", "expires_at": "2099-01-01T00:00:00Z", "scopes": ["connect"]}))
    gate = ActionGate(path)
    gate.require("connect")
    with pytest.raises(ActionsClosed):
        gate.require("send")


def test_pymax_adapter_checks_gate_and_requires_provider_message_id(tmp_path):
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps({"status": "authorized", "contract_reference": "ref", "expires_at": "2099-01-01T00:00:00Z", "scopes": ["connect", "send"]}))

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
    adapter = PyMaxAdapter(client, ActionGate(path))
    asyncio.run(adapter.connect())
    accepted = asyncio.run(adapter.send_message(chat_id=12, text="hello"))
    assert accepted.message_id == "msg-1"
    assert client.calls == ["connect", {"chat_id": 12, "text": "hello"}]
    closed = PyMaxAdapter(client, ActionGate(tmp_path / "missing.json"))
    with pytest.raises(ActionsClosed):
        asyncio.run(closed.send_message(chat_id=12, text="hello"))
    assert len(client.calls) == 2


def test_pinned_pymax_client_constructs_with_proxy_and_encrypted_session_vault(tmp_path):
    from importlib.metadata import version
    assert version("maxapi-python") == "2.4.1"
    vault = EncryptedSessionFile(10, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    adapter = PyMaxAdapter.create(phone="+70000000000", work_dir="", session_name="", proxy="socks5://127.0.0.1:1080", gate=ActionGate(tmp_path / "no-permission.json"), session_vault=vault)
    assert adapter.client is not None
    assert adapter.client.extra_config.proxy == "socks5://127.0.0.1:1080"
    assert not (tmp_path / "encrypted" / "account-10.session.enc").exists()


def test_membership_proof_rejects_wrong_group_and_missing_join_time():
    member = SimpleNamespace(id=12, status=SimpleNamespace(value="member"), join_time=123)
    assert member_proof(member, "12")
    assert not member_proof(member, "13")
    assert not member_proof(SimpleNamespace(id=12, status="member", join_time=0), "12")


def test_session_snapshot_is_encrypted_and_restorable(tmp_path):
    box = SecretBox(SecretBox.generate_key())
    vault = EncryptedSessionFile(7, durable_dir=tmp_path / "durable", runtime_dir=tmp_path / "runtime", box=box)
    work_dir, filename = vault.open()
    session = tmp_path / "runtime" / "account-7" / filename
    session.write_bytes(b"session token secret")
    vault.seal()
    encrypted = (tmp_path / "durable" / "account-7.session.enc").read_bytes()
    assert b"session token secret" not in encrypted
    assert not session.exists()
    vault.open()
    assert session.read_bytes() == b"session token secret"


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
