import asyncio
import threading

import bcrypt
import pytest
from pymax.exceptions import ApiError
from pymax.protocol.enums import Opcode
from fastapi.testclient import TestClient

from maxbot_v2.app import create_app
from maxbot_v2.crypto import SecretBox
from maxbot_v2.db import connect
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.scheduling import create_weekly_slot
from maxbot_v2.security import digest_token


def owner_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    monkeypatch.setattr("maxbot_v2.app.host_addresses", lambda: {"62.109.20.186"})
    monkeypatch.setattr("maxbot_v2.egress.host_addresses", lambda: {"62.109.20.186"})
    monkeypatch.setattr("maxbot_v2.egress.probe_address", lambda _address: True)
    app = create_app(
        db_path=tmp_path / "app.db",
        data_dir=tmp_path / "data",
        owner_username="edifier8989",
        owner_password_hash=bcrypt.hashpw(b"correct horse battery", bcrypt.gensalt()).decode(),
        secret_key="unit-test-app-secret-key-with-32-chars",
        secure_cookies=False,
    )
    client = TestClient(app, base_url="https://test.local")
    db = connect(app.state.database)
    db.execute("INSERT INTO server_ips(address,enabled,available) VALUES('62.109.20.186',1,1)")
    db.close()
    response = client.post("/api/auth/login", json={"username": "edifier8989", "password": "correct horse battery"})
    assert response.status_code == 200
    return client, response.json()["csrf_token"]


def test_group_invite_and_message_pool_are_owner_scoped(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"})
    assert group.status_code == 201
    group_id = group.json()["id"]
    issued = client.post(f"/api/groups/{group_id}/onboarding-link?days=7", headers=headers, json={})
    assert issued.status_code == 200
    guest_url = issued.json()["url"]
    token = guest_url.rsplit("/", 1)[1]
    assert client.get(f"/join-info/{token}").json()["group"] == "Клуб"
    assert client.delete(f"/api/groups/{group_id}/onboarding-link", headers=headers).json()["revoked"]
    assert client.get(f"/join-info/{token}").status_code == 404
    saved = client.put("/api/messages", headers=headers, json={"texts": ["Один", "Два"]})
    assert saved.status_code == 200
    assert client.get("/api/messages").json()["texts"] == ["Один", "Два"]
    assert client.put("/api/messages", headers=headers, json={"texts": ["same", "same"]}).status_code == 422


def test_reopening_onboarding_link_returns_the_existing_group_link(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]

    first = client.post(f"/api/groups/{group_id}/onboarding-link", headers=headers, json={})
    assert first.status_code == 200
    first_token = first.json()["url"].rsplit("/", 1)[1]
    second = client.post(f"/api/groups/{group_id}/onboarding-link", headers=headers, json={})

    assert second.status_code == 200
    assert second.json()["url"] == first.json()["url"]
    assert client.get(f"/join-info/{first_token}").status_code == 200


def test_new_group_has_a_guest_link_without_second_admin_action(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    first = client.get(f"/api/groups/{group_id}/onboarding-link").json()
    second = client.get(f"/api/groups/{group_id}/onboarding-link").json()
    assert first["status"] == "active"
    assert first["url"] == second["url"]
    assert first["max_uses"] is None


def test_new_group_link_is_short_and_opens_guest_form(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post(
        "/api/groups", headers={"X-CSRF-Token": csrf},
        json={"name": "Клуб", "invite_link": "https://max.ru/join/test"},
    ).json()["id"]

    url = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"]
    assert url.startswith("https://test.local/j/")
    token = url.rsplit("/", 1)[1]
    assert len(token) == 22
    assert client.get(f"/j/{token}").status_code == 200
    assert client.get(f"/join-info/{token}").json()["group"] == "Клуб"


def test_existing_long_link_keeps_its_url_and_opens_guest_form(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post(
        "/api/groups", headers={"X-CSRF-Token": csrf},
        json={"name": "Клуб", "invite_link": "https://max.ru/join/test"},
    ).json()["id"]
    old_token = "a" * 43
    connection = connect(client.app.state.database)
    try:
        connection.execute(
            "UPDATE onboarding_invites SET token_hash=?, token_ciphertext=? WHERE group_id=?",
            (digest_token(old_token, "unit-test-app-secret-key-with-32-chars"),
             SecretBox().encrypt(old_token), group_id),
        )
    finally:
        connection.close()

    expected_url = f"https://test.local/join/{old_token}"
    assert client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"] == expected_url
    assert client.post(
        f"/api/groups/{group_id}/onboarding-link", headers={"X-CSRF-Token": csrf}, json={},
    ).json()["url"] == expected_url
    assert client.get(f"/join/{old_token}").status_code == 200


def test_start_normalizes_phone_and_reuses_legacy_pending_account(tmp_path, monkeypatch):
    real_create_task = asyncio.create_task

    def skip(coro, **_kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coro.close()
            return None
        return real_create_task(coro, **_kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip)
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    db = connect(client.app.state.database)
    legacy_id = db.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,'+89991234567','Иван','pending')", (group_id,)).lastrowid
    ip_id = db.execute("SELECT id FROM server_ips WHERE address='62.109.20.186'").fetchone()[0]
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (legacy_id, ip_id))
    db.close()
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]
    start = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "8 (999) 123-45-67"})
    assert start.status_code == 200
    db = connect(client.app.state.database)
    row = db.execute("SELECT id,phone FROM accounts WHERE id=?", (legacy_id,)).fetchone()
    assert (row["id"], row["phone"]) == (legacy_id, "+79991234567")
    assert db.execute("SELECT phone FROM onboarding_sessions WHERE id=?", (start.json()["session_id"],)).fetchone()[0] == "+79991234567"
    db.close()


def test_authenticated_membership_attempt_survives_auth_expiry_and_cannot_retry_login(tmp_path, monkeypatch):
    real_create_task = asyncio.create_task

    def skip(coro, **_kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coro.close()
            return None
        return real_create_task(coro, **_kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip)
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]
    first = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "89991234567"})
    db = connect(client.app.state.database)
    db.execute("UPDATE onboarding_sessions SET state='waiting_membership',expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (first.json()["session_id"],))
    db.execute("UPDATE accounts SET status='needs_membership',auth_state='authenticated' WHERE phone='+79991234567'")
    db.close()
    monkeypatch.setattr("maxbot_v2.app.bootstrap_ips", lambda _connection: None)

    with TestClient(client.app, base_url="https://test.local") as restarted:
        status = restarted.get(f"/api/public/onboarding/{token}/{first.json()['session_id']}")
        second = restarted.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79991234567"})

    assert status.json()["state"] == "waiting_membership"
    assert status.json()["retryable"] is False
    connection = connect(client.app.state.database)
    invite_expiry = connection.execute("SELECT expires_at FROM onboarding_invites WHERE group_id=?", (group_id,)).fetchone()[0]
    connection.close()
    assert status.json()["expires_at"] == invite_expiry
    assert second.status_code == 409
    assert second.json()["detail"] == "phone_already_exists"
    connection = connect(client.app.state.database)
    connection.execute("UPDATE onboarding_invites SET expires_at='2000-01-01T00:00:00+00:00' WHERE group_id=?", (group_id,))
    connection.close()
    expired = client.get(f"/api/public/onboarding/{token}/{first.json()['session_id']}")
    assert expired.json()["state"] == "cancelled"
    assert expired.json()["error"] == "invite_unavailable"
    assert expired.json()["retryable"] is False


def test_expired_attempt_releases_one_use_invite_before_capacity_check(tmp_path, monkeypatch):
    real_create_task = asyncio.create_task

    def skip(coro, **_kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coro.close()
            return None
        return real_create_task(coro, **_kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip)
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    token = client.post(f"/api/groups/{group_id}/onboarding-link?max_uses=1", headers=headers, json={}).json()["url"].rsplit("/", 1)[1]
    first = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79991234567"})
    assert first.status_code == 200
    connection = connect(client.app.state.database)
    connection.execute("UPDATE onboarding_sessions SET state='waiting_code',expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (first.json()["session_id"],))
    connection.close()

    second = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Пётр", "phone": "+79991234568"})

    assert second.status_code == 200
    connection = connect(client.app.state.database)
    states = [row[0] for row in connection.execute("SELECT state FROM onboarding_sessions ORDER BY created_at,id")]
    connection.close()
    assert states == ["expired", "starting"]


def test_ip_api_splits_assignments_authentication_and_live_attempts(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    ip_id = client.get("/api/ips").json()[0]["id"]
    connection = connect(client.app.state.database)
    accounts = []
    for index in range(3):
        account_id = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'pending')", (group_id, f'+7999000000{index}', 'guest')).lastrowid
        connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
        accounts.append(account_id)
    connection.execute("UPDATE accounts SET auth_state='authenticated',status='needs_membership',ever_authenticated=1 WHERE id=?", (accounts[0],))
    invite = connection.execute("SELECT id,token_hash FROM onboarding_invites WHERE group_id=?", (group_id,)).fetchone()
    invite_id = invite["id"]
    connection.execute("INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,state,account_id,expires_at,created_at,updated_at) VALUES('live-count',?,'hash-counts','csrf','waiting_code',?,'2099-01-01','2026-09-27','2026-09-27')", (invite_id, accounts[1]))
    connection.execute("UPDATE onboarding_sessions SET token_hash=? WHERE id='live-count'", (invite["token_hash"],))
    connection.execute("INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,state,account_id,expires_at,created_at,updated_at) VALUES('failed-count',?,?,?,'failed',?,'2099-01-01','2026-09-27','2026-09-27')", (invite_id, invite["token_hash"], 'csrf', accounts[2]))
    connection.close()

    ip = next(row for row in client.get("/api/ips").json() if row["id"] == ip_id)

    assert ip["assigned_count"] == 3
    assert ip["authenticated_count"] == 1
    assert ip["in_progress_count"] == 1
    assert ip["unconfirmed_count"] == 1
    group = next(row for row in client.get("/api/groups").json() if row["id"] == group_id)
    assert group["account_count"] == 1
    assert group["authenticated_account_count"] == 1
    assert group["onboarding_attempt_count"] == 1
    assert group["in_progress_account_count"] == 1
    assert group["unconfirmed_account_count"] == 1


def test_guest_form_rejects_duplicate_code_and_password_while_verifying(tmp_path, monkeypatch):
    real_create_task = asyncio.create_task

    def skip(coro, **_kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coro.close()
            return None
        return real_create_task(coro, **_kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip)
    client, csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]
    session_id = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"}).json()["session_id"]
    runtime = client.app.state.onboarding_flows[session_id]
    connection = connect(client.app.state.database)
    connection.execute("UPDATE onboarding_sessions SET state='waiting_code' WHERE id=?", (session_id,))
    connection.close()

    code = client.post(f"/api/public/onboarding/{token}/{session_id}/code", json={"code": "123456"})
    duplicate_code = client.post(f"/api/public/onboarding/{token}/{session_id}/code", json={"code": "654321"})

    assert code.status_code == 200
    assert duplicate_code.status_code == 409
    assert duplicate_code.json()["detail"] == "onboarding_session_not_waiting_for_code"
    assert runtime["flow"].codes.qsize() == 1

    runtime["flow"].codes.get_nowait()
    connection = connect(client.app.state.database)
    connection.execute("UPDATE onboarding_sessions SET state='waiting_password' WHERE id=?", (session_id,))
    connection.close()
    password = client.post(f"/api/public/onboarding/{token}/{session_id}/password", json={"password": "synthetic-password"})
    duplicate_password = client.post(f"/api/public/onboarding/{token}/{session_id}/password", json={"password": "another-password"})

    assert password.status_code == 200
    assert password.json()["state"] == "verifying_password"
    assert duplicate_password.status_code == 409
    assert duplicate_password.json()["detail"] == "onboarding_session_not_waiting_for_password"
    assert runtime["flow"].passwords.qsize() == 1


def test_rejected_pymax_session_requires_a_new_generation_on_manual_retry(tmp_path, monkeypatch):
    coroutines = []
    real_create_task = asyncio.create_task

    def capture(coro, **_kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coroutines.append(coro)
            return None
        return real_create_task(coro, **_kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", capture)
    client, csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]

    class FakeAdapter:
        async def connect(self):
            raise ApiError(opcode=Opcode.LOGIN.value, error="FAIL_LOGIN_TOKEN", message="safe synthetic provider error")

        async def close(self):
            return None

    monkeypatch.setattr("maxbot_v2.app.PyMaxAdapter.create", classmethod(lambda _cls, **_kwargs: FakeAdapter()))
    first = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    asyncio.run(coroutines.pop())
    connection = connect(client.app.state.database)
    account_id = connection.execute("SELECT account_id FROM onboarding_sessions WHERE id=?", (first.json()["session_id"],)).fetchone()[0]
    original_ip = connection.execute("SELECT ip_id FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone()[0]
    assert connection.execute("SELECT auth_state FROM accounts WHERE id=?", (account_id,)).fetchone()[0] == "reauth_required"
    assert connection.execute("SELECT error_code FROM onboarding_sessions WHERE id=?", (first.json()["session_id"],)).fetchone()[0] == "saved_session_rejected"
    connection.close()

    retry = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    connection = connect(client.app.state.database)
    reset = connection.execute("SELECT session_generation,auth_state FROM accounts WHERE id=?", (account_id,)).fetchone()
    assert (reset["session_generation"], reset["auth_state"]) == (1, "unverified")
    assert connection.execute("SELECT ip_id FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone()[0] == original_ip
    assert connection.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone()[0] == 1
    connection.close()
    coroutines.pop().close()
    assert retry.status_code == 200


def test_active_account_with_rejected_saved_session_can_start_manual_reauth(tmp_path, monkeypatch):
    coroutines = []
    real_create_task = asyncio.create_task

    def capture(coro, **kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coroutines.append(coro)
            return None
        return real_create_task(coro, **kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", capture)
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]
    ip_id = client.get("/api/ips").json()[0]["id"]
    connection = connect(client.app.state.database)
    account_id = connection.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state,max_user_id,ever_authenticated) VALUES(?,?,?,'active','authenticated','max-user',1)",
        (group_id, "+79990000000", "Иван"),
    ).lastrowid
    connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    connection.close()

    class RejectedAdapter:
        async def connect(self):
            raise ApiError(opcode=Opcode.LOGIN.value, error="FAIL_LOGIN_TOKEN", message="safe synthetic provider error")

        async def close(self):
            return None

    monkeypatch.setattr("maxbot_v2.app.PyMaxAdapter.create", classmethod(lambda _cls, **_kwargs: RejectedAdapter()))
    checked = client.post(f"/api/groups/{group_id}/verify-destination", headers=headers, json={})
    assert checked.status_code == 503
    connection = connect(client.app.state.database)
    assert connection.execute("SELECT auth_state FROM accounts WHERE id=?", (account_id,)).fetchone()[0] == "reauth_required"
    assert connection.execute("SELECT ever_authenticated,lifecycle FROM accounts WHERE id=?", (account_id,)).fetchone()[:] == (1, "active")
    invite = connection.execute("SELECT id,token_hash FROM onboarding_invites WHERE group_id=?", (group_id,)).fetchone()
    connection.execute("UPDATE onboarding_invites SET max_uses=1,uses_count=1 WHERE id=?", (invite["id"],))
    connection.execute("UPDATE accounts SET status='needs_membership' WHERE id=?", (account_id,))
    connection.execute(
        "INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,phone,full_name,state,account_id,ip_id,expires_at,created_at,updated_at) "
        "VALUES('old-membership',?,?,?,'+79990000000','Иван','waiting_membership',?,?, '2099-01-01T00:00:00+00:00','2026-09-27T00:00:00+00:00','2026-09-27T00:00:00+00:00')",
        (invite["id"], invite["token_hash"], "synthetic-csrf-hash", account_id, ip_id),
    )
    connection.close()

    restarted = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    assert restarted.status_code == 200
    connection = connect(client.app.state.database)
    account = connection.execute("SELECT status,auth_state,session_generation FROM accounts WHERE id=?", (account_id,)).fetchone()
    assert tuple(account) == ("pending", "unverified", 1)
    assert tuple(connection.execute("SELECT state,error_code FROM onboarding_sessions WHERE id='old-membership'").fetchone()) == ("cancelled", "reauthentication_started")
    assert connection.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone()[0] == 1
    connection.close()
    asyncio.run(coroutines.pop())
    connection = connect(client.app.state.database)
    assert connection.execute("SELECT ever_authenticated,lifecycle,auth_state FROM accounts WHERE id=?", (account_id,)).fetchone()[:] == (1, "active", "reauth_required")
    assert connection.execute("SELECT phone,full_name FROM onboarding_sessions WHERE id=?", (restarted.json()["session_id"],)).fetchone()[:] == (None, None)
    connection.close()


def test_invalid_body_does_not_echo_password(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    secret = "synthetic-secret-" * 30
    response = client.post("/api/auth/login", json={"username": "owner", "password": secret})
    assert response.status_code == 422
    assert secret not in response.text


def test_account_list_does_not_return_full_phone(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    db = connect(client.app.state.database)
    db.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,'+79991234567','Иван','pending')", (group_id,))
    db.close()
    account = client.get(f"/api/groups/{group_id}/accounts").json()[0]
    assert "phone" not in account
    assert "+79991234567" not in str(account)


def test_owner_deletion_erases_all_session_generations_and_preserves_history(tmp_path, monkeypatch):
    from maxbot_v2.session_vault import EncryptedSessionFile

    monkeypatch.setenv("SESSION_RUNTIME_DIR", str(tmp_path / "runtime"))
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post(
        "/api/groups", headers=headers,
        json={"name": "Клуб", "invite_link": "https://max.ru/join/test"},
    ).json()["id"]
    connection = connect(client.app.state.database)
    account_id = connection.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state,ever_authenticated,phone_fingerprint) "
        "VALUES(?, '+79990000001','Guest','active','authenticated',1,'private-fingerprint')",
        (group_id,),
    ).lastrowid
    ip_id = connection.execute("SELECT id FROM server_ips LIMIT 1").fetchone()[0]
    connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    event_id = connection.execute(
        "INSERT INTO onboarding_events(created_at,attempt_id,group_id,account_id,ip_id,stage,result) "
        "VALUES('2026-09-27','attempt-1',?,?,?,'request_code','failed')",
        (group_id, account_id, ip_id),
    ).lastrowid
    connection.close()

    data_dir = client.app.state.data_dir
    box = SecretBox()
    vaults = [
        EncryptedSessionFile(account_id, generation=generation, durable_dir=data_dir / "sessions", runtime_dir=tmp_path / "runtime", box=box)
        for generation in (0, 1)
    ]
    neighbor = EncryptedSessionFile(account_id + 1, durable_dir=data_dir / "sessions", runtime_dir=tmp_path / "runtime", box=box)
    for vault in (*vaults, neighbor):
        vault.open()
        vault.work_path.write_bytes(b"temporary sqlite")
        vault.encrypted_path.write_bytes(box.encrypt_bytes(b"encrypted session"))

    response = client.delete(f"/api/accounts/{account_id}", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"deleted": True}
    connection = connect(client.app.state.database)
    account = connection.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    assert account["lifecycle"] == "deleted"
    assert account["phone"] == f"deleted:{account_id}"
    assert account["full_name"] == ""
    assert account["phone_fingerprint"] == "private-fingerprint"
    assert connection.execute("SELECT 1 FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone() is None
    assert connection.execute("SELECT id FROM onboarding_events WHERE id=?", (event_id,)).fetchone()[0] == event_id
    cleanup_event = connection.execute(
        "SELECT ip_id,result FROM onboarding_events WHERE account_id=? AND stage='session_cleanup' ORDER BY id DESC LIMIT 1",
        (account_id,),
    ).fetchone()
    assert tuple(cleanup_event) == (ip_id, "deleted")
    deletion_event = connection.execute(
        "SELECT ip_id,result FROM onboarding_events WHERE account_id=? AND stage='deletion' ORDER BY id DESC LIMIT 1",
        (account_id,),
    ).fetchone()
    assert tuple(deletion_event) == (ip_id, "started")
    assert connection.execute("SELECT COUNT(*) FROM accounts WHERE phone='+79990000001'").fetchone()[0] == 0
    connection.close()
    assert all(not vault.encrypted_path.exists() and not vault.work_dir.exists() for vault in vaults)
    assert neighbor.encrypted_path.exists() and neighbor.work_path.exists()


def test_owner_deletion_waits_for_live_auth_client_to_close(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_RUNTIME_DIR", str(tmp_path / "runtime"))
    real_create_task = asyncio.create_task
    tasks = []

    def create_tracked_task(coro, **kwargs):
        task = real_create_task(coro, **kwargs)
        if coro.cr_code.co_name == "run_onboarding_auth":
            tasks.append(task)
        return task

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", create_tracked_task)
    started = threading.Event()
    closed = threading.Event()

    class BlockingAdapter:
        async def connect(self):
            started.set()
            await asyncio.sleep(3600)

        async def close(self):
            closed.set()

    monkeypatch.setattr(
        "maxbot_v2.app.PyMaxAdapter.create",
        classmethod(lambda _cls, **_kwargs: BlockingAdapter()),
    )
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post(
        "/api/groups", headers=headers,
        json={"name": "Гонка удаления", "invite_link": "https://max.ru/join/delete-race"},
    ).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]
    attempt = client.post(
        f"/api/public/onboarding/{token}/start",
        json={"full_name": "Тестовый пользователь", "phone": "+79990000444"},
    )
    assert attempt.status_code == 200
    assert started.wait(timeout=3)
    connection = connect(client.app.state.database)
    account_id = connection.execute(
        "SELECT account_id FROM onboarding_sessions WHERE id=?", (attempt.json()["session_id"],),
    ).fetchone()[0]
    connection.close()

    response = client.delete(f"/api/accounts/{account_id}", headers=headers)

    assert response.status_code == 200
    assert closed.wait(timeout=1)
    connection = connect(client.app.state.database)
    account = connection.execute(
        "SELECT lifecycle,phone FROM accounts WHERE id=?", (account_id,),
    ).fetchone()
    attempt_row = connection.execute(
        "SELECT state,phone,full_name FROM onboarding_sessions WHERE id=?", (attempt.json()["session_id"],),
    ).fetchone()
    connection.close()
    assert tuple(account) == ("deleted", f"deleted:{account_id}")
    assert tuple(attempt_row) == ("cancelled", None, None)


def test_failed_new_onboarding_cleans_account_and_logs_safe_failure_before_retry(tmp_path, monkeypatch):
    coroutines = []
    real_create_task = asyncio.create_task

    def capture(coro, **_kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coroutines.append(coro)
            return None
        return real_create_task(coro, **_kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", capture)
    client, _csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post(
        "/api/groups", headers={"X-CSRF-Token": _csrf},
        json={"name": "Клуб", "invite_link": "https://max.ru/join/test"},
    ).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]

    class FakeAdapter:
        async def connect(self):
            raise OSError("synthetic network text must never be logged")

        async def close(self):
            return None

    monkeypatch.setattr("maxbot_v2.app.PyMaxAdapter.create", classmethod(lambda _cls, **_kwargs: FakeAdapter()))
    first = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79991234567"})
    connection = connect(client.app.state.database)
    old_id = int(connection.execute("SELECT account_id FROM onboarding_sessions WHERE id=?", (first.json()["session_id"],)).fetchone()[0])
    connection.close()
    asyncio.run(coroutines.pop())

    connection = connect(client.app.state.database)
    account = connection.execute("SELECT lifecycle,phone,full_name FROM accounts WHERE id=?", (old_id,)).fetchone()
    attempt = connection.execute("SELECT state,phone,full_name FROM onboarding_sessions WHERE id=?", (first.json()["session_id"],)).fetchone()
    assert tuple(account) == ("deleted", f"deleted:{old_id}", "")
    assert tuple(attempt) == ("failed", None, None)
    assert connection.execute("SELECT 1 FROM ip_assignments WHERE account_id=?", (old_id,)).fetchone() is None
    connection.close()
    log = client.get("/api/log").json()
    failure = next(entry for entry in log if entry.get("attempt_id") == first.json()["session_id"] and entry["detail"].startswith("failed"))
    assert failure["kind"] == "connect"
    assert failure["error_class"] == "OSError"
    assert "+79991234567" not in str(log) and "synthetic network text" not in str(log)
    assert client.get("/api/overview").json()["counts"]["accounts"] == 0

    second = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79991234567"})
    assert second.status_code == 200
    connection = connect(client.app.state.database)
    new_id = int(connection.execute("SELECT account_id FROM onboarding_sessions WHERE id=?", (second.json()["session_id"],)).fetchone()[0])
    assert new_id != old_id
    assert connection.execute("SELECT COUNT(*) FROM accounts WHERE phone='+79991234567' AND lifecycle='active'", ()).fetchone()[0] == 1
    connection.close()
    coroutines.pop().close()


def test_failed_attempt_cleanup_failure_blocks_reuse_until_retry_completes(tmp_path, monkeypatch):
    from maxbot_v2.session_vault import EncryptedSessionFile

    coroutines = []
    real_create_task = asyncio.create_task

    def capture(coro, **kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coroutines.append(coro)
            return None
        return real_create_task(coro, **kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", capture)
    client, _csrf = owner_client(tmp_path, monkeypatch)
    group_id = client.post(
        "/api/groups", headers={"X-CSRF-Token": _csrf},
        json={"name": "Сбой очистки", "invite_link": "https://max.ru/join/cleanup-retry"},
    ).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]

    class FailedAdapter:
        async def connect(self):
            raise OSError("safe synthetic connection failure")

        async def close(self):
            return None

    monkeypatch.setattr("maxbot_v2.app.PyMaxAdapter.create", classmethod(lambda _cls, **_kwargs: FailedAdapter()))
    delete_all = EncryptedSessionFile.delete_all_generations
    monkeypatch.setattr(EncryptedSessionFile, "delete_all_generations", lambda _self: (_ for _ in ()).throw(OSError("private path")))
    first = client.post(
        f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000999"},
    )
    connection = connect(client.app.state.database)
    account_id = connection.execute(
        "SELECT account_id FROM onboarding_sessions WHERE id=?", (first.json()["session_id"],),
    ).fetchone()[0]
    connection.close()
    asyncio.run(coroutines.pop())

    connection = connect(client.app.state.database)
    failed = connection.execute("SELECT state,phone,full_name FROM onboarding_sessions WHERE id=?", (first.json()["session_id"],)).fetchone()
    pending = connection.execute("SELECT lifecycle FROM accounts WHERE id=?", (account_id,)).fetchone()[0]
    connection.close()
    assert tuple(failed) == ("failed", None, None)
    assert pending == "delete_pending"
    retry_while_blocked = client.post(
        f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000999"},
    )
    assert retry_while_blocked.status_code == 409
    assert retry_while_blocked.json()["detail"] == "account_deletion_incomplete"

    monkeypatch.setattr(EncryptedSessionFile, "delete_all_generations", delete_all)
    retry = client.post(
        f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000999"},
    )
    assert retry.status_code == 200
    connection = connect(client.app.state.database)
    new_id = connection.execute(
        "SELECT account_id FROM onboarding_sessions WHERE id=?", (retry.json()["session_id"],),
    ).fetchone()[0]
    assert new_id != account_id
    assert connection.execute("SELECT lifecycle FROM accounts WHERE id=?", (account_id,)).fetchone()[0] == "deleted"
    connection.close()
    coroutines.pop().close()


@pytest.mark.parametrize("operation_status", ["in_flight", "unknown"])
def test_owner_delete_conflicts_unresolved_send_without_changing_account_or_ip(tmp_path, monkeypatch, operation_status):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post(
        "/api/groups", headers=headers,
        json={"name": "Клуб", "invite_link": "https://max.ru/join/test"},
    ).json()["id"]
    db = connect(client.app.state.database)
    account_id = db.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state) VALUES(?, '+79990000002','Member','active','authenticated')",
        (group_id,),
    ).lastrowid
    ip_id = db.execute("SELECT id FROM server_ips LIMIT 1").fetchone()[0]
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    version_id = db.execute(
        "INSERT INTO message_versions(created_at,checksum) VALUES('2026-09-27','test-version')"
    ).lastrowid
    slot = create_weekly_slot(db, account_id=account_id, week_start="2026-09-21", scheduled_date="2026-09-21", text="hello", message_version_id=version_id)
    db.execute(
        "INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) VALUES('unresolved-op',?,?,?,?, '2026-09-21')",
        (slot["slot_id"], account_id, group_id, operation_status),
    )
    db.close()

    response = client.delete(f"/api/accounts/{account_id}", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == "operation_reconciliation_required"
    db = connect(client.app.state.database)
    assert db.execute("SELECT lifecycle,phone FROM accounts WHERE id=?", (account_id,)).fetchone()["lifecycle"] == "active"
    assert db.execute("SELECT ip_id FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone()[0] == ip_id
    assert db.execute("SELECT status FROM operations WHERE operation_id='unresolved-op'").fetchone()[0] == operation_status
    db.close()


def test_owner_delete_keeps_retryable_state_when_session_file_removal_fails(tmp_path, monkeypatch):
    from maxbot_v2.session_vault import EncryptedSessionFile

    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post(
        "/api/groups", headers=headers,
        json={"name": "Клуб", "invite_link": "https://max.ru/join/test"},
    ).json()["id"]
    db = connect(client.app.state.database)
    account_id = db.execute(
        "INSERT INTO accounts(group_id,phone,full_name,status,auth_state,ever_authenticated) VALUES(?, '+79990000003','Member','active','authenticated',1)",
        (group_id,),
    ).lastrowid
    ip_id = db.execute("SELECT id FROM server_ips LIMIT 1").fetchone()[0]
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    db.close()
    original_delete = EncryptedSessionFile.delete_all_generations

    def fail_delete(_vault):
        raise OSError("private path")

    monkeypatch.setattr(EncryptedSessionFile, "delete_all_generations", fail_delete)
    first = client.delete(f"/api/accounts/{account_id}", headers=headers)
    assert first.status_code == 503
    db = connect(client.app.state.database)
    pending = db.execute("SELECT lifecycle,phone FROM accounts WHERE id=?", (account_id,)).fetchone()
    assert tuple(pending) == ("delete_pending", "+79990000003")
    assert db.execute("SELECT 1 FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone() is None
    db.close()

    monkeypatch.setattr(EncryptedSessionFile, "delete_all_generations", original_delete)
    second = client.delete(f"/api/accounts/{account_id}", headers=headers)
    assert second.status_code == 200
    assert second.json() == {"deleted": True}
    assert client.delete(f"/api/accounts/{account_id}", headers=headers).json() == {"deleted": True}


def test_refresh_finds_new_ip_disabled_and_owner_can_reassign(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    db = connect(client.app.state.database)
    account_id = db.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,'+79991234567','Иван','active')", (group_id,)).lastrowid
    ip_id = db.execute("SELECT id FROM server_ips WHERE address='62.109.20.186'").fetchone()[0]
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    db.close()

    from maxbot_v2.egress import refresh_ips
    monkeypatch.setattr("maxbot_v2.app.refresh_ips", lambda db: refresh_ips(db, addresses={"62.109.20.186", "62.109.20.187"}, probe=lambda _address: True))
    monkeypatch.setattr("maxbot_v2.app.host_addresses", lambda: {"62.109.20.186", "62.109.20.187"})
    rows = client.post("/api/ips/refresh", headers=headers).json()
    new = next(row for row in rows if row["address"] == "62.109.20.187")
    assert new["enabled"] == 0 and new["available"] == 1
    assert client.post(f"/api/accounts/{account_id}/ip", headers=headers, json={"ip_id": new["id"]}).status_code == 422
    assert client.patch(f"/api/ips/{new['id']}", headers=headers, json={"enabled": True}).status_code == 200
    assert client.post(f"/api/accounts/{account_id}/ip", headers=headers, json={"ip_id": new["id"]}).json() == {"ip_id": new["id"], "ip_address": "62.109.20.187"}
    assert client.get(f"/api/groups/{group_id}/accounts").json()[0]["ip_id"] == new["id"]


def test_legacy_proxy_api_removed_without_dropping_historical_rows(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    db = connect(client.app.state.database)
    db.execute("INSERT INTO proxies(group_id,url_ciphertext,label,position) VALUES(?,'ciphertext','archived',0)", (group_id,))
    db.close()
    assert client.get(f"/api/groups/{group_id}/proxies").status_code == 404
    db = connect(client.app.state.database)
    assert db.execute("SELECT COUNT(*) FROM proxies").fetchone()[0] == 1
    db.close()


def test_reenabling_ip_resumes_future_blocked_slot(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    db = connect(client.app.state.database)
    account_id = db.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,'+79991234567','Иван','active')", (group_id,)).lastrowid
    ip_id = db.execute("SELECT id FROM server_ips WHERE address='62.109.20.186'").fetchone()[0]
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    version = replace_message_pool(db, ["test"])
    create_weekly_slot(db, account_id=account_id, week_start="2099-01-05", scheduled_date="2099-01-05", text="test", message_version_id=version)
    db.close()
    assert client.patch(f"/api/ips/{ip_id}", headers=headers, json={"enabled": False}).status_code == 200
    db = connect(client.app.state.database)
    assert db.execute("SELECT status FROM weekly_slots WHERE account_id=?", (account_id,)).fetchone()[0] == "blocked"
    db.close()
    assert client.patch(f"/api/ips/{ip_id}", headers=headers, json={"enabled": True}).status_code == 200
    db = connect(client.app.state.database)
    assert db.execute("SELECT status FROM weekly_slots WHERE account_id=?", (account_id,)).fetchone()[0] == "queued"
    db.close()


def test_membership_check_stops_when_assigned_ip_changes_during_connect(tmp_path, monkeypatch):
    real_create_task = asyncio.create_task

    def skip(coro, **_kwargs):
        if coro.cr_code.co_name == "run_onboarding_auth":
            coro.close()
            return None
        return real_create_task(coro, **_kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip)
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    token = client.get(f"/api/groups/{group_id}/onboarding-link").json()["url"].rsplit("/", 1)[1]
    session_id = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79991234567"}).json()["session_id"]
    db = connect(client.app.state.database)
    db.execute("UPDATE groups SET chat_id='7001' WHERE id=?", (group_id,))
    db.execute("UPDATE onboarding_sessions SET state='waiting_membership' WHERE id=?", (session_id,))
    db.execute("UPDATE accounts SET status='needs_membership',auth_state='authenticated' WHERE id=(SELECT account_id FROM onboarding_sessions WHERE id=?)", (session_id,))
    db.close()

    class FakeAdapter:
        async def connect(self):
            db = connect(client.app.state.database)
            db.execute("UPDATE server_ips SET enabled=0 WHERE address='62.109.20.186'")
            db.close()

        async def get_chat(self, _chat_id):
            raise AssertionError("stale IP must not be used")

        async def close(self):
            return None

    monkeypatch.setattr("maxbot_v2.app.PyMaxAdapter.create", classmethod(lambda _cls, **_kwargs: FakeAdapter()))
    response = client.post(f"/api/public/onboarding/{token}/{session_id}/check-membership", json={})
    assert response.status_code == 409
    assert response.json()["detail"] == "account_assignment_changed_during_verification"


def test_explicit_link_rotation_invalidates_old_link(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]

    first = client.post(f"/api/groups/{group_id}/onboarding-link", headers=headers, json={})
    first_token = first.json()["url"].rsplit("/", 1)[1]
    second = client.post(f"/api/groups/{group_id}/onboarding-link?rotate=1", headers=headers, json={})

    assert second.status_code == 200
    assert second.json()["url"] != first.json()["url"]
    assert second.json()["url"].startswith("https://test.local/j/")
    assert len(second.json()["url"].rsplit("/", 1)[1]) == 22
    assert client.get(f"/join-info/{first_token}").status_code == 404
    assert client.get(f"/join-info/{second.json()['url'].rsplit('/', 1)[1]}").status_code == 200


def test_group_link_can_be_read_after_reload_and_is_not_cached(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    issued = client.post(f"/api/groups/{group_id}/onboarding-link", headers=headers, json={}).json()

    response = client.get(f"/api/groups/{group_id}/onboarding-link")

    assert response.status_code == 200
    assert response.json()["url"] == issued["url"]
    assert response.json()["status"] == "active"
    assert "no-store" in response.headers["cache-control"]


def test_group_link_read_hides_revoked_and_expired_urls(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    client.post(f"/api/groups/{group_id}/onboarding-link", headers=headers, json={})
    connection = connect(client.app.state.database)
    try:
        connection.execute("UPDATE onboarding_invites SET expires_at='2000-01-01T00:00:00+00:00' WHERE group_id=?", (group_id,))
    finally:
        connection.close()

    expired = client.get(f"/api/groups/{group_id}/onboarding-link").json()
    assert expired["url"] is None
    assert expired["status"] == "expired"

    client.post(f"/api/groups/{group_id}/onboarding-link?rotate=1", headers=headers, json={})
    client.delete(f"/api/groups/{group_id}/onboarding-link", headers=headers)
    revoked = client.get(f"/api/groups/{group_id}/onboarding-link").json()
    assert revoked["url"] is None
    assert revoked["status"] == "revoked"


def test_owner_link_status_ignores_failed_attempts_in_stored_use_count(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    issued = client.post(f"/api/groups/{group_id}/onboarding-link?max_uses=1", headers=headers, json={}).json()
    connection = connect(client.app.state.database)
    try:
        invite = connection.execute("SELECT id,token_hash FROM onboarding_invites WHERE group_id=?", (group_id,)).fetchone()
        connection.execute("UPDATE onboarding_invites SET uses_count=1 WHERE id=?", (invite["id"],))
        connection.execute(
            "INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,state,expires_at,created_at,updated_at) "
            "VALUES('failed-attempt',?,?,?,'failed','2099-01-01T00:00:00+00:00','2026-09-25','2026-09-25')",
            (invite["id"], invite["token_hash"], "csrf-hash"),
        )
    finally:
        connection.close()

    response = client.get(f"/api/groups/{group_id}/onboarding-link")

    assert response.json()["status"] == "active"
    assert response.json()["url"] == issued["url"]


def test_editing_group_does_not_resume_a_stopped_group(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    client.post(f"/api/groups/{group_id}/active", headers=headers, json={"enabled": False})

    response = client.put(f"/api/groups/{group_id}", headers=headers, json={"name": "Новое имя", "invite_link": "https://max.ru/join/test"})

    assert response.status_code == 200
    assert response.json()["active"] == 0


def test_disabled_ip_keeps_account_assignment_but_blocks_verification(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    ip_id = client.get("/api/ips").json()[0]["id"]
    connection = connect(client.app.state.database)
    try:
        connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'active')", (group_id, "+79990000000", "Иван"))
        account_id = connection.execute("SELECT id FROM accounts WHERE phone=?", ("+79990000000",)).fetchone()[0]
        connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    finally:
        connection.close()

    assert client.patch(f"/api/ips/{ip_id}", headers=headers, json={"enabled": False}).status_code == 200
    account = client.get(f"/api/groups/{group_id}/accounts").json()[0]
    assert account["ip_id"] == ip_id
    assert account["ip_enabled"] == 0
    assert client.get("/api/groups").json()[0]["verifiable_account_count"] == 0


def test_group_invite_link_must_be_resolvable_by_pinned_pymax(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    response = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/group/test"})
    assert response.status_code == 422
    assert response.json()["detail"] == "invalid_max_invite_link"
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    response = client.put(f"/api/groups/{group_id}", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/group/test", "active": True})
    assert response.status_code == 422


def test_guest_auth_start_is_not_blocked_by_local_authorization_file(tmp_path, monkeypatch):
    async def no_worker_sync(_manager):
        return None

    real_create_task = asyncio.create_task

    def skip_onboarding_network(coroutine, **kwargs):
        if coroutine.cr_code.co_name == "run_onboarding_auth":
            coroutine.close()
            return None
        return real_create_task(coroutine, **kwargs)

    monkeypatch.setenv("MAX_AUTHORIZATION_FILE", str(tmp_path / "missing.json"))
    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip_onboarding_network)
    monkeypatch.setattr("maxbot_v2.workers.GroupWorkerManager._sync_group_workers", no_worker_sync)
    client, _csrf = owner_client(tmp_path, monkeypatch)
    no_csrf = client.post("/api/groups", json={"name": "Клуб", "invite_link": "https://max.ru/join/test"})
    assert no_csrf.status_code == 403
    csrf = client.cookies.get("owner_csrf")
    group = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"})
    link = client.post(f"/api/groups/{group.json()['id']}/onboarding-link", headers={"X-CSRF-Token": csrf}, json={}).json()["url"]
    token = link.rsplit("/", 1)[1]
    response = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    assert response.status_code == 200
    assert response.json()["state"] == "starting"


def test_failed_first_onboarding_can_retry_same_phone_with_one_use_link(tmp_path, monkeypatch):
    async def no_worker_sync(_manager):
        return None

    real_create_task = asyncio.create_task

    def skip_onboarding_network(coroutine, **kwargs):
        if coroutine.cr_code.co_name == "run_onboarding_auth":
            coroutine.close()
            return None
        return real_create_task(coroutine, **kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip_onboarding_network)
    monkeypatch.setattr("maxbot_v2.workers.GroupWorkerManager._sync_group_workers", no_worker_sync)
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    link = client.post(f"/api/groups/{group_id}/onboarding-link?max_uses=1", headers=headers, json={}).json()["url"]
    token = link.rsplit("/", 1)[1]
    first = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    assert first.status_code == 200

    connection = connect(client.app.state.database)
    try:
        connection.execute("UPDATE onboarding_sessions SET state='failed',error_code='timeouterror' WHERE id=?", (first.json()["session_id"],))
        first_account_id = connection.execute("SELECT account_id FROM onboarding_sessions WHERE id=?", (first.json()["session_id"],)).fetchone()[0]
        connection.execute("UPDATE accounts SET auth_state='reauth_required' WHERE id=?", (first_account_id,))
        original_ip = connection.execute("SELECT ip_id FROM ip_assignments WHERE account_id=?", (first_account_id,)).fetchone()[0]
    finally:
        connection.close()

    retry = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    assert retry.status_code == 200
    assert retry.json()["session_id"] != first.json()["session_id"]
    connection = connect(client.app.state.database)
    try:
        retry_account_id = connection.execute("SELECT account_id FROM onboarding_sessions WHERE id=?", (retry.json()["session_id"],)).fetchone()[0]
        assert retry_account_id == first_account_id
        assert connection.execute("SELECT session_generation FROM accounts WHERE id=?", (first_account_id,)).fetchone()[0] == 1
        assert connection.execute("SELECT ip_id FROM ip_assignments WHERE account_id=?", (first_account_id,)).fetchone()[0] == original_ip
        assert connection.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (first_account_id,)).fetchone()[0] == 1
        assert connection.execute("SELECT uses_count FROM onboarding_invites WHERE group_id=?", (group_id,)).fetchone()[0] == 1
    finally:
        connection.close()


def test_unknown_operation_can_be_manually_resolved_without_duplicate_count(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    connection = connect(client.app.state.database)
    try:
        connection.execute("INSERT INTO groups(name,invite_link,chat_id) VALUES('Клуб','https://max.ru/join/test','123')")
        connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(1,'+79990000000','Иван','active')")
        version = replace_message_pool(connection, ["hello"])
        slot = create_weekly_slot(connection, account_id=1, week_start="2026-09-21", scheduled_date="2026-09-21", text="hello", message_version_id=version)
        connection.execute("INSERT INTO operations(operation_id,slot_id,account_id,group_id,status,started_at) VALUES('op-unknown',?,1,1,'unknown','2026-09-21T10:00:00Z')", (slot["slot_id"],))
    finally:
        connection.close()
    headers = {"X-CSRF-Token": csrf}
    resolved = client.post("/api/operations/op-unknown/resolve", headers=headers, json={"outcome": "accepted", "provider_message_id": "max-123"})
    assert resolved.status_code == 200
    assert client.post("/api/operations/op-unknown/resolve", headers=headers, json={"outcome": "accepted", "provider_message_id": "max-123"}).status_code == 409
    connection = connect(client.app.state.database)
    try:
        assert connection.execute("SELECT COUNT(*) FROM send_log").fetchone()[0] == 1
        assert connection.execute("SELECT status FROM weekly_slots").fetchone()[0] == "accepted"
    finally:
        connection.close()


def test_rotating_guest_link_cancels_existing_attempt_and_rejects_otp(tmp_path, monkeypatch):
    async def no_worker_sync(_manager):
        return None

    real_create_task = asyncio.create_task

    def skip_onboarding_network(coroutine, **kwargs):
        if coroutine.cr_code.co_name == "run_onboarding_auth":
            coroutine.close()
            return None
        return real_create_task(coroutine, **kwargs)

    monkeypatch.setattr("maxbot_v2.app.asyncio.create_task", skip_onboarding_network)
    monkeypatch.setattr("maxbot_v2.workers.GroupWorkerManager._sync_group_workers", no_worker_sync)
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    token = client.post(f"/api/groups/{group_id}/onboarding-link", headers=headers, json={}).json()["url"].rsplit("/", 1)[1]
    started = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"}).json()
    session_id = started["session_id"]
    connection = connect(client.app.state.database)
    try:
        connection.execute("UPDATE onboarding_sessions SET state='waiting_code' WHERE id=?", (session_id,))
    finally:
        connection.close()

    rotated = client.post(f"/api/groups/{group_id}/onboarding-link?rotate=1", headers=headers, json={})

    assert rotated.status_code == 200
    status = client.get(f"/api/public/onboarding/{token}/{session_id}")
    assert status.status_code == 200
    assert status.json()["state"] == "cancelled"
    rejected = client.post(f"/api/public/onboarding/{token}/{session_id}/code", json={"code": "123456"})
    assert rejected.status_code == 410


def test_destination_verification_includes_accounts_needing_membership(tmp_path, monkeypatch):
    from types import SimpleNamespace

    class FakeAdapter:
        async def connect(self):
            return None

        async def resolve_group_by_link(self, _link):
            return SimpleNamespace(id=123)

        async def get_chat(self, _chat_id):
            return SimpleNamespace(id=123, status="member", join_time=1)

        async def close(self):
            return None

    monkeypatch.setattr("maxbot_v2.app.PyMaxAdapter.create", classmethod(lambda _cls, **_kwargs: FakeAdapter()))
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    ip_id = client.get("/api/ips").json()[0]["id"]
    connection = connect(client.app.state.database)
    try:
        connection.execute("INSERT INTO accounts(group_id,phone,full_name,status,auth_state) VALUES(?,?,?,'needs_membership','authenticated')", (group_id, "+79990000000", "Иван"))
        account_id = connection.execute("SELECT id FROM accounts WHERE phone='+79990000000'").fetchone()[0]
        connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    finally:
        connection.close()

    response = client.post(f"/api/groups/{group_id}/verify-destination", headers=headers, json={})

    assert response.status_code == 200
    assert response.json()["verified_accounts"] == 1
    assert client.get(f"/api/groups/{group_id}/accounts").json()[0]["status"] == "active"


def test_destination_verification_stops_when_ip_changes_during_connect(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    ip_id = client.get("/api/ips").json()[0]["id"]
    connection = connect(client.app.state.database)
    account_id = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status,auth_state) VALUES(?,?,?,'needs_membership','authenticated')", (group_id, "+79990000000", "Иван")).lastrowid
    connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
    connection.close()

    class FakeAdapter:
        async def connect(self):
            connection = connect(client.app.state.database)
            connection.execute("UPDATE server_ips SET enabled=0 WHERE id=?", (ip_id,))
            connection.close()

        async def resolve_group_by_link(self, _link):
            raise AssertionError("must not use an obsolete IP")

        async def close(self):
            return None

    monkeypatch.setattr("maxbot_v2.app.PyMaxAdapter.create", classmethod(lambda _cls, **_kwargs: FakeAdapter()))
    response = client.post(f"/api/groups/{group_id}/verify-destination", headers=headers, json={})
    assert response.status_code == 409
    assert response.json()["detail"] == "account_assignment_changed_during_verification"


def test_destination_verification_button_requires_an_assigned_enabled_ip(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    ip_id = client.get("/api/ips").json()[0]["id"]
    connection = connect(client.app.state.database)
    try:
        connection.execute("INSERT INTO accounts(group_id,phone,full_name,status,auth_state) VALUES(?,?,?,'needs_membership','authenticated')", (group_id, "+79990000000", "Иван"))
        account_id = connection.execute("SELECT id FROM accounts WHERE phone='+79990000000'").fetchone()[0]
    finally:
        connection.close()

    assert client.get("/api/groups").json()[0]["verifiable_account_count"] == 0
    connection = connect(client.app.state.database)
    try:
        connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, ip_id))
        connection.execute("UPDATE server_ips SET enabled=0 WHERE id=?", (ip_id,))
    finally:
        connection.close()
    assert client.get("/api/groups").json()[0]["verifiable_account_count"] == 0


def test_manual_run_control_is_independent_from_restart_autostart(tmp_path, monkeypatch):
    monkeypatch.setenv("BUILD_REVISION", "test-revision")
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    settings = client.get("/api/settings").json()
    settings["auto_run"] = False
    assert client.put("/api/settings", headers=headers, json=settings).status_code == 200

    assert client.post("/api/run/stop", headers=headers, json={}).json()["stopped"] is True
    started = client.post("/api/run/start", headers=headers, json={})

    assert started.json()["stopped"] is False
    overview = client.get("/api/overview").json()
    assert overview["stopped"] is False
    assert overview["auto_run"] is False
    assert overview["run_wait_reason"]
    assert client.get("/health").json() == {"status": "ok", "revision": "test-revision"}


def test_autostart_off_starts_stopped_but_manual_start_works(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    connection = connect(client.app.state.database)
    try:
        connection.execute("UPDATE settings SET value='0' WHERE key='auto_run'")
        connection.execute("UPDATE settings SET value='0' WHERE key='global_stop'")
    finally:
        connection.close()

    with client:
        overview = client.get("/api/overview").json()
        assert overview["auto_run"] is False
        assert overview["stopped"] is True
        assert client.post("/api/run/start", headers=headers, json={}).json()["stopped"] is False
        assert client.get("/api/overview").json()["stopped"] is False


def test_api_log_sorts_sqlite_and_iso_timestamps_chronologically(tmp_path, monkeypatch):
    client, _csrf = owner_client(tmp_path, monkeypatch)
    connection = connect(client.app.state.database)
    connection.executemany(
        "INSERT INTO audit_log(created_at,kind,detail) VALUES(?,?,?)",
        [
            ("2026-09-27 10:00:00", "later", "later"),
            ("2026-09-27T09:59:00+00:00", "earlier", "earlier"),
        ],
    )
    connection.close()

    entries = client.get("/api/log").json()

    assert [entry["detail"] for entry in entries[:2]] == ["later", "earlier"]
