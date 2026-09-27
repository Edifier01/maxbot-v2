import asyncio

import bcrypt
from fastapi.testclient import TestClient

from maxbot_v2.app import create_app
from maxbot_v2.crypto import SecretBox
from maxbot_v2.db import connect
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.scheduling import create_weekly_slot


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


def test_expired_membership_attempt_allows_new_start(tmp_path, monkeypatch):
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
    db.close()
    second = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79991234567"})
    assert second.status_code == 200
    assert second.json()["session_id"] != first.json()["session_id"]


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
    finally:
        connection.close()

    retry = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    assert retry.status_code == 200
    assert retry.json()["session_id"] != first.json()["session_id"]
    connection = connect(client.app.state.database)
    try:
        retry_account_id = connection.execute("SELECT account_id FROM onboarding_sessions WHERE id=?", (retry.json()["session_id"],)).fetchone()[0]
        assert retry_account_id == first_account_id
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
        connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'needs_membership')", (group_id, "+79990000000", "Иван"))
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
    account_id = connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'needs_membership')", (group_id, "+79990000000", "Иван")).lastrowid
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
        connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'needs_membership')", (group_id, "+79990000000", "Иван"))
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
