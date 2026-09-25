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
    app = create_app(
        db_path=tmp_path / "app.db",
        data_dir=tmp_path / "data",
        owner_username="edifier8989",
        owner_password_hash=bcrypt.hashpw(b"correct horse battery", bcrypt.gensalt()).decode(),
        secret_key="unit-test-app-secret-key-with-32-chars",
        secure_cookies=False,
    )
    client = TestClient(app, base_url="https://test.local")
    response = client.post("/api/auth/login", json={"username": "edifier8989", "password": "correct horse battery"})
    assert response.status_code == 200
    return client, response.json()["csrf_token"]


def test_group_proxy_invite_and_message_pool_are_owner_scoped(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"})
    assert group.status_code == 201
    group_id = group.json()["id"]
    proxy = client.post(f"/api/groups/{group_id}/proxies", headers=headers, json={"label": "proxy 1", "url": "socks5://user:pass@127.0.0.1:1080"})
    assert proxy.status_code == 201
    assert "pass" not in proxy.text
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


def test_bulk_proxy_import_is_atomic_and_reports_line_numbers(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]

    invalid = client.post(f"/api/groups/{group_id}/proxies/bulk", headers=headers, json={"lines": "http://127.0.0.1:1080\nnot-a-proxy"})
    assert invalid.status_code == 422
    assert "2" in str(invalid.json()["detail"])
    assert client.get(f"/api/groups/{group_id}/proxies").json() == []

    duplicate = client.post(f"/api/groups/{group_id}/proxies/bulk", headers=headers, json={"lines": "http://127.0.0.1:1080\n\nhttp://127.0.0.1:1080"})
    assert duplicate.status_code == 422
    assert "1" in str(duplicate.json()["detail"]) and "3" in str(duplicate.json()["detail"])
    assert client.get(f"/api/groups/{group_id}/proxies").json() == []

    added = client.post(f"/api/groups/{group_id}/proxies/bulk", headers=headers, json={"lines": "socks5://127.0.0.1:1080\n\nhttp://127.0.0.1:1081"})
    assert added.status_code == 201
    rows = client.get(f"/api/groups/{group_id}/proxies").json()
    assert [row["label"] for row in rows] == ["Прокси 1", "Прокси 2"]


def test_editing_group_does_not_resume_a_stopped_group(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    client.post(f"/api/groups/{group_id}/active", headers=headers, json={"enabled": False})

    response = client.put(f"/api/groups/{group_id}", headers=headers, json={"name": "Новое имя", "invite_link": "https://max.ru/join/test"})

    assert response.status_code == 200
    assert response.json()["active"] == 0


def test_proxy_counts_separate_available_proxies_and_accounts_use_proxy_id(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    proxy = client.post(f"/api/groups/{group_id}/proxies", headers=headers, json={"label": "main", "url": "socks5://127.0.0.1:1080"}).json()
    connection = connect(client.app.state.database)
    try:
        connection.execute("INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'active')", (group_id, "+79990000000", "Иван"))
        account_id = connection.execute("SELECT id FROM accounts WHERE phone=?", ("+79990000000",)).fetchone()[0]
        connection.execute("INSERT INTO proxy_assignments(account_id,proxy_id) VALUES(?,?)", (account_id, proxy["id"]))
        connection.execute("UPDATE proxies SET enabled=0 WHERE id=?", (proxy["id"],))
    finally:
        connection.close()

    group = next(row for row in client.get("/api/groups").json() if row["id"] == group_id)
    assert group["proxy_count"] == 1
    assert group["available_proxy_count"] == 0
    assert client.get(f"/api/groups/{group_id}/accounts").json()[0]["proxy_id"] == proxy["id"]


def test_proxy_url_only_accepts_schemes_supported_by_pinned_pymax(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    for scheme in ("https", "socks5h"):
        response = client.post(f"/api/groups/{group_id}/proxies", headers=headers, json={"label": scheme, "url": f"{scheme}://127.0.0.1:1080"})
        assert response.status_code == 422
        assert response.json()["detail"] == "invalid_proxy_url"
    for url in ("socks5://127.0.0.1", "http://127.0.0.1:99999"):
        response = client.post(f"/api/groups/{group_id}/proxies", headers=headers, json={"label": "invalid", "url": url})
        assert response.status_code == 422
    for scheme in ("http", "socks5"):
        response = client.post(f"/api/groups/{group_id}/proxies", headers=headers, json={"label": scheme, "url": f"{scheme}://127.0.0.1:1080"})
        assert response.status_code == 201


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
    client.post(f"/api/groups/{group.json()['id']}/proxies", headers={"X-CSRF-Token": csrf}, json={"label": "test", "url": "socks5://127.0.0.1:1080"})
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
    client.post(f"/api/groups/{group_id}/proxies", headers=headers, json={"label": "proxy", "url": "socks5://127.0.0.1:1080"})
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


def test_unreadable_proxy_does_not_consume_onboarding_attempt(tmp_path, monkeypatch):
    client, csrf = owner_client(tmp_path, monkeypatch)
    headers = {"X-CSRF-Token": csrf}
    group_id = client.post("/api/groups", headers=headers, json={"name": "Клуб", "invite_link": "https://max.ru/join/test"}).json()["id"]
    client.post(f"/api/groups/{group_id}/proxies", headers=headers, json={"label": "proxy", "url": "socks5://127.0.0.1:1080"})
    token = client.post(f"/api/groups/{group_id}/onboarding-link", headers=headers, json={}).json()["url"].rsplit("/", 1)[1]

    connection = connect(client.app.state.database)
    try:
        connection.execute("UPDATE proxies SET url_ciphertext='unreadable' WHERE group_id=?", (group_id,))
    finally:
        connection.close()

    response = client.post(f"/api/public/onboarding/{token}/start", json={"full_name": "Иван", "phone": "+79990000000"})
    assert response.status_code == 503
    assert response.json()["detail"] == "proxy_unavailable"

    connection = connect(client.app.state.database)
    try:
        assert connection.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM onboarding_sessions").fetchone()[0] == 0
        assert connection.execute("SELECT uses_count FROM onboarding_invites WHERE group_id=?", (group_id,)).fetchone()[0] == 0
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
