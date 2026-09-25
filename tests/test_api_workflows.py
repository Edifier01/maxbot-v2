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
