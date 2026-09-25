from fastapi.testclient import TestClient
import bcrypt

from maxbot_v2.app import create_app


def test_owner_login_uses_secure_server_session_and_csrf(tmp_path):
    app = create_app(
        db_path=tmp_path / "app.db",
        data_dir=tmp_path / "data",
        owner_username="edifier8989",
        owner_password_hash=bcrypt.hashpw(b"initial-test-password", bcrypt.gensalt()).decode(),
        secret_key="test-secret-key-at-least-32-characters-long",
        secure_cookies=False,
    )
    client = TestClient(app, base_url="https://example.test")
    bad = client.post("/api/auth/login", json={"username": "edifier8989", "password": "wrong"})
    assert bad.status_code == 401
    response = client.post(
        "/api/auth/login",
        json={"username": "edifier8989", "password": "initial-test-password"},
    )
    assert response.status_code == 200
    assert "owner_session" in response.cookies
    assert response.cookies.get("owner_session")
    token = response.json()["csrf_token"]
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    rejected = client.post("/api/run/stop")
    assert rejected.status_code == 403
    accepted = client.post("/api/run/stop", headers={"X-CSRF-Token": token})
    assert accepted.status_code == 200


def test_owner_credentials_are_required_in_production(tmp_path, monkeypatch):
    monkeypatch.delenv("OWNER_PASSWORD", raising=False)
    app = create_app(
        db_path=tmp_path / "app.db",
        data_dir=tmp_path / "data",
        owner_username="edifier8989",
        owner_password_hash="",
        secret_key="test-secret-key-at-least-32-characters-long",
    )
    response = TestClient(app).post(
        "/api/auth/login", json={"username": "edifier8989", "password": "x"}
    )
    assert response.status_code == 503
