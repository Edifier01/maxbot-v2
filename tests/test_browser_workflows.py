from __future__ import annotations

import socket
import sqlite3
import threading
import time
from types import SimpleNamespace
from urllib.request import urlopen

import bcrypt
import pytest

playwright = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Page, expect

from maxbot_v2.app import create_app
from maxbot_v2.crypto import SecretBox
from maxbot_v2.db import connect


@pytest.fixture
def fake_pymax(monkeypatch):
    class FakeAuth:
        async def request_code(self, _phone):
            return SimpleNamespace(token="fixture-auth-token", code_length=6, request_count_left=3, request_max_duration=300)

        async def send_code(self, token, code):
            assert token == "fixture-auth-token"
            assert code == "123456"
            return SimpleNamespace(login_token="fixture-login-token", password_challenge=None, register_token=None)

    class FakeAdapter:
        def __init__(self, phone, auth_flow, session_vault):
            self.auth_flow = auth_flow
            self.session_vault = session_vault
            self.client = SimpleNamespace(me=SimpleNamespace(contact=SimpleNamespace(id=314159)))
            self.phone = phone
            session_vault.open()

        async def connect(self):
            if self.auth_flow is not None:
                app = SimpleNamespace(
                    api=SimpleNamespace(auth=FakeAuth()),
                    config=SimpleNamespace(phone=self.phone),
                )
                await self.auth_flow.authenticate(app)
                connection = sqlite3.connect(self.session_vault.work_path)
                try:
                    connection.execute("CREATE TABLE IF NOT EXISTS fake_session (authenticated INTEGER NOT NULL)")
                    connection.execute("DELETE FROM fake_session")
                    connection.execute("INSERT INTO fake_session(authenticated) VALUES(1)")
                    connection.commit()
                finally:
                    connection.close()

        async def resolve_group_by_link(self, _link):
            return SimpleNamespace(id=7001)

        async def get_chat(self, _chat_id):
            return SimpleNamespace(id=7001, status="member", join_time=1)

        async def close(self):
            self.session_vault.seal()

    monkeypatch.setattr(
        "maxbot_v2.app.PyMaxAdapter.create",
        classmethod(lambda _cls, *, phone, auth_flow=None, session_vault, **_kwargs: FakeAdapter(phone, auth_flow, session_vault)),
    )


@pytest.fixture
def local_app(tmp_path, monkeypatch, fake_pymax):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    monkeypatch.setenv("SESSION_RUNTIME_DIR", str(tmp_path / "runtime"))
    password = "Browser-test-password-42"
    app = create_app(
        db_path=tmp_path / "browser.sqlite3",
        data_dir=tmp_path / "data",
        owner_username="owner",
        owner_password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        secret_key="browser-test-app-secret-key-with-32-characters",
        secure_cookies=False,
    )
    app.state.worker_manager.poll_seconds = 0.05
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]

    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2) as response:
                if response.status != 200:
                    raise RuntimeError("test application returned an unhealthy response")
                break
        except OSError:
            time.sleep(0.05)
    else:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("test application did not start")

    try:
        yield SimpleNamespace(app=app, url=f"http://127.0.0.1:{port}", password=password)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=5)
        listener.close()


def login(page: Page, local_app):
    page.goto(local_app.url)
    page.get_by_label("Логин").fill("owner")
    page.get_by_label("Пароль").fill(local_app.password)
    page.get_by_role("button", name="Войти").click()
    expect(page.locator("#title")).to_have_text("Обзор")


@pytest.mark.parametrize("width", [390, 768, 1440])
def test_owner_login_navigation_and_run_controls_at_supported_widths(page: Page, local_app, width):
    page.set_viewport_size({"width": width, "height": 900})
    login(page, local_app)

    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert page.get_by_role("button", name="Остановить").is_enabled()
    page.get_by_role("button", name="Остановить").focus()
    page.keyboard.press("Enter")
    expect(page.locator("#run-state")).to_have_text("Остановлено")
    page.get_by_role("button", name="Запустить").click()
    expect(page.locator("#run-state")).to_have_text("Работа сейчас включена")

    for name, heading in (
        ("Группы, номера и прокси", "Группы, номера и прокси"),
        ("Пул сообщений", "Пул сообщений"),
        ("Настройки", "Настройки"),
        ("Журнал", "Журнал"),
        ("Обзор", "Обзор"),
    ):
        page.get_by_role("button", name=name).click()
        expect(page.locator("#title")).to_have_text(heading)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    page.get_by_role("button", name="Группы, номера и прокси").click()
    page.get_by_label("Название", exact=True).fill("Неверная ссылка")
    page.get_by_label("Ссылка MAX").fill("https://example.com/join/test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    expect(page.locator("#new-group [data-form-error]")).to_contain_text("Укажите действующую ссылку приглашения MAX")
    expect(page.get_by_label("Ссылка MAX")).to_have_value("https://example.com/join/test")

    page.get_by_role("button", name="Пул сообщений").click()
    page.locator("#texts").fill("Первый тестовый текст\nВторой тестовый текст")
    page.get_by_role("button", name="Сохранить новый цикл").click()
    expect(page.locator("#view")).to_contain_text("2 текстов")

    page.get_by_role("button", name="Настройки").click()
    page.get_by_role("button", name="Сохранить", exact=True).click()
    expect(page.locator("#notice")).to_have_text("Настройки сохранены")


def test_guest_connect_survives_reload_and_verifies_membership(page: Page, browser, local_app):
    page.set_viewport_size({"width": 390, "height": 844})
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и прокси").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/browser-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    expect(page.get_by_role("button", name="Проверить назначение")).to_be_disabled()
    page.locator(".bulk-proxy-form textarea").fill("socks5://127.0.0.1:1080")
    page.get_by_role("button", name="Добавить прокси из списка").click()
    page.get_by_role("button", name="Создать новую ссылку").click()
    invite = page.locator(".invite-link a")
    expect(invite).to_be_visible()

    guest = browser.new_page(viewport={"width": 390, "height": 844})
    guest.goto(invite.get_attribute("href"))
    guest.get_by_label("ФИО").fill("Тестовый пользователь")
    guest.get_by_label("Телефон").fill("+79990000000")
    guest.get_by_role("button", name="Начать подключение").click()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    expect(guest.locator("#code-hint")).to_contain_text("не подтверждает доставку SMS")
    assert page_has_no_overflow(guest)
    stored = guest.evaluate("({count: sessionStorage.length, values: Object.values(sessionStorage)})")
    assert stored["count"] == 1
    assert len(stored["values"][0]) >= 20

    guest.reload()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    guest.get_by_label("Код").fill("123456")
    guest.get_by_role("button", name="Проверить код").click()
    assert page_has_no_overflow(guest)
    stored = guest.evaluate("Object.values(sessionStorage).join(' ')")
    assert "123456" not in stored
    guest.get_by_role("button", name="Проверить вступление").click()
    expect(guest.locator("#flow")).to_contain_text("Номер подключён", timeout=5000)

    connection = connect(local_app.app.state.database)
    try:
        assert connection.execute("SELECT status FROM accounts WHERE phone='+79990000000'").fetchone()[0] == "active"
        assert connection.execute("SELECT state FROM onboarding_sessions").fetchone()[0] == "completed"
        account_id = connection.execute("SELECT id FROM accounts WHERE phone='+79990000000'").fetchone()[0]
        assert (local_app.app.state.data_dir / "sessions" / f"account-{account_id}.session.enc").exists()
    finally:
        connection.close()


def test_guest_can_cancel_an_authorization_attempt(page: Page, browser, local_app):
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и прокси").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/cancel-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    page.locator(".bulk-proxy-form textarea").fill("socks5://127.0.0.1:1080")
    page.get_by_role("button", name="Добавить прокси из списка").click()
    page.get_by_role("button", name="Создать новую ссылку").click()

    guest = browser.new_page()
    guest.goto(page.locator(".invite-link a").get_attribute("href"))
    guest.get_by_label("ФИО").fill("Тестовый пользователь")
    guest.get_by_label("Телефон").fill("+79990000000")
    guest.get_by_role("button", name="Начать подключение").click()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    guest.get_by_role("button", name="Отменить подключение").click()
    expect(guest.get_by_role("button", name="Повторить подключение")).to_be_visible()

    connection = connect(local_app.app.state.database)
    try:
        assert connection.execute("SELECT state FROM onboarding_sessions").fetchone()[0] == "cancelled"
        assert guest.evaluate("sessionStorage.length") == 0
    finally:
        connection.close()


def page_has_no_overflow(page):
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
