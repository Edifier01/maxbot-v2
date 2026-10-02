from __future__ import annotations

import socket
import sqlite3
import threading
import time
from types import SimpleNamespace
from urllib.request import urlopen

import bcrypt
import pytest
from pymax.auth.sms import SmsAuthFlow
from pymax.exceptions import ApiError

playwright = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Page, expect

from maxbot_v2.app import create_app
from maxbot_v2.crypto import SecretBox
from maxbot_v2.db import connect


@pytest.fixture
def fake_pymax(monkeypatch):
    code_requests = []
    joined_requests = []
    memberships = set()
    join_should_fail = set()
    resolve_should_fail = set()
    auth_error = {"value": None}
    password_attempts = []

    class FakeAuth:
        async def request_code(self, phone):
            code_requests.append((phone, "62.109.20.186"))
            return SimpleNamespace(token="fixture-auth-token", code_length=6, request_count_left=3, request_max_duration=300)

        async def send_code(self, token, code):
            assert token == "fixture-auth-token"
            assert code == "123456"
            if auth_error["value"] == "password_challenge":
                return SimpleNamespace(login_token=None, password_challenge=SimpleNamespace(track_id="fixture-track", hint="Проверьте облачный пароль"), register_token=None)
            if auth_error["value"]:
                raise ApiError(opcode=18, error=auth_error["value"])
            return SimpleNamespace(login_token="fixture-login-token", password_challenge=None, register_token=None)

        async def check_password(self, track_id, password):
            assert track_id == "fixture-track"
            accepted = password == "correct-two-factor"
            password_attempts.append(accepted)
            if not accepted:
                raise ApiError(opcode=18, error="wrong_password")
            return SimpleNamespace(error=None, login_token="fixture-login-token")

    class FakeAdapter:
        def __init__(self, phone, code_provider, password_provider, session_vault):
            self.auth_flow = SmsAuthFlow(code_provider, password_provider) if code_provider is not None else None
            self.session_vault = session_vault
            self.client = SimpleNamespace(me=SimpleNamespace(contact=SimpleNamespace(id=314159)))
            self.phone = phone
            session_vault.open()

        async def connect(self):
            if self.auth_flow is not None:
                app = SimpleNamespace(
                    api=SimpleNamespace(auth=FakeAuth()),
                    config=SimpleNamespace(phone=self.phone, registration_config=None, password_max_attempts=5),
                )
                await self.auth_flow.authenticate(app)
                connection = sqlite3.connect(self.session_vault.work_path)
                try:
                    connection.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT NOT NULL PRIMARY KEY)")
                    connection.execute("INSERT OR REPLACE INTO sessions(token) VALUES('fixture-auth-token')")
                    connection.commit()
                finally:
                    connection.close()

        def persist_session_snapshot(self):
            return self.session_vault.snapshot()

        async def resolve_group_by_link(self, _link):
            if self.phone in resolve_should_fail:
                raise RuntimeError("invalid invite")
            return SimpleNamespace(id=7001)

        async def join_group(self, link):
            joined_requests.append((self.phone, link))
            if self.phone in join_should_fail:
                raise TimeoutError("uncertain join result")
            memberships.add(self.phone)
            return SimpleNamespace(id=7001)

        async def get_chat(self, _chat_id):
            joined = self.phone in memberships
            return SimpleNamespace(id=7001, status="member" if joined else "none", join_time=1 if joined else 0)

        async def close(self):
            self.session_vault.seal()

    monkeypatch.setattr(
        "maxbot_v2.app.PyMaxAdapter.create",
        classmethod(lambda _cls, *, phone, code_provider=None, password_provider=None, session_vault, **_kwargs: FakeAdapter(phone, code_provider, password_provider, session_vault)),
    )
    return SimpleNamespace(code_requests=code_requests, joined_requests=joined_requests, memberships=memberships, join_should_fail=join_should_fail, resolve_should_fail=resolve_should_fail, auth_error=auth_error, password_attempts=password_attempts)


@pytest.fixture
def local_app(tmp_path, monkeypatch, fake_pymax):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    monkeypatch.setenv("SESSION_RUNTIME_DIR", str(tmp_path / "runtime"))
    from maxbot_v2.egress import bootstrap_ips
    monkeypatch.setattr("maxbot_v2.app.bootstrap_ips", lambda db: bootstrap_ips(db, addresses={"62.109.20.186"}, probe=lambda _address: True))
    monkeypatch.setattr("maxbot_v2.app.host_addresses", lambda: {"62.109.20.186"})
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
        yield SimpleNamespace(app=app, url=f"http://127.0.0.1:{port}", password=password, code_requests=fake_pymax.code_requests, joined_requests=fake_pymax.joined_requests, memberships=fake_pymax.memberships, join_should_fail=fake_pymax.join_should_fail, resolve_should_fail=fake_pymax.resolve_should_fail, auth_error=fake_pymax.auth_error, password_attempts=fake_pymax.password_attempts)
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
def test_owner_adds_number_from_selected_group(page: Page, local_app, width):
    page.set_viewport_size({"width": width, "height": 900})
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    for name, link in (
        ("Первая группа", "https://max.ru/join/first-owner-group"),
        ("Группа администратора", "https://max.ru/join/owner-group"),
    ):
        form = page.locator("#new-group")
        form.get_by_label("Название", exact=True).fill(name)
        form.get_by_label("Ссылка MAX").fill(link)
        form.get_by_role("button", name="Добавить", exact=True).click()
        expect(page.locator(".group-card").filter(has_text=name)).to_be_visible()

    group = page.locator(".group-card").filter(has_text="Группа администратора")
    add_number = group.get_by_role("link", name="Добавить номер", exact=True)
    expect(add_number).to_be_visible()
    assert page_has_no_overflow(page)
    add_number.focus()
    with page.expect_popup() as popup:
        page.keyboard.press("Enter")
    connection_page = popup.value
    expect(connection_page.get_by_role("heading", name="Группа администратора")).to_be_visible()
    assert local_app.code_requests == []
    connection_page.get_by_label("ФИО").fill("Администратор теста")
    connection_page.get_by_label("Телефон").fill("8 (999) 000-00-00")
    connection_page.get_by_role("button", name="Начать подключение").click()
    expect(connection_page.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    connection_page.get_by_label("Код").fill("123456")
    connection_page.get_by_role("button", name="Проверить код").click()
    expect(connection_page.locator("#flow")).to_contain_text("Номер подключён")
    assert page_has_no_overflow(connection_page)
    group.get_by_role("button", name="Номера", exact=True).click()
    expect(group).to_contain_text("Администратор теста")
    expect(group).to_contain_text("подключён")
    assert "79990000000" not in group.inner_text()
    connection = connect(local_app.app.state.database)
    try:
        account = connection.execute(
            "SELECT a.auth_state,a.status,g.name FROM accounts a JOIN groups g ON g.id=a.group_id"
        ).fetchone()
        assert tuple(account) == ("authenticated", "active", "Группа администратора")
    finally:
        connection.close()
        connection_page.close()


@pytest.mark.parametrize("width", [390, 768, 1440])
def test_ip_list_is_compact_and_keyboard_operable(page: Page, local_app, monkeypatch, width):
    from maxbot_v2.egress import refresh_ips
    monkeypatch.setattr(
        "maxbot_v2.app.refresh_ips",
        lambda connection: refresh_ips(connection, addresses={"62.109.20.186"}, probe=lambda _address: True),
    )
    connection = connect(local_app.app.state.database)
    try:
        connection.executemany(
            "INSERT INTO server_ips(address,enabled,available) VALUES(?,0,1)",
            [(f"62.109.20.{number}",) for number in range(187, 199)],
        )
        connection.commit()
    finally:
        connection.close()
    page.set_viewport_size({"width": width, "height": 900})
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    expect(page.locator("#ip-list .row")).to_have_count(13)
    expect(page.get_by_role("button", name="Обновить IP")).to_be_hidden()
    expect(page.locator("#ip-list")).to_be_hidden()
    summary = page.locator("#ip-panel summary")
    expect(summary).to_contain_text("13")
    assert page.locator("#ip-panel").bounding_box()["height"] < 130
    summary.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("button", name="Обновить IP")).to_be_visible()
    expect(page.locator("#ip-list")).to_be_visible()
    assert page.locator("#ip-list").bounding_box()["height"] <= 420
    assert page.locator("#ip-list").evaluate("element => element.scrollHeight > element.clientHeight")
    assert page_has_no_overflow(page)
    row = page.locator("#ip-list .row").filter(has_text="62.109.20.186")
    row.get_by_role("button", name="Отключить", exact=True).click()
    expect(row.get_by_role("button", name="Включить", exact=True)).to_be_enabled()
    expect(page.locator("#ip-list")).to_be_visible()
    page.get_by_role("button", name="Обновить IP").click()
    expect(page.locator("#notice")).to_have_text("Список IP обновлён")
    expect(page.locator("#ip-list")).to_be_visible()
    expect(page.locator("#ip-list .row")).to_have_count(13)
    summary.focus()
    page.keyboard.press("Enter")
    expect(page.locator("#ip-list")).to_be_hidden()
    assert page_has_no_overflow(page)


def test_owner_add_number_tracks_invite_rotation_and_revocation(page: Page, local_app):
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Обновление подключения")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/owner-rotate")
    page.get_by_role("button", name="Добавить", exact=True).click()
    add_number = page.get_by_role("link", name="Добавить номер", exact=True)
    expect(add_number).to_be_visible()
    previous_link = add_number.get_attribute("href")
    page.on("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Заменить ссылку", exact=True).click()
    expect(add_number).not_to_have_attribute("href", previous_link)
    page.get_by_role("button", name="Отозвать", exact=True).click()
    expect(page.get_by_role("button", name="Добавить номер", exact=True)).to_be_disabled()
    expect(add_number).to_have_count(0)
    page.get_by_role("button", name="Создать новую ссылку", exact=True).click()
    expect(add_number).to_be_visible()
    assert local_app.code_requests == []


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
        ("Группы, номера и IP", "Группы, номера и IP"),
        ("Пул сообщений", "Пул сообщений"),
        ("Настройки", "Настройки"),
        ("Журнал", "Журнал"),
        ("Обзор", "Обзор"),
    ):
        page.get_by_role("button", name=name).click()
        expect(page.locator("#title")).to_have_text(heading)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    page.get_by_role("button", name="Группы, номера и IP").click()
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
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/browser-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    expect(page.get_by_role("button", name="Проверить назначение")).to_be_disabled()
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
    expect(guest.locator("#flow")).to_contain_text("Номер подключён", timeout=5000)
    assert local_app.code_requests == [
        ("+79990000000", "62.109.20.186")
    ]
    assert local_app.joined_requests == [("+79990000000", "https://max.ru/join/browser-test")]

    connection = connect(local_app.app.state.database)
    try:
        assert connection.execute("SELECT status FROM accounts WHERE phone='+79990000000'").fetchone()[0] == "active"
        assert connection.execute("SELECT state FROM onboarding_sessions").fetchone()[0] == "completed"
        account_id = connection.execute("SELECT id FROM accounts WHERE phone='+79990000000'").fetchone()[0]
        assert (local_app.app.state.data_dir / "sessions" / f"account-{account_id}.session.enc").exists()
    finally:
        connection.close()


def test_guest_2fa_retries_wrong_password_without_requesting_a_new_otp(page: Page, browser, local_app):
    local_app.auth_error["value"] = "password_challenge"
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Двухфакторная группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/two-factor-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    guest = browser.new_page()
    guest.goto(page.locator(".invite-link a").get_attribute("href"))
    guest.get_by_label("ФИО").fill("Тестовый пользователь")
    guest.get_by_label("Телефон").fill("+79990000000")
    guest.get_by_role("button", name="Начать подключение").click()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    guest.get_by_label("Код").fill("123456")
    guest.get_by_role("button", name="Проверить код").click()

    expect(guest.get_by_role("heading", name="Облачный пароль MAX")).to_be_visible()
    guest.get_by_label("Пароль").fill("incorrect-two-factor")
    guest.get_by_role("button", name="Продолжить").click()
    session_id = guest.evaluate("Object.values(sessionStorage)[0]")
    flow = local_app.app.state.onboarding_flows[session_id]["flow"]
    deadline = time.monotonic() + 5
    while (not local_app.password_attempts or flow.waiting_for != "password") and time.monotonic() < deadline:
        time.sleep(0.01)
    assert local_app.password_attempts == [False]
    assert flow.waiting_for == "password"
    expect(guest.locator("#password-hint")).to_contain_text("не принял предыдущий облачный пароль", timeout=5000)
    guest.get_by_label("Пароль").fill("correct-two-factor")
    guest.get_by_role("button", name="Продолжить").click()
    expect(guest.locator("#flow")).to_contain_text("Номер подключён", timeout=5000)

    assert len(local_app.code_requests) == 1
    assert local_app.password_attempts == [False, True]


def test_guest_can_cancel_an_authorization_attempt(page: Page, browser, local_app):
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/cancel-test")
    page.get_by_role("button", name="Добавить", exact=True).click()

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


def test_no2fa_after_otp_cleans_unverified_account_without_automatic_code_retry(page: Page, browser, local_app):
    local_app.auth_error["value"] = "error.profile.active.session.no2fa"
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/no2fa-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    guest = browser.new_page()
    guest.goto(page.locator(".invite-link a").get_attribute("href"))
    guest.get_by_label("ФИО").fill("Тестовый пользователь")
    guest.get_by_label("Телефон").fill("+79990000000")
    guest.get_by_role("button", name="Начать подключение").click()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    guest.get_by_label("Код").fill("123456")
    guest.get_by_role("button", name="Проверить код").click()
    expect(guest.locator("#flow")).to_contain_text("MAX требует пароль для входа", timeout=5000)
    assert len(local_app.code_requests) == 1
    connection = connect(local_app.app.state.database)
    try:
        account = connection.execute("SELECT id,lifecycle,phone FROM accounts WHERE full_name=''").fetchone()
        assert account["lifecycle"] == "deleted"
        assert account["phone"] == f"deleted:{account['id']}"
        assert connection.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (account["id"],)).fetchone()[0] == 0
        assert connection.execute("SELECT error_code FROM onboarding_sessions").fetchone()[0] == "max_password_required_on_active_session"
        assert connection.execute("SELECT phone,full_name FROM onboarding_sessions").fetchone()[:] == (None, None)
    finally:
        connection.close()


def test_expired_attempt_releases_account_lock_for_new_start(page: Page, browser, local_app):
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/expiry-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    guest = browser.new_page()
    guest.goto(page.locator(".invite-link a").get_attribute("href"))
    guest.get_by_label("ФИО").fill("Тестовый пользователь")
    guest.get_by_label("Телефон").fill("89990000000")
    guest.get_by_role("button", name="Начать подключение").click()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    guest.close()
    connection = connect(local_app.app.state.database)
    old_account_id = connection.execute("SELECT account_id FROM onboarding_sessions").fetchone()[0]
    connection.execute("UPDATE onboarding_sessions SET expires_at='2000-01-01T00:00:00+00:00' WHERE state='waiting_code'")
    connection.close()
    second = browser.new_page()
    second.goto(page.locator(".invite-link a").get_attribute("href"))
    second.get_by_label("ФИО").fill("Тестовый пользователь")
    second.get_by_label("Телефон").fill("+79990000000")
    second.get_by_role("button", name="Начать подключение").click()
    expect(second.get_by_role("heading", name="Введите код MAX")).to_be_visible(timeout=5000)
    assert len(local_app.code_requests) == 2
    connection = connect(local_app.app.state.database)
    try:
        new_account_id = connection.execute(
            "SELECT account_id FROM onboarding_sessions WHERE id=(SELECT id FROM onboarding_sessions ORDER BY created_at DESC LIMIT 1)",
        ).fetchone()[0]
        assert new_account_id != old_account_id
        assert connection.execute("SELECT lifecycle FROM accounts WHERE id=?", (old_account_id,)).fetchone()[0] == "deleted"
        assert connection.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (old_account_id,)).fetchone()[0] == 0
    finally:
        connection.close()


def test_failed_auto_join_keeps_session_for_manual_membership_check(page: Page, browser, local_app):
    phone = "+79990000000"
    local_app.join_should_fail.add(phone)
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/manual-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    guest = browser.new_page(viewport={"width": 390, "height": 844})
    guest.goto(page.locator(".invite-link a").get_attribute("href"))
    guest.get_by_label("ФИО").fill("Тестовый пользователь")
    guest.get_by_label("Телефон").fill("89990000000")
    guest.get_by_role("button", name="Начать подключение").click()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    guest.get_by_label("Код").fill("123456")
    guest.get_by_role("button", name="Проверить код").click()
    expect(guest.get_by_role("button", name="Проверить вступление")).to_be_visible()
    expect(guest.get_by_role("button", name="Отменить подключение")).to_have_count(0)
    connection = connect(local_app.app.state.database)
    try:
        account = connection.execute(
            "SELECT id,status,auth_state,ever_authenticated FROM accounts WHERE phone=?", (phone,),
        ).fetchone()
        assert account["status"] == "needs_membership"
        assert account["auth_state"] == "authenticated" and account["ever_authenticated"] == 1
        attempt = connection.execute(
            "SELECT state,phone,full_name FROM onboarding_sessions WHERE account_id=?", (account["id"],),
        ).fetchone()
        assert tuple(attempt) == ("waiting_membership", phone, "Тестовый пользователь")
    finally:
        connection.close()
    local_app.memberships.add(phone)
    guest.get_by_role("button", name="Проверить вступление").click()
    expect(guest.locator("#flow")).to_contain_text("Номер подключён")
    connection = connect(local_app.app.state.database)
    try:
        attempt = connection.execute(
            "SELECT state,phone,full_name FROM onboarding_sessions WHERE account_id=?", (account["id"],),
        ).fetchone()
        assert tuple(attempt) == ("completed", None, None)
    finally:
        connection.close()


def test_invalid_group_link_preserves_login_for_owner_repair(page: Page, browser, local_app):
    phone = "+79990000000"
    local_app.resolve_should_fail.add(phone)
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Тестовая группа")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/invalid-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    guest = browser.new_page()
    guest.goto(page.locator(".invite-link a").get_attribute("href"))
    guest.get_by_label("ФИО").fill("Тестовый пользователь")
    guest.get_by_label("Телефон").fill("89990000000")
    guest.get_by_role("button", name="Начать подключение").click()
    expect(guest.get_by_role("heading", name="Введите код MAX")).to_be_visible()
    guest.get_by_label("Код").fill("123456")
    guest.get_by_role("button", name="Проверить код").click()
    expect(guest.get_by_role("button", name="Проверить вступление")).to_be_visible()
    connection = connect(local_app.app.state.database)
    try:
        account = connection.execute("SELECT id,status FROM accounts WHERE phone=?", (phone,)).fetchone()
        assert account["status"] == "needs_membership"
        assert (local_app.app.state.data_dir / "sessions" / f"account-{account['id']}.session.enc").exists()
    finally:
        connection.close()


@pytest.mark.parametrize("width", [390, 768, 1440])
def test_owner_deletes_account_and_sessions_with_keyboard_confirmation(page: Page, local_app, width):
    page.set_viewport_size({"width": width, "height": 900})
    login(page, local_app)
    page.get_by_role("button", name="Группы, номера и IP").click()
    page.get_by_label("Название", exact=True).fill("Очистка аккаунта")
    page.get_by_label("Ссылка MAX").fill("https://max.ru/join/delete-test")
    page.get_by_role("button", name="Добавить", exact=True).click()
    expect(page.locator("#group-list")).to_contain_text("Очистка аккаунта")
    connection = connect(local_app.app.state.database)
    try:
        group = connection.execute("SELECT id FROM groups ORDER BY id DESC LIMIT 1").fetchone()
        account_id = connection.execute(
            "INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?, '+79990000123','Тестовый аккаунт','pending')",
            (group["id"],),
        ).lastrowid
    finally:
        connection.close()
    page.get_by_role("button", name="Номера", exact=True).click()
    delete = page.get_by_role("button", name="Удалить номер и сессию")
    expect(delete).to_be_visible()
    assert page_has_no_overflow(page)
    page.on("dialog", lambda dialog: dialog.accept())
    delete.focus()
    page.keyboard.press("Enter")
    expect(page.locator("#notice")).to_have_text("Номер и сессии удалены")
    expect(page.locator(f'[data-account-delete="{account_id}"]')).to_have_count(0)
    assert page_has_no_overflow(page)


def page_has_no_overflow(page):
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
