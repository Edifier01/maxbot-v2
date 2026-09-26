import asyncio
import logging
import sys
from types import ModuleType, SimpleNamespace

from maxbot_v2.onboarding import WebCodeAuthFlow


def test_auth_requests_code_directly_then_uses_proxy_auth_api_and_safe_logs(monkeypatch, caplog):
    calls = []

    class AuthResult:
        def __init__(self, token):
            self.token = token

    models = ModuleType("pymax.auth.models")
    models.AuthResult = AuthResult
    monkeypatch.setitem(sys.modules, "pymax.auth.models", models)

    async def direct_request_code(phone):
        calls.append(("direct_request_code", phone))
        return SimpleNamespace(token="private-token", code_length=6, request_count_left=2, request_max_duration=300)

    class AuthApi:

        async def send_code(self, token, code):
            calls.append(("send_code", token, code))
            return SimpleNamespace(login_token="login-token", password_challenge=None, register_token=None)

    app = SimpleNamespace(api=SimpleNamespace(auth=AuthApi()), config=SimpleNamespace(phone="+79990000000"))
    updates = []
    flow = WebCodeAuthFlow(
        lambda state, hint: updates.append((state, hint)),
        request_code=direct_request_code,
        account_id=42,
        proxy_id=9,
        session_id="attempt-1",
    )
    flow.codes.put_nowait("123456")

    with caplog.at_level(logging.INFO, logger="maxbot_v2.onboarding"):
        result = asyncio.run(flow.authenticate(app))

    assert [call[0] for call in calls] == ["direct_request_code", "send_code"]
    assert result.token == "login-token"
    assert updates[0][0] == "requesting_code"
    assert updates[1][0] == "waiting_code"
    assert "не подтверждает доставку SMS" in updates[1][1]
    assert "stage=request_code" in caplog.text
    assert "stage=send_code" in caplog.text
    assert "account_id=42" in caplog.text and "proxy_id=9" in caplog.text
    assert "session_id=attempt-1" in caplog.text
    assert "code_length=6" in caplog.text and "request_count_left=2" in caplog.text
    assert "+79990000000" not in caplog.text
    assert "123456" not in caplog.text
    assert "private-token" not in caplog.text


def test_request_code_failure_logs_only_error_class(caplog):
    async def direct_request_code(_phone):
        raise RuntimeError("private-code-and-proxy-value")

    app = SimpleNamespace(api=SimpleNamespace(auth=SimpleNamespace()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(
        lambda _state, _hint: None,
        request_code=direct_request_code,
        account_id=42,
        proxy_id=9,
    )

    with caplog.at_level(logging.WARNING, logger="maxbot_v2.onboarding"):
        try:
            asyncio.run(flow.authenticate(app))
        except RuntimeError:
            pass
        else:
            raise AssertionError("expected authentication failure")

    assert "error_class=RuntimeError" in caplog.text
    assert "private-code-and-proxy-value" not in caplog.text
    assert "+79990000000" not in caplog.text


def test_rejected_code_records_its_pymax_stage_without_logging_remote_text(monkeypatch, caplog):
    class AuthResult:
        def __init__(self, token):
            self.token = token

    class ApiError(Exception):
        pass

    models = ModuleType("pymax.auth.models")
    models.AuthResult = AuthResult
    monkeypatch.setitem(sys.modules, "pymax.auth.models", models)

    async def direct_request_code(_phone):
        return SimpleNamespace(token="private-token", code_length=6, request_count_left=2)

    class AuthApi:
        async def send_code(self, _token, _code):
            raise ApiError("private remote response")

    app = SimpleNamespace(api=SimpleNamespace(auth=AuthApi()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(
        lambda _state, _hint: None,
        request_code=direct_request_code,
        session_id="attempt-2",
    )
    flow.codes.put_nowait("123456")

    with caplog.at_level(logging.WARNING, logger="maxbot_v2.onboarding"):
        try:
            asyncio.run(flow.authenticate(app))
        except ApiError:
            pass
        else:
            raise AssertionError("expected MAX to reject the code")

    assert flow.current_stage == "send_code"
    assert "stage=send_code" in caplog.text
    assert "error_class=ApiError" in caplog.text
    assert "private remote response" not in caplog.text
    assert "private-token" not in caplog.text
    assert "123456" not in caplog.text


def test_password_challenge_uses_proxy_after_direct_code_request(monkeypatch):
    calls = []

    class AuthResult:
        def __init__(self, token):
            self.token = token

    models = ModuleType("pymax.auth.models")
    models.AuthResult = AuthResult
    monkeypatch.setitem(sys.modules, "pymax.auth.models", models)

    async def direct_request_code(phone):
        calls.append(("direct_request_code", phone))
        return SimpleNamespace(token="challenge-token", code_length=6)

    class ProxyAuthApi:
        async def send_code(self, token, code):
            calls.append(("proxy_send_code", token, code))
            return SimpleNamespace(
                login_token=None,
                password_challenge=SimpleNamespace(track_id="track-1", hint=None),
                register_token=None,
            )

        async def check_password(self, track_id, password):
            calls.append(("proxy_check_password", track_id, password))
            return SimpleNamespace(error=None, login_token="login-token")

    app = SimpleNamespace(api=SimpleNamespace(auth=ProxyAuthApi()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(lambda _state, _hint: None, request_code=direct_request_code)
    flow.codes.put_nowait("123456")
    flow.passwords.put_nowait("secret-password")

    result = asyncio.run(flow.authenticate(app))

    assert calls == [
        ("direct_request_code", "+79990000000"),
        ("proxy_send_code", "challenge-token", "123456"),
        ("proxy_check_password", "track-1", "secret-password"),
    ]
    assert result.token == "login-token"
