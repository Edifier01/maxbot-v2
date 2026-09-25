import asyncio
import logging
import sys
from types import ModuleType, SimpleNamespace

from maxbot_v2.onboarding import WebCodeAuthFlow


def test_auth_keeps_pymax_code_request_order_and_safe_stage_logs(monkeypatch, caplog):
    calls = []

    class AuthResult:
        def __init__(self, token):
            self.token = token

    models = ModuleType("pymax.auth.models")
    models.AuthResult = AuthResult
    monkeypatch.setitem(sys.modules, "pymax.auth.models", models)

    class AuthApi:
        async def request_code(self, phone):
            calls.append(("request_code", phone))
            return SimpleNamespace(token="private-token")

        async def send_code(self, token, code):
            calls.append(("send_code", token, code))
            return SimpleNamespace(login_token="login-token", password_challenge=None, register_token=None)

    app = SimpleNamespace(api=SimpleNamespace(auth=AuthApi()), config=SimpleNamespace(phone="+79990000000"))
    updates = []
    flow = WebCodeAuthFlow(lambda state, hint: updates.append((state, hint)), account_id=42, proxy_id=9)
    flow.codes.put_nowait("123456")

    with caplog.at_level(logging.INFO, logger="maxbot_v2.onboarding"):
        result = asyncio.run(flow.authenticate(app))

    assert [call[0] for call in calls] == ["request_code", "send_code"]
    assert result.token == "login-token"
    assert ("waiting_code", "MAX принял запрос кода. Ожидайте сообщение с кодом.") in updates
    assert "stage=request_code" in caplog.text
    assert "stage=send_code" in caplog.text
    assert "account_id=42" in caplog.text and "proxy_id=9" in caplog.text
    assert "+79990000000" not in caplog.text
    assert "123456" not in caplog.text
    assert "private-token" not in caplog.text


def test_request_code_failure_logs_only_error_class(caplog):
    class AuthApi:
        async def request_code(self, _phone):
            raise RuntimeError("private-code-and-proxy-value")

    app = SimpleNamespace(api=SimpleNamespace(auth=AuthApi()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(lambda _state, _hint: None, account_id=42, proxy_id=9)

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
