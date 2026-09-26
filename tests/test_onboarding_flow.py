import asyncio
import logging
import sys
from types import ModuleType, SimpleNamespace

from maxbot_v2.onboarding import WebCodeAuthFlow, join_group_and_confirm_membership


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
        validate_proxy=lambda: None,
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
        validate_proxy=lambda: None,
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
        validate_proxy=lambda: None,
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
    flow = WebCodeAuthFlow(
        lambda _state, _hint: None,
        request_code=direct_request_code,
        validate_proxy=lambda: calls.append(("validate_proxy",)),
    )
    flow.codes.put_nowait("123456")
    flow.passwords.put_nowait("secret-password")

    result = asyncio.run(flow.authenticate(app))

    assert calls == [
        ("validate_proxy",),
        ("direct_request_code", "+79990000000"),
        ("validate_proxy",),
        ("proxy_send_code", "challenge-token", "123456"),
        ("validate_proxy",),
        ("proxy_check_password", "track-1", "secret-password"),
        ("validate_proxy",),
    ]
    assert result.token == "login-token"


def test_stale_proxy_assignment_blocks_direct_code_request():
    calls = []

    def validate_proxy():
        calls.append("validate_proxy")
        raise RuntimeError("proxy_assignment_changed")

    async def direct_request_code(_phone):
        calls.append("direct_request_code")
        return SimpleNamespace(token="challenge-token", code_length=6)

    app = SimpleNamespace(api=SimpleNamespace(auth=SimpleNamespace()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(
        lambda _state, _hint: None,
        request_code=direct_request_code,
        validate_proxy=validate_proxy,
    )

    try:
        asyncio.run(flow.authenticate(app))
    except RuntimeError as exc:
        assert str(exc) == "proxy_assignment_changed"
    else:
        raise AssertionError("expected stale proxy assignment to stop authentication")

    assert calls == ["validate_proxy"]


def test_proxy_is_revalidated_before_code_submission():
    calls = []

    def validate_proxy():
        calls.append("validate_proxy")
        if calls.count("validate_proxy") == 2:
            raise RuntimeError("proxy_assignment_changed")

    async def direct_request_code(_phone):
        calls.append("direct_request_code")
        return SimpleNamespace(token="challenge-token", code_length=6)

    class ProxyAuthApi:
        async def send_code(self, *_args):
            calls.append("proxy_send_code")
            return SimpleNamespace(login_token="login-token", password_challenge=None, register_token=None)

    app = SimpleNamespace(api=SimpleNamespace(auth=ProxyAuthApi()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(
        lambda _state, _hint: None,
        request_code=direct_request_code,
        validate_proxy=validate_proxy,
    )
    flow.codes.put_nowait("123456")

    try:
        asyncio.run(flow.authenticate(app))
    except RuntimeError as exc:
        assert str(exc) == "proxy_assignment_changed"
    else:
        raise AssertionError("expected stale proxy assignment to stop code submission")

    assert calls == ["validate_proxy", "direct_request_code", "validate_proxy"]


def test_proxy_is_revalidated_before_password_submission():
    calls = []

    def validate_proxy():
        calls.append("validate_proxy")
        if calls.count("validate_proxy") == 3:
            raise RuntimeError("proxy_assignment_changed")

    async def direct_request_code(_phone):
        calls.append("direct_request_code")
        return SimpleNamespace(token="challenge-token", code_length=6)

    class ProxyAuthApi:
        async def send_code(self, *_args):
            calls.append("proxy_send_code")
            return SimpleNamespace(
                login_token=None,
                password_challenge=SimpleNamespace(track_id="track-1", hint=None),
                register_token=None,
            )

        async def check_password(self, *_args):
            calls.append("proxy_check_password")
            return SimpleNamespace(error=None, login_token="login-token")

    app = SimpleNamespace(api=SimpleNamespace(auth=ProxyAuthApi()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(
        lambda _state, _hint: None,
        request_code=direct_request_code,
        validate_proxy=validate_proxy,
    )
    flow.codes.put_nowait("123456")
    flow.passwords.put_nowait("secret-password")

    try:
        asyncio.run(flow.authenticate(app))
    except RuntimeError as exc:
        assert str(exc) == "proxy_assignment_changed"
    else:
        raise AssertionError("expected stale proxy assignment to stop password submission")

    assert calls == [
        "validate_proxy",
        "direct_request_code",
        "validate_proxy",
        "proxy_send_code",
        "validate_proxy",
    ]


def test_join_group_confirms_membership_and_returns_safe_fallback_reason():
    class Adapter:
        def __init__(self, *, joined=None, chat=None, join_error=None):
            self.joined = joined
            self.chat = chat
            self.join_error = join_error

        async def join_group(self, _link):
            if self.join_error:
                raise self.join_error
            return self.joined

        async def get_chat(self, _chat_id):
            return self.chat

    confirmed, reason = asyncio.run(join_group_and_confirm_membership(
        Adapter(joined=SimpleNamespace(id=123), chat=SimpleNamespace(id=123, status="member", join_time=10)),
        "https://max.ru/join/test",
        "123",
    ))
    assert (confirmed, reason) == (True, None)

    confirmed, reason = asyncio.run(join_group_and_confirm_membership(
        Adapter(join_error=RuntimeError("private remote error"), chat=SimpleNamespace(id=123, status="left", join_time=0)),
        "https://max.ru/join/test",
        "123",
    ))
    assert (confirmed, reason) == (False, "auto_join_failed")


def test_proxy_is_revalidated_after_successful_code_verification():
    calls = []

    def validate_proxy():
        calls.append("validate_proxy")
        if calls.count("validate_proxy") == 3:
            raise RuntimeError("proxy_assignment_changed")

    async def direct_request_code(_phone):
        calls.append("direct_request_code")
        return SimpleNamespace(token="challenge-token", code_length=6)

    class ProxyAuthApi:
        async def send_code(self, *_args):
            calls.append("proxy_send_code")
            return SimpleNamespace(login_token="login-token", password_challenge=None, register_token=None)

    app = SimpleNamespace(api=SimpleNamespace(auth=ProxyAuthApi()), config=SimpleNamespace(phone="+79990000000"))
    flow = WebCodeAuthFlow(
        lambda _state, _hint: None,
        request_code=direct_request_code,
        validate_proxy=validate_proxy,
    )
    flow.codes.put_nowait("123456")

    try:
        asyncio.run(flow.authenticate(app))
    except RuntimeError as exc:
        assert str(exc) == "proxy_assignment_changed"
    else:
        raise AssertionError("expected changed proxy assignment to stop session establishment")

    assert calls == [
        "validate_proxy",
        "direct_request_code",
        "validate_proxy",
        "proxy_send_code",
        "validate_proxy",
    ]
