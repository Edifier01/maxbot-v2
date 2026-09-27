import asyncio
from types import SimpleNamespace

import pytest
from pymax.auth.sms import SmsAuthFlow
from pymax.auth.exceptions import PasswordAttemptsExceededError
from pymax.exceptions import ApiError

from maxbot_v2.onboarding import WebAuthProviders


def test_web_provider_waits_for_otp_once_and_updates_state():
    updates = []
    provider = WebAuthProviders(lambda state, hint: updates.append((state, hint)), session_id="test", account_id=1, ip_id=2)

    async def run():
        task = asyncio.create_task(provider.get_code("+79990000000"))
        await asyncio.sleep(0)
        assert provider.waiting_for == "code"
        provider.codes.put_nowait("123456")
        assert await task == "123456"

    asyncio.run(run())
    assert updates[0][0] == "waiting_code"
    assert updates[-1][0] == "verifying_code"


def test_password_provider_marks_verification_before_returning_password():
    updates = []
    provider = WebAuthProviders(lambda state, hint: updates.append(state), session_id="test", account_id=1, ip_id=2)

    async def run():
        task = asyncio.create_task(provider.get_password())
        await asyncio.sleep(0)
        assert provider.waiting_for == "password"
        provider.passwords.put_nowait("synthetic-password")
        assert await task == "synthetic-password"

    asyncio.run(run())
    assert updates == ["waiting_password", "verifying_password"]


def test_sms_flow_requests_one_code_then_retries_password_after_two_factor_challenge():
    updates = []
    provider = WebAuthProviders(lambda state, _hint: updates.append(state), session_id="test", account_id=1, ip_id=2)
    calls = {"request_code": 0, "send_code": 0, "passwords": []}

    class Auth:
        async def request_code(self, _phone):
            calls["request_code"] += 1
            return SimpleNamespace(token="request-token")

        async def send_code(self, token, code):
            calls["send_code"] += 1
            assert token == "request-token"
            assert code == "123456"
            return SimpleNamespace(login_token=None, password_challenge=SimpleNamespace(track_id="track", hint="hint"), register_token=None)

        async def check_password(self, track_id, password):
            assert track_id == "track"
            calls["passwords"].append(password)
            if password != "correct-password":
                raise ApiError(opcode=18, error="password_rejected")
            return SimpleNamespace(error=None, login_token="authenticated-token")

    app = SimpleNamespace(
        config=SimpleNamespace(phone="+79990000000", password_max_attempts=5, registration_config=None),
        api=SimpleNamespace(auth=Auth()),
    )

    async def run():
        provider.codes.put_nowait("123456")
        provider.passwords.put_nowait("incorrect-password")
        task = asyncio.create_task(SmsAuthFlow(provider, provider).authenticate(app))
        for _ in range(1000):
            if updates.count("waiting_password") == 2:
                break
            await asyncio.sleep(0)
        else:
            raise AssertionError("PyMax did not request the password again after the rejected value")
        provider.passwords.put_nowait("correct-password")
        result = await task
        return result

    result = asyncio.run(run())

    assert result.token == "authenticated-token"
    assert calls["request_code"] == 1
    assert calls["send_code"] == 1
    assert calls["passwords"] == ["incorrect-password", "correct-password"]
    assert updates.count("verifying_password") == 2


def test_sms_flow_stops_after_five_password_rejections_without_requesting_another_code():
    updates = []
    provider = WebAuthProviders(lambda state, _hint: updates.append(state), session_id="test", account_id=1, ip_id=2)
    calls = {"request_code": 0, "send_code": 0, "password_checks": 0}

    class Auth:
        async def request_code(self, _phone):
            calls["request_code"] += 1
            return SimpleNamespace(token="request-token")

        async def send_code(self, _token, _code):
            calls["send_code"] += 1
            return SimpleNamespace(login_token=None, password_challenge=SimpleNamespace(track_id="track", hint=None), register_token=None)

        async def check_password(self, _track_id, _password):
            calls["password_checks"] += 1
            raise ApiError(opcode=18, error="password_rejected")

    app = SimpleNamespace(
        config=SimpleNamespace(phone="+79990000000", password_max_attempts=5, registration_config=None),
        api=SimpleNamespace(auth=Auth()),
    )

    async def run():
        provider.codes.put_nowait("123456")
        task = asyncio.create_task(SmsAuthFlow(provider, provider).authenticate(app))
        for expected in range(1, 6):
            for _ in range(1000):
                if updates.count("waiting_password") == expected:
                    break
                await asyncio.sleep(0)
            else:
                raise AssertionError("PyMax stopped requesting a password before the configured attempt limit")
            provider.passwords.put_nowait(f"wrong-password-{expected}")
        with pytest.raises(PasswordAttemptsExceededError):
            await task

    asyncio.run(run())

    assert calls == {"request_code": 1, "send_code": 1, "password_checks": 5}
