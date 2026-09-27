import asyncio
from importlib.metadata import version

import pytest
from pymax.exceptions import ApiError
from pymax.protocol.enums import Opcode

from maxbot_v2.crypto import SecretBox
from maxbot_v2.max_adapter import AdapterUnavailable, PyMaxAdapter
from maxbot_v2.session_vault import EncryptedSessionFile


def test_pinned_client_uses_standard_sms_flow_and_bound_transport(tmp_path, monkeypatch):
    assert version("maxapi-python") == "2.4.1"
    vault = EncryptedSessionFile(10, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))

    class Provider:
        async def get_code(self, _phone):
            return "123456"

        async def get_password(self, _hint=None):
            return "secret"

    adapter = PyMaxAdapter.create(phone="+70000000000", source_ip="62.109.20.186", session_vault=vault, code_provider=Provider(), password_provider=Provider())
    assert adapter.client.extra_config.proxy is None
    assert type(adapter.client._auth_flow).__name__ == "SmsAuthFlow"

    called = {}

    async def fake_open(_host, _port, **kwargs):
        called.update(kwargs)
        raise OSError("stop before network")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    connection = adapter.client._build_connection()
    try:
        asyncio.run(connection.transport.connect())
    except OSError:
        pass
    assert called["local_addr"] == ("62.109.20.186", 0)

    saved_session = PyMaxAdapter.create(
        phone="+70000000000", source_ip="62.109.20.186",
        session_vault=EncryptedSessionFile(34, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key())),
    )
    assert type(saved_session.client._auth_flow).__name__ == "NoInteractiveAuthFlow"


def test_legacy_ip_is_rejected_before_opening_session(tmp_path):
    vault = EncryptedSessionFile(11, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    with pytest.raises(AdapterUnavailable, match="ip_assignment_required"):
        PyMaxAdapter.create(phone="+70000000000", source_ip="62.109.10.109", session_vault=vault)
    assert not vault.work_path.exists()


def test_bound_transport_checks_current_account_route_before_each_write(tmp_path, monkeypatch):
    from maxbot_v2.crypto import SecretBox
    from maxbot_v2.max_adapter import PyMaxAdapter
    from maxbot_v2.session_vault import EncryptedSessionFile

    current = {"allowed": True}
    calls = []

    def verify_route():
        calls.append(current["allowed"])
        if not current["allowed"]:
            raise RuntimeError("ip_assignment_changed")

    vault = EncryptedSessionFile(33, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    adapter = PyMaxAdapter.create(phone="+70000000000", source_ip="62.109.20.186", session_vault=vault, before_network_action=verify_route)
    transport = adapter.client._build_connection().transport
    writes = []

    class Reader:
        def at_eof(self):
            return False

    class Writer:
        def get_extra_info(self, name):
            return ("62.109.20.186", 1234) if name == "sockname" else None

        def write(self, data):
            writes.append(data)

        async def drain(self):
            return None

    async def fake_open(_host, _port, **_kwargs):
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)

    async def run():
        await transport.connect()
        current["allowed"] = False
        with pytest.raises(RuntimeError, match="ip_assignment_changed"):
            await transport.send(b"synthetic frame")

    asyncio.run(run())

    assert calls == [True, False]
    assert writes == []


def test_only_explicit_pymax_login_token_errors_require_a_new_session_generation():
    assert PyMaxAdapter.is_invalid_saved_session_error(ApiError(opcode=Opcode.LOGIN.value, error="FAIL_LOGIN_TOKEN"))
    assert PyMaxAdapter.is_invalid_saved_session_error(ApiError(opcode=Opcode.LOGIN.value, error="FAIL_LOGOUT_ALL"))
    assert not PyMaxAdapter.is_invalid_saved_session_error(ApiError(opcode=Opcode.PROFILE.value, error="FAIL_LOGIN_TOKEN"))
    assert not PyMaxAdapter.is_invalid_saved_session_error(RuntimeError("network timeout"))
