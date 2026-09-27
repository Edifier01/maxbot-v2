import asyncio
from importlib.metadata import version

import pytest

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


def test_legacy_ip_is_rejected_before_opening_session(tmp_path):
    vault = EncryptedSessionFile(11, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    with pytest.raises(AdapterUnavailable, match="ip_assignment_required"):
        PyMaxAdapter.create(phone="+70000000000", source_ip="62.109.10.109", session_vault=vault)
    assert not vault.work_path.exists()
