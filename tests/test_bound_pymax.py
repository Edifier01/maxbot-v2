import asyncio
import sqlite3
from contextlib import closing
from importlib.metadata import version
from types import SimpleNamespace

import pytest
from pymax.exceptions import ApiError
from pymax.connection import ConnectionManager
from pymax.protocol.enums import Command, Opcode
from pymax.protocol.models import InboundFrame
from pymax.session import SessionStore

from maxbot_v2.crypto import SecretBox
from maxbot_v2.max_adapter import AdapterUnavailable, PyMaxAdapter
from maxbot_v2.session_vault import EncryptedSessionFile


def test_channel_adapter_reads_only_publications_and_checks_own_reaction():
    async def scenario():
        async def fetch_history(**kwargs):
            assert kwargs == {"chat_id": -10, "backward": 25, "from_time": 900}
            return [
                SimpleNamespace(id=1, chat_id=-10, post_id=None, time=700, type="USER"),
                SimpleNamespace(id=2, chat_id=-10, post_id=1, time=710, type="USER"),
                SimpleNamespace(id=3, chat_id=9, post_id=None, time=720, type="USER"),
                SimpleNamespace(id=4, chat_id=-10, post_id=None, time=730, type="CONTROL"),
            ]

        async def get_reactions(**kwargs):
            assert kwargs == {"chat_id": -10, "message_ids": [1]}
            return {"1": SimpleNamespace(your_reaction="🔥")}

        async def add_reaction(**kwargs):
            assert kwargs == {"chat_id": -10, "message_id": 1, "reaction": "👍"}
            return SimpleNamespace(your_reaction="👍")

        adapter = PyMaxAdapter(SimpleNamespace(
            fetch_history=fetch_history, get_reactions=get_reactions, add_reaction=add_reaction,
        ))
        page = await adapter.fetch_channel_posts(-10, before_ms=900, limit=25)
        assert [(post.id, post.published_at_ms) for post in page if post.is_publication] == [(1, 700)]
        assert len(page) == 4
        assert await adapter.read_channel_reaction(-10, 1) == "🔥"
        assert await adapter.write_channel_reaction(-10, 1, "👍") == "👍"

    asyncio.run(scenario())


def test_channel_adapter_resolves_public_link_without_joining():
    async def invoke(opcode, payload):
        assert opcode == Opcode.LINK_INFO
        assert payload == {"link": "https://max.ru/public-channel"}
        return InboundFrame(opcode=opcode, payload={
            "chat": {"id": -45, "type": "CHANNEL", "status": "LEFT", "owner": 17},
        })

    adapter = PyMaxAdapter(SimpleNamespace(_app=SimpleNamespace(invoke=invoke)))
    resolved = asyncio.run(adapter.resolve_channel("https://max.ru/public-channel"))
    assert resolved.id == -45
    assert resolved.type == "CHANNEL"


def test_channel_adapter_checks_post_before_treating_missing_reactions_as_empty():
    async def scenario():
        async def get_reactions(**_kwargs):
            return None

        async def get_message(**kwargs):
            return {1: SimpleNamespace(reaction_info=SimpleNamespace(your_reaction="🔥")),
                    2: SimpleNamespace(reaction_info=None)}.get(kwargs["message_id"])

        adapter = PyMaxAdapter(SimpleNamespace(get_reactions=get_reactions, get_message=get_message))
        assert await adapter.read_channel_reaction(-10, 1) == "🔥"
        assert await adapter.read_channel_reaction(-10, 2) is None
        with pytest.raises(LookupError, match="channel_post_unavailable"):
            await adapter.read_channel_reaction(-10, 3)

    asyncio.run(scenario())


def test_pinned_client_uses_standard_sms_flow_and_bound_transport(tmp_path, monkeypatch):
    assert version("maxapi-python") == "2.5.0"
    vault = EncryptedSessionFile(10, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))

    class Provider:
        async def get_code(self, _phone):
            return "123456"

        async def get_password(self, _hint=None):
            return "secret"

    adapter = PyMaxAdapter.create(phone="+70000000000", source_ip="62.109.20.186", session_vault=vault, code_provider=Provider(), password_provider=Provider())
    assert adapter.client.extra_config.proxy is None
    assert not adapter.client.extra_config.reconnect
    assert not adapter.client.extra_config.relogin
    assert adapter.client.extra_config.persist_session
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


def test_pymax_reopens_an_existing_encrypted_session_without_network(tmp_path):
    vault = EncryptedSessionFile(19, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    vault.open()
    phone = "+70000000019"
    with closing(sqlite3.connect(vault.work_path)) as database:
        database.execute("CREATE TABLE sessions(token TEXT NOT NULL PRIMARY KEY,device_id TEXT NOT NULL,phone TEXT NOT NULL)")
        database.execute("INSERT INTO sessions VALUES(?,?,?)", ("synthetic-token", "synthetic-device", phone))
        database.commit()
    vault.seal()
    assert not vault.work_path.exists()

    async def reopen():
        work_dir, session_name = vault.open()
        store = SessionStore(work_dir, session_name)
        try:
            session = await store.load_session_by_phone(phone)
            assert session is not None
            assert session.token == "synthetic-token"
        finally:
            await store.close()
            vault.seal()

    asyncio.run(reopen())
    assert vault.has_saved_session_token()
    assert not vault.work_path.exists()


def test_bound_pymax_reports_only_definite_cloud_password_verdicts(tmp_path, monkeypatch):
    vault = EncryptedSessionFile(24, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    results = []
    password_opcode = Opcode.AUTH_LOGIN_CHECK_PASSWORD
    adapter = PyMaxAdapter.create(
        phone="+70000000000", source_ip="62.109.20.186", session_vault=vault,
        code_provider=object(), password_provider=object(), cloud_password_result=results.append,
    )
    frames = iter([
        TimeoutError(),
        OSError(),
        InboundFrame(opcode=password_opcode, cmd=Command.ERROR, payload={"error": "login.cred", "message": "FAIL_INVALID_TRACK"}),
        InboundFrame(opcode=Opcode.LOGIN, cmd=Command.ERROR, payload={"error": "login.cred", "message": "FAIL_WRONG_PASSWORD"}),
        InboundFrame(opcode=password_opcode, payload={"error": "unknown_error"}),
        InboundFrame(opcode=password_opcode, payload={"tokenAttrs": {}}),
        InboundFrame(opcode=password_opcode, cmd=Command.ERROR, payload={"error": "login.cred", "message": "FAIL_WRONG_PASSWORD"}),
        InboundFrame(opcode=password_opcode, payload={"error": "wrong_password"}),
        InboundFrame(opcode=password_opcode, payload={"tokenAttrs": {"LOGIN": {"token": "fixture"}}}),
    ])

    async def request(_manager, frame, **_kwargs):
        assert frame.opcode == password_opcode
        result = next(frames)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(ConnectionManager, "request", request)

    async def check():
        await adapter.client._ensure_runtime()
        auth = adapter.client._app.api.auth
        for error in (TimeoutError, OSError, ApiError, ApiError):
            with pytest.raises(error):
                await auth.check_password("fixture-track", "fixture-password")
        await auth.check_password("fixture-track", "fixture-password")
        await auth.check_password("fixture-track", "fixture-password")
        assert results == []

        with pytest.raises(ApiError):
            await auth.check_password("fixture-track", "fixture-password")
        await auth.check_password("fixture-track", "fixture-password")
        await auth.check_password("fixture-track", "fixture-password")
        assert results == [False, False, True]

    asyncio.run(check())


def test_legacy_ip_is_rejected_before_opening_session(tmp_path):
    vault = EncryptedSessionFile(11, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    with pytest.raises(AdapterUnavailable, match="ip_assignment_required"):
        PyMaxAdapter.create(phone="+70000000000", source_ip="62.109.10.109", session_vault=vault)
    assert not vault.work_path.exists()


def test_external_proxy_address_normalization_is_idempotent():
    from maxbot_v2.send_proxies import normalize_proxy_url

    credential = "!" * 180
    url = f"socks5://{credential}:{credential}@8.8.4.4:1080"
    canonical = normalize_proxy_url(url)
    assert normalize_proxy_url(canonical) == canonical
    for address in ["62.109.10.109.", "127.0.0.1.", "224.0.0.2"]:
        with pytest.raises(ValueError, match="invalid_send_proxy"):
            normalize_proxy_url(f"socks5://{address}:1080")
    with pytest.raises(ValueError, match="invalid_send_proxy"):
        normalize_proxy_url("socks5://sample:%C3%A9@8.8.4.4:1080")


def test_external_proxy_connects_from_assigned_ip_and_keeps_tls_for_max(tmp_path, monkeypatch):
    from python_socks.async_.asyncio import Proxy

    vault = EncryptedSessionFile(22, durable_dir=tmp_path / "encrypted", runtime_dir=tmp_path / "runtime", box=SecretBox(SecretBox.generate_key()))
    address = "62.109.20.186"
    url = "socks5://sample-user:sample-password@8.8.4.4:1080"
    with pytest.raises(AdapterUnavailable):
        PyMaxAdapter.create(phone="+70000000000", source_ip=address, session_vault=vault, code_provider=object(), send_proxy_url=url)

    class FakeSocket:
        def getsockname(self):
            return address, 12345

        def close(self):
            calls.append("closed")

        def get_extra_info(self, name):
            return self.getsockname() if name == "sockname" else None

        async def wait_closed(self):
            pass

    sock = FakeSocket()
    calls = []

    async def tunnel(self, **kwargs):
        calls.append(kwargs)
        return sock

    async def wrap_tls(*args, **kwargs):
        assert not args
        assert kwargs["sock"] is sock
        assert kwargs["ssl"] is not None
        assert kwargs["server_hostname"] == calls[0]["dest_host"]
        return object(), sock

    monkeypatch.setattr(Proxy, "connect", tunnel)
    monkeypatch.setattr(asyncio, "open_connection", wrap_tls)
    adapter = PyMaxAdapter.create(phone="+70000000000", source_ip=address, session_vault=vault, send_proxy_url=url)
    transport = adapter.client._build_connection().transport
    asyncio.run(transport.connect())
    assert len(calls) == 1
    assert calls[0]["local_addr"] == (address, 0)
    assert calls[0]["dest_port"] == 443
    installed_route = calls.pop()

    def unexpected_client(*args, **kwargs):
        pytest.fail("Route probe must not create a MAX client or send any application data")

    monkeypatch.setattr("pymax.Client", unexpected_client)
    assert asyncio.run(PyMaxAdapter.check_send_proxy(source_ip=address, url=url)) == "ok"
    assert calls == [installed_route, "closed"]
    async def unavailable(self, **kwargs):
        raise OSError("synthetic proxy failure")

    monkeypatch.setattr(Proxy, "connect", unavailable)
    with pytest.raises(AdapterUnavailable, match="tunnel_failed"):
        asyncio.run(adapter.client._build_connection().transport.connect())


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        ("connection", "connection_failed"),
        ("timeout", "socks_timeout"),
        ("auth", "auth_failed"),
        ("tunnel", "tunnel_failed"),
        ("source", "source_ip_mismatch"),
        ("tls", "tls_failed"),
    ],
)
def test_proxy_probe_maps_safe_stage_and_closes_socket(monkeypatch, failure, expected_status):
    from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError
    from python_socks._protocols.errors import ReplyError
    from python_socks.async_.asyncio import Proxy

    address = "62.109.20.186"
    url = "socks5://sample-user:sample-password@8.8.4.4:1080"
    closed = []
    errors = {
        "connection": ProxyConnectionError("sample-password"),
        "timeout": ProxyTimeoutError(),
        "auth": ProxyError(ReplyError("Username and password authentication failure")),
        "tunnel": ProxyError(ReplyError("Username and password authentication failure (remote error)"), error_code=4),
    }

    class Socket:
        def getsockname(self):
            return ("62.109.20.187" if failure == "source" else address), 1234

        def close(self):
            closed.append(True)

    async def tunnel(self, **kwargs):
        assert kwargs["local_addr"] == (address, 0)
        if failure in errors:
            raise errors[failure]
        return Socket()

    async def wrap_tls(*args, **kwargs):
        assert failure == "tls"
        assert kwargs["server_hostname"] == "api2.oneme.ru"
        assert kwargs["ssl"].check_hostname
        raise OSError("sample-password")

    monkeypatch.setattr(Proxy, "connect", tunnel)
    monkeypatch.setattr(asyncio, "open_connection", wrap_tls)
    assert asyncio.run(PyMaxAdapter.check_send_proxy(source_ip=address, url=url)) == expected_status
    assert closed == ([True] if failure in {"source", "tls"} else [])


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


def test_auth_opcode_to_safe_diagnostic_stage_mapping():
    assert PyMaxAdapter.auth_stage_for_opcode(17) == "request_code"
    assert PyMaxAdapter.auth_stage_for_opcode(18) == "otp"
    assert PyMaxAdapter.auth_stage_for_opcode(115) == "two_factor"
    assert PyMaxAdapter.auth_stage_for_opcode(19) == "login"
    assert PyMaxAdapter.auth_stage_for_opcode(16) == "profile"
    assert PyMaxAdapter.auth_stage_for_opcode(56) == "resolve_group"
    assert PyMaxAdapter.auth_stage_for_opcode(57) == "join_group"
    assert PyMaxAdapter.auth_stage_for_opcode(9999) is None
