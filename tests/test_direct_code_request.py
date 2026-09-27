import asyncio
from types import ModuleType, SimpleNamespace

import pytest

from maxbot_v2.max_adapter import AdapterUnavailable, PyMaxAdapter


def test_direct_code_request_uses_ephemeral_client_and_closes_it(monkeypatch):
    calls = []
    response = SimpleNamespace(token="challenge-secret", code_length=6)
    created = []

    class FakeAuthApi:
        async def request_code(self, phone):
            calls.append(("request_code", phone))
            return response

    class FakeClient:
        def __init__(self, *, phone, work_dir, session_name, extra_config, auth_flow):
            self.phone = phone
            self.work_dir = work_dir
            self.session_name = session_name
            self.extra_config = extra_config
            self.auth_flow = auth_flow
            self.closed = False
            created.append(self)

        async def connect(self):
            app = SimpleNamespace(
                api=SimpleNamespace(auth=FakeAuthApi()),
                config=SimpleNamespace(phone=self.phone),
            )
            await self.auth_flow.authenticate(app)

        async def close(self):
            self.closed = True

    pymax = ModuleType("pymax")
    pymax.Client = FakeClient
    pymax.ExtraConfig = lambda **kwargs: SimpleNamespace(**kwargs)
    monkeypatch.setitem(__import__("sys").modules, "pymax", pymax)
    monkeypatch.setattr("maxbot_v2.max_adapter.version", lambda _name: "2.4.1")

    result = asyncio.run(
        PyMaxAdapter.request_code_direct(
            phone="+79990000000",
            assigned_proxy="socks5://127.0.0.1:1080",
        )
    )

    assert result is response
    assert calls == [("request_code", "+79990000000")]
    assert len(created) == 1 and created[0].closed
    assert created[0].extra_config.proxy is None
    assert created[0].extra_config.persist_session is False
    assert created[0].extra_config.reconnect is False


def test_direct_code_request_stops_before_pymax_without_assigned_proxy(monkeypatch):
    constructed = []

    class FakeClient:
        def __init__(self, **_kwargs):
            constructed.append(True)

    pymax = ModuleType("pymax")
    pymax.Client = FakeClient
    pymax.ExtraConfig = lambda **kwargs: SimpleNamespace(**kwargs)
    monkeypatch.setitem(__import__("sys").modules, "pymax", pymax)

    with pytest.raises(AdapterUnavailable, match="proxy_assignment_required"):
        asyncio.run(
            PyMaxAdapter.request_code_direct(
                phone="+79990000000",
                assigned_proxy="",
            )
        )

    assert constructed == []


def test_direct_code_request_holds_connection_after_one_response(monkeypatch):
    calls = []
    response_seen = asyncio.Event()
    release_hold = asyncio.Event()
    clients = []
    response = SimpleNamespace(token="private-token", code_length=6)

    class FakeAuthApi:
        async def request_code(self, phone):
            calls.append(("request_code", phone))
            response_seen.set()
            return response

    class FakeClient:
        def __init__(self, *, phone, work_dir, session_name, extra_config, auth_flow):
            self.phone = phone
            self.auth_flow = auth_flow
            self.extra_config = extra_config
            self.closed = False
            clients.append(self)

        async def connect(self):
            app = SimpleNamespace(
                api=SimpleNamespace(auth=FakeAuthApi()),
                config=SimpleNamespace(phone=self.phone),
                connection=SimpleNamespace(is_open=True),
            )
            await self.auth_flow.authenticate(app)

        async def close(self):
            self.closed = True

    pymax = ModuleType("pymax")
    pymax.Client = FakeClient
    pymax.ExtraConfig = lambda **kwargs: SimpleNamespace(**kwargs)
    monkeypatch.setitem(__import__("sys").modules, "pymax", pymax)
    monkeypatch.setattr("maxbot_v2.max_adapter.version", lambda _name: "2.4.1")
    async def check():
        task = asyncio.create_task(
            PyMaxAdapter.request_code_direct(
                phone="+79990000000",
                assigned_proxy="socks5://127.0.0.1:1080",
                hold_open_until=release_hold,
            )
        )
        await asyncio.wait_for(response_seen.wait(), timeout=1)
        await asyncio.sleep(0)
        assert calls == [("request_code", "+79990000000")]
        assert len(clients) == 1 and not clients[0].closed
        assert clients[0].extra_config.proxy is None
        assert clients[0].extra_config.persist_session is False
        release_hold.set()
        assert await task is response
        assert clients[0].closed

    asyncio.run(check())


def test_held_code_request_reports_closed_transport(monkeypatch):
    response = SimpleNamespace(token="private-token")

    class FakeAuthApi:
        async def request_code(self, _phone):
            return response

    class FakeClient:
        def __init__(self, *, phone, auth_flow, **_kwargs):
            self.phone = phone
            self.auth_flow = auth_flow
            self.closed = False

        async def connect(self):
            app = SimpleNamespace(
                api=SimpleNamespace(auth=FakeAuthApi()),
                config=SimpleNamespace(phone=self.phone),
                connection=SimpleNamespace(is_open=False),
            )
            await self.auth_flow.authenticate(app)

        async def close(self):
            self.closed = True

    pymax = ModuleType("pymax")
    pymax.Client = FakeClient
    pymax.ExtraConfig = lambda **kwargs: SimpleNamespace(**kwargs)
    monkeypatch.setitem(__import__("sys").modules, "pymax", pymax)
    monkeypatch.setattr("maxbot_v2.max_adapter.version", lambda _name: "2.4.1")
    release_hold = asyncio.Event()
    release_hold.set()

    with pytest.raises(RuntimeError, match="direct_probe_connection_closed"):
        asyncio.run(
            PyMaxAdapter.request_code_direct(
                phone="+79990000000",
                assigned_proxy="socks5://127.0.0.1:1080",
                hold_open_until=release_hold,
            )
        )
