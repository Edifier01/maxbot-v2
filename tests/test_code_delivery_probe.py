import asyncio
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from maxbot_v2.crypto import SecretBox
from maxbot_v2.db import SCHEMA
from scripts import probe_code_delivery as probe


def test_probe_preflight_requires_enabled_assigned_proxy_and_no_active_attempt(tmp_path, monkeypatch):
    path = tmp_path / "test.sqlite3"
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", SecretBox.generate_key())
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'test','test')")
        db.execute("INSERT INTO accounts(id,group_id,phone,full_name) VALUES(82,1,'+79990000000','test')")
        db.execute("INSERT INTO proxies(id,group_id,url_ciphertext,label,position,enabled) VALUES(1,1,?,'test',1,1)", (SecretBox().encrypt("socks5://127.0.0.1:1080"),))
        db.execute("INSERT INTO proxy_assignments(account_id,proxy_id) VALUES(82,1)")
        db.execute("INSERT INTO settings(key,value) VALUES('global_stop','1')")
        db.commit()
    target = probe.load_target(path, 82)
    assert target.account_id == 82 and target.proxy_id == 1
    assert target.phone == "+79990000000"

    with sqlite3.connect(path) as db:
        db.execute("UPDATE proxies SET enabled=0 WHERE id=1")
        db.commit()
    with pytest.raises(probe.PreflightError, match="proxy_assignment_required"):
        probe.load_target(path, 82)


def test_probe_holds_after_one_response_then_releases(monkeypatch):
    calls = []
    response = SimpleNamespace(token="secret", code_length=6, request_count_left=10, request_max_duration=60000)

    async def fake_request(*, phone, assigned_proxy, hold_open_until, response_received):
        calls.append((phone, assigned_proxy))
        response_received.set()
        assert not hold_open_until.is_set()
        await hold_open_until.wait()
        return response

    monkeypatch.setattr(probe.PyMaxAdapter, "request_code_direct", fake_request)

    async def check():
        result = await probe.request_and_hold(
            probe.Target(82, 1, "+79990000000", "socks5://127.0.0.1:1080"),
            hold_seconds=0.01,
        )
        assert result is response

    asyncio.run(check())
    assert calls == [("+79990000000", "socks5://127.0.0.1:1080")]


def test_probe_reports_closed_transport_without_exposing_exception_text(monkeypatch, capsys):
    async def fail(_account_id):
        raise RuntimeError("direct_probe_connection_closed")

    monkeypatch.setattr(probe, "run", fail)
    monkeypatch.setattr(sys, "argv", ["probe_code_delivery", "82"])
    assert probe.main() == 1
    assert capsys.readouterr().out == "PROBE_FAILED error_code=direct_probe_connection_closed error_class=RuntimeError\n"


def test_probe_final_output_contains_only_safe_response_presence(monkeypatch, capsys):
    target = probe.Target(82, 1, "+79990000000", "socks5://127.0.0.1:1080")
    response = SimpleNamespace(token="private-token", code_length=6, request_count_left=10)
    monkeypatch.setattr(probe, "load_target", lambda _path, _account_id: target)
    async def no_network(_proxy_url):
        pass
    async def fake_request(_target):
        return response
    monkeypatch.setattr(probe, "check_proxy", no_network)
    monkeypatch.setattr(probe, "request_and_hold", fake_request)
    asyncio.run(probe.run(82))
    output = capsys.readouterr().out
    assert "HOLD_FINISHED response_present=True" in output
    assert "private-token" not in output
    assert "code_length" not in output
    assert "request_count_left" not in output
