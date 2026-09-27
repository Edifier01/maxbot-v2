"""One authorized VDS OTP request with the direct PyMax connection held open.

Prints only safe IDs, stages, and response metadata. Never prints exception text.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3

from maxbot_v2.crypto import SecretBox
from maxbot_v2.max_adapter import PyMaxAdapter


class PreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class Target:
    account_id: int
    proxy_id: int
    phone: str
    proxy_url: str


def load_target(path: Path, account_id: int) -> Target:
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        setting = db.execute("SELECT value FROM settings WHERE key='global_stop'").fetchone()
        if setting is None or setting["value"] != "1":
            raise PreflightError("global_stop_required")
        row = db.execute(
            "SELECT a.phone,a.status,a.group_id,pa.proxy_id,p.group_id AS proxy_group_id,"
            "p.enabled,p.url_ciphertext FROM accounts a "
            "LEFT JOIN proxy_assignments pa ON pa.account_id=a.id "
            "LEFT JOIN proxies p ON p.id=pa.proxy_id WHERE a.id=?", (account_id,),
        ).fetchone()
        if row is None or row["status"] != "pending":
            raise PreflightError("pending_account_required")
        if (row["proxy_id"] is None or row["enabled"] != 1
                or row["group_id"] != row["proxy_group_id"]):
            raise PreflightError("proxy_assignment_required")
        active = db.execute(
            "SELECT 1 FROM onboarding_sessions WHERE account_id=? "
            "AND state NOT IN ('failed','completed','expired','cancelled') LIMIT 1",
            (account_id,),
        ).fetchone()
        if active is not None:
            raise PreflightError("onboarding_in_progress")
        try:
            proxy_url = SecretBox().decrypt(row["url_ciphertext"])
        except ValueError as exc:
            raise PreflightError("proxy_decryption_failed") from exc
        if not proxy_url.strip():
            raise PreflightError("proxy_decryption_failed")
        return Target(account_id, row["proxy_id"], row["phone"], proxy_url)


async def check_proxy(proxy_url: str) -> None:
    from python_socks.async_.asyncio import Proxy

    sock = await Proxy.from_url(proxy_url).connect("api2.oneme.ru", 443, timeout=10)
    sock.close()


async def request_and_hold(target: Target, *, hold_seconds: float = 90):
    release = asyncio.Event()
    response_received = asyncio.Event()
    task = asyncio.create_task(PyMaxAdapter.request_code_direct(
        phone=target.phone,
        assigned_proxy=target.proxy_url,
        hold_open_until=release,
        response_received=response_received,
    ))
    waiter = asyncio.create_task(response_received.wait())
    try:
        done, _ = await asyncio.wait({task, waiter}, timeout=45,
                                     return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            return await task
        if waiter not in done:
            raise TimeoutError("request_response_timeout")
        print(f"RESPONSE_RECEIVED account_id={target.account_id} proxy_id={target.proxy_id} hold_seconds={hold_seconds:g}", flush=True)
        await asyncio.sleep(hold_seconds)
        release.set()
        return await asyncio.wait_for(task, timeout=10)
    finally:
        release.set()
        if not waiter.done():
            waiter.cancel()
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


async def run(account_id: int) -> None:
    path = Path(os.getenv("DATABASE_PATH", "/data/maxbot.sqlite3"))
    target = load_target(path, account_id)
    await check_proxy(target.proxy_url)
    if load_target(path, account_id) != target:
        raise PreflightError("assignment_changed")
    print(f"PREFLIGHT_OK account_id={target.account_id} proxy_id={target.proxy_id}", flush=True)
    print("REQUEST_START route=direct count=1", flush=True)
    response = await request_and_hold(target)
    print(f"HOLD_FINISHED response_present={response is not None}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="One held direct MAX code request")
    parser.add_argument("account_id", type=int)
    args = parser.parse_args()
    try:
        asyncio.run(run(args.account_id))
    except Exception as exc:
        error_code = (
            " error_code=direct_probe_connection_closed"
            if type(exc) is RuntimeError and str(exc) == "direct_probe_connection_closed"
            else ""
        )
        print(f"PROBE_FAILED{error_code} error_class={type(exc).__name__}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
