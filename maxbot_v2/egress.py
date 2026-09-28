"""Persistent account-to-VDS-IP routing. No MAX request may fall back to another IP."""

from __future__ import annotations

import ipaddress
import json
import socket
import sqlite3
import subprocess
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


LEGACY_MAX_IP = "62.109.10.109"
INITIAL_MAX_IP = "62.109.20.186"
MAX_HOST = "api2.oneme.ru"


def allowed_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return isinstance(ip, ipaddress.IPv4Address) and ip.is_global and address != LEGACY_MAX_IP


def host_addresses() -> set[str]:
    try:
        result = subprocess.run(["ip", "-j", "-4", "addr", "show", "scope", "global"], capture_output=True, text=True, check=True, timeout=10)
    except (FileNotFoundError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return set()
    addresses = {
        item["local"]
        for interface in json.loads(result.stdout)
        for item in interface.get("addr_info", [])
        if item.get("family") == "inet" and "local" in item
    }
    return {address for address in addresses if allowed_address(address)}


def probe_address(address: str, host: str = MAX_HOST, port: int = 443) -> bool:
    if not allowed_address(address):
        return False
    try:
        with socket.create_connection((host, port), timeout=5, source_address=(address, 0)) as connection:
            return connection.getsockname()[0] == address
    except (OSError, TimeoutError):
        return False


def refresh_ips(connection: sqlite3.Connection, *, addresses: set[str] | None = None, probe=probe_address) -> list[dict]:
    """Discover current host IPs; new ones remain disabled until owner action."""
    addresses = host_addresses() if addresses is None else addresses
    discovered = {address for address in addresses if allowed_address(address)}
    verified = {address for address in discovered if probe(address)}
    now = datetime.now(timezone.utc).isoformat()
    connection.execute("UPDATE server_ips SET available=0,last_checked_at=?", (now,))
    for address in sorted(discovered):
        connection.execute(
            "INSERT INTO server_ips(address,available,last_checked_at) VALUES(?,?,?) "
            "ON CONFLICT(address) DO UPDATE SET available=excluded.available,last_checked_at=excluded.last_checked_at",
            (address, int(address in verified), now),
        )
    connection.execute(
        "UPDATE weekly_slots SET status='blocked',error_code='ip_assignment_unavailable',updated_at=? "
        "WHERE status='queued' AND account_id IN "
        "(SELECT ia.account_id FROM ip_assignments ia JOIN server_ips p ON p.id=ia.ip_id "
        "WHERE p.enabled=0 OR p.available=0)",
        (now,),
    )
    tzrow = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
    today = datetime.now(ZoneInfo(tzrow[0] if tzrow else "Europe/Moscow")).date().isoformat()
    connection.execute(
        "UPDATE weekly_slots SET status=CASE WHEN scheduled_date>=? THEN 'queued' ELSE 'missed' END,"
        "error_code=NULL,updated_at=? WHERE status='blocked' AND error_code='ip_assignment_unavailable' "
        "AND account_id IN (SELECT ia.account_id FROM ip_assignments ia JOIN server_ips p ON p.id=ia.ip_id "
        "WHERE p.enabled=1 AND p.available=1)",
        (today, now),
    )
    return [dict(row) for row in connection.execute("SELECT id,address,enabled,available,last_checked_at FROM server_ips ORDER BY address")]


def enable_ip(connection: sqlite3.Connection, ip_id: int, enabled: bool) -> None:
    row = connection.execute("SELECT address,available FROM server_ips WHERE id=?", (ip_id,)).fetchone()
    if row is None:
        raise ValueError("ip_not_found")
    if enabled and (not allowed_address(row["address"]) or not row["available"]):
        raise ValueError("ip_unavailable")
    connection.execute("UPDATE server_ips SET enabled=? WHERE id=?", (int(enabled), ip_id))


def assigned_ip(connection: sqlite3.Connection, account_id: int) -> tuple[int, str] | None:
    row = connection.execute(
        "SELECT p.id,p.address,p.enabled,p.available FROM ip_assignments a "
        "JOIN server_ips p ON p.id=a.ip_id WHERE a.account_id=?", (account_id,),
    ).fetchone()
    if row is None or not row["enabled"] or not row["available"] or not allowed_address(row["address"]):
        return None
    return int(row["id"]), str(row["address"])


def assign_ip(connection: sqlite3.Connection, account_id: int) -> str:
    current = connection.execute("SELECT ip_id FROM ip_assignments WHERE account_id=?", (account_id,)).fetchone()
    if current is not None:
        assigned = assigned_ip(connection, account_id)
        if assigned is None:
            raise ValueError("ip_assignment_unavailable")
        return assigned[1]
    now = datetime.now(timezone.utc).isoformat()
    candidates = connection.execute(
        "SELECT p.id,p.address,COUNT(DISTINCT CASE WHEN a.lifecycle='active' AND (a.auth_state='authenticated' OR EXISTS ("
        "SELECT 1 FROM onboarding_sessions s WHERE s.account_id=a.id AND s.state IN "
        "('starting','requesting_code','waiting_code','verifying_code','waiting_password','verifying_password','joining_group') "
        "AND s.expires_at>?)) THEN a.id END) AS load FROM server_ips p "
        "LEFT JOIN ip_assignments ia ON ia.ip_id=p.id LEFT JOIN accounts a ON a.id=ia.account_id "
        "WHERE p.enabled=1 AND p.available=1 GROUP BY p.id "
        "ORDER BY load,COALESCE(p.last_assigned_at,''),p.id",
        (now,),
    ).fetchall()
    chosen = next((row for row in candidates if allowed_address(row["address"])), None)
    if chosen is None:
        raise ValueError("ip_assignment_required")
    connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?)", (account_id, chosen["id"]))
    connection.execute("UPDATE server_ips SET last_assigned_at=? WHERE id=?", (now, chosen["id"]))
    return str(chosen["address"])


def bootstrap_ips(connection: sqlite3.Connection, *, addresses: set[str] | None = None, probe=probe_address) -> None:
    """Idempotently activate the user's already approved IP and migrate assignments."""
    rows = refresh_ips(connection, addresses=addresses, probe=probe)
    done = connection.execute("SELECT 1 FROM settings WHERE key='max_ip_bootstrap_done'").fetchone()
    if done:
        return
    initial = next((row for row in rows if row["address"] == INITIAL_MAX_IP and row["available"]), None)
    if initial is None:
        return
    enable_ip(connection, initial["id"], True)
    for account in connection.execute("SELECT id FROM accounts WHERE lifecycle='active' ORDER BY id"):
        if connection.execute("SELECT 1 FROM ip_assignments WHERE account_id=?", (account["id"],)).fetchone() is None:
            assign_ip(connection, account["id"])
    connection.execute("INSERT INTO settings(key,value) VALUES('max_ip_bootstrap_done','1')")
