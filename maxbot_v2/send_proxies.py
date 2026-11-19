from __future__ import annotations

import re
import sqlite3
from datetime import date, datetime, timezone
from ipaddress import ip_address
from urllib.parse import quote, unquote, urlsplit

from .egress import allowed_address


def allowed_proxy_address(address: str) -> bool:
    return allowed_address(address) and not ip_address(address).is_multicast


def normalize_proxy_url(raw: str) -> str:
    try:
        url = raw.strip()
        if len(url) > 2048 or any(char.isspace() or ord(char) < 32 for char in url):
            raise ValueError
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
        if parsed.scheme != "socks5" or not host or not port or parsed.path or parsed.query or parsed.fragment:
            raise ValueError
        host = host.encode("idna").decode("ascii").rstrip(".")
        if len(host) > 253:
            raise ValueError
        try:
            ip_address(host)
        except ValueError:
            labels = host.split(".")
            if len(labels) < 2 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
                raise ValueError
        else:
            if not allowed_proxy_address(host):
                raise ValueError
        username, password = parsed.username, parsed.password
        if username is None and password is None:
            return f"socks5://{host}:{port}"
        if not username or not password:
            raise ValueError
        credentials = [unquote(value, errors="strict") for value in (username, password)]
        if any(len(value) > 255 or any(not 32 <= ord(char) < 127 for char in value) for value in credentials):
            raise ValueError
        user, secret = (quote(value, safe="") for value in credentials)
        return f"socks5://{user}:{secret}@{host}:{port}"
    except (UnicodeError, ValueError):
        raise ValueError("invalid_send_proxy") from None


def assigned_or_allocate_proxy(connection: sqlite3.Connection, account_id: int, ip_id: int) -> sqlite3.Row | None:
    """Keep existing assignments; allocate in the caller's write transaction."""
    assigned = connection.execute(
        "SELECT p.id,p.ip_id,p.enabled,p.check_status,p.url_ciphertext FROM send_proxy_assignments a "
        "JOIN send_proxies p ON p.id=a.proxy_id WHERE a.account_id=?", (account_id,),
    ).fetchone()
    if assigned is not None:
        return assigned
    candidate = connection.execute(
        "SELECT p.id,p.ip_id,p.enabled,p.check_status,p.url_ciphertext FROM send_proxies p "
        "LEFT JOIN send_proxy_assignments s ON s.proxy_id=p.id "
        "LEFT JOIN accounts a ON a.id=s.account_id AND a.lifecycle='active' "
        "WHERE p.ip_id=? AND p.enabled=1 AND p.check_status='ok' GROUP BY p.id ORDER BY COUNT(a.id),p.id LIMIT 1",
        (ip_id,),
    ).fetchone()
    if candidate is not None:
        connection.execute(
            "INSERT INTO send_proxy_assignments(account_id,proxy_id) VALUES(?,?)",
            (account_id, candidate["id"]),
        )
    return candidate


def resume_proxy_blocked_slots(connection: sqlite3.Connection, group_id: int, today: date) -> None:
    connection.execute(
        "UPDATE weekly_slots SET status=CASE WHEN scheduled_date<? THEN 'missed' ELSE 'queued' END, "
        "error_code=NULL,updated_at=? WHERE group_id=? AND status='blocked' "
        "AND error_code IN ('send_proxy_required','send_proxy_unavailable') AND EXISTS ("
        "SELECT 1 FROM ip_assignments i LEFT JOIN send_proxy_assignments a ON a.account_id=i.account_id "
        "JOIN send_proxies p ON p.ip_id=i.ip_id AND p.enabled=1 AND p.check_status='ok' AND (a.proxy_id IS NULL OR a.proxy_id=p.id) "
        "WHERE i.account_id=weekly_slots.account_id)",
        (today.isoformat(), datetime.now(timezone.utc).isoformat(), group_id),
    )
