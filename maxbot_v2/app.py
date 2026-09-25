from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sqlite3
import time
from time import perf_counter
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import connect, initialize
from .security import digest_token as _digest_token, new_token, password_matches
from .crypto import SecretBox
from .message_pool import replace_message_pool
from .onboarding import WebCodeAuthFlow, attach_group_on_first_account, member_proof, prepare_account
from .max_adapter import PyMaxAdapter
from .session_vault import EncryptedSessionFile
from .workers import GroupWorkerManager
from .sender import recover_in_flight
from .session_lock import AccountSessionLocks


logger = logging.getLogger(__name__)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class GroupBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    invite_link: str = Field(min_length=1, max_length=1000)


class GroupUpdateBody(GroupBody):
    pass


class RunBody(BaseModel):
    enabled: bool


class TextsBody(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=5000)


class SettingsBody(BaseModel):
    timezone: str = Field(min_length=1, max_length=64)
    send_windows_weekday: str = Field(min_length=1, max_length=100)
    send_windows_weekend: str = Field(min_length=1, max_length=100)
    delay_min_sec: int = Field(ge=5, le=300)
    delay_max_sec: int = Field(ge=5, le=300)
    auto_run: bool


class ProxyBody(BaseModel):
    url: str = Field(min_length=8, max_length=512)
    label: str = Field(min_length=1, max_length=80)


class ProxyLinesBody(BaseModel):
    lines: str = Field(min_length=1, max_length=60000)


class ProxyAssignmentBody(BaseModel):
    proxy_id: int = Field(gt=0)


class OperationResolutionBody(BaseModel):
    outcome: str = Field(pattern="^(accepted|confirmed_not_sent)$")
    provider_message_id: str | None = Field(default=None, max_length=200)


def _valid_max_invite_link(link: str) -> bool:
    try:
        parsed = urlsplit(link.strip())
        return (
            parsed.scheme == "https"
            and parsed.hostname in {"max.ru", "max.im"}
            and parsed.port is None
            and parsed.path.startswith("/join/")
            and len(parsed.path) > len("/join/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def create_app(
    *,
    db_path: str | Path | None = None,
    data_dir: str | Path | None = None,
    owner_username: str = "edifier8989",
    owner_password_hash: str | None = None,
    secret_key: str | None = None,
    secure_cookies: bool | None = None,
) -> FastAPI:
    database = Path(db_path or os.getenv("DATABASE_PATH", "/data/maxbot.sqlite3"))
    data = Path(data_dir or os.getenv("DATA_DIR", "/data"))
    database.parent.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    secret = secret_key or os.getenv("APP_SECRET_KEY", "")
    password_hash = owner_password_hash if owner_password_hash is not None else os.getenv("OWNER_PASSWORD_HASH", "")
    cookie_secure = secure_cookies if secure_cookies is not None else os.getenv("COOKIE_SECURE", "1") == "1"

    def digest_token(value: str) -> str:
        return _digest_token(value, secret)

    @contextmanager
    def db() -> Iterator[sqlite3.Connection]:
        connection = connect(database)
        try:
            yield connection
        finally:
            connection.close()

    with db() as connection:
        initialize(connection)

    runtime_dir = Path(os.getenv("SESSION_RUNTIME_DIR", "/run/maxbot-sessions"))
    sessions_dir = data / "sessions"
    account_session_locks = AccountSessionLocks()

    class LockedAdapter:
        def __init__(self, adapter, lock: asyncio.Lock):
            self._adapter = adapter
            self._lock = lock
            self._closed = False

        def __getattr__(self, name):
            return getattr(self._adapter, name)

        async def close(self):
            if self._closed:
                return
            self._closed = True
            try:
                await self._adapter.close()
            finally:
                self._lock.release()

    async def scheduled_provider(slot):
        with db() as connection:
            row = connection.execute(
                "SELECT a.phone,p.id AS proxy_id,p.url_ciphertext FROM accounts a JOIN proxy_assignments pa ON pa.account_id=a.id "
                "JOIN proxies p ON p.id=pa.proxy_id WHERE a.id=? AND p.enabled=1",
                (slot["account_id"],),
            ).fetchone()
        if row is None:
            raise RuntimeError("proxy_assignment_unavailable")
        proxy = SecretBox().decrypt(row["url_ciphertext"])
        vault = EncryptedSessionFile(slot["account_id"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
        lock = account_session_locks.for_account(slot["account_id"])
        await lock.acquire()
        adapter = None
        try:
            adapter = PyMaxAdapter.create(phone=row["phone"], work_dir="", session_name="", proxy=proxy, session_vault=vault)
            await adapter.connect()
            return LockedAdapter(adapter, lock)
        except BaseException:
            if adapter is not None:
                try:
                    await adapter.close()
                except Exception as exc:
                    logger.warning("session_close_failed account_id=%s proxy_id=%s error_class=%s", slot["account_id"], row["proxy_id"], type(exc).__name__)
            lock.release()
            raise

    worker_manager = GroupWorkerManager(database, scheduled_provider)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        with db() as connection:
            recover_in_flight(connection)
            connection.execute("UPDATE onboarding_sessions SET state='failed',error_code='process_interrupted',updated_at=? WHERE state NOT IN ('completed','failed')", (datetime.now(timezone.utc).isoformat(),))
        await worker_manager.start()
        try:
            yield
        finally:
            await worker_manager.stop()

    app = FastAPI(title="MAXBOT v2", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.database = database
    app.state.data_dir = data
    app.state.owner_username = owner_username
    app.state.owner_password_hash = password_hash
    app.state.secret_key = secret
    app.state.cookie_secure = cookie_secure
    app.state.db_context = db
    app.state.onboarding_flows = {}
    app.state.worker_manager = worker_manager
    app.state.account_session_locks = account_session_locks

    def current_session(request: Request) -> sqlite3.Row:
        raw = request.cookies.get("owner_session", "")
        if not raw:
            raise HTTPException(401, "authentication_required")
        with db() as connection:
            row = connection.execute(
                "SELECT token_hash, csrf_hash, expires_at FROM owner_sessions WHERE token_hash=?",
                (digest_token(raw),),
            ).fetchone()
        if row is None or row["expires_at"] <= datetime.now(timezone.utc).isoformat():
            raise HTTPException(401, "authentication_required")
        return row

    def require_csrf(request: Request, session: sqlite3.Row = Depends(current_session)) -> sqlite3.Row:
        _require_same_origin(request)
        token = request.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(digest_token(token), session["csrf_hash"]):
            raise HTTPException(403, "csrf_required")
        return session

    def rate_limited(key: str, limit: int, seconds: int) -> bool:
        now = int(time.time())
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM auth_attempts WHERE window_start<?", (now - 86400,))
            row = connection.execute("SELECT count, window_start FROM auth_attempts WHERE attempt_key=?", (key,)).fetchone()
            if row is None or now - int(row["window_start"]) >= seconds:
                connection.execute(
                    "INSERT INTO auth_attempts(attempt_key,count,window_start) VALUES(?,?,?) "
                    "ON CONFLICT(attempt_key) DO UPDATE SET count=1,window_start=excluded.window_start",
                    (key, 1, now),
                )
                connection.commit()
                return False
            count = int(row["count"])
            connection.execute("UPDATE auth_attempts SET count=count+1 WHERE attempt_key=?", (key,))
            connection.commit()
            return count >= limit

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/auth/login")
    def login(body: LoginBody, request: Request, response: Response) -> dict[str, str]:
        _require_same_origin(request)
        remote = request.client.host if request.client else "unknown"
        key = f"login:{digest_token(remote)}"
        if rate_limited(key, 5, 900):
            raise HTTPException(429, "login_rate_limited")
        if not secret or len(secret) < 32 or not password_hash:
            raise HTTPException(503, "owner_credentials_not_configured")
        if body.username != owner_username or not password_matches(body.password, password_hash):
            raise HTTPException(401, "invalid_credentials")
        session_token, csrf_token = new_token(), new_token(24)
        now = datetime.now(timezone.utc)
        with db() as connection:
            connection.execute(
                "INSERT INTO owner_sessions(token_hash,csrf_hash,created_at,expires_at) VALUES(?,?,?,?)",
                (digest_token(session_token), digest_token(csrf_token), now.isoformat(), (now + timedelta(days=7)).isoformat()),
            )
        response.set_cookie(
            "owner_session", session_token, httponly=True, secure=cookie_secure,
            samesite="strict", path="/", max_age=7 * 24 * 3600,
        )
        response.set_cookie(
            "owner_csrf", csrf_token, httponly=False, secure=cookie_secure,
            samesite="strict", path="/", max_age=7 * 24 * 3600,
        )
        return {"ok": "true", "csrf_token": csrf_token}

    @app.post("/api/auth/logout")
    def logout(response: Response, request: Request, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, str]:
        raw = request.cookies.get("owner_session", "")
        with db() as connection:
            connection.execute("DELETE FROM owner_sessions WHERE token_hash=?", (digest_token(raw),))
        response.delete_cookie("owner_session", path="/", secure=cookie_secure, httponly=True, samesite="strict")
        response.delete_cookie("owner_csrf", path="/", secure=cookie_secure, httponly=False, samesite="strict")
        return {"ok": "true"}

    @app.get("/api/auth/me")
    def me(_session: sqlite3.Row = Depends(current_session)) -> dict[str, str]:
        return {"username": owner_username}

    @app.get("/api/overview")
    def overview(_session: sqlite3.Row = Depends(current_session)) -> dict[str, object]:
        with db() as connection:
            counts = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("groups", "accounts", "weekly_slots")
            }
            settings = dict(connection.execute("SELECT key,value FROM settings WHERE key IN ('auto_run','global_stop')").fetchall())
        return {"counts": counts, "auto_run": settings.get("auto_run") == "1", "stopped": settings.get("global_stop") == "1"}

    @app.get("/api/groups")
    def groups(_session: sqlite3.Row = Depends(current_session)) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                "SELECT g.id,g.name,g.invite_link,g.chat_id,g.active,COUNT(DISTINCT a.id) account_count,"
                "COUNT(DISTINCT CASE WHEN a.status='active' THEN a.id END) connected_account_count,"
                "COUNT(DISTINCT p.id) proxy_count,COUNT(DISTINCT CASE WHEN p.enabled=1 THEN p.id END) available_proxy_count FROM groups g "
                "LEFT JOIN accounts a ON a.group_id=g.id LEFT JOIN proxies p ON p.group_id=g.id "
                "GROUP BY g.id ORDER BY g.id"
            ).fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/groups/{group_id}/onboarding-link")
    def get_onboarding_link(group_id: int, request: Request, response: Response, _session: sqlite3.Row = Depends(current_session)) -> dict[str, object]:
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Vary"] = "Cookie"
        with db() as connection:
            row = connection.execute(
                "SELECT i.id,i.token_hash,i.token_ciphertext,i.expires_at,i.max_uses,i.active,"
                "(SELECT COUNT(*) FROM onboarding_sessions s WHERE s.invite_id=i.id AND s.token_hash=i.token_hash "
                "AND s.state NOT IN ('failed','expired')) AS active_uses "
                "FROM onboarding_invites i WHERE i.group_id=?",
                (group_id,),
            ).fetchone()
            group = connection.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone()
        if group is None:
            raise HTTPException(404, "group_not_found")
        if row is None:
            return {"url": None, "expires_at": None, "max_uses": None, "status": "missing"}
        now = datetime.now(timezone.utc).isoformat()
        if not row["active"]:
            status = "revoked"
        elif row["expires_at"] <= now:
            status = "expired"
        elif row["max_uses"] is not None and row["active_uses"] >= row["max_uses"]:
            status = "exhausted"
        else:
            status = "active"
        token = SecretBox().decrypt(row["token_ciphertext"]) if status == "active" else None
        base = str(request.base_url).rstrip("/")
        return {"url": f"{base}/join/{token}" if token else None, "expires_at": row["expires_at"], "max_uses": row["max_uses"], "status": status}

    @app.post("/api/groups/{group_id}/onboarding-link")
    def issue_onboarding_link(group_id: int, request: Request, response: Response, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        response.headers["Cache-Control"] = "no-store, private"
        body = request.query_params
        rotate = body.get("rotate") == "1"
        try:
            lifetime_days = int(body.get("days", "7"))
            max_uses = int(body["max_uses"]) if body.get("max_uses") else None
        except ValueError as exc:
            raise HTTPException(422, "invalid_invite_limits") from exc
        if not 1 <= lifetime_days <= 30 or (max_uses is not None and not 1 <= max_uses <= 1000):
            raise HTTPException(422, "invalid_invite_limits")
        now = datetime.now(timezone.utc)
        box = SecretBox()
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            group = connection.execute("SELECT id FROM groups WHERE id=?", (group_id,)).fetchone()
            if group is None:
                raise HTTPException(404, "group_not_found")
            current = connection.execute(
                "SELECT token_ciphertext,expires_at,max_uses,active FROM onboarding_invites WHERE group_id=?",
                (group_id,),
            ).fetchone()
            if current is not None and current["active"] and current["expires_at"] > now.isoformat() and not rotate:
                token = box.decrypt(current["token_ciphertext"])
                expires_at = current["expires_at"]
                max_uses = current["max_uses"]
            else:
                token = new_token(32)
                expires_at = (now + timedelta(days=lifetime_days)).isoformat()
                connection.execute(
                    "INSERT INTO onboarding_invites(group_id,token_hash,token_ciphertext,created_at,expires_at,max_uses,uses_count,active) "
                    "VALUES(?,?,?,?,?,?,0,1) ON CONFLICT(group_id) DO UPDATE SET "
                    "token_hash=excluded.token_hash,token_ciphertext=excluded.token_ciphertext,created_at=excluded.created_at,"
                    "expires_at=excluded.expires_at,max_uses=excluded.max_uses,uses_count=0,active=1",
                    (group_id, digest_token(token), box.encrypt(token), now.isoformat(), expires_at, max_uses),
                )
            connection.commit()
        base = str(request.base_url).rstrip("/")
        return {"url": f"{base}/join/{token}", "expires_at": expires_at, "max_uses": max_uses}

    @app.delete("/api/groups/{group_id}/onboarding-link")
    def revoke_onboarding_link(group_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        with db() as connection:
            connection.execute("UPDATE onboarding_invites SET active=0 WHERE group_id=?", (group_id,))
        return {"revoked": True}

    @app.get("/api/groups/{group_id}/proxies")
    def list_proxies(group_id: int, _session: sqlite3.Row = Depends(current_session)) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute("SELECT id,label,position,enabled FROM proxies WHERE group_id=? ORDER BY position,id", (group_id,)).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/groups/{group_id}/proxies", status_code=201)
    def add_proxy(group_id: int, body: ProxyBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        try:
            parsed = urlsplit(body.url)
            valid = parsed.scheme in ("http", "socks5") and bool(parsed.hostname) and parsed.port is not None and parsed.port > 0
        except ValueError:
            valid = False
        if not valid:
            raise HTTPException(422, "invalid_proxy_url")
        try:
            encrypted = SecretBox().encrypt(body.url)
        except ValueError as exc:
            raise HTTPException(503, "encryption_not_configured") from exc
        with db() as connection:
            if connection.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone() is None:
                raise HTTPException(404, "group_not_found")
            position = int(connection.execute("SELECT COALESCE(MAX(position),-1)+1 FROM proxies WHERE group_id=?", (group_id,)).fetchone()[0])
            cursor = connection.execute("INSERT INTO proxies(group_id,url_ciphertext,label,position) VALUES(?,?,?,?)", (group_id, encrypted, body.label.strip(), position))
        return {"id": cursor.lastrowid, "label": body.label.strip(), "position": position, "enabled": True}

    @app.post("/api/groups/{group_id}/proxies/bulk", status_code=201)
    def add_proxies_bulk(group_id: int, body: ProxyLinesBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        lines = [(number, line.strip()) for number, line in enumerate(body.lines.splitlines(), 1) if line.strip()]
        if not 1 <= len(lines) <= 100:
            raise HTTPException(422, "proxy_line_count_must_be_between_1_and_100")
        invalid_lines: list[int] = []
        duplicate_values: dict[str, list[int]] = {}
        for number, url in lines:
            duplicate_values.setdefault(url, []).append(number)
            try:
                parsed = urlsplit(url)
                valid = parsed.scheme in ("http", "socks5") and bool(parsed.hostname) and parsed.port is not None and parsed.port > 0
            except ValueError:
                valid = False
            if not valid:
                invalid_lines.append(number)
        duplicate_lines = [number for positions in duplicate_values.values() if len(positions) > 1 for number in positions]
        errors = []
        if invalid_lines:
            errors.append("invalid_lines=" + ",".join(map(str, invalid_lines)))
        if duplicate_lines:
            errors.append("duplicate_lines=" + ",".join(map(str, duplicate_lines)))
        if errors:
            raise HTTPException(422, "invalid_proxy_lines:" + ";".join(errors))
        try:
            encrypted_urls = [SecretBox().encrypt(url) for _, url in lines]
        except ValueError as exc:
            raise HTTPException(503, "encryption_not_configured") from exc
        created: list[dict[str, object]] = []
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone() is None:
                connection.rollback()
                raise HTTPException(404, "group_not_found")
            position = int(connection.execute("SELECT COALESCE(MAX(position),-1)+1 FROM proxies WHERE group_id=?", (group_id,)).fetchone()[0])
            try:
                existing = connection.execute("SELECT url_ciphertext FROM proxies WHERE group_id=?", (group_id,)).fetchall()
                existing_urls = {SecretBox().decrypt(row["url_ciphertext"]) for row in existing}
                duplicate_existing = [number for number, url in lines if url in existing_urls]
                if duplicate_existing:
                    connection.rollback()
                    raise HTTPException(422, "invalid_proxy_lines:duplicate_lines=" + ",".join(map(str, duplicate_existing)))
                for index, encrypted in enumerate(encrypted_urls, 1):
                    label = f"Прокси {position + index}"
                    cursor = connection.execute("INSERT INTO proxies(group_id,url_ciphertext,label,position) VALUES(?,?,?,?)", (group_id, encrypted, label, position + index - 1))
                    created.append({"id": cursor.lastrowid, "label": label, "position": position + index - 1, "enabled": True})
                connection.commit()
            except sqlite3.Error:
                connection.rollback()
                raise
        return {"proxies": created, "count": len(created)}

    @app.delete("/api/groups/{group_id}/proxies/{proxy_id}")
    def remove_proxy(group_id: int, proxy_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        with db() as connection:
            assigned = connection.execute("SELECT 1 FROM proxy_assignments WHERE proxy_id=? LIMIT 1", (proxy_id,)).fetchone()
            if assigned:
                connection.execute("UPDATE proxies SET enabled=0 WHERE group_id=? AND id=?", (group_id, proxy_id))
            else:
                connection.execute("DELETE FROM proxies WHERE group_id=? AND id=?", (group_id, proxy_id))
        return {"disabled": bool(assigned)}

    @app.get("/api/messages")
    def messages(_session: sqlite3.Row = Depends(current_session)) -> dict[str, object]:
        with db() as connection:
            version = connection.execute("SELECT id,created_at FROM message_versions ORDER BY id DESC LIMIT 1").fetchone()
            rows = connection.execute("SELECT text FROM messages WHERE version_id=? ORDER BY ordinal", (version["id"],)).fetchall() if version else []
        return {"version": version["id"] if version else None, "created_at": version["created_at"] if version else None, "texts": [r["text"] for r in rows]}

    @app.put("/api/messages")
    def update_messages(body: TextsBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, int]:
        with db() as connection:
            try:
                version = replace_message_pool(connection, body.texts)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
        return {"version": version, "count": len(body.texts)}

    @app.get("/api/settings")
    def settings(_session: sqlite3.Row = Depends(current_session)) -> dict[str, object]:
        with db() as connection:
            values = dict(connection.execute("SELECT key,value FROM settings").fetchall())
        return {"timezone": values["timezone"], "send_windows_weekday": values["send_windows_weekday"], "send_windows_weekend": values["send_windows_weekend"], "delay_min_sec": int(values["delay_min_sec"]), "delay_max_sec": int(values["delay_max_sec"]), "auto_run": values["auto_run"] == "1", "global_stop": values["global_stop"] == "1"}

    @app.put("/api/settings")
    def update_settings(body: SettingsBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        if body.delay_max_sec < body.delay_min_sec:
            raise HTTPException(422, "invalid_delay_range")
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(body.timezone)
            _validate_windows(body.send_windows_weekday)
            _validate_windows(body.send_windows_weekend)
        except Exception as exc:
            raise HTTPException(422, "invalid_schedule_settings") from exc
        values = {"timezone": body.timezone, "send_windows_weekday": body.send_windows_weekday, "send_windows_weekend": body.send_windows_weekend, "delay_min_sec": str(body.delay_min_sec), "delay_max_sec": str(body.delay_max_sec), "auto_run": "1" if body.auto_run else "0"}
        with db() as connection:
            connection.executemany("UPDATE settings SET value=? WHERE key=?", [(v, k) for k, v in values.items()])
        return {"ok": True}

    @app.get("/api/log")
    def log(_session: sqlite3.Row = Depends(current_session)) -> list[dict[str, object]]:
        with db() as connection:
            audit = connection.execute(
                "SELECT created_at,kind,group_id,account_id,detail FROM audit_log ORDER BY id DESC LIMIT 200"
            ).fetchall()
            operations = connection.execute(
                "SELECT COALESCE(o.finished_at,o.started_at) AS created_at,o.status AS kind,o.operation_id,o.group_id,o.account_id,"
                "COALESCE(o.error_code,'') AS detail FROM operations o ORDER BY o.id DESC LIMIT 200"
            ).fetchall()
        return sorted([dict(row) for row in [*audit, *operations]], key=lambda row: row["created_at"], reverse=True)[:200]

    @app.post("/api/operations/{operation_id}/resolve")
    def resolve_operation(operation_id: str, body: OperationResolutionBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, str]:
        if body.outcome == "accepted" and not (body.provider_message_id or "").strip():
            raise HTTPException(422, "provider_message_id_required")
        now = datetime.now(timezone.utc).isoformat()
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                "SELECT o.*,s.text,s.scheduled_date FROM operations o JOIN weekly_slots s ON s.slot_id=o.slot_id WHERE o.operation_id=?",
                (operation_id,),
            ).fetchone()
            if operation is None:
                connection.rollback()
                raise HTTPException(404, "operation_not_found")
            if operation["status"] != "unknown":
                connection.rollback()
                raise HTTPException(409, "operation_not_unknown")
            if body.outcome == "accepted":
                message_id = (body.provider_message_id or "").strip()
                try:
                    connection.execute("INSERT INTO send_log(account_id,group_id,slot_id,sent_at,provider_message_id,text) VALUES(?,?,?,?,?,?)", (operation["account_id"], operation["group_id"], operation["slot_id"], now, message_id, operation["text"]))
                except sqlite3.IntegrityError as exc:
                    connection.rollback()
                    raise HTTPException(409, "slot_already_counted") from exc
                connection.execute("UPDATE operations SET status='accepted',finished_at=?,provider_message_id=?,error_code='manually_verified' WHERE operation_id=?", (now, message_id, operation_id))
                connection.execute("UPDATE weekly_slots SET status='accepted',error_code=NULL,updated_at=? WHERE slot_id=?", (now, operation["slot_id"]))
            else:
                tzrow = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
                from zoneinfo import ZoneInfo
                from datetime import datetime as dt
                today = dt.now(ZoneInfo(tzrow[0] if tzrow else "Europe/Moscow")).date().isoformat()
                next_status = "queued" if operation["scheduled_date"] >= today else "missed"
                connection.execute("UPDATE operations SET status='rejected',finished_at=?,error_code='manually_confirmed_not_sent' WHERE operation_id=?", (now, operation_id))
                connection.execute("UPDATE weekly_slots SET status=?,error_code='manually_confirmed_not_sent',updated_at=? WHERE slot_id=?", (next_status, now, operation["slot_id"]))
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,account_id,detail) VALUES(?,?,?,?,?)", (now, "operation_manually_resolved", operation["group_id"], operation["account_id"], '{"resolution":"' + body.outcome + '"}'))
            connection.commit()
        return {"status": "accepted" if body.outcome == "accepted" else "queued_or_missed"}

    @app.get("/join/{token}")
    def guest_join(token: str) -> FileResponse:
        with db() as connection:
            row = connection.execute("SELECT 1 FROM onboarding_invites WHERE token_hash=? AND active=1", (digest_token(token),)).fetchone()
        if row is None:
            raise HTTPException(404, "invite_unavailable")
        return FileResponse(static_dir / "join.html")

    def invite_row(connection, token: str):
        with db() as connection:
            row = connection.execute(
                "SELECT i.id,i.group_id,i.expires_at,i.max_uses,"
                "(SELECT COUNT(*) FROM onboarding_sessions s WHERE s.invite_id=i.id AND s.token_hash=i.token_hash "
                "AND s.state NOT IN ('failed','expired')) AS uses_count,g.name,g.invite_link,g.chat_id "
                "FROM onboarding_invites i JOIN groups g ON g.id=i.group_id WHERE i.token_hash=? AND i.active=1",
                (digest_token(token),),
            ).fetchone()
        if row is None or row["expires_at"] <= datetime.now(timezone.utc).isoformat() or (row["max_uses"] is not None and row["uses_count"] >= row["max_uses"]):
            raise HTTPException(404, "invite_unavailable")
        return row

    @app.get("/join-info/{token}")
    def join_info(token: str) -> dict[str, str]:
        row = invite_row(None, token)
        return {"group": row["name"], "invite_link": row["invite_link"]}

    @app.post("/api/public/onboarding/{token}/start")
    async def onboarding_start(token: str, request: Request) -> dict[str, str]:
        _require_same_origin(request)
        remote = request.client.host if request.client else "unknown"
        if rate_limited(f"guest-start:{digest_token(remote)}:{digest_token(token)}", 5, 900):
            raise HTTPException(429, "onboarding_rate_limited")
        payload = await request.json()
        full_name = str(payload.get("full_name", "")).strip()[:120]
        phone = str(payload.get("phone", "")).strip()
        import re
        digits = re.sub(r"\D", "", phone)
        if not full_name or not 7 <= len(digits) <= 15:
            raise HTTPException(422, "invalid_name_or_phone")
        phone = "+" + digits
        row = invite_row(None, token)
        session_id = new_token(16)
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("SELECT 1 FROM proxies WHERE group_id=? AND enabled=1 LIMIT 1", (row["group_id"],)).fetchone() is None:
                    connection.rollback()
                    raise HTTPException(409, "proxy_assignment_required")
                active_uses = connection.execute(
                    "SELECT COUNT(*) FROM onboarding_sessions WHERE invite_id=? AND token_hash=? "
                    "AND state NOT IN ('failed','expired')",
                    (row["id"], digest_token(token)),
                ).fetchone()[0]
                if row["max_uses"] is not None and active_uses >= row["max_uses"]:
                    connection.rollback()
                    raise HTTPException(404, "invite_unavailable")
                existing = connection.execute("SELECT id,group_id,status FROM accounts WHERE phone=?", (phone,)).fetchone()
                if existing is None:
                    account_id, proxy_id = prepare_account(connection, group_id=row["group_id"], phone=phone, full_name=full_name)
                else:
                    if existing["group_id"] != row["group_id"] or existing["status"] != "pending":
                        connection.rollback()
                        raise HTTPException(409, "phone_already_exists")
                    in_progress = connection.execute(
                        "SELECT 1 FROM onboarding_sessions WHERE account_id=? AND state NOT IN ('failed','completed','expired') LIMIT 1",
                        (existing["id"],),
                    ).fetchone()
                    if in_progress is not None:
                        connection.rollback()
                        raise HTTPException(409, "onboarding_in_progress")
                    assignment = connection.execute(
                        "SELECT pa.proxy_id FROM proxy_assignments pa JOIN proxies p ON p.id=pa.proxy_id "
                        "WHERE pa.account_id=? AND p.group_id=? AND p.enabled=1",
                        (existing["id"], row["group_id"]),
                    ).fetchone()
                    if assignment is None:
                        connection.rollback()
                        raise HTTPException(409, "proxy_assignment_required")
                    account_id, proxy_id = existing["id"], assignment["proxy_id"]
                    connection.execute("UPDATE accounts SET full_name=? WHERE id=?", (full_name, account_id))
                connection.execute(
                    "INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,phone,full_name,state,account_id,proxy_id,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,?,?,?,?)",
                    (session_id, row["id"], digest_token(token), digest_token(new_token()), phone, full_name, "starting", account_id, proxy_id, (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(), now, now),
                )
                connection.execute("UPDATE onboarding_invites SET uses_count=? WHERE id=?", (active_uses + 1, row["id"]))
                proxy = connection.execute("SELECT url_ciphertext FROM proxies WHERE id=?", (proxy_id,)).fetchone()["url_ciphertext"]
                connection.commit()
            try:
                proxy_url = SecretBox().decrypt(proxy)
            except ValueError as exc:
                raise HTTPException(503, "proxy_unavailable") from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "phone_already_exists") from exc
        flow = WebCodeAuthFlow(
            lambda state, hint: (set_onboarding_state(session_id, state, hint), setattr(flow, "hint", hint)),
            account_id=account_id,
            proxy_id=proxy_id,
        )
        app.state.onboarding_flows[session_id] = {"flow": flow, "account_id": account_id, "proxy_id": proxy_id, "group_id": row["group_id"], "phone": phone, "proxy": proxy_url}
        asyncio.create_task(run_onboarding_auth(session_id, row["invite_link"]))
        return {"session_id": session_id, "state": "starting", "group": row["name"]}

    def set_onboarding_state(session_id: str, state: str, hint: str = "") -> None:
        with db() as connection:
            connection.execute("UPDATE onboarding_sessions SET state=?,error_code=?,updated_at=? WHERE id=?", (state, hint[:120], datetime.now(timezone.utc).isoformat(), session_id))

    async def run_onboarding_auth(session_id: str, invite_link: str) -> None:
        runtime = app.state.onboarding_flows.get(session_id)
        if runtime is None:
            return
        vault = EncryptedSessionFile(runtime["account_id"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
        adapter = None
        lock = account_session_locks.for_account(runtime["account_id"])
        stage = "session_open"
        stage_started = perf_counter()
        await lock.acquire()
        try:
            logger.info("onboarding_stage account_id=%s proxy_id=%s stage=%s", runtime["account_id"], runtime["proxy_id"], stage)
            adapter = PyMaxAdapter.create(phone=runtime["phone"], work_dir="", session_name="", proxy=runtime["proxy"], auth_flow=runtime["flow"], session_vault=vault)
            logger.info("onboarding_stage account_id=%s proxy_id=%s stage=%s duration_ms=%d", runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
            stage = "connect"
            stage_started = perf_counter()
            await adapter.connect()
            logger.info("onboarding_stage account_id=%s proxy_id=%s stage=%s duration_ms=%d", runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
            stage = "resolve_group"
            stage_started = perf_counter()
            profile = getattr(adapter.client, "me", None)
            contact = getattr(profile, "contact", None)
            max_user_id = str(getattr(contact, "id", "") or getattr(profile, "id", ""))
            if not max_user_id:
                raise RuntimeError("max_user_id_missing")
            resolved = await adapter.resolve_group_by_link(invite_link)
            logger.info("onboarding_stage account_id=%s proxy_id=%s stage=%s duration_ms=%d", runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
            chat_id = str(getattr(resolved, "id", "") or getattr(resolved, "chat_id", ""))
            if not chat_id:
                raise RuntimeError("group_resolution_failed")
            with db() as connection:
                attach_group_on_first_account(connection, runtime["group_id"], chat_id)
                connection.execute("UPDATE accounts SET max_user_id=? WHERE id=?", (max_user_id, runtime["account_id"]))
                connection.execute("UPDATE onboarding_sessions SET state='waiting_membership',max_user_id=?,updated_at=? WHERE id=?", (max_user_id, datetime.now(timezone.utc).isoformat(), session_id))
        except Exception as exc:
            safe = str(exc) if str(exc) in {"group_destination_mismatch", "max_user_id_missing", "group_resolution_failed", "account_registration_required", "cloud_password_rejected"} else type(exc).__name__.lower()
            logger.warning("onboarding_failed account_id=%s proxy_id=%s stage=%s duration_ms=%d error_class=%s", runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000), type(exc).__name__)
            set_onboarding_state(session_id, "failed", safe)
        finally:
            if adapter is not None:
                try:
                    stage = "session_close_seal"
                    stage_started = perf_counter()
                    await adapter.close()
                    logger.info("onboarding_stage account_id=%s proxy_id=%s stage=%s duration_ms=%d", runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
                except Exception:
                    logger.warning("onboarding_failed account_id=%s proxy_id=%s stage=session_close_seal error_class=SessionSaveError", runtime["account_id"], runtime["proxy_id"])
                    set_onboarding_state(session_id, "failed", "session_save_failed")
            lock.release()
            app.state.onboarding_flows.pop(session_id, None)

    @app.post("/api/public/onboarding/{token}/{session_id}/code")
    async def onboarding_code(token: str, session_id: str, request: Request) -> dict[str, str]:
        _require_same_origin(request)
        remote = request.client.host if request.client else "unknown"
        if rate_limited(f"guest-code:{digest_token(remote)}:{digest_token(session_id)}", 8, 900):
            raise HTTPException(429, "code_rate_limited")
        payload = await request.json()
        code = str(payload.get("code", "")).strip()
        runtime = app.state.onboarding_flows.get(session_id)
        with db() as connection:
            row = connection.execute("SELECT token_hash,state FROM onboarding_sessions WHERE id=?", (session_id,)).fetchone()
        if row is None or row["token_hash"] != digest_token(token) or runtime is None or row["state"] != "waiting_code":
            raise HTTPException(404, "onboarding_session_unavailable")
        if not code.isdigit() or not 4 <= len(code) <= 8:
            raise HTTPException(422, "invalid_code")
        if runtime["flow"].codes.full():
            runtime["flow"].codes.get_nowait()
        runtime["flow"].codes.put_nowait(code)
        return {"state": "verifying_code"}

    @app.post("/api/public/onboarding/{token}/{session_id}/password")
    async def onboarding_password(token: str, session_id: str, request: Request) -> dict[str, str]:
        _require_same_origin(request)
        remote = request.client.host if request.client else "unknown"
        if rate_limited(f"guest-password:{digest_token(remote)}:{digest_token(session_id)}", 8, 900):
            raise HTTPException(429, "password_rate_limited")
        payload = await request.json()
        password = str(payload.get("password", ""))
        runtime = app.state.onboarding_flows.get(session_id)
        with db() as connection:
            row = connection.execute("SELECT token_hash,state FROM onboarding_sessions WHERE id=?", (session_id,)).fetchone()
        if row is None or row["token_hash"] != digest_token(token) or runtime is None or row["state"] != "waiting_password":
            raise HTTPException(404, "onboarding_session_unavailable")
        if not password or len(password) > 256:
            raise HTTPException(422, "invalid_password")
        if runtime["flow"].passwords.full():
            runtime["flow"].passwords.get_nowait()
        runtime["flow"].passwords.put_nowait(password)
        return {"state": "verifying_password"}

    @app.get("/api/public/onboarding/{token}/{session_id}")
    def onboarding_status(token: str, session_id: str) -> dict[str, str]:
        with db() as connection:
            row = connection.execute("SELECT token_hash,state,error_code FROM onboarding_sessions WHERE id=?", (session_id,)).fetchone()
        if row is None or row["token_hash"] != digest_token(token):
            raise HTTPException(404, "onboarding_session_unavailable")
        flow = app.state.onboarding_flows.get(session_id, {}).get("flow")
        return {"state": row["state"], "hint": flow_hint(flow) or (row["error_code"] or ""), "error": row["error_code"] or ""}

    def flow_hint(flow) -> str:
        return str(getattr(flow, "hint", "") or "")

    @app.post("/api/public/onboarding/{token}/{session_id}/check-membership")
    async def onboarding_check_membership(token: str, session_id: str, request: Request) -> dict[str, bool]:
        _require_same_origin(request)
        remote = request.client.host if request.client else "unknown"
        if rate_limited(f"guest-membership:{digest_token(remote)}:{digest_token(session_id)}", 12, 900):
            raise HTTPException(429, "membership_check_rate_limited")
        with db() as connection:
            row = connection.execute(
                "SELECT s.*,a.group_id,a.phone,g.chat_id,pa.proxy_id,p.url_ciphertext FROM onboarding_sessions s "
                "JOIN accounts a ON a.id=s.account_id JOIN groups g ON g.id=a.group_id "
                "JOIN proxy_assignments pa ON pa.account_id=a.id JOIN proxies p ON p.id=pa.proxy_id WHERE s.id=?",
                (session_id,),
            ).fetchone()
        if row is None or row["token_hash"] != digest_token(token) or row["state"] != "waiting_membership" or not row["chat_id"]:
            raise HTTPException(404, "onboarding_session_unavailable")
        lock = account_session_locks.for_account(row["account_id"])
        adapter = None
        await lock.acquire()
        try:
            proxy_url = SecretBox().decrypt(row["url_ciphertext"])
            vault = EncryptedSessionFile(row["account_id"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
            adapter = PyMaxAdapter.create(phone=row["phone"], work_dir="", session_name="", proxy=proxy_url, session_vault=vault)
            await adapter.connect()
            chat = await adapter.get_chat(int(row["chat_id"]))
            joined = member_proof(chat, str(row["chat_id"]))
        except Exception:
            raise HTTPException(503, "membership_check_unavailable")
        finally:
            if adapter is not None:
                try:
                    await adapter.close()
                except Exception:
                    pass
            lock.release()
        if joined:
            with db() as connection:
                connection.execute("UPDATE accounts SET status='active' WHERE id=?", (row["account_id"],))
                connection.execute("UPDATE onboarding_sessions SET state='completed',updated_at=? WHERE id=?", (datetime.now(timezone.utc).isoformat(), session_id))
        return {"joined": joined, "completed": joined}

    @app.post("/api/groups", status_code=201)
    async def add_group(body: GroupBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        if not _valid_max_invite_link(body.invite_link):
            raise HTTPException(422, "invalid_max_invite_link")
        with db() as connection:
            cursor = connection.execute("INSERT INTO groups(name,invite_link) VALUES(?,?)", (body.name.strip(), body.invite_link.strip()))
            result = connection.execute("SELECT id,name,chat_id,active FROM groups WHERE id=?", (cursor.lastrowid,)).fetchone()
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,detail) VALUES(CURRENT_TIMESTAMP,'group_created',?,'{}')", (cursor.lastrowid,))
        await worker_manager._sync_group_workers()
        return dict(result)

    @app.put("/api/groups/{group_id}")
    async def update_group(group_id: int, body: GroupUpdateBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        if not _valid_max_invite_link(body.invite_link):
            raise HTTPException(422, "invalid_max_invite_link")
        with db() as connection:
            old = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            if old is None:
                raise HTTPException(404, "group_not_found")
            changed = old["invite_link"] != body.invite_link
            connection.execute("UPDATE groups SET name=?,invite_link=?,chat_id=CASE WHEN ? THEN NULL ELSE chat_id END WHERE id=?", (body.name.strip(), body.invite_link.strip(), int(changed), group_id))
            if changed:
                connection.execute("UPDATE onboarding_invites SET active=0 WHERE group_id=?", (group_id,))
                connection.execute("UPDATE accounts SET status='needs_membership' WHERE group_id=? AND status='active'", (group_id,))
                connection.execute("UPDATE weekly_slots SET status='blocked',error_code='destination_unverified',updated_at=CURRENT_TIMESTAMP WHERE group_id=? AND status='queued'", (group_id,))
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,detail) VALUES(CURRENT_TIMESTAMP,?,?,?)", ("group_destination_changed" if changed else "group_updated", group_id, "{}"))
            row = connection.execute("SELECT id,name,chat_id,active FROM groups WHERE id=?", (group_id,)).fetchone()
        await worker_manager._sync_group_workers()
        return dict(row)

    @app.post("/api/groups/{group_id}/active")
    async def set_group_active(group_id: int, body: RunBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        with db() as connection:
            cursor = connection.execute("UPDATE groups SET active=? WHERE id=?", (int(body.enabled), group_id))
            if cursor.rowcount == 0:
                raise HTTPException(404, "group_not_found")
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,detail) VALUES(CURRENT_TIMESTAMP,?,?,?)", ("group_enabled" if body.enabled else "group_disabled", group_id, "{}"))
        await worker_manager._sync_group_workers()
        return {"active": body.enabled}

    @app.get("/api/groups/{group_id}/accounts")
    def list_accounts(group_id: int, _session: sqlite3.Row = Depends(current_session)) -> list[dict[str, object]]:
        with db() as connection:
            from zoneinfo import ZoneInfo
            from .scheduling import monday_of
            timezone_row = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
            week_start = monday_of(datetime.now(ZoneInfo(timezone_row[0] if timezone_row else "Europe/Moscow")).date()).isoformat()
            rows = connection.execute(
                "SELECT a.id,a.full_name,a.phone,a.status,a.send_weekday,pa.proxy_id,p.label AS proxy_label,p.enabled AS proxy_enabled,"
                "s.scheduled_date,s.status AS slot_status,s.error_code FROM accounts a "
                "LEFT JOIN proxy_assignments pa ON pa.account_id=a.id LEFT JOIN proxies p ON p.id=pa.proxy_id "
                "LEFT JOIN weekly_slots s ON s.account_id=a.id AND s.week_start=? "
                "WHERE a.group_id=? ORDER BY a.id",
                (week_start, group_id),
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/groups/{group_id}/verify-destination")
    async def verify_destination(group_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        with db() as connection:
            group = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            accounts = connection.execute(
                "SELECT a.id,a.phone,p.url_ciphertext FROM accounts a JOIN proxy_assignments pa ON pa.account_id=a.id "
                "JOIN proxies p ON p.id=pa.proxy_id WHERE a.group_id=? AND a.status='active' AND p.enabled=1 ORDER BY a.id",
                (group_id,),
            ).fetchall()
        if group is None:
            raise HTTPException(404, "group_not_found")
        if not accounts:
            raise HTTPException(409, "no_connected_account_for_verification")
        chat_id = ""
        states: dict[int, bool] = {}
        for index, account in enumerate(accounts):
            adapter = None
            lock = account_session_locks.for_account(account["id"])
            await lock.acquire()
            try:
                proxy = SecretBox().decrypt(account["url_ciphertext"])
                vault = EncryptedSessionFile(account["id"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
                adapter = PyMaxAdapter.create(phone=account["phone"], work_dir="", session_name="", proxy=proxy, session_vault=vault)
                await adapter.connect()
                if index == 0:
                    resolved = await adapter.resolve_group_by_link(group["invite_link"])
                    chat_id = str(getattr(resolved, "id", "") or getattr(resolved, "chat_id", ""))
                    if not chat_id:
                        raise RuntimeError("group_resolution_failed")
                states[int(account["id"])] = member_proof(await adapter.get_chat(int(chat_id)), chat_id)
            except Exception as exc:
                if index == 0:
                    raise HTTPException(503, "group_resolution_failed") from exc
                states[int(account["id"])] = False
            finally:
                if adapter is not None:
                    try:
                        await adapter.close()
                    except Exception:
                        pass
                lock.release()
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            if current is None or current["invite_link"] != group["invite_link"]:
                connection.rollback()
                raise HTTPException(409, "group_invite_changed_during_verification")
            connection.execute("UPDATE groups SET chat_id=? WHERE id=?", (chat_id, group_id))
            for account_id, joined in states.items():
                connection.execute("UPDATE accounts SET status=? WHERE id=?", ("active" if joined else "needs_membership", account_id))
                tzrow = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
                from zoneinfo import ZoneInfo
                today = datetime.now(ZoneInfo(tzrow[0] if tzrow else "Europe/Moscow")).date().isoformat()
                next_status = "queued" if joined else "blocked"
                connection.execute(
                    "UPDATE weekly_slots SET status=CASE WHEN scheduled_date>=? THEN ? ELSE 'missed' END,"
                    "error_code=CASE WHEN ?='queued' THEN NULL ELSE 'account_not_active' END,updated_at=? "
                    "WHERE account_id=? AND status='blocked' AND error_code IN ('destination_unverified','account_not_active')",
                    (today, next_status, next_status, datetime.now(timezone.utc).isoformat(), account_id),
                )
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,detail) VALUES(CURRENT_TIMESTAMP,'group_destination_verified',?,'{}')", (group_id,))
            connection.commit()
        return {"chat_id": chat_id, "verified_accounts": sum(states.values()), "accounts_needing_membership": sum(not v for v in states.values())}

    @app.post("/api/accounts/{account_id}/proxy")
    def reassign_proxy(account_id: int, body: ProxyAssignmentBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            account = connection.execute("SELECT group_id FROM accounts WHERE id=?", (account_id,)).fetchone()
            proxy = connection.execute("SELECT id,group_id,label,enabled FROM proxies WHERE id=?", (body.proxy_id,)).fetchone()
            if account is None or proxy is None:
                connection.rollback()
                raise HTTPException(404, "account_or_proxy_not_found")
            if int(account["group_id"]) != int(proxy["group_id"]) or not int(proxy["enabled"]):
                connection.rollback()
                raise HTTPException(422, "proxy_group_mismatch_or_disabled")
            connection.execute("INSERT INTO proxy_assignments(account_id,proxy_id) VALUES(?,?) ON CONFLICT(account_id) DO UPDATE SET proxy_id=excluded.proxy_id,assigned_at=CURRENT_TIMESTAMP", (account_id, body.proxy_id))
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,account_id,detail) VALUES(CURRENT_TIMESTAMP,'proxy_reassigned',?,?,?)", (account["group_id"], account_id, "{}"))
            connection.commit()
        return {"proxy_id": proxy["id"], "proxy_label": proxy["label"]}

    @app.post("/api/run/stop")
    def stop(_session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        with db() as connection:
            connection.execute("UPDATE settings SET value='1' WHERE key='global_stop'")
        return {"stopped": True}

    @app.post("/api/run/start")
    def start(_session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        with db() as connection:
            connection.execute("UPDATE settings SET value='0' WHERE key='global_stop'")
        return {"stopped": False}

    static_dir = Path(__file__).resolve().parent.parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(static_dir / "index.html")

    return app


def _validate_windows(value: str) -> None:
    import re
    intervals = [item.strip() for item in value.split(",")]
    if not intervals or any(not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d-(?:[01]\d|2[0-3]):[0-5]\d", item) for item in intervals):
        raise ValueError("invalid_window")
    for item in intervals:
        start, end = item.split("-")
        if start >= end:
            raise ValueError("invalid_window_order")


def _require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    parsed = urlsplit(origin)
    if parsed.netloc.lower() != request.url.netloc.lower() or parsed.scheme not in ("https", "http"):
        raise HTTPException(403, "invalid_origin")
