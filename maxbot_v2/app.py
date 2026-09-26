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
from .onboarding import WebCodeAuthFlow, attach_group_on_first_account, join_group_and_confirm_membership, member_proof, normalize_russian_phone, prepare_account
from .max_adapter import PyMaxAdapter, probe_proxy
from .session_vault import EncryptedSessionFile
from .workers import GroupWorkerManager, _inside_window
from .sender import DispatchPaused, recover_in_flight
from .session_lock import AccountSessionLocks
from .scheduling import assign_proxy


logger = logging.getLogger(__name__)
logging.getLogger("maxbot_v2").setLevel(os.getenv("APP_LOG_LEVEL", "INFO").upper())


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

    async def check_proxy_url(proxy_url: str, proxy_id: int | None = None) -> tuple[str, str | None, int]:
        started = perf_counter()
        try:
            await probe_proxy(proxy_url)
            status, error = "healthy", None
        except Exception as exc:
            raw_code = getattr(exc, "code", "")
            error = raw_code[:64] if isinstance(raw_code, str) and raw_code.isidentifier() else "proxy_check_failed"
            status = "failed"
        duration_ms = int((perf_counter() - started) * 1000)
        logger.info(
            "proxy_check proxy_id=%s stage=complete healthy=%s duration_ms=%d error_code=%s",
            proxy_id, status == "healthy", duration_ms, error or "none",
        )
        return status, error, duration_ms

    with db() as connection:
        initialize(connection)

    runtime_dir = Path(os.getenv("SESSION_RUNTIME_DIR", "/run/maxbot-sessions"))
    sessions_dir = data / "sessions"
    account_session_locks = AccountSessionLocks()
    terminal_onboarding_states = ("completed", "failed", "expired", "cancelled")

    class LockedAdapter:
        def __init__(self, adapter, lock: asyncio.Lock, proxy_id: int):
            self._adapter = adapter
            self._lock = lock
            self.proxy_id = proxy_id
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
                "SELECT a.phone,a.session_generation,p.id AS proxy_id,p.url_ciphertext,p.check_status FROM accounts a JOIN proxy_assignments pa ON pa.account_id=a.id "
                "JOIN proxies p ON p.id=pa.proxy_id WHERE a.id=? AND p.enabled=1",
                (slot["account_id"],),
            ).fetchone()
        if row is None:
            raise DispatchPaused("proxy_assignment_unavailable", blocked=True)
        try:
            proxy = SecretBox().decrypt(row["url_ciphertext"])
        except ValueError as exc:
            raise DispatchPaused("proxy_unavailable", blocked=True) from exc
        if row["check_status"] == "failed":
            raise DispatchPaused("proxy_check_failed", blocked=True)
        vault = EncryptedSessionFile(slot["account_id"], generation=row["session_generation"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
        lock = account_session_locks.for_account(slot["account_id"])
        await lock.acquire()
        adapter = None
        try:
            adapter = PyMaxAdapter.create(phone=row["phone"], work_dir="", session_name="", proxy=proxy, session_vault=vault)
            await adapter.connect()
            return LockedAdapter(adapter, lock, int(row["proxy_id"]))
        except BaseException:
            try:
                if adapter is not None:
                    try:
                        await adapter.close()
                    except Exception as exc:
                        logger.warning("session_close_failed account_id=%s proxy_id=%s error_class=%s", slot["account_id"], row["proxy_id"], type(exc).__name__)
            finally:
                lock.release()
            raise

    worker_manager = GroupWorkerManager(database, scheduled_provider)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        with db() as connection:
            recover_in_flight(connection)
            connection.execute("UPDATE onboarding_sessions SET state='failed',error_code='process_interrupted',updated_at=? WHERE state NOT IN ('completed','failed','expired','cancelled')", (datetime.now(timezone.utc).isoformat(),))
            settings = dict(connection.execute("SELECT key,value FROM settings WHERE key IN ('auto_run','global_stop')").fetchall())
            if settings.get("auto_run") != "1":
                connection.execute("UPDATE settings SET value='1' WHERE key='global_stop'")
        await worker_manager.start()
        try:
            yield
        finally:
            await worker_manager.stop()
            tasks = list(app.state.onboarding_tasks.items())
            with db() as connection:
                connection.execute(
                    "UPDATE onboarding_sessions SET state='failed',error_code='process_interrupted',updated_at=? "
                    "WHERE state NOT IN ('completed','failed','expired','cancelled')",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            for _session_id, task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*(task for _session_id, task in tasks), return_exceptions=True)
            app.state.onboarding_flows.clear()

    app = FastAPI(title="MAXBOT v2", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.database = database
    app.state.data_dir = data
    app.state.owner_username = owner_username
    app.state.owner_password_hash = password_hash
    app.state.secret_key = secret
    app.state.cookie_secure = cookie_secure
    app.state.db_context = db
    app.state.onboarding_flows = {}
    app.state.onboarding_tasks = {}
    app.state.worker_manager = worker_manager
    app.state.account_session_locks = account_session_locks

    def cancel_onboarding_tasks(session_ids: list[str]) -> None:
        for session_id in session_ids:
            task = app.state.onboarding_tasks.get(session_id)
            if task is not None and not task.done():
                task.get_loop().call_soon_threadsafe(task.cancel)

    def cancel_group_onboarding(connection: sqlite3.Connection, group_id: int, reason: str) -> list[str]:
        ids = [row[0] for row in connection.execute(
            "SELECT s.id FROM onboarding_sessions s JOIN accounts a ON a.id=s.account_id "
            "WHERE a.group_id=? AND s.state NOT IN ('completed','failed','expired','cancelled')",
            (group_id,),
        ).fetchall()]
        if ids:
            stamp = datetime.now(timezone.utc).isoformat()
            connection.execute(
                "UPDATE onboarding_sessions SET state='cancelled',error_code=?,updated_at=? "
                "WHERE state NOT IN ('completed','failed','expired','cancelled') AND id IN (" + ",".join("?" for _ in ids) + ")",
                (reason, stamp, *ids),
            )
        return ids

    def guest_onboarding_session(token: str, session_id: str) -> dict[str, object]:
        with db() as connection:
            row = connection.execute(
                "SELECT s.*,i.active AS invite_active,i.expires_at AS invite_expires_at,i.token_hash AS current_invite_hash "
                "FROM onboarding_sessions s JOIN onboarding_invites i ON i.id=s.invite_id WHERE s.id=?",
                (session_id,),
            ).fetchone()
            if row is None or row["token_hash"] != digest_token(token):
                raise HTTPException(404, "onboarding_session_unavailable")
            state = row["state"]
            if state not in terminal_onboarding_states:
                now = datetime.now(timezone.utc).isoformat()
                if row["expires_at"] <= now:
                    state, error = "expired", "onboarding_attempt_expired"
                elif (not row["invite_active"] or row["current_invite_hash"] != row["token_hash"] or row["invite_expires_at"] <= now):
                    state, error = "cancelled", "invite_unavailable"
                else:
                    error = None
                if error:
                    connection.execute(
                        "UPDATE onboarding_sessions SET state=?,error_code=?,updated_at=? WHERE id=?",
                        (state, error, now, session_id),
                    )
            else:
                error = row["error_code"]
            result = dict(row)
            result["state"] = state
            result["error_code"] = error
            active_invite = bool(row["invite_active"] and row["current_invite_hash"] == row["token_hash"] and row["invite_expires_at"] > datetime.now(timezone.utc).isoformat())
        if state in {"expired", "cancelled"}:
            cancel_onboarding_tasks([session_id])
            app.state.onboarding_flows.pop(session_id, None)
        with db() as connection:
            capacity = connection.execute(
                "SELECT i.max_uses,(SELECT COUNT(*) FROM onboarding_sessions other WHERE other.invite_id=i.id "
                "AND other.token_hash=i.token_hash AND other.state NOT IN ('failed','expired','cancelled')) AS uses_count "
                "FROM onboarding_invites i WHERE i.id=?",
                (row["invite_id"],),
            ).fetchone()
        has_capacity = bool(capacity and (capacity["max_uses"] is None or capacity["uses_count"] < capacity["max_uses"]))
        result["retryable"] = bool(state in {"failed", "expired", "cancelled"} and active_invite and has_capacity)
        return result

    def cancel_onboarding(session_id: str, state: str, reason: str) -> None:
        stamp = datetime.now(timezone.utc).isoformat()
        with db() as connection:
            connection.execute(
                "UPDATE onboarding_sessions SET state=?,error_code=?,updated_at=? WHERE id=? "
                "AND state NOT IN ('completed','failed','expired','cancelled')",
                (state, reason, stamp, session_id),
            )
        cancel_onboarding_tasks([session_id])
        app.state.onboarding_flows.pop(session_id, None)

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
        return {"status": "ok", "revision": os.getenv("BUILD_REVISION", os.getenv("GIT_SHA", "unknown"))}

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
            counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("groups", "weekly_slots")}
            counts["accounts"] = connection.execute("SELECT COUNT(*) FROM accounts WHERE status!='removed'").fetchone()[0]
            settings = dict(connection.execute("SELECT key,value FROM settings").fetchall())
            active_groups = connection.execute("SELECT COUNT(*) FROM groups WHERE active=1").fetchone()[0]
            ready_accounts = connection.execute(
                "SELECT COUNT(*) FROM accounts a JOIN groups g ON g.id=a.group_id "
                "JOIN proxy_assignments pa ON pa.account_id=a.id JOIN proxies p ON p.id=pa.proxy_id "
                "WHERE a.status='active' AND g.active=1 AND g.chat_id IS NOT NULL AND p.enabled=1"
            ).fetchone()[0]
        stopped = settings.get("global_stop") == "1"
        if stopped:
            wait_reason = "Работа сейчас остановлена. Запустите её кнопкой вверху панели."
        elif not active_groups:
            wait_reason = "Нет включённых групп. Запуск не отправит сообщения, пока группу не включат."
        elif not ready_accounts:
            wait_reason = "Нет подключённых аккаунтов с проверенной группой и доступным прокси."
        else:
            from zoneinfo import ZoneInfo
            now = datetime.now(ZoneInfo(settings.get("timezone", "Europe/Moscow")))
            wait_reason = "Ожидание разрешённого окна отправки." if not _inside_window(now, settings) else "Работа включена; сообщения ждут назначенного дня и окна."
        return {
            "counts": counts,
            "auto_run": settings.get("auto_run") == "1",
            "stopped": stopped,
            "run_wait_reason": wait_reason,
        }

    @app.get("/api/groups")
    def groups(_session: sqlite3.Row = Depends(current_session)) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                "SELECT g.id,g.name,g.invite_link,g.chat_id,g.active,COUNT(DISTINCT CASE WHEN a.status!='removed' THEN a.id END) account_count,"
                "COUNT(DISTINCT CASE WHEN a.status='active' THEN a.id END) connected_account_count,"
                "COUNT(DISTINCT CASE WHEN a.status IN ('active','needs_membership') AND EXISTS ("
                "SELECT 1 FROM proxy_assignments pa JOIN proxies assigned_proxy ON assigned_proxy.id=pa.proxy_id "
                "WHERE pa.account_id=a.id AND assigned_proxy.enabled=1 AND assigned_proxy.check_status!='failed') THEN a.id END) verifiable_account_count,"
                "COUNT(DISTINCT p.id) proxy_count,COUNT(DISTINCT CASE WHEN p.enabled=1 AND p.check_status='healthy' THEN p.id END) available_proxy_count FROM groups g "
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
                "AND s.state NOT IN ('failed','expired','cancelled')) AS active_uses "
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
        cancelled_sessions: list[str] = []
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
                cancelled_sessions = cancel_group_onboarding(connection, group_id, "invite_unavailable")
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
        cancel_onboarding_tasks(cancelled_sessions)
        base = str(request.base_url).rstrip("/")
        return {"url": f"{base}/join/{token}", "expires_at": expires_at, "max_uses": max_uses}

    @app.delete("/api/groups/{group_id}/onboarding-link")
    def revoke_onboarding_link(group_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        with db() as connection:
            connection.execute("UPDATE onboarding_invites SET active=0 WHERE group_id=?", (group_id,))
            cancelled_sessions = cancel_group_onboarding(connection, group_id, "invite_unavailable")
        cancel_onboarding_tasks(cancelled_sessions)
        return {"revoked": True}

    @app.get("/api/groups/{group_id}/proxies")
    def list_proxies(group_id: int, _session: sqlite3.Row = Depends(current_session)) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                "SELECT p.id,p.label,p.position,p.enabled,p.check_status,p.checked_at,p.check_error,COUNT(pa.account_id) AS assigned_count FROM proxies p "
                "LEFT JOIN proxy_assignments pa ON pa.proxy_id=p.id WHERE p.group_id=? GROUP BY p.id ORDER BY p.position,p.id",
                (group_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/groups/{group_id}/proxies", status_code=201)
    async def add_proxy(group_id: int, body: ProxyBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
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
            proxy_id = int(cursor.lastrowid)
        check_status, check_error, _duration_ms = await check_proxy_url(body.url, proxy_id)
        checked_at = datetime.now(timezone.utc).isoformat()
        with db() as connection:
            connection.execute("UPDATE proxies SET check_status=?,checked_at=?,check_error=? WHERE id=? AND group_id=?", (check_status, checked_at, check_error, proxy_id, group_id))
        return {"id": proxy_id, "label": body.label.strip(), "position": position, "enabled": True, "check_status": check_status, "checked_at": checked_at, "check_error": check_error}

    @app.post("/api/groups/{group_id}/proxies/bulk", status_code=201)
    async def add_proxies_bulk(group_id: int, body: ProxyLinesBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
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
        semaphore = asyncio.Semaphore(10)

        async def check_added(item, url):
            async with semaphore:
                status, error, _duration_ms = await check_proxy_url(url, int(item["id"]))
            return int(item["id"]), status, error

        results = await asyncio.gather(*(check_added(item, url) for item, (_, url) in zip(created, lines, strict=True)))
        checked_at = datetime.now(timezone.utc).isoformat()
        with db() as connection:
            connection.executemany("UPDATE proxies SET check_status=?,checked_at=?,check_error=? WHERE id=? AND group_id=?", [(status, checked_at, error, proxy_id, group_id) for proxy_id, status, error in results])
        by_id = {proxy_id: (status, error) for proxy_id, status, error in results}
        for item in created:
            item["check_status"], item["check_error"] = by_id[int(item["id"])]
            item["checked_at"] = checked_at
        healthy_count = sum(status == "healthy" for _, status, _ in results)
        return {"proxies": created, "count": len(created), "healthy": healthy_count, "failed": len(created) - healthy_count}

    @app.post("/api/groups/{group_id}/proxies/{proxy_id}/check")
    async def check_proxy(group_id: int, proxy_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        with db() as connection:
            row = connection.execute("SELECT id,url_ciphertext FROM proxies WHERE id=? AND group_id=?", (proxy_id, group_id)).fetchone()
        if row is None:
            raise HTTPException(404, "proxy_not_found")
        try:
            proxy_url = SecretBox().decrypt(row["url_ciphertext"])
        except ValueError:
            check_status, check_error = "failed", "proxy_unavailable"
        else:
            check_status, check_error, _duration_ms = await check_proxy_url(proxy_url, proxy_id)
        checked_at = datetime.now(timezone.utc).isoformat()
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT id FROM proxies WHERE id=? AND group_id=?", (proxy_id, group_id)).fetchone()
            if current is None:
                connection.rollback()
                raise HTTPException(409, "proxy_changed_during_check")
            connection.execute("UPDATE proxies SET check_status=?,checked_at=?,check_error=? WHERE id=?", (check_status, checked_at, check_error, proxy_id))
            if check_status == "failed":
                connection.execute(
                    "UPDATE weekly_slots SET status='blocked',error_code='proxy_check_failed',updated_at=? "
                    "WHERE status='queued' AND account_id IN (SELECT account_id FROM proxy_assignments WHERE proxy_id=?)",
                    (checked_at, proxy_id),
                )
            else:
                timezone_row = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
                from zoneinfo import ZoneInfo
                today = datetime.now(ZoneInfo(timezone_row[0] if timezone_row else "Europe/Moscow")).date().isoformat()
                connection.execute(
                    "UPDATE weekly_slots SET status=CASE WHEN scheduled_date>=? THEN 'queued' ELSE 'missed' END,"
                    "error_code=CASE WHEN scheduled_date>=? THEN NULL ELSE 'proxy_check_failed' END,updated_at=? "
                    "WHERE status='blocked' AND error_code='proxy_check_failed' AND account_id IN "
                    "(SELECT account_id FROM proxy_assignments WHERE proxy_id=?)",
                    (today, today, checked_at, proxy_id),
                )
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,detail) VALUES(?,?,?,?)", (checked_at, "proxy_checked", group_id, '{"status":"' + check_status + '","error":"' + (check_error or "") + '"}'))
            connection.commit()
        return {"id": proxy_id, "check_status": check_status, "checked_at": checked_at, "check_error": check_error}

    @app.delete("/api/groups/{group_id}/proxies/{proxy_id}")
    def remove_proxy(group_id: int, proxy_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, bool]:
        with db() as connection:
            assigned = connection.execute("SELECT account_id FROM proxy_assignments WHERE proxy_id=?", (proxy_id,)).fetchall()
            if assigned:
                connection.execute("UPDATE proxies SET enabled=0 WHERE group_id=? AND id=?", (group_id, proxy_id))
                connection.executemany(
                    "UPDATE weekly_slots SET status='blocked',error_code='proxy_assignment_unavailable',updated_at=? "
                    "WHERE account_id=? AND status='queued'",
                    [(datetime.now(timezone.utc).isoformat(), row["account_id"]) for row in assigned],
                )
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

    def invite_row(connection, token: str, *, require_capacity: bool = True):
        with db() as connection:
            row = connection.execute(
                "SELECT i.id,i.group_id,i.expires_at,i.max_uses,"
                "(SELECT COUNT(*) FROM onboarding_sessions s WHERE s.invite_id=i.id AND s.token_hash=i.token_hash "
                "AND s.state NOT IN ('failed','expired','cancelled')) AS uses_count,g.name,g.invite_link,g.chat_id "
                "FROM onboarding_invites i JOIN groups g ON g.id=i.group_id WHERE i.token_hash=? AND i.active=1",
                (digest_token(token),),
            ).fetchone()
        if row is None or row["expires_at"] <= datetime.now(timezone.utc).isoformat() or (
            require_capacity and row["max_uses"] is not None and row["uses_count"] >= row["max_uses"]
        ):
            raise HTTPException(404, "invite_unavailable")
        return row

    @app.get("/join-info/{token}")
    def join_info(token: str) -> dict[str, str]:
        row = invite_row(None, token, require_capacity=False)
        return {"group": row["name"], "invite_link": row["invite_link"]}

    @app.post("/api/public/onboarding/{token}/start")
    async def onboarding_start(token: str, request: Request) -> dict[str, str]:
        _require_same_origin(request)
        remote = request.client.host if request.client else "unknown"
        if rate_limited(f"guest-start:{digest_token(remote)}:{digest_token(token)}", 5, 900):
            raise HTTPException(429, "onboarding_rate_limited")
        payload = await request.json()
        full_name = str(payload.get("full_name", "")).strip()[:120]
        raw_phone = str(payload.get("phone", "")).strip()
        if not full_name:
            raise HTTPException(422, "invalid_name")
        try:
            phone = normalize_russian_phone(raw_phone)
        except ValueError as exc:
            raise HTTPException(422, "invalid_russian_phone") from exc
        row = invite_row(None, token)
        session_id = new_token(16)
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current_invite = connection.execute(
                    "SELECT active,token_hash,expires_at,max_uses FROM onboarding_invites WHERE id=?",
                    (row["id"],),
                ).fetchone()
                if (current_invite is None or not current_invite["active"]
                        or current_invite["token_hash"] != digest_token(token) or current_invite["expires_at"] <= now):
                    connection.rollback()
                    raise HTTPException(404, "invite_unavailable")
                active_uses = connection.execute(
                    "SELECT COUNT(*) FROM onboarding_sessions WHERE invite_id=? AND token_hash=? "
                    "AND state NOT IN ('failed','expired','cancelled')",
                    (row["id"], digest_token(token)),
                ).fetchone()[0]
                if current_invite["max_uses"] is not None and active_uses >= current_invite["max_uses"]:
                    connection.rollback()
                    raise HTTPException(404, "invite_unavailable")
                existing = connection.execute("SELECT id,group_id,status,session_generation FROM accounts WHERE phone=?", (phone,)).fetchone()
                if existing is not None and existing["status"] == "removing":
                    connection.rollback()
                    raise HTTPException(409, "account_removal_in_progress")
                if existing is None or existing["status"] == "removed":
                    if connection.execute("SELECT 1 FROM proxies WHERE group_id=? AND enabled=1 AND check_status='healthy' LIMIT 1", (row["group_id"],)).fetchone() is None:
                        connection.rollback()
                        raise HTTPException(409, "proxy_assignment_required")
                    if existing is None:
                        try:
                            account_id, proxy_id = prepare_account(connection, group_id=row["group_id"], phone=phone, full_name=full_name)
                        except ValueError as exc:
                            connection.rollback()
                            raise HTTPException(409, "proxy_assignment_required") from exc
                    else:
                        account_id = int(existing["id"])
                        connection.execute(
                            "UPDATE accounts SET group_id=?,full_name=?,max_user_id=NULL,status='pending' WHERE id=?",
                            (row["group_id"], full_name, account_id),
                        )
                        try:
                            proxy_id = assign_proxy(connection, account_id, row["group_id"])
                        except ValueError as exc:
                            connection.rollback()
                            raise HTTPException(409, "proxy_assignment_required") from exc
                else:
                    if existing["group_id"] != row["group_id"] or existing["status"] != "pending":
                        connection.rollback()
                        raise HTTPException(409, "phone_already_exists")
                    in_progress = connection.execute(
                        "SELECT 1 FROM onboarding_sessions WHERE account_id=? AND state NOT IN ('failed','completed','expired','cancelled') LIMIT 1",
                        (existing["id"],),
                    ).fetchone()
                    if in_progress is not None:
                        connection.rollback()
                        raise HTTPException(409, "onboarding_in_progress")
                    assignment = connection.execute(
                        "SELECT pa.proxy_id,p.check_status FROM proxy_assignments pa JOIN proxies p ON p.id=pa.proxy_id "
                        "WHERE pa.account_id=? AND p.group_id=? AND p.enabled=1",
                        (existing["id"], row["group_id"]),
                    ).fetchone()
                    if assignment is not None and assignment["check_status"] != "healthy":
                        connection.rollback()
                        raise HTTPException(409, "proxy_check_failed" if assignment["check_status"] == "failed" else "proxy_not_healthy")
                    if assignment is None:
                        connection.rollback()
                        raise HTTPException(409, "proxy_assignment_required")
                    account_id, proxy_id = existing["id"], assignment["proxy_id"]
                    connection.execute("UPDATE accounts SET full_name=? WHERE id=?", (full_name, account_id))
                proxy_row = connection.execute(
                    "SELECT url_ciphertext,check_status FROM proxies WHERE id=? AND enabled=1", (proxy_id,)
                ).fetchone()
                if proxy_row is None:
                    connection.rollback()
                    raise HTTPException(409, "proxy_assignment_required")
                if proxy_row["check_status"] != "healthy":
                    connection.rollback()
                    raise HTTPException(409, "proxy_check_failed" if proxy_row["check_status"] == "failed" else "proxy_not_healthy")
                try:
                    proxy_url = SecretBox().decrypt(proxy_row["url_ciphertext"])
                except ValueError as exc:
                    connection.rollback()
                    raise HTTPException(503, "proxy_unavailable") from exc
                connection.execute(
                    "INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,phone,full_name,state,account_id,proxy_id,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,?,?,?,?)",
                    (session_id, row["id"], digest_token(token), digest_token(new_token()), phone, full_name, "starting", account_id, proxy_id, (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(), now, now),
                )
                connection.execute("UPDATE onboarding_invites SET uses_count=? WHERE id=?", (active_uses + 1, row["id"]))
                session_generation = int(connection.execute("SELECT session_generation FROM accounts WHERE id=?", (account_id,)).fetchone()[0])
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "phone_already_exists") from exc

        def validate_onboarding_proxy() -> None:
            with db() as connection:
                current_proxy = connection.execute(
                    "SELECT pa.proxy_id,p.enabled,p.group_id,p.url_ciphertext,p.check_status "
                    "FROM proxy_assignments pa JOIN proxies p ON p.id=pa.proxy_id "
                    "WHERE pa.account_id=?",
                    (account_id,),
                ).fetchone()
            if (current_proxy is None or int(current_proxy["proxy_id"]) != int(proxy_id)
                    or int(current_proxy["enabled"]) != 1 or int(current_proxy["group_id"]) != int(row["group_id"])):
                raise RuntimeError("proxy_assignment_changed")
            if current_proxy["check_status"] != "healthy":
                raise RuntimeError("proxy_check_failed" if current_proxy["check_status"] == "failed" else "proxy_not_healthy")
            try:
                current_url = SecretBox().decrypt(current_proxy["url_ciphertext"])
            except ValueError as exc:
                raise RuntimeError("proxy_assignment_changed") from exc
            if current_url != proxy_url:
                raise RuntimeError("proxy_assignment_changed")

        flow = WebCodeAuthFlow(
            lambda state, hint: (set_onboarding_state(session_id, state, hint), setattr(flow, "hint", hint)),
            request_code=lambda requested_phone: PyMaxAdapter.request_code_direct(
                phone=requested_phone,
                assigned_proxy=proxy_url,
            ),
            validate_proxy=validate_onboarding_proxy,
            account_id=account_id,
            proxy_id=proxy_id,
            session_id=session_id,
        )
        app.state.onboarding_flows[session_id] = {"flow": flow, "account_id": account_id, "session_generation": session_generation, "proxy_id": proxy_id, "group_id": row["group_id"], "phone": phone, "proxy": proxy_url}
        task = asyncio.create_task(run_onboarding_auth(session_id, row["invite_link"]))
        if task is not None:
            app.state.onboarding_tasks[session_id] = task
            task.add_done_callback(lambda done, sid=session_id: app.state.onboarding_tasks.pop(sid, None))
        return {"session_id": session_id, "state": "starting", "group": row["name"]}

    def set_onboarding_state(session_id: str, state: str, hint: str = "") -> None:
        with db() as connection:
            connection.execute(
                "UPDATE onboarding_sessions SET state=?,error_code=?,updated_at=? WHERE id=? "
                "AND state NOT IN ('completed','failed','expired','cancelled')",
                (state, hint[:120], datetime.now(timezone.utc).isoformat(), session_id),
            )

    async def run_onboarding_auth(session_id: str, invite_link: str) -> None:
        runtime = app.state.onboarding_flows.get(session_id)
        if runtime is None:
            return
        vault = EncryptedSessionFile(runtime["account_id"], generation=runtime["session_generation"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
        adapter = None
        lock = account_session_locks.for_account(runtime["account_id"])
        stage = "session_open"
        stage_started = perf_counter()
        lock_acquired = False
        try:
            await lock.acquire()
            lock_acquired = True
            with db() as connection:
                current = connection.execute(
                    "SELECT s.state,a.status,pa.proxy_id,p.enabled,p.check_status FROM onboarding_sessions s "
                    "JOIN accounts a ON a.id=s.account_id LEFT JOIN proxy_assignments pa ON pa.account_id=a.id "
                    "LEFT JOIN proxies p ON p.id=pa.proxy_id WHERE s.id=?",
                    (session_id,),
                ).fetchone()
            if current is None or current["state"] in terminal_onboarding_states:
                return
            if current["proxy_id"] != runtime["proxy_id"] or current["enabled"] != 1:
                raise RuntimeError("proxy_assignment_changed")
            if current["check_status"] != "healthy":
                raise RuntimeError("proxy_check_failed" if current["check_status"] == "failed" else "proxy_not_healthy")
            logger.info("onboarding_stage session_id=%s account_id=%s proxy_id=%s stage=%s", session_id, runtime["account_id"], runtime["proxy_id"], stage)
            adapter = PyMaxAdapter.create(phone=runtime["phone"], work_dir="", session_name="", proxy=runtime["proxy"], auth_flow=runtime["flow"], session_vault=vault)
            logger.info("onboarding_stage session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d", session_id, runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
            stage = "connect"
            stage_started = perf_counter()
            await adapter.connect()
            logger.info("onboarding_stage session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d", session_id, runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
            runtime["flow"].validate_proxy()
            stage = "resolve_group"
            stage_started = perf_counter()
            profile = getattr(adapter.client, "me", None)
            contact = getattr(profile, "contact", None)
            max_user_id = str(getattr(contact, "id", "") or getattr(profile, "id", ""))
            if not max_user_id:
                raise RuntimeError("max_user_id_missing")
            runtime["flow"].validate_proxy()
            resolved = await adapter.resolve_group_by_link(invite_link)
            logger.info("onboarding_stage session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d", session_id, runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
            chat_id = str(getattr(resolved, "id", "") or getattr(resolved, "chat_id", ""))
            if not chat_id:
                raise RuntimeError("group_resolution_failed")
            stage = "auto_join"
            stage_started = perf_counter()
            joined, join_error = await join_group_and_confirm_membership(
                adapter,
                invite_link,
                chat_id,
                before_action=runtime["flow"].validate_proxy,
            )
            logger.info(
                "onboarding_stage session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d joined=%s error_code=%s",
                session_id, runtime["account_id"], runtime["proxy_id"], stage,
                int((perf_counter() - stage_started) * 1000), joined, join_error or "none",
            )
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    "SELECT s.state,s.expires_at,s.token_hash AS session_token_hash,i.active,i.expires_at AS invite_expires_at,"
                    "i.token_hash AS invite_token_hash,a.status AS account_status,pa.proxy_id AS assigned_proxy_id,"
                    "p.enabled AS assigned_proxy_enabled,p.check_status AS assigned_proxy_check_status "
                    "FROM onboarding_sessions s JOIN onboarding_invites i ON i.id=s.invite_id "
                    "JOIN accounts a ON a.id=s.account_id LEFT JOIN proxy_assignments pa ON pa.account_id=a.id "
                    "LEFT JOIN proxies p ON p.id=pa.proxy_id WHERE s.id=?",
                    (session_id,),
                ).fetchone()
                now = datetime.now(timezone.utc).isoformat()
                if (current is None or current["state"] in terminal_onboarding_states or current["expires_at"] <= now
                        or not current["active"] or current["session_token_hash"] != current["invite_token_hash"]
                        or current["invite_expires_at"] <= now or current["account_status"] != "pending"
                        or current["assigned_proxy_id"] != runtime["proxy_id"] or current["assigned_proxy_enabled"] != 1
                        or current["assigned_proxy_check_status"] != "healthy"):
                    connection.rollback()
                    if current is not None and current["assigned_proxy_check_status"] != "healthy":
                        raise RuntimeError("proxy_check_failed" if current["assigned_proxy_check_status"] == "failed" else "proxy_not_healthy")
                    if current is not None and (current["assigned_proxy_id"] != runtime["proxy_id"] or current["assigned_proxy_enabled"] != 1):
                        raise RuntimeError("proxy_assignment_changed")
                    raise RuntimeError("invite_unavailable")
                attach_group_on_first_account(connection, runtime["group_id"], chat_id)
                connection.execute("UPDATE accounts SET max_user_id=?,status=? WHERE id=?", (max_user_id, "active" if joined else "pending", runtime["account_id"]))
                connection.execute(
                    "UPDATE onboarding_sessions SET state=?,error_code=?,max_user_id=?,updated_at=? WHERE id=?",
                    ("completed" if joined else "waiting_membership", join_error, max_user_id, now, session_id),
                )
                connection.commit()
        except Exception as exc:
            waiting_for = getattr(runtime["flow"], "waiting_for", None)
            auth_stage = getattr(runtime["flow"], "current_stage", None)
            if stage == "connect" and auth_stage:
                stage = auth_stage
            if isinstance(exc, TimeoutError):
                safe = f"{waiting_for}_entry_timeout" if waiting_for else "network_timeout"
            elif type(exc).__name__ == "ApiError" and auth_stage == "send_code":
                safe = "code_rejected"
            elif type(exc).__name__ == "ApiError" and auth_stage == "check_password":
                safe = "password_rejected"
            elif type(exc).__name__ == "ApiError" and auth_stage == "request_code":
                safe = "max_auth_request_failed"
            elif str(exc) in {"group_destination_mismatch", "max_user_id_missing", "group_resolution_failed", "account_registration_required", "cloud_password_rejected", "invite_unavailable", "proxy_assignment_changed", "proxy_check_failed", "proxy_not_healthy"}:
                safe = str(exc)
            else:
                safe = type(exc).__name__.lower()
            logger.warning("onboarding_failed session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d error_class=%s", session_id, runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000), type(exc).__name__)
            set_onboarding_state(session_id, "failed", safe)
        finally:
            try:
                if adapter is not None:
                    try:
                        stage = "session_close_seal"
                        stage_started = perf_counter()
                        await adapter.close()
                        logger.info("onboarding_stage session_id=%s account_id=%s proxy_id=%s stage=%s duration_ms=%d", session_id, runtime["account_id"], runtime["proxy_id"], stage, int((perf_counter() - stage_started) * 1000))
                    except Exception:
                        logger.warning("onboarding_failed session_id=%s account_id=%s proxy_id=%s stage=session_close_seal error_class=SessionSaveError", session_id, runtime["account_id"], runtime["proxy_id"])
                        set_onboarding_state(session_id, "failed", "session_save_failed")
            finally:
                if lock_acquired:
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
        attempt = guest_onboarding_session(token, session_id)
        runtime = app.state.onboarding_flows.get(session_id)
        if attempt["state"] in {"expired", "cancelled"}:
            raise HTTPException(410, str(attempt["error_code"] or "onboarding_session_unavailable"))
        if runtime is None or attempt["state"] != "waiting_code":
            raise HTTPException(409, "onboarding_session_not_waiting_for_code")
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
        attempt = guest_onboarding_session(token, session_id)
        runtime = app.state.onboarding_flows.get(session_id)
        if attempt["state"] in {"expired", "cancelled"}:
            raise HTTPException(410, str(attempt["error_code"] or "onboarding_session_unavailable"))
        if runtime is None or attempt["state"] != "waiting_password":
            raise HTTPException(409, "onboarding_session_not_waiting_for_password")
        if not password or len(password) > 256:
            raise HTTPException(422, "invalid_password")
        if runtime["flow"].passwords.full():
            runtime["flow"].passwords.get_nowait()
        runtime["flow"].passwords.put_nowait(password)
        return {"state": "verifying_password"}

    @app.get("/api/public/onboarding/{token}/{session_id}")
    def onboarding_status(token: str, session_id: str) -> dict[str, object]:
        row = guest_onboarding_session(token, session_id)
        flow = app.state.onboarding_flows.get(session_id, {}).get("flow")
        return {
            "state": row["state"],
            "hint": flow_hint(flow),
            "error": row["error_code"] or "",
            "expires_at": row["expires_at"],
            "retryable": row["retryable"],
            "retry_after_seconds": None,
            "request_count_left": getattr(flow, "request_count_left", None),
            "code_length": getattr(flow, "code_length", None),
        }

    @app.post("/api/public/onboarding/{token}/{session_id}/cancel")
    async def onboarding_cancel(token: str, session_id: str, request: Request) -> dict[str, str]:
        _require_same_origin(request)
        attempt = guest_onboarding_session(token, session_id)
        if attempt["state"] == "completed":
            raise HTTPException(409, "onboarding_already_completed")
        if attempt["state"] not in terminal_onboarding_states:
            cancel_onboarding(session_id, "cancelled", "cancelled_by_guest")
        return {"state": "cancelled"}

    def flow_hint(flow) -> str:
        return str(getattr(flow, "hint", "") or "")

    @app.post("/api/public/onboarding/{token}/{session_id}/check-membership")
    async def onboarding_check_membership(token: str, session_id: str, request: Request) -> dict[str, bool]:
        _require_same_origin(request)
        remote = request.client.host if request.client else "unknown"
        if rate_limited(f"guest-membership:{digest_token(remote)}:{digest_token(session_id)}", 12, 900):
            raise HTTPException(429, "membership_check_rate_limited")
        attempt = guest_onboarding_session(token, session_id)
        if attempt["state"] in {"expired", "cancelled"}:
            raise HTTPException(410, str(attempt["error_code"] or "onboarding_session_unavailable"))
        with db() as connection:
            row = connection.execute(
                "SELECT s.*,a.group_id,a.phone,a.session_generation,g.chat_id,pa.proxy_id,p.url_ciphertext,p.check_status FROM onboarding_sessions s "
                "JOIN accounts a ON a.id=s.account_id JOIN groups g ON g.id=a.group_id "
                "JOIN proxy_assignments pa ON pa.account_id=a.id JOIN proxies p ON p.id=pa.proxy_id AND p.enabled=1 WHERE s.id=?",
                (session_id,),
            ).fetchone()
        if row is None or row["token_hash"] != digest_token(token) or row["state"] != "waiting_membership" or not row["chat_id"]:
            raise HTTPException(404, "onboarding_session_unavailable")
        if row["check_status"] != "healthy":
            raise HTTPException(409, "proxy_check_failed" if row["check_status"] == "failed" else "proxy_not_healthy")
        lock = account_session_locks.for_account(row["account_id"])
        adapter = None
        await lock.acquire()

        def current_membership_proxy_url() -> str:
            with db() as connection:
                current_proxy = connection.execute(
                    "SELECT pa.proxy_id,p.enabled,p.group_id,p.url_ciphertext,p.check_status "
                    "FROM proxy_assignments pa JOIN proxies p ON p.id=pa.proxy_id WHERE pa.account_id=?",
                    (row["account_id"],),
                ).fetchone()
            if (current_proxy is None or int(current_proxy["proxy_id"]) != int(row["proxy_id"])
                    or int(current_proxy["enabled"]) != 1 or int(current_proxy["group_id"]) != int(row["group_id"])):
                raise HTTPException(409, "account_assignment_changed_during_verification")
            if current_proxy["check_status"] != "healthy":
                raise HTTPException(409, "proxy_check_failed" if current_proxy["check_status"] == "failed" else "proxy_not_healthy")
            try:
                return SecretBox().decrypt(current_proxy["url_ciphertext"])
            except ValueError as exc:
                raise HTTPException(503, "proxy_unavailable") from exc

        try:
            proxy_url = current_membership_proxy_url()
            vault = EncryptedSessionFile(row["account_id"], generation=row["session_generation"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
            adapter = PyMaxAdapter.create(phone=row["phone"], work_dir="", session_name="", proxy=proxy_url, session_vault=vault)
            await adapter.connect()
            if current_membership_proxy_url() != proxy_url:
                raise HTTPException(409, "account_assignment_changed_during_verification")
            chat = await adapter.get_chat(int(row["chat_id"]))
            joined = member_proof(chat, str(row["chat_id"]))
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, "membership_check_unavailable") from exc
        finally:
            try:
                if adapter is not None:
                    try:
                        await adapter.close()
                    except Exception as exc:
                        logger.error(
                            "membership_check_session_close_failed account_id=%s error_class=%s",
                            row["account_id"], type(exc).__name__,
                        )
                        raise HTTPException(503, "session_save_failed") from exc
            finally:
                lock.release()
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT s.state,s.expires_at,s.token_hash AS session_token_hash,i.active,"
                "i.expires_at AS invite_expires_at,i.token_hash AS invite_token_hash,a.group_id,a.status AS account_status,"
                "g.chat_id,pa.proxy_id AS assigned_proxy_id,p.enabled AS assigned_proxy_enabled,p.check_status AS assigned_proxy_check_status "
                "FROM onboarding_sessions s JOIN onboarding_invites i ON i.id=s.invite_id "
                "JOIN accounts a ON a.id=s.account_id JOIN groups g ON g.id=a.group_id "
                "LEFT JOIN proxy_assignments pa ON pa.account_id=a.id LEFT JOIN proxies p ON p.id=pa.proxy_id "
                "WHERE s.id=?",
                (session_id,),
            ).fetchone()
            now = datetime.now(timezone.utc).isoformat()
            if (current is None or current["state"] != "waiting_membership" or current["expires_at"] <= now
                    or not current["active"] or current["session_token_hash"] != current["invite_token_hash"]
                    or current["invite_expires_at"] <= now):
                connection.rollback()
                raise HTTPException(410, "onboarding_session_unavailable")
            if (int(current["group_id"]) != int(row["group_id"]) or str(current["chat_id"] or "") != str(row["chat_id"])
                    or current["account_status"] != "pending"):
                connection.rollback()
                raise HTTPException(409, "group_invite_changed_during_verification")
            if current["assigned_proxy_id"] != row["proxy_id"] or current["assigned_proxy_enabled"] != 1:
                connection.rollback()
                raise HTTPException(409, "account_assignment_changed_during_verification")
            if current["assigned_proxy_check_status"] != "healthy":
                connection.rollback()
                raise HTTPException(
                    409,
                    "proxy_check_failed" if current["assigned_proxy_check_status"] == "failed" else "proxy_not_healthy",
                )
            if joined:
                connection.execute("UPDATE accounts SET status='active' WHERE id=?", (row["account_id"],))
                connection.execute("UPDATE onboarding_sessions SET state='completed',updated_at=? WHERE id=?", (now, session_id))
            connection.commit()
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
        cancelled_sessions: list[str] = []
        with db() as connection:
            old = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            if old is None:
                raise HTTPException(404, "group_not_found")
            changed = old["invite_link"] != body.invite_link
            connection.execute("UPDATE groups SET name=?,invite_link=?,chat_id=CASE WHEN ? THEN NULL ELSE chat_id END WHERE id=?", (body.name.strip(), body.invite_link.strip(), int(changed), group_id))
            if changed:
                connection.execute("UPDATE onboarding_invites SET active=0 WHERE group_id=?", (group_id,))
                cancelled_sessions = cancel_group_onboarding(connection, group_id, "invite_unavailable")
                connection.execute("UPDATE accounts SET status='needs_membership' WHERE group_id=? AND status='active'", (group_id,))
                connection.execute("UPDATE weekly_slots SET status='blocked',error_code='destination_unverified',updated_at=CURRENT_TIMESTAMP WHERE group_id=? AND status='queued'", (group_id,))
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,detail) VALUES(CURRENT_TIMESTAMP,?,?,?)", ("group_destination_changed" if changed else "group_updated", group_id, "{}"))
            row = connection.execute("SELECT id,name,chat_id,active FROM groups WHERE id=?", (group_id,)).fetchone()
        cancel_onboarding_tasks(cancelled_sessions)
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
                "SELECT a.id,a.full_name,a.status,a.send_weekday,pa.proxy_id,p.label AS proxy_label,p.enabled AS proxy_enabled,p.check_status AS proxy_check_status,"
                "s.scheduled_date,s.status AS slot_status,s.error_code,"
                "(SELECT os.state FROM onboarding_sessions os WHERE os.account_id=a.id ORDER BY os.created_at DESC LIMIT 1) AS onboarding_state,"
                "(SELECT os.error_code FROM onboarding_sessions os WHERE os.account_id=a.id ORDER BY os.created_at DESC LIMIT 1) AS onboarding_error "
                "FROM accounts a "
                "LEFT JOIN proxy_assignments pa ON pa.account_id=a.id LEFT JOIN proxies p ON p.id=pa.proxy_id "
                "LEFT JOIN weekly_slots s ON s.account_id=a.id AND s.week_start=? "
                "WHERE a.group_id=? AND a.status!='removed' ORDER BY a.id",
                (week_start, group_id),
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/groups/{group_id}/verify-destination")
    async def verify_destination(group_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        used_proxy_ids: dict[int, int] = {}
        with db() as connection:
            group = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            accounts = connection.execute(
                "SELECT a.id,a.phone,a.session_generation,p.id AS proxy_id,p.url_ciphertext,p.check_status FROM accounts a JOIN proxy_assignments pa ON pa.account_id=a.id "
                "JOIN proxies p ON p.id=pa.proxy_id WHERE a.group_id=? AND a.status IN ('active','needs_membership') AND p.enabled=1 AND p.check_status='healthy' ORDER BY a.id",
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
            close_failed = False
            failure_code = None
            failure = None
            failure_response: HTTPException | None = None
            stage = "resolve_group" if index == 0 else "check_membership"
            lock = account_session_locks.for_account(account["id"])
            await lock.acquire()

            def validate_current_proxy() -> None:
                with db() as connection:
                    current = connection.execute(
                        "SELECT a.status,pa.proxy_id,p.enabled,p.check_status FROM accounts a "
                        "JOIN proxy_assignments pa ON pa.account_id=a.id JOIN proxies p ON p.id=pa.proxy_id "
                        "WHERE a.id=? AND a.group_id=?",
                        (account["id"], group_id),
                    ).fetchone()
                if (current is None or current["status"] not in {"active", "needs_membership"}
                        or int(current["proxy_id"]) != int(account["proxy_id"])):
                    raise HTTPException(409, "account_assignment_changed_during_verification")
                if not current["enabled"]:
                    raise HTTPException(409, "proxy_disabled")
                if current["check_status"] != "healthy":
                    raise HTTPException(409, "proxy_check_failed" if current["check_status"] == "failed" else "proxy_not_healthy")

            try:
                validate_current_proxy()
                proxy = SecretBox().decrypt(account["url_ciphertext"])
                vault = EncryptedSessionFile(account["id"], generation=account["session_generation"], durable_dir=sessions_dir, runtime_dir=runtime_dir)
                adapter = PyMaxAdapter.create(phone=account["phone"], work_dir="", session_name="", proxy=proxy, session_vault=vault)
                validate_current_proxy()
                await adapter.connect()
                if index == 0:
                    validate_current_proxy()
                    resolved = await adapter.resolve_group_by_link(group["invite_link"])
                    chat_id = str(getattr(resolved, "id", "") or getattr(resolved, "chat_id", ""))
                    if not chat_id:
                        raise RuntimeError("group_resolution_failed")
                    stage = "check_membership"
                validate_current_proxy()
                states[int(account["id"])] = member_proof(await adapter.get_chat(int(chat_id)), chat_id)
            except Exception as exc:
                if isinstance(exc, HTTPException):
                    failure_response = exc
                else:
                    failure_code = "group_resolution_failed" if stage == "resolve_group" else "membership_check_unavailable"
                    failure = exc
            finally:
                if adapter is not None:
                    try:
                        await adapter.close()
                    except Exception as exc:
                        close_failed = True
                        logger.error("destination_verification_session_close_failed account_id=%s error_class=%s", account["id"], type(exc).__name__)
                lock.release()
            if close_failed:
                raise HTTPException(503, "session_save_failed")
            if failure_response is not None:
                raise failure_response
            if failure_code:
                raise HTTPException(503, failure_code) from failure
            used_proxy_ids[int(account["id"])] = int(account["proxy_id"])
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            if current is None or current["invite_link"] != group["invite_link"]:
                connection.rollback()
                raise HTTPException(409, "group_invite_changed_during_verification")
            for account_id in states:
                assignment = connection.execute(
                    "SELECT a.status,pa.proxy_id,p.enabled,p.check_status FROM accounts a JOIN proxy_assignments pa ON pa.account_id=a.id "
                    "JOIN proxies p ON p.id=pa.proxy_id WHERE a.id=? AND a.group_id=?",
                    (account_id, group_id),
                ).fetchone()
                if assignment is not None and assignment["check_status"] != "healthy":
                    connection.rollback()
                    raise HTTPException(409, "proxy_check_failed" if assignment["check_status"] == "failed" else "proxy_not_healthy")
                if (assignment is None or assignment["status"] not in {"active", "needs_membership"}
                        or not assignment["enabled"] or int(assignment["proxy_id"]) != used_proxy_ids[account_id]):
                    connection.rollback()
                    raise HTTPException(409, "account_assignment_changed_during_verification")
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
            account = connection.execute("SELECT group_id,status FROM accounts WHERE id=?", (account_id,)).fetchone()
            proxy = connection.execute("SELECT id,group_id,label,enabled,check_status FROM proxies WHERE id=?", (body.proxy_id,)).fetchone()
            if account is None or proxy is None:
                connection.rollback()
                raise HTTPException(404, "account_or_proxy_not_found")
            if account["status"] == "removed":
                connection.rollback()
                raise HTTPException(404, "account_not_found")
            if int(account["group_id"]) != int(proxy["group_id"]) or not int(proxy["enabled"]):
                connection.rollback()
                raise HTTPException(422, "proxy_group_mismatch_or_disabled")
            if proxy["check_status"] != "healthy":
                connection.rollback()
                raise HTTPException(422, "proxy_not_healthy")
            connection.execute("INSERT INTO proxy_assignments(account_id,proxy_id) VALUES(?,?) ON CONFLICT(account_id) DO UPDATE SET proxy_id=excluded.proxy_id,assigned_at=CURRENT_TIMESTAMP", (account_id, body.proxy_id))
            timezone_row = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
            from zoneinfo import ZoneInfo
            today = datetime.now(ZoneInfo(timezone_row[0] if timezone_row else "Europe/Moscow")).date().isoformat()
            connection.execute(
                "UPDATE weekly_slots SET status=CASE WHEN scheduled_date>=? THEN 'queued' ELSE 'missed' END,"
                "error_code=NULL,updated_at=? WHERE account_id=? AND status='blocked' AND error_code IN ('proxy_assignment_unavailable','proxy_check_failed')",
                (today, datetime.now(timezone.utc).isoformat(), account_id),
            )
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,account_id,detail) VALUES(CURRENT_TIMESTAMP,'proxy_reassigned',?,?,?)", (account["group_id"], account_id, "{}"))
            connection.commit()
        return {"proxy_id": proxy["id"], "proxy_label": proxy["label"]}

    @app.delete("/api/accounts/{account_id}")
    async def remove_account(account_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            account = connection.execute("SELECT id,status FROM accounts WHERE id=?", (account_id,)).fetchone()
            if account is None or account["status"] == "removed":
                connection.rollback()
                raise HTTPException(404, "account_not_found")
            unresolved = connection.execute(
                "SELECT 1 FROM operations WHERE account_id=? AND status IN ('in_flight','unknown') LIMIT 1",
                (account_id,),
            ).fetchone()
            if unresolved is not None:
                connection.rollback()
                raise HTTPException(409, "account_has_unresolved_operation")
            connection.execute("UPDATE accounts SET status='removing' WHERE id=?", (account_id,))
            session_ids = [row[0] for row in connection.execute(
                "SELECT id FROM onboarding_sessions WHERE account_id=? AND state NOT IN ('completed','failed','expired','cancelled')",
                (account_id,),
            ).fetchall()]
            if session_ids:
                connection.execute(
                    "UPDATE onboarding_sessions SET state='cancelled',error_code='account_removed',updated_at=? "
                    "WHERE id IN (" + ",".join("?" for _ in session_ids) + ")",
                    (datetime.now(timezone.utc).isoformat(), *session_ids),
                )
            connection.commit()
        cancel_onboarding_tasks(session_ids)
        pending_tasks = [app.state.onboarding_tasks[session_id] for session_id in session_ids if session_id in app.state.onboarding_tasks]
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)

        lock = account_session_locks.for_account(account_id)
        await lock.acquire()
        try:
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute("SELECT id,status FROM accounts WHERE id=?", (account_id,)).fetchone()
                if current is None:
                    connection.rollback()
                    raise HTTPException(404, "account_not_found")
                if current["status"] != "removed":
                    unresolved = connection.execute(
                        "SELECT 1 FROM operations WHERE account_id=? AND status IN ('in_flight','unknown') LIMIT 1",
                        (account_id,),
                    ).fetchone()
                    if unresolved is not None:
                        connection.rollback()
                        raise HTTPException(409, "account_has_unresolved_operation")
                    now = datetime.now(timezone.utc).isoformat()
                    connection.execute(
                        "UPDATE accounts SET status='removed',max_user_id=NULL,session_generation=session_generation+1 WHERE id=?",
                        (account_id,),
                    )
                    connection.execute("DELETE FROM proxy_assignments WHERE account_id=?", (account_id,))
                    connection.execute(
                        "UPDATE weekly_slots SET status='blocked',error_code='account_removed',updated_at=? "
                        "WHERE account_id=? AND status='queued'",
                        (now, account_id),
                    )
                    connection.execute(
                        "INSERT INTO audit_log(created_at,kind,group_id,account_id,detail) "
                        "SELECT ?, 'account_removed', group_id, id, '{}' FROM accounts WHERE id=?",
                        (now, account_id),
                    )
                    connection.commit()
        finally:
            lock.release()
        for session_id in session_ids:
            app.state.onboarding_flows.pop(session_id, None)
        return {"account_id": account_id, "status": "removed"}

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
