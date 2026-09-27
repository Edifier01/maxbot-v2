from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sqlite3
import sys
import time
from time import perf_counter
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import connect, initialize
from .security import digest_token as _digest_token, new_token, password_matches
from .crypto import SecretBox
from .message_pool import replace_message_pool
from .onboarding import WebAuthProviders, attach_group_on_first_account, join_group_and_confirm_membership, member_proof, normalize_russian_phone, prepare_account
from .max_adapter import PyMaxAdapter
from .egress import assign_ip, assigned_ip, bootstrap_ips, enable_ip, host_addresses, refresh_ips, allowed_address
from .session_vault import EncryptedSessionFile
from .workers import GroupWorkerManager, _inside_window
from .sender import DispatchPaused, recover_in_flight
from .session_lock import AccountSessionLocks


logger = logging.getLogger(__name__)
project_logger = logging.getLogger("maxbot_v2")
project_logger.setLevel(os.getenv("APP_LOG_LEVEL", "INFO").upper())
diagnostic_handler = logging.StreamHandler(sys.__stderr__ or sys.stderr)
diagnostic_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
project_logger.addHandler(diagnostic_handler)
project_logger.propagate = False


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


class IPStateBody(BaseModel):
    enabled: bool


class IPAssignmentBody(BaseModel):
    ip_id: int = Field(gt=0)


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
    terminal_onboarding_states = ("completed", "failed", "expired", "cancelled")

    def session_vault_for(account_id: int) -> EncryptedSessionFile:
        with db() as connection:
            row = connection.execute("SELECT session_generation FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row is None:
            raise ValueError("account_not_found")
        return EncryptedSessionFile(account_id, generation=row["session_generation"], durable_dir=sessions_dir, runtime_dir=runtime_dir)

    class LockedAdapter:
        def __init__(self, adapter, lock: asyncio.Lock, ip_id: int, address: str):
            self._adapter = adapter
            self._lock = lock
            self.ip_id = ip_id
            self.address = address
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
                "SELECT a.phone,p.id AS ip_id,p.address FROM accounts a JOIN ip_assignments ia ON ia.account_id=a.id "
                "JOIN server_ips p ON p.id=ia.ip_id WHERE a.id=? AND p.enabled=1 AND p.available=1",
                (slot["account_id"],),
            ).fetchone()
        if row is None or not allowed_address(row["address"]) or row["address"] not in host_addresses():
            raise DispatchPaused("ip_assignment_unavailable", blocked=True)
        vault = session_vault_for(slot["account_id"])
        lock = account_session_locks.for_account(slot["account_id"])
        await lock.acquire()
        adapter = None
        try:
            def require_same_ip() -> None:
                with db() as connection:
                    current = connection.execute(
                        "SELECT ia.ip_id,p.address,p.enabled,p.available FROM ip_assignments ia "
                        "JOIN server_ips p ON p.id=ia.ip_id WHERE ia.account_id=?",
                        (slot["account_id"],),
                    ).fetchone()
                if (current is None or not current["enabled"] or not current["available"]
                        or int(current["ip_id"]) != int(row["ip_id"]) or current["address"] != row["address"]
                        or row["address"] not in host_addresses()):
                    raise DispatchPaused("ip_assignment_changed")

            require_same_ip()
            adapter = PyMaxAdapter.create(phone=row["phone"], source_ip=row["address"], session_vault=vault)
            await adapter.connect()
            require_same_ip()
            return LockedAdapter(adapter, lock, int(row["ip_id"]), row["address"])
        except BaseException:
            try:
                if adapter is not None:
                    try:
                        await adapter.close()
                    except Exception as exc:
                        logger.warning("session_close_failed account_id=%s ip_id=%s error_class=%s", slot["account_id"], row["ip_id"], type(exc).__name__)
            finally:
                lock.release()
            raise

    worker_manager = GroupWorkerManager(database, scheduled_provider)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        with db() as connection:
            bootstrap_ips(connection)
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

    @app.exception_handler(RequestValidationError)
    async def safe_validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "invalid_request"})
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
            counts = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("groups", "accounts", "weekly_slots")
            }
            settings = dict(connection.execute("SELECT key,value FROM settings").fetchall())
            active_groups = connection.execute("SELECT COUNT(*) FROM groups WHERE active=1").fetchone()[0]
            ready_accounts = connection.execute(
                "SELECT COUNT(*) FROM accounts a JOIN groups g ON g.id=a.group_id "
                "JOIN ip_assignments ia ON ia.account_id=a.id JOIN server_ips p ON p.id=ia.ip_id "
                "WHERE a.status='active' AND g.active=1 AND g.chat_id IS NOT NULL AND p.enabled=1 AND p.available=1"
            ).fetchone()[0]
        stopped = settings.get("global_stop") == "1"
        if stopped:
            wait_reason = "Работа сейчас остановлена. Запустите её кнопкой вверху панели."
        elif not active_groups:
            wait_reason = "Нет включённых групп. Запуск не отправит сообщения, пока группу не включат."
        elif not ready_accounts:
            wait_reason = "Нет подключённых аккаунтов с проверенной группой и доступным IP VDS."
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
                "SELECT g.id,g.name,g.invite_link,g.chat_id,g.active,COUNT(DISTINCT a.id) account_count,"
                "COUNT(DISTINCT CASE WHEN a.status='active' THEN a.id END) connected_account_count,"
                "COUNT(DISTINCT CASE WHEN a.status IN ('active','needs_membership') AND EXISTS ("
                "SELECT 1 FROM ip_assignments ia JOIN server_ips assigned_ip ON assigned_ip.id=ia.ip_id "
                "WHERE ia.account_id=a.id AND assigned_ip.enabled=1 AND assigned_ip.available=1) THEN a.id END) verifiable_account_count "
                "FROM groups g LEFT JOIN accounts a ON a.group_id=g.id "
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

    @app.get("/api/ips")
    def list_ips(_session: sqlite3.Row = Depends(current_session)) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                "SELECT p.id,p.address,p.enabled,p.available,p.last_checked_at,"
                "COUNT(ia.account_id) AS assigned_count FROM server_ips p "
                "LEFT JOIN ip_assignments ia ON ia.ip_id=p.id GROUP BY p.id ORDER BY p.id"
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/ips/refresh")
    def refresh_server_ips(_session: sqlite3.Row = Depends(require_csrf)) -> list[dict[str, object]]:
        with db() as connection:
            rows = refresh_ips(connection)
        return rows

    @app.patch("/api/ips/{ip_id}")
    def set_ip_state(ip_id: int, body: IPStateBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                enable_ip(connection, ip_id, body.enabled)
            except ValueError as exc:
                connection.rollback()
                raise HTTPException(409, str(exc)) from exc
            if not body.enabled:
                connection.execute(
                    "UPDATE weekly_slots SET status='blocked',error_code='ip_assignment_unavailable',updated_at=? "
                    "WHERE account_id IN (SELECT account_id FROM ip_assignments WHERE ip_id=?) AND status='queued'",
                    (datetime.now(timezone.utc).isoformat(), ip_id),
                )
            else:
                from zoneinfo import ZoneInfo
                tzrow = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
                today = datetime.now(ZoneInfo(tzrow[0] if tzrow else "Europe/Moscow")).date().isoformat()
                connection.execute(
                    "UPDATE weekly_slots SET status=CASE WHEN scheduled_date>=? THEN 'queued' ELSE 'missed' END,"
                    "error_code=NULL,updated_at=? WHERE account_id IN "
                    "(SELECT account_id FROM ip_assignments WHERE ip_id=?) AND status='blocked' "
                    "AND error_code='ip_assignment_unavailable'",
                    (today, datetime.now(timezone.utc).isoformat(), ip_id),
                )
            connection.commit()
        return {"id": ip_id, "enabled": body.enabled}

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
        if not full_name:
            raise HTTPException(422, "invalid_name_or_phone")
        try:
            phone = normalize_russian_phone(str(payload.get("phone", "")))
        except ValueError as exc:
            raise HTTPException(422, "invalid_russian_phone") from exc
        row = invite_row(None, token)
        session_id = new_token(16)
        now = datetime.now(timezone.utc).isoformat()
        expired_session_ids: list[str] = []
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
                if connection.execute("SELECT 1 FROM server_ips WHERE enabled=1 AND available=1 LIMIT 1").fetchone() is None:
                    connection.rollback()
                    raise HTTPException(409, "ip_assignment_required")
                expired_session_ids = [old[0] for old in connection.execute(
                    "SELECT id FROM onboarding_sessions WHERE state NOT IN ('completed','failed','expired','cancelled') AND expires_at<=?",
                    (now,),
                ).fetchall()]
                connection.execute(
                    "UPDATE onboarding_sessions SET state='expired',error_code='onboarding_attempt_expired',updated_at=? "
                    "WHERE state NOT IN ('completed','failed','expired','cancelled') AND expires_at<=?",
                    (now, now),
                )
                active_uses = connection.execute(
                    "SELECT COUNT(*) FROM onboarding_sessions WHERE invite_id=? AND token_hash=? "
                    "AND state NOT IN ('failed','expired','cancelled')",
                    (row["id"], digest_token(token)),
                ).fetchone()[0]
                if current_invite["max_uses"] is not None and active_uses >= current_invite["max_uses"]:
                    connection.rollback()
                    raise HTTPException(404, "invite_unavailable")
                matches = []
                for candidate in connection.execute("SELECT id,group_id,status,phone FROM accounts"):
                    old_phone = str(candidate["phone"] or "")
                    try:
                        canonical = normalize_russian_phone(old_phone.removeprefix("+8") if old_phone.startswith("+8") else old_phone)
                    except ValueError:
                        continue
                    if canonical == phone:
                        matches.append(candidate)
                if len(matches) > 1:
                    connection.rollback()
                    raise HTTPException(409, "phone_already_exists")
                existing = matches[0] if matches else None
                if existing is None:
                    account_id, ip_id = prepare_account(connection, group_id=row["group_id"], phone=phone, full_name=full_name)
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
                    try:
                        address = assign_ip(connection, existing["id"])
                    except ValueError as exc:
                        connection.rollback()
                        raise HTTPException(409, "ip_assignment_unavailable") from exc
                    account_id = existing["id"]
                    ip_id = connection.execute("SELECT id FROM server_ips WHERE address=?", (address,)).fetchone()["id"]
                    connection.execute("UPDATE accounts SET full_name=?,phone=? WHERE id=?", (full_name, phone, account_id))
                ip_row = connection.execute("SELECT address FROM server_ips WHERE id=? AND enabled=1 AND available=1", (ip_id,)).fetchone()
                if ip_row is None or not allowed_address(ip_row["address"]) or ip_row["address"] not in host_addresses():
                    connection.rollback()
                    raise HTTPException(409, "ip_assignment_unavailable")
                source_ip = ip_row["address"]
                connection.execute(
                    "INSERT INTO onboarding_sessions(id,invite_id,token_hash,csrf_hash,phone,full_name,state,account_id,ip_id,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,?,?,?,?)",
                    (session_id, row["id"], digest_token(token), digest_token(new_token()), phone, full_name, "starting", account_id, ip_id, (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(), now, now),
                )
                connection.execute("UPDATE onboarding_invites SET uses_count=? WHERE id=?", (active_uses + 1, row["id"]))
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "phone_already_exists") from exc
        cancel_onboarding_tasks(expired_session_ids)

        def validate_onboarding_ip() -> None:
            with db() as connection:
                current = assigned_ip(connection, account_id)
            if current != (ip_id, source_ip) or source_ip not in host_addresses():
                raise RuntimeError("ip_assignment_changed")

        flow = WebAuthProviders(
            lambda state, hint: set_onboarding_state(session_id, state, hint),
            account_id=account_id, ip_id=ip_id, session_id=session_id,
        )
        app.state.onboarding_flows[session_id] = {"flow": flow, "account_id": account_id, "ip_id": ip_id, "group_id": row["group_id"], "phone": phone, "source_ip": source_ip, "validate_ip": validate_onboarding_ip}
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
        vault = session_vault_for(runtime["account_id"])
        adapter = None
        lock = account_session_locks.for_account(runtime["account_id"])
        stage = "session_open"
        stage_started = perf_counter()
        lock_acquired = False

        def validate_target(expected_chat_id: str | None = None) -> None:
            runtime["validate_ip"]()
            with db() as connection:
                current = connection.execute(
                    "SELECT s.state,s.expires_at,s.token_hash AS session_token_hash,i.active,i.expires_at AS invite_expires_at,"
                    "i.token_hash AS invite_token_hash,a.status AS account_status,g.invite_link,g.chat_id "
                    "FROM onboarding_sessions s JOIN onboarding_invites i ON i.id=s.invite_id "
                    "JOIN accounts a ON a.id=s.account_id JOIN groups g ON g.id=a.group_id WHERE s.id=?",
                    (session_id,),
                ).fetchone()
            now = datetime.now(timezone.utc).isoformat()
            if (current is None or current["state"] in terminal_onboarding_states or current["expires_at"] <= now
                    or not current["active"] or current["session_token_hash"] != current["invite_token_hash"]
                    or current["invite_expires_at"] <= now or current["account_status"] != "pending"
                    or current["invite_link"] != invite_link):
                raise RuntimeError("invite_unavailable")
            if current["chat_id"] and expected_chat_id and str(current["chat_id"]) != str(expected_chat_id):
                raise ValueError("group_destination_mismatch")

        try:
            await lock.acquire()
            lock_acquired = True
            validate_target()
            logger.info("onboarding_stage session_id=%s account_id=%s ip_id=%s stage=%s", session_id, runtime["account_id"], runtime["ip_id"], stage)
            adapter = PyMaxAdapter.create(phone=runtime["phone"], source_ip=runtime["source_ip"], code_provider=runtime["flow"], password_provider=runtime["flow"], session_vault=vault)
            logger.info("onboarding_stage session_id=%s account_id=%s ip_id=%s stage=%s duration_ms=%d", session_id, runtime["account_id"], runtime["ip_id"], stage, int((perf_counter() - stage_started) * 1000))
            stage = "connect"
            stage_started = perf_counter()
            await adapter.connect()
            validate_target()
            logger.info("onboarding_stage session_id=%s account_id=%s ip_id=%s stage=%s duration_ms=%d", session_id, runtime["account_id"], runtime["ip_id"], stage, int((perf_counter() - stage_started) * 1000))
            stage = "resolve_group"
            stage_started = perf_counter()
            profile = getattr(adapter.client, "me", None)
            contact = getattr(profile, "contact", None)
            max_user_id = str(getattr(contact, "id", "") or getattr(profile, "id", ""))
            if not max_user_id:
                raise RuntimeError("max_user_id_missing")
            validate_target()
            try:
                resolved = await adapter.resolve_group_by_link(invite_link)
                chat_id = str(getattr(resolved, "id", "") or getattr(resolved, "chat_id", ""))
            except Exception:
                chat_id = ""
            logger.info("onboarding_stage session_id=%s account_id=%s ip_id=%s stage=%s duration_ms=%d resolved=%s", session_id, runtime["account_id"], runtime["ip_id"], stage, int((perf_counter() - stage_started) * 1000), bool(chat_id))
            if chat_id:
                validate_target(chat_id)
                set_onboarding_state(session_id, "joining_group")
                stage = "join_group"
                stage_started = perf_counter()
                joined, join_error = await join_group_and_confirm_membership(
                    adapter, invite_link, chat_id, before_action=lambda: validate_target(chat_id),
                )
            else:
                joined, join_error = False, "group_resolution_failed"
            logger.info(
                "onboarding_stage session_id=%s account_id=%s ip_id=%s stage=%s duration_ms=%d membership_confirmed=%s",
                session_id, runtime["account_id"], runtime["ip_id"], stage,
                int((perf_counter() - stage_started) * 1000), joined,
            )
            validate_target(chat_id)
            stage = "session_close_seal"
            await adapter.close()
            adapter = None
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    "SELECT s.state,s.expires_at,s.token_hash AS session_token_hash,i.active,i.expires_at AS invite_expires_at,"
                    "i.token_hash AS invite_token_hash,a.status AS account_status,g.invite_link,g.chat_id,"
                    "ia.ip_id AS assigned_ip_id,p.enabled AS assigned_ip_enabled,p.available AS assigned_ip_available,p.address "
                    "FROM onboarding_sessions s JOIN onboarding_invites i ON i.id=s.invite_id "
                    "JOIN accounts a ON a.id=s.account_id JOIN groups g ON g.id=a.group_id "
                    "LEFT JOIN ip_assignments ia ON ia.account_id=a.id "
                    "LEFT JOIN server_ips p ON p.id=ia.ip_id WHERE s.id=?",
                    (session_id,),
                ).fetchone()
                now = datetime.now(timezone.utc).isoformat()
                if (current is None or current["state"] in terminal_onboarding_states or current["expires_at"] <= now
                        or not current["active"] or current["session_token_hash"] != current["invite_token_hash"]
                        or current["invite_expires_at"] <= now or current["account_status"] != "pending"
                        or current["invite_link"] != invite_link
                        or current["assigned_ip_id"] != runtime["ip_id"] or current["assigned_ip_enabled"] != 1
                        or current["assigned_ip_available"] != 1 or current["address"] != runtime["source_ip"]):
                    connection.rollback()
                    if current is not None and (current["assigned_ip_id"] != runtime["ip_id"] or current["assigned_ip_enabled"] != 1):
                        raise RuntimeError("ip_assignment_changed")
                    raise RuntimeError("invite_unavailable")
                runtime["validate_ip"]()
                if current["chat_id"] and chat_id and str(current["chat_id"]) != chat_id:
                    connection.rollback()
                    raise ValueError("group_destination_mismatch")
                if chat_id:
                    attach_group_on_first_account(connection, runtime["group_id"], chat_id)
                connection.execute("UPDATE accounts SET max_user_id=?,status=? WHERE id=?", (max_user_id, "active" if joined else "needs_membership", runtime["account_id"]))
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
            elif type(exc).__name__ == "ApiError" and getattr(exc, "error", None) == "error.profile.active.session.no2fa":
                safe = "max_password_required_on_active_session"
            elif type(exc).__name__ == "ApiError" and auth_stage == "send_code":
                safe = "code_rejected"
            elif type(exc).__name__ == "ApiError" and auth_stage == "check_password":
                safe = "password_rejected"
            elif type(exc).__name__ == "ApiError" and auth_stage == "request_code":
                safe = "max_auth_request_failed"
            elif str(exc) == "RegistrationConfig is required to register a new account":
                safe = "account_registration_required"
            elif type(exc).__name__ == "PasswordAttemptsExceededError":
                safe = "password_rejected"
            elif str(exc) == "Authentication failed: no token received":
                safe = "auth_token_missing"
            elif str(exc) in {"group_destination_mismatch", "max_user_id_missing", "group_resolution_failed", "account_registration_required", "cloud_password_rejected", "invite_unavailable", "ip_assignment_changed"}:
                safe = str(exc)
            else:
                safe = type(exc).__name__.lower()
            logger.warning("onboarding_failed session_id=%s account_id=%s ip_id=%s stage=%s duration_ms=%d error_class=%s", session_id, runtime["account_id"], runtime["ip_id"], stage, int((perf_counter() - stage_started) * 1000), type(exc).__name__)
            set_onboarding_state(session_id, "failed", safe)
        finally:
            try:
                if adapter is not None:
                    try:
                        stage = "session_close_seal"
                        stage_started = perf_counter()
                        await adapter.close()
                        logger.info("onboarding_stage session_id=%s account_id=%s ip_id=%s stage=%s duration_ms=%d", session_id, runtime["account_id"], runtime["ip_id"], stage, int((perf_counter() - stage_started) * 1000))
                    except Exception:
                        logger.warning("onboarding_failed session_id=%s account_id=%s ip_id=%s stage=session_close_seal error_class=SessionSaveError", session_id, runtime["account_id"], runtime["ip_id"])
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
                "SELECT s.*,a.group_id,a.phone,g.chat_id,p.address FROM onboarding_sessions s "
                "JOIN accounts a ON a.id=s.account_id JOIN groups g ON g.id=a.group_id "
                "JOIN ip_assignments ia ON ia.account_id=a.id JOIN server_ips p ON p.id=ia.ip_id "
                "AND p.enabled=1 AND p.available=1 WHERE s.id=?",
                (session_id,),
            ).fetchone()
        if row is None or row["token_hash"] != digest_token(token) or row["state"] != "waiting_membership":
            raise HTTPException(404, "onboarding_session_unavailable")
        if not row["chat_id"]:
            raise HTTPException(503, "group_resolution_failed")
        lock = account_session_locks.for_account(row["account_id"])
        adapter = None

        def current_membership_ip() -> str:
            with db() as connection:
                assigned = assigned_ip(connection, row["account_id"])
            if assigned != (row["ip_id"], row["address"]) or row["address"] not in host_addresses():
                raise HTTPException(409, "account_assignment_changed_during_verification")
            return row["address"]

        await lock.acquire()
        try:
            source_ip = current_membership_ip()
            vault = session_vault_for(row["account_id"])
            adapter = PyMaxAdapter.create(phone=row["phone"], source_ip=source_ip, session_vault=vault)
            await adapter.connect()
            current_membership_ip()
            chat = await adapter.get_chat(int(row["chat_id"]))
            current_membership_ip()
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
                "g.chat_id,ia.ip_id AS assigned_ip_id,p.enabled AS assigned_ip_enabled,p.available AS assigned_ip_available,p.address "
                "FROM onboarding_sessions s JOIN onboarding_invites i ON i.id=s.invite_id "
                "JOIN accounts a ON a.id=s.account_id JOIN groups g ON g.id=a.group_id "
                "LEFT JOIN ip_assignments ia ON ia.account_id=a.id LEFT JOIN server_ips p ON p.id=ia.ip_id "
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
                    or current["account_status"] not in {"pending", "needs_membership"}):
                connection.rollback()
                raise HTTPException(409, "group_invite_changed_during_verification")
            if (current["assigned_ip_id"] != row["ip_id"] or current["assigned_ip_enabled"] != 1
                    or current["assigned_ip_available"] != 1 or current["address"] != row["address"]):
                connection.rollback()
                raise HTTPException(409, "account_assignment_changed_during_verification")
            if joined:
                connection.execute("UPDATE accounts SET status='active' WHERE id=?", (row["account_id"],))
                connection.execute("UPDATE onboarding_sessions SET state='completed',updated_at=? WHERE id=?", (now, session_id))
            connection.commit()
        return {"joined": joined, "completed": joined}

    @app.post("/api/groups", status_code=201)
    async def add_group(body: GroupBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        if not _valid_max_invite_link(body.invite_link):
            raise HTTPException(422, "invalid_max_invite_link")
        now = datetime.now(timezone.utc)
        token = new_token(32)
        encrypted_token = SecretBox().encrypt(token)
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute("INSERT INTO groups(name,invite_link) VALUES(?,?)", (body.name.strip(), body.invite_link.strip()))
            connection.execute(
                "INSERT INTO onboarding_invites(group_id,token_hash,token_ciphertext,created_at,expires_at,max_uses,uses_count,active) "
                "VALUES(?,?,?,?,?,NULL,0,1)",
                (cursor.lastrowid, digest_token(token), encrypted_token, now.isoformat(), (now + timedelta(days=7)).isoformat()),
            )
            result = connection.execute("SELECT id,name,chat_id,active FROM groups WHERE id=?", (cursor.lastrowid,)).fetchone()
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,detail) VALUES(CURRENT_TIMESTAMP,'group_created',?,'{}')", (cursor.lastrowid,))
            connection.commit()
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
                "SELECT a.id,a.full_name,a.status,a.send_weekday,ia.ip_id,p.address AS ip_address,p.enabled AS ip_enabled,p.available AS ip_available,"
                "s.scheduled_date,s.status AS slot_status,s.error_code,"
                "(SELECT os.state FROM onboarding_sessions os WHERE os.account_id=a.id ORDER BY os.created_at DESC LIMIT 1) AS onboarding_state,"
                "(SELECT os.error_code FROM onboarding_sessions os WHERE os.account_id=a.id ORDER BY os.created_at DESC LIMIT 1) AS onboarding_error "
                "FROM accounts a "
                "LEFT JOIN ip_assignments ia ON ia.account_id=a.id LEFT JOIN server_ips p ON p.id=ia.ip_id "
                "LEFT JOIN weekly_slots s ON s.account_id=a.id AND s.week_start=? "
                "WHERE a.group_id=? ORDER BY a.id",
                (week_start, group_id),
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/groups/{group_id}/verify-destination")
    async def verify_destination(group_id: int, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        used_ips: dict[int, tuple[int, str]] = {}
        with db() as connection:
            group = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            accounts = connection.execute(
                "SELECT a.id,a.phone,p.id AS ip_id,p.address FROM accounts a JOIN ip_assignments ia ON ia.account_id=a.id "
                "JOIN server_ips p ON p.id=ia.ip_id WHERE a.group_id=? AND a.status IN ('active','needs_membership') "
                "AND p.enabled=1 AND p.available=1 ORDER BY a.id",
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
            stage = "resolve_group" if index == 0 else "check_membership"
            lock = account_session_locks.for_account(account["id"])
            await lock.acquire()
            try:
                def require_current_assignment() -> None:
                    with db() as connection:
                        current = connection.execute(
                            "SELECT a.status,ia.ip_id,p.address,p.enabled,p.available FROM accounts a "
                            "JOIN ip_assignments ia ON ia.account_id=a.id JOIN server_ips p ON p.id=ia.ip_id "
                            "WHERE a.id=? AND a.group_id=?",
                            (account["id"], group_id),
                        ).fetchone()
                        current_group = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
                    if current_group is None or current_group["invite_link"] != group["invite_link"]:
                        raise HTTPException(409, "group_invite_changed_during_verification")
                    if (current is None or current["status"] not in {"active", "needs_membership"}
                            or not current["enabled"] or not current["available"] or int(current["ip_id"]) != int(account["ip_id"])
                            or current["address"] != account["address"] or account["address"] not in host_addresses()):
                        raise HTTPException(409, "account_assignment_changed_during_verification")

                require_current_assignment()
                vault = session_vault_for(account["id"])
                adapter = PyMaxAdapter.create(phone=account["phone"], source_ip=account["address"], session_vault=vault)
                await adapter.connect()
                require_current_assignment()
                if index == 0:
                    resolved = await adapter.resolve_group_by_link(group["invite_link"])
                    require_current_assignment()
                    chat_id = str(getattr(resolved, "id", "") or getattr(resolved, "chat_id", ""))
                    if not chat_id:
                        raise RuntimeError("group_resolution_failed")
                    stage = "check_membership"
                states[int(account["id"])] = member_proof(await adapter.get_chat(int(chat_id)), chat_id)
                require_current_assignment()
            except Exception as exc:
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
            if failure_code:
                if isinstance(failure, HTTPException):
                    raise failure
                raise HTTPException(503, failure_code) from failure
            used_ips[int(account["id"])] = (int(account["ip_id"]), account["address"])
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT invite_link FROM groups WHERE id=?", (group_id,)).fetchone()
            if current is None or current["invite_link"] != group["invite_link"]:
                connection.rollback()
                raise HTTPException(409, "group_invite_changed_during_verification")
            for account_id in states:
                assignment = connection.execute(
                    "SELECT a.status,ia.ip_id,p.address,p.enabled,p.available FROM accounts a JOIN ip_assignments ia ON ia.account_id=a.id "
                    "JOIN server_ips p ON p.id=ia.ip_id WHERE a.id=? AND a.group_id=?",
                    (account_id, group_id),
                ).fetchone()
                if (assignment is None or assignment["status"] not in {"active", "needs_membership"}
                        or not assignment["enabled"] or not assignment["available"] or int(assignment["ip_id"]) != used_ips[account_id][0]
                        or assignment["address"] != used_ips[account_id][1]):
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

    @app.post("/api/accounts/{account_id}/ip")
    def reassign_ip(account_id: int, body: IPAssignmentBody, _session: sqlite3.Row = Depends(require_csrf)) -> dict[str, object]:
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            account = connection.execute("SELECT group_id FROM accounts WHERE id=?", (account_id,)).fetchone()
            ip_row = connection.execute("SELECT id,address,enabled,available FROM server_ips WHERE id=?", (body.ip_id,)).fetchone()
            if account is None or ip_row is None:
                connection.rollback()
                raise HTTPException(404, "account_or_ip_not_found")
            if not ip_row["enabled"] or not ip_row["available"] or not allowed_address(ip_row["address"]) or ip_row["address"] not in host_addresses():
                connection.rollback()
                raise HTTPException(422, "ip_unavailable")
            connection.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,?) ON CONFLICT(account_id) DO UPDATE SET ip_id=excluded.ip_id,assigned_at=CURRENT_TIMESTAMP", (account_id, body.ip_id))
            timezone_row = connection.execute("SELECT value FROM settings WHERE key='timezone'").fetchone()
            from zoneinfo import ZoneInfo
            today = datetime.now(ZoneInfo(timezone_row[0] if timezone_row else "Europe/Moscow")).date().isoformat()
            connection.execute(
                "UPDATE weekly_slots SET status=CASE WHEN scheduled_date>=? THEN 'queued' ELSE 'missed' END,"
                "error_code=NULL,updated_at=? WHERE account_id=? AND status='blocked' AND error_code='ip_assignment_unavailable'",
                (today, datetime.now(timezone.utc).isoformat(), account_id),
            )
            connection.execute("INSERT INTO audit_log(created_at,kind,group_id,account_id,detail) VALUES(CURRENT_TIMESTAMP,'ip_reassigned',?,?,?)", (account["group_id"], account_id, "{}"))
            connection.commit()
        return {"ip_id": ip_row["id"], "ip_address": ip_row["address"]}

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
