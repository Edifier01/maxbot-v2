from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version
import logging
import tempfile
from typing import Any

from .session_vault import EncryptedSessionFile


REQUIRED_PYMAX_VERSION = "2.4.1"


class AdapterUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class AcceptedMessage:
    message_id: str
    accepted_at: datetime


class NoInteractiveAuthFlow:
    async def authenticate(self, app: Any):
        raise RuntimeError("saved_session_required")


class _DirectCodeRequestDone(Exception):
    """Stop the temporary PyMax connection immediately after requesting one code."""


class _DirectCodeRequestFlow:
    def __init__(self, hold_open_until: asyncio.Event | None = None):
        self.response: Any = None
        self.hold_open_until = hold_open_until

    async def authenticate(self, app: Any):
        self.response = await app.api.auth.request_code(str(app.config.phone))
        if self.hold_open_until is not None:
            await self.hold_open_until.wait()
            if not app.connection.is_open:
                raise RuntimeError("direct_probe_connection_closed")
        raise _DirectCodeRequestDone()


class PyMaxAdapter:
    """The single boundary for PyMax calls."""

    @staticmethod
    def _silence_pymax_logs() -> None:
        # PyMax ERROR/WARNING messages can contain remote text and proxy URLs.
        provider_logger = logging.getLogger("pymax")
        provider_logger.handlers[:] = [logging.NullHandler()]
        provider_logger.propagate = False

    def __init__(self, client: Any):
        self.client = client

    @classmethod
    async def request_code_direct(
        cls, *, phone: str, assigned_proxy: str,
        hold_open_until: asyncio.Event | None = None,
    ):
        """Request one OTP directly, without creating or persisting a MAX session.

        The assigned proxy is required as a fail-closed precondition, but this
        one request deliberately uses a separate temporary client without it.
        All subsequent authorization calls use the regular proxied adapter.
        """
        if not assigned_proxy or not assigned_proxy.strip():
            raise AdapterUnavailable("proxy_assignment_required")
        try:
            installed = version("maxapi-python")
            if installed != REQUIRED_PYMAX_VERSION:
                raise AdapterUnavailable("pymax_version_mismatch")
            from pymax import Client, ExtraConfig
        except AdapterUnavailable:
            raise
        except Exception as exc:
            raise AdapterUnavailable("pymax_unavailable") from exc

        auth_flow = _DirectCodeRequestFlow(hold_open_until)
        client = None
        with tempfile.TemporaryDirectory(prefix="maxbot-direct-auth-") as work_dir:
            try:
                extra = ExtraConfig(
                    proxy=None,
                    reconnect=False,
                    relogin=False,
                    persist_session=False,
                    telemetry=False,
                    log_level="WARNING",
                )
                client = Client(
                    phone=phone,
                    work_dir=work_dir,
                    session_name="request-code.db",
                    extra_config=extra,
                    auth_flow=auth_flow,
                )
                cls._silence_pymax_logs()
                try:
                    await client.connect()
                except _DirectCodeRequestDone:
                    pass
            finally:
                if client is not None:
                    try:
                        await client.close()
                    except Exception:
                        # A cleanup failure must not expose provider details or
                        # turn an already accepted request into an automatic retry.
                        pass

        if auth_flow.response is None:
            raise RuntimeError("request_code_response_missing")
        return auth_flow.response

    @classmethod
    def create(cls, *, phone: str, work_dir: str, session_name: str, proxy: str | None, auth_flow: Any = None, session_vault: EncryptedSessionFile | None = None):
        runtime_opened = False
        try:
            if not proxy:
                raise AdapterUnavailable("proxy_assignment_required")
            if session_vault is None:
                raise AdapterUnavailable("encrypted_session_vault_required")
            installed = version("maxapi-python")
            if installed != REQUIRED_PYMAX_VERSION:
                raise AdapterUnavailable("pymax_version_mismatch")
            from pymax import Client, ExtraConfig
            extra = ExtraConfig(proxy=proxy, reconnect=False, relogin=False, persist_session=True, telemetry=False, log_level="WARNING")
            runtime_opened = True
            work_dir, session_name = session_vault.open()
            client = Client(phone=phone, work_dir=work_dir, session_name=session_name, extra_config=extra, auth_flow=auth_flow or NoInteractiveAuthFlow())
            cls._silence_pymax_logs()
        except AdapterUnavailable:
            raise
        except Exception as exc:
            if runtime_opened:
                try:
                    session_vault.discard_working_copy()
                except OSError as cleanup_error:
                    raise AdapterUnavailable("session_cleanup_failed") from cleanup_error
            raise AdapterUnavailable("pymax_unavailable") from exc
        result = cls(client)
        result._session_vault = session_vault
        return result

    async def connect(self) -> None:
        await self.client.connect()

    async def resolve_group_by_link(self, link: str):
        return await self.client.resolve_group_by_link(link)

    async def join_group(self, link: str):
        return await self.client.join_group(link)

    async def get_chat(self, chat_id: int):
        # PyMax 2.4.1 otherwise returns the chat cached during login.
        self.client._app.api.chats._remove_cached_chat(chat_id)
        return await self.client.get_chat(chat_id)

    async def send_message(self, *, chat_id: int, text: str) -> AcceptedMessage:
        response = await self.client.send_message(chat_id=chat_id, text=text)
        message_id = str(getattr(response, "id", "") or "").strip()
        if not message_id:
            raise RuntimeError("provider_ack_missing")
        return AcceptedMessage(message_id, datetime.now(timezone.utc))

    async def close(self) -> None:
        try:
            await self.client.close()
        finally:
            if getattr(self, "_session_vault", None) is not None:
                self._session_vault.seal()
