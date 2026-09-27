from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version
from time import perf_counter
from typing import Any, Callable

from .egress import allowed_address
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


class PyMaxAdapter:
    """The single boundary for PyMax calls and per-account source-IP binding."""

    @staticmethod
    def _silence_pymax_logs() -> None:
        provider_logger = logging.getLogger("pymax")
        provider_logger.handlers[:] = [logging.NullHandler()]
        provider_logger.propagate = False

    def __init__(self, client: Any):
        self.client = client

    @staticmethod
    def auth_stage_for_opcode(opcode: int) -> str | None:
        """Map PyMax 2.4.1 protocol opcodes to safe authentication stages."""
        try:
            from pymax.protocol.enums import Opcode
            value = int(opcode)
        except (ImportError, TypeError, ValueError):
            return None
        return {
            int(Opcode.SESSION_INIT): "handshake",
            int(Opcode.AUTH_REQUEST): "request_code",
            int(Opcode.AUTH): "otp",
            int(Opcode.AUTH_LOGIN_CHECK_PASSWORD): "two_factor",
            int(Opcode.LOGIN): "login",
            int(Opcode.PROFILE): "profile",
            int(Opcode.CHAT_CHECK_LINK): "resolve_group",
            int(Opcode.CHAT_JOIN): "join_group",
            int(Opcode.CHAT_INFO): "check_membership",
        }.get(value)

    @classmethod
    def create(
        cls, *, phone: str, source_ip: str, session_vault: EncryptedSessionFile | None = None,
        code_provider: Any = None, password_provider: Any = None,
        before_network_action: Callable[[], None] | None = None,
        diagnostic_callback: Callable[[str, str, int, bool, str | None], None] | None = None,
    ):
        if not allowed_address(source_ip):
            raise AdapterUnavailable("ip_assignment_required")
        if session_vault is None:
            raise AdapterUnavailable("encrypted_session_vault_required")
        try:
            if version("maxapi-python") != REQUIRED_PYMAX_VERSION:
                raise AdapterUnavailable("pymax_version_mismatch")
            from pymax import Client, ExtraConfig
            from pymax.connection import ConnectionManager
            from pymax.connection.readers import TCPReader
            from pymax.protocol.enums import Command
            from pymax.protocol.tcp import TcpProtocol
            from pymax.protocol.tcp.framing import TcpPacketFramer
            from pymax.transport.tcp import TCPTransport
        except AdapterUnavailable:
            raise
        except Exception as exc:
            raise AdapterUnavailable("pymax_unavailable") from exc

        class BoundTransport(TCPTransport):
            async def connect(self):
                started = perf_counter()
                if before_network_action is not None:
                    before_network_action()
                if self._proxy:
                    raise AdapterUnavailable("proxy_route_forbidden")
                try:
                    self._reader, self._writer = await asyncio.open_connection(
                        self._host, self._port, ssl=self._ssl_ctx if self._use_ssl else None,
                        family=socket.AF_INET, local_addr=(source_ip, 0),
                    )
                    actual = self._writer.get_extra_info("sockname")
                    if actual is None or actual[0] != source_ip:
                        await self.close()
                        raise AdapterUnavailable("source_ip_mismatch")
                except BaseException as exc:
                    if diagnostic_callback is not None and not isinstance(exc, asyncio.CancelledError):
                        diagnostic_callback("connect", "failed", int((perf_counter() - started) * 1000), False, type(exc).__name__)
                    raise
                if diagnostic_callback is not None:
                    diagnostic_callback("connect", "connected", int((perf_counter() - started) * 1000), False, None)

            async def send(self, data):
                if before_network_action is not None:
                    before_network_action()
                await super().send(data)

        class BoundClient(Client):
            def _build_connection(self):
                transport = BoundTransport(
                    host=self.extra_config.host, port=self.extra_config.port,
                    use_ssl=self.extra_config.use_ssl, proxy=None,
                )

                class DiagnosticConnectionManager(ConnectionManager):
                    async def request(self, frame, *, timeout=None):
                        stage = PyMaxAdapter.auth_stage_for_opcode(frame.opcode)
                        started = perf_counter()
                        try:
                            response = await super().request(frame, timeout=timeout)
                        except BaseException as exc:
                            if (diagnostic_callback is not None and stage is not None
                                    and not isinstance(exc, asyncio.CancelledError)):
                                diagnostic_callback(stage, "failed", int((perf_counter() - started) * 1000), False, type(exc).__name__)
                            raise
                        if diagnostic_callback is not None and stage is not None:
                            rejected = response.cmd == Command.ERROR
                            diagnostic_callback(
                                stage, "rejected" if rejected else "response",
                                int((perf_counter() - started) * 1000), True,
                                "ApiError" if rejected else None,
                            )
                        return response

                return DiagnosticConnectionManager(
                    reader=TCPReader(transport=transport, framer=TcpPacketFramer()),
                    transport=transport, protocol=TcpProtocol(),
                )

        opened = False
        try:
            extra = ExtraConfig(
                proxy=None, reconnect=False, relogin=False, persist_session=True,
                telemetry=False, log_level="WARNING", password_max_attempts=5,
            )
            work_dir, session_name = session_vault.open()
            opened = True
            auth_kwargs = (
                {"sms_code_provider": code_provider, "password_provider": password_provider}
                if code_provider is not None else {"auth_flow": NoInteractiveAuthFlow()}
            )
            client = BoundClient(
                phone=phone, work_dir=work_dir, session_name=session_name,
                extra_config=extra, **auth_kwargs,
            )
            cls._silence_pymax_logs()
        except Exception as exc:
            if opened:
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

    def persist_session_snapshot(self) -> bool:
        vault = getattr(self, "_session_vault", None)
        if vault is None:
            return False
        return vault.snapshot()

    @staticmethod
    def is_invalid_saved_session_error(exc: Exception) -> bool:
        """Match PyMax 2.4.1's explicit invalid-login-token condition safely."""
        try:
            from pymax.exceptions import ApiError
            from pymax.protocol.enums import Opcode
        except Exception:
            return False
        if not isinstance(exc, ApiError) or getattr(exc, "opcode", None) != Opcode.LOGIN:
            return False
        values = {str(getattr(exc, "error", "")), str(getattr(exc, "message", ""))}
        return bool(values & {"FAIL_LOGIN_TOKEN", "FAIL_LOGOUT_ALL"})

    async def resolve_group_by_link(self, link: str):
        return await self.client.resolve_group_by_link(link)

    async def join_group(self, link: str):
        return await self.client.join_group(link)

    async def get_chat(self, chat_id: int):
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
