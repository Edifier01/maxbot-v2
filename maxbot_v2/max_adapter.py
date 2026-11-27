from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version
from ssl import SSLContext
from time import perf_counter
from typing import Any, Awaitable, Callable
from urllib.parse import unquote, urlsplit

from .egress import allowed_address
from .send_proxies import allowed_proxy_address, normalize_proxy_url
from .session_vault import EncryptedSessionFile


REQUIRED_PYMAX_VERSION = "2.5.0"
SEND_PROXY_CONNECT_TIMEOUT = 7
# python-socks 3.2.2 wraps these SOCKS5 authentication replies without a reply code.
SOCKS5_AUTH_REJECTIONS = frozenset({
    "No acceptable authentication methods were offered",
    "Username and password authentication failure",
})
CLOUD_PASSWORD_REJECTIONS = frozenset({
    "fail_wrong_password", "wrong_password", "incorrect_password", "invalid_password", "password_rejected",
    "wrong password", "incorrect password", "invalid password", "неверный пароль", "неправильный пароль",
})


class AdapterUnavailable(RuntimeError):
    pass


async def _open_send_proxy_tunnel(
    *, url: str, source_ip: str, host: str, port: int, ssl_context: SSLContext,
    before_network_action: Callable[[], None] | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    from python_socks import ProxyConnectionError, ProxyError, ProxyType
    from python_socks._protocols.errors import ReplyError
    from python_socks.async_.asyncio import Proxy

    endpoint = urlsplit(url)
    proxy_address = endpoint.hostname
    failure = "connection_failed"
    try:
        async with asyncio.timeout(SEND_PROXY_CONNECT_TIMEOUT):
            if not allowed_proxy_address(proxy_address):
                addresses = await asyncio.get_running_loop().getaddrinfo(
                    proxy_address, endpoint.port, family=socket.AF_INET, type=socket.SOCK_STREAM,
                )
                proxy_address = next((address[0] for *_, address in addresses if allowed_proxy_address(address[0])), None)
                if proxy_address is None:
                    raise AdapterUnavailable("connection_failed")
            proxy = Proxy(
                ProxyType.SOCKS5, proxy_address, endpoint.port,
                unquote(endpoint.username) if endpoint.username else None,
                unquote(endpoint.password) if endpoint.password else None,
                rdns=True,
            )
            if before_network_action is not None:
                before_network_action()
            failure = "tunnel_failed"
            sock = await proxy.connect(
                dest_host=host, dest_port=port, timeout=SEND_PROXY_CONNECT_TIMEOUT, local_addr=(source_ip, 0),
            )
            try:
                failure = "source_ip_mismatch"
                if sock.getsockname()[0] != source_ip:
                    raise AdapterUnavailable(failure)
                failure = "tls_failed"
                reader, writer = await asyncio.open_connection(sock=sock, ssl=ssl_context, server_hostname=host)
            except BaseException:
                sock.close()
                raise
            actual = writer.get_extra_info("sockname")
            if actual is None or actual[0] != source_ip:
                writer.close()
                raise AdapterUnavailable("source_ip_mismatch")
            return reader, writer
    except ProxyConnectionError:
        raise AdapterUnavailable("connection_failed") from None
    except ProxyError as exc:
        reply = exc.args[0] if exc.args else None
        if exc.error_code is None and isinstance(reply, ReplyError) and str(reply) in SOCKS5_AUTH_REJECTIONS:
            raise AdapterUnavailable("auth_failed") from None
        raise AdapterUnavailable("tunnel_failed") from None
    except TimeoutError:
        raise AdapterUnavailable("socks_timeout" if failure == "tunnel_failed" else failure) from None
    except OSError:
        raise AdapterUnavailable(failure) from None


@dataclass(frozen=True)
class AcceptedMessage:
    message_id: str
    accepted_at: datetime


@dataclass(frozen=True)
class ChannelPost:
    id: int
    published_at_ms: int
    is_publication: bool


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
    async def check_send_proxy(*, source_ip: str, url: str) -> str:
        """Check only the same SOCKS5 and verified TLS route used for dispatch."""
        try:
            url = normalize_proxy_url(url)
        except ValueError:
            return "config_invalid"
        if not allowed_address(source_ip):
            return "source_ip_mismatch"
        try:
            if version("maxapi-python") != REQUIRED_PYMAX_VERSION:
                return "check_unavailable"
            from pymax import ExtraConfig
            from pymax.transport.tcp import TCPTransport

            config = ExtraConfig()
            transport = TCPTransport(host=config.host, port=config.port, use_ssl=config.use_ssl, proxy=None)
            _, writer = await _open_send_proxy_tunnel(
                url=url, source_ip=source_ip, host=config.host, port=config.port, ssl_context=transport._ssl_ctx,
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except (OSError, TimeoutError):
                writer.transport.abort()
            return "ok"
        except AdapterUnavailable as exc:
            return str(exc)
        except Exception:
            return "check_unavailable"

    @staticmethod
    def auth_stage_for_opcode(opcode: int) -> str | None:
        """Map PyMax protocol opcodes to safe authentication stages."""
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

    @staticmethod
    def observe_cloud_password(
        check_password: Callable[[str, str], Awaitable[Any]], on_result: Callable[[bool], None],
    ) -> Callable[[str, str], Awaitable[Any]]:
        """Observe the credential verdict before SmsAuthFlow handles a retry."""
        from pymax.exceptions import ApiError
        from pymax.protocol.enums import Opcode

        def rejected(*values: object) -> bool:
            return any(
                isinstance(value, str) and value.strip().rstrip(".!").casefold() in CLOUD_PASSWORD_REJECTIONS
                for value in values
            )

        async def check(track_id: str, password: str):
            try:
                result = await check_password(track_id, password)
            except ApiError as exc:
                if exc.opcode == Opcode.AUTH_LOGIN_CHECK_PASSWORD and rejected(exc.error, exc.message, exc.localized_message):
                    on_result(False)
                raise
            if rejected(result.error):
                on_result(False)
            elif not result.error and result.login_token:
                on_result(True)
            return result

        return check

    @classmethod
    def create(
        cls, *, phone: str, source_ip: str, session_vault: EncryptedSessionFile | None = None,
        code_provider: Any = None, password_provider: Any = None,
        send_proxy_url: str | None = None,
        before_network_action: Callable[[], None] | None = None,
        diagnostic_callback: Callable[[str, str, int, bool, str | None], None] | None = None,
        cloud_password_result: Callable[[bool], None] | None = None,
    ):
        if not allowed_address(source_ip):
            raise AdapterUnavailable("ip_assignment_required")
        if session_vault is None:
            raise AdapterUnavailable("encrypted_session_vault_required")
        if send_proxy_url is not None:
            if code_provider is not None or password_provider is not None:
                raise AdapterUnavailable("interactive_auth_requires_direct_ip")
            try:
                send_proxy_url = normalize_proxy_url(send_proxy_url)
            except ValueError:
                raise AdapterUnavailable("invalid_send_proxy") from None
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
                try:
                    if send_proxy_url is None:
                        self._reader, self._writer = await asyncio.open_connection(
                            self._host, self._port, ssl=self._ssl_ctx if self._use_ssl else None,
                            family=socket.AF_INET, local_addr=(source_ip, 0),
                        )
                        actual = self._writer.get_extra_info("sockname")
                        if actual is None or actual[0] != source_ip:
                            await self.close()
                            raise AdapterUnavailable("source_ip_mismatch")
                    else:
                        self._reader, self._writer = await _open_send_proxy_tunnel(
                            url=send_proxy_url, source_ip=source_ip, host=self._host, port=self._port,
                            ssl_context=self._ssl_ctx, before_network_action=before_network_action,
                        )
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
            def _build_app(self):
                app = super()._build_app()
                if cloud_password_result is not None:
                    auth = app.api.auth
                    auth.check_password = cls.observe_cloud_password(auth.check_password, cloud_password_result)
                return app

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
        """Match PyMax's explicit invalid-login-token condition safely."""
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

    async def resolve_channel(self, link: str):
        from pymax.api.chats.enums import ChatPayloadKey
        from pymax.api.chats.payloads import LinkInfoPayload
        from pymax.api.response import parse_payload_item_model
        from pymax.protocol import Opcode
        from pymax.types.domain import Chat

        # PyMax's public resolver accepts only group invite links.
        response = await self.client._app.invoke(Opcode.LINK_INFO, LinkInfoPayload(link=link).to_payload())
        return parse_payload_item_model(response, ChatPayloadKey.CHAT, Chat)

    async def join_channel(self, link: str):
        return await self.client.join_channel(link)

    async def fetch_channel_posts(self, chat_id: int, *, before_ms: int, limit: int) -> list[ChannelPost]:
        messages = await self.client.fetch_history(chat_id=chat_id, backward=limit, from_time=before_ms)
        posts = []
        for message in messages:
            if message.time <= 0:
                raise RuntimeError("channel_history_timestamp_missing")
            control = any(getattr(attachment, "type", None) == "CONTROL" for attachment in getattr(message, "attaches", ()))
            publication = (
                message.chat_id in (chat_id, None) and message.post_id is None
                and message.type not in {"CONTROL", "SYSTEM", "SERVICE"}
                and getattr(message, "status", None) != "REMOVED" and not control
            )
            posts.append(ChannelPost(message.id, message.time, publication))
        return posts

    async def read_channel_reaction(self, chat_id: int, post_id: int) -> str | None:
        reactions = await self.client.get_reactions(chat_id=chat_id, message_ids=[post_id])
        reaction = (reactions or {}).get(str(post_id))
        if reaction is not None:
            return reaction.your_reaction
        post = await self.client.get_message(chat_id=chat_id, message_id=post_id)
        if post is None or getattr(post, "status", None) == "REMOVED":
            raise LookupError("channel_post_unavailable")
        return getattr(post.reaction_info, "your_reaction", None)

    async def write_channel_reaction(self, chat_id: int, post_id: int, emoji: str) -> str | None:
        reaction = await self.client.add_reaction(chat_id=chat_id, message_id=post_id, reaction=emoji)
        return getattr(reaction, "your_reaction", None)

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
