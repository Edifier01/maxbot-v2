from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version
import tempfile
from typing import Any
from urllib.parse import unquote, urlsplit

from .session_vault import EncryptedSessionFile


REQUIRED_PYMAX_VERSION = "2.4.1"
PYMAX_HOST = "api2.oneme.ru"
PYMAX_PORT = 443


class ProxyProbeError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


async def probe_proxy(proxy_url: str, *, timeout: float = 6.0) -> None:
    """Check that a proxy can open PyMax's configured TCP endpoint."""
    try:
        parsed = urlsplit(proxy_url)
        host, port = parsed.hostname, parsed.port
        if parsed.scheme not in {"http", "socks5"} or not host or port is None or not 1 <= port <= 65535:
            raise ProxyProbeError("invalid_proxy_url")
    except ValueError as exc:
        raise ProxyProbeError("invalid_proxy_url") from exc

    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            if parsed.scheme == "http":
                await _http_connect_tunnel(reader, writer, parsed)
            else:
                await _socks5_connect_tunnel(reader, writer, parsed)
    except ProxyProbeError:
        raise
    except asyncio.TimeoutError as exc:
        raise ProxyProbeError("proxy_check_timeout") from exc
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        raise ProxyProbeError("proxy_connection_failed") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def _http_connect_tunnel(reader, writer, parsed) -> None:
    target = f"{PYMAX_HOST}:{PYMAX_PORT}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Connection: keep-alive"]
    if parsed.username is not None:
        credentials = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}".encode()
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(credentials).decode("ascii"))
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    response = await reader.readuntil(b"\r\n\r\n")
    status = response.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or not status[1].isdigit():
        raise ProxyProbeError("proxy_protocol_error")
    code = int(status[1])
    if code == 407:
        raise ProxyProbeError("proxy_authentication_failed")
    if not 200 <= code < 300:
        raise ProxyProbeError("proxy_tunnel_rejected")


async def _socks5_connect_tunnel(reader, writer, parsed) -> None:
    has_credentials = parsed.username is not None
    methods = b"\x00\x02" if has_credentials else b"\x00"
    writer.write(b"\x05" + bytes([len(methods)]) + methods)
    await writer.drain()
    version_byte, method = await reader.readexactly(2)
    if version_byte != 5 or method == 0xFF:
        raise ProxyProbeError("proxy_authentication_failed")
    if method == 2:
        if not has_credentials:
            raise ProxyProbeError("proxy_authentication_failed")
        username = unquote(parsed.username or "").encode()
        password = unquote(parsed.password or "").encode()
        if not username or len(username) > 255 or len(password) > 255:
            raise ProxyProbeError("proxy_authentication_failed")
        writer.write(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        await writer.drain()
        auth_version, auth_status = await reader.readexactly(2)
        if auth_version != 1 or auth_status != 0:
            raise ProxyProbeError("proxy_authentication_failed")
    elif method != 0:
        raise ProxyProbeError("proxy_authentication_failed")
    elif has_credentials:
        raise ProxyProbeError("proxy_authentication_failed")

    host = PYMAX_HOST.encode("ascii")
    writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + PYMAX_PORT.to_bytes(2, "big"))
    await writer.drain()
    response = await reader.readexactly(4)
    version_byte, result, _reserved, address_type = response
    if version_byte != 5 or result != 0:
        raise ProxyProbeError("proxy_tunnel_rejected")
    if address_type == 1:
        await reader.readexactly(4 + 2)
    elif address_type == 3:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    elif address_type == 4:
        await reader.readexactly(16 + 2)
    else:
        raise ProxyProbeError("proxy_protocol_error")


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
    def __init__(self):
        self.response: Any = None

    async def authenticate(self, app: Any):
        self.response = await app.api.auth.request_code(str(app.config.phone))
        raise _DirectCodeRequestDone()


class PyMaxAdapter:
    """The single boundary for PyMax calls."""
    def __init__(self, client: Any):
        self.client = client

    @classmethod
    async def request_code_direct(cls, *, phone: str, assigned_proxy: str):
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

        auth_flow = _DirectCodeRequestFlow()
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
            work_dir, session_name = session_vault.open()
            client = Client(phone=phone, work_dir=work_dir, session_name=session_name, extra_config=extra, auth_flow=auth_flow or NoInteractiveAuthFlow())
        except AdapterUnavailable:
            raise
        except Exception as exc:
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
