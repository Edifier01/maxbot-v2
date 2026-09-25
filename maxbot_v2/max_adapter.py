from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version
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


class PyMaxAdapter:
    """The single boundary for PyMax calls."""
    def __init__(self, client: Any):
        self.client = client

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
