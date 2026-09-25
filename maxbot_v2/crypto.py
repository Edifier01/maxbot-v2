from __future__ import annotations

import os
from cryptography.fernet import Fernet, InvalidToken


class SecretBox:
    def __init__(self, key: str | bytes | None = None):
        raw = key if key is not None else os.getenv("DATA_ENCRYPTION_KEY", "")
        if isinstance(raw, str):
            raw = raw.encode()
        if not raw:
            raise ValueError("data_encryption_key_not_configured")
        try:
            self._fernet = Fernet(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid_data_encryption_key") from exc

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode("ascii")

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError) as exc:
            raise ValueError("encrypted_value_unavailable") from exc

    def encrypt_bytes(self, value: bytes) -> bytes:
        return self._fernet.encrypt(value)

    def decrypt_bytes(self, value: bytes) -> bytes:
        try:
            return self._fernet.decrypt(value)
        except InvalidToken as exc:
            raise ValueError("encrypted_value_unavailable") from exc
