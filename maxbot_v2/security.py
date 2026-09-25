from __future__ import annotations

import hashlib
import hmac
import secrets
import bcrypt


def digest_token(value: str, secret: str | bytes | None = None) -> str:
    data = value.encode("utf-8")
    if secret:
        key = secret.encode("utf-8") if isinstance(secret, str) else secret
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def new_token(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def password_matches(password: str, encoded_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), encoded_hash.encode("ascii"))
    except (ValueError, TypeError, UnicodeError):
        return False
