from __future__ import annotations

import hashlib
import hmac


def phone_fingerprint(phone: str, key: str | bytes) -> str:
    """Return a keyed, domain-separated identifier for retained send history."""
    secret = key.encode("utf-8") if isinstance(key, str) else key
    if len(secret) < 16:
        raise ValueError("phone_fingerprint_key_unavailable")
    value = b"maxbot-account-phone-v1:" + phone.encode("utf-8")
    return hmac.new(secret, value, hashlib.sha256).hexdigest()
