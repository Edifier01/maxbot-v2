from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class ActionsClosed(RuntimeError):
    pass


class ActionGate:
    """Default-deny runtime check for externally authorized MAX actions."""
    def __init__(self, authorization_file: str | Path | None = None):
        self.path = Path(authorization_file or os.getenv("MAX_AUTHORIZATION_FILE", "/run/secrets/max-authorization.json"))

    def require(self, action: str) -> None:
        try:
            record = json.loads(self.path.read_text(encoding="utf-8"))
            expiry = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
            scopes = set(record["scopes"])
            valid = (
                record.get("status") == "authorized"
                and bool(str(record.get("contract_reference", "")).strip())
                and expiry.tzinfo is not None
                and expiry > datetime.now(timezone.utc)
                and action in scopes
            )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            valid = False
        if not valid:
            raise ActionsClosed("max_actions_not_authorized")

    def enabled(self, action: str) -> bool:
        try:
            self.require(action)
            return True
        except ActionsClosed:
            return False
