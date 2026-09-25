from __future__ import annotations

import asyncio
from collections import defaultdict


class AccountSessionLocks:
    """Serialize access to each account's shared temporary session file."""

    def __init__(self) -> None:
        self._locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    def for_account(self, account_id: int) -> asyncio.Lock:
        return self._locks[int(account_id)]
