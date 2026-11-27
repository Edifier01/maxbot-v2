from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import sqlite3
import time
import unicodedata
from contextlib import asynccontextmanager, contextmanager
from urllib.parse import urlsplit

from .db import connect
from .onboarding import member_proof
from .sender import DispatchPaused


logger = logging.getLogger(__name__)
HISTORY_PAGE_SIZE = 50
MAX_HISTORY_PAGE_SIZE = 800
RETRY_MS = 60_000
ACTIVE_ACCOUNT = "a.status='active' AND a.auth_state='authenticated' AND a.lifecycle='active'"


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _current_config(db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM channel_reaction_configs WHERE retired_at_ms IS NULL").fetchone()


def _stopped(db: sqlite3.Connection) -> bool:
    row = db.execute("SELECT value FROM settings WHERE key='global_stop'").fetchone()
    return row is None or row[0] != "0"


def get_channel_reaction_settings(db: sqlite3.Connection) -> dict[str, object]:
    row = _current_config(db)
    return {
        "enabled": bool(row and row["enabled"]),
        "channel_url": row["channel_url"] if row else "",
        "reactions": json.loads(row["reactions"]) if row else [],
        "stopped": _stopped(db),
    }


def _public_channel_url(link: str) -> str:
    link = link.strip()
    if not link:
        return ""
    try:
        url = urlsplit(link)
    except ValueError:
        raise ValueError("invalid_channel_url") from None
    name = re.fullmatch(r"/([a-zA-Z0-9_.-]{1,128})/?", url.path)
    if (
        url.scheme != "https" or url.netloc.lower() not in {"max.ru", "www.max.ru"}
        or "?" in link or "#" in link or not name or name[1].casefold() in {"join", ".", ".."}
        or any(character.isspace() or ord(character) < 32 for character in link)
    ):
        raise ValueError("invalid_channel_url")
    return f"https://max.ru/{name[1]}"


def _reaction_choices(values: list[str], *, enabled: bool) -> list[str]:
    choices = list({_emoji_key(item.strip()): unicodedata.normalize("NFC", item.strip()) for item in values}.values())
    if not choices and not enabled:
        return []
    if not 2 <= len(choices) <= 32:
        raise ValueError("invalid_channel_reactions")
    if not all(_is_single_reaction(emoji) for emoji in choices):
        raise ValueError("invalid_channel_reactions")
    return choices


def _is_single_reaction(emoji: str) -> bool:
    if not 1 <= len(emoji) <= 16:
        return False
    regional_start, regional_end = 0x1F1E6, 0x1F1FF
    if len(emoji) == 2 and all(regional_start <= ord(part) <= regional_end for part in emoji):
        return True
    if re.fullmatch(r"[0-9#*]\ufe0f?\u20e3", emoji):
        return True
    for part in emoji.split("\u200d"):
        if not part or unicodedata.category(part[0]) != "So" or regional_start <= ord(part[0]) <= regional_end:
            return False
        suffix = part[1:]
        if suffix.startswith(("\ufe0e", "\ufe0f")):
            suffix = suffix[1:]
        if suffix and (len(suffix) != 1 or not 0x1F3FB <= ord(suffix) <= 0x1F3FF):
            return False
    return True


def _emoji_key(emoji: str) -> str:
    return unicodedata.normalize("NFC", emoji).replace("\ufe0f", "").replace("\ufe0e", "")


def _update_pause(db: sqlite3.Connection, *, scope: int, stopped: bool, now: int) -> None:
    if stopped:
        db.execute(
            "INSERT OR IGNORE INTO channel_reaction_pauses(scope,started_at_ms) VALUES(?,?)",
            (scope, now),
        )
    else:
        db.execute(
            "UPDATE channel_reaction_pauses SET resumed_at_ms=MAX(started_at_ms,?) "
            "WHERE scope=? AND resumed_at_ms IS NULL",
            (now, scope),
        )


def set_channel_reactions_run(db: sqlite3.Connection, *, stopped: bool) -> None:
    _update_pause(db, scope=0, stopped=stopped, now=_now_ms())


def save_channel_reaction_settings(
    db: sqlite3.Connection, *, enabled: bool, channel_url: str, reactions: list[str]
) -> dict[str, object]:
    link = _public_channel_url(channel_url)
    if enabled and not link:
        raise ValueError("channel_url_required")
    choices = json.dumps(_reaction_choices(reactions, enabled=enabled), ensure_ascii=False)
    now = _now_ms()
    row = _current_config(db)
    if row and row["channel_url"] == link:
        db.execute("UPDATE channel_reaction_configs SET enabled=?,reactions=? WHERE id=?", (enabled, choices, row["id"]))
        _update_pause(db, scope=row["id"], stopped=not enabled, now=now)
    else:
        if row:
            db.execute(
                "UPDATE channel_reaction_configs SET enabled=0,retired_at_ms=? WHERE id=?", (now, row["id"])
            )
            db.execute(
                "UPDATE channel_reaction_operations SET status='retired' WHERE config_id=? AND status='queued'",
                (row["id"],),
            )
        if link:
            db.execute(
                "INSERT INTO channel_reaction_configs(channel_url,reactions,enabled) VALUES(?,?,?)",
                (link, choices, enabled),
            )
    return get_channel_reaction_settings(db)


def enroll_channel_account(db: sqlite3.Connection, account_id: int) -> None:
    db.execute(
        "INSERT OR IGNORE INTO channel_subscriptions(account_id,config_id) "
        "SELECT a.id,c.id FROM accounts a CROSS JOIN channel_reaction_configs c "
        "WHERE a.id=? AND a.ever_authenticated=0 AND a.lifecycle='active' "
        "AND c.retired_at_ms IS NULL AND c.enabled=1",
        (account_id,),
    )


def channel_subscription_for_accounts(db: sqlite3.Connection, group_id: int) -> dict[int, dict[str, str | None]]:
    rows = db.execute(
        "SELECT s.account_id,CASE WHEN c.retired_at_ms IS NOT NULL THEN 'retired' "
        "WHEN s.status='joining' THEN 'pending' ELSE s.status END AS channel_subscription_status,"
        "CASE WHEN c.retired_at_ms IS NULL THEN s.error_code END AS channel_subscription_error "
        "FROM channel_subscriptions s JOIN channel_reaction_configs c ON c.id=s.config_id "
        "JOIN accounts a ON a.id=s.account_id WHERE a.group_id=? AND a.lifecycle<>'deleted'",
        (group_id,),
    )
    return {row["account_id"]: {key: row[key] for key in row.keys() if key != "account_id"} for row in rows}


def list_channel_reaction_reviews(db: sqlite3.Connection) -> list[dict[str, object]]:
    return [
        dict(row) for row in db.execute(
            "SELECT o.id,o.account_id,CAST(o.chat_id AS TEXT) AS chat_id,CAST(o.post_id AS TEXT) AS post_id,"
            "o.emoji,o.published_at_ms,c.channel_url FROM channel_reaction_operations o "
            "JOIN channel_reaction_configs c ON c.id=o.config_id WHERE o.status='unknown' ORDER BY o.id"
        )
    ]


def reconcile_channel_reaction(db: sqlite3.Connection, operation_id: int, *, outcome: str) -> bool:
    if outcome not in {"confirmed", "not_applied"}:
        raise ValueError("invalid_channel_reaction_outcome")
    row = db.execute(
        "UPDATE channel_reaction_operations SET status=?,inspect_pending=0 WHERE id=? AND status='unknown' "
        "RETURNING account_id,emoji",
        (outcome, operation_id),
    ).fetchone()
    if row is not None and outcome == "confirmed" and row["emoji"]:
        _remember_emoji(db, row["account_id"], row["emoji"])
    return row is not None


def _remember_emoji(db: sqlite3.Connection, account_id: int, emoji: str) -> None:
    db.execute("UPDATE channel_subscriptions SET last_emoji=? WHERE account_id=?", (emoji, account_id))


def has_unresolved_reactions(db: sqlite3.Connection, account_id: int) -> bool:
    return db.execute(
        "SELECT 1 FROM channel_reaction_operations WHERE account_id=? AND status IN ('in_flight','unknown')",
        (account_id,),
    ).fetchone() is not None


def recover_channel_reactions(db: sqlite3.Connection) -> None:
    db.execute(
        "UPDATE channel_reaction_operations SET status='unknown',inspect_pending=1,next_attempt_ms=0 "
        "WHERE status='in_flight'"
    )
    db.execute(
        "UPDATE channel_subscriptions SET status='join_uncertain',error_code='channel_membership_unconfirmed',"
        "next_attempt_ms=0 WHERE status='joining'"
    )


class ChannelWorkPaused(Exception):
    pass


def _channel_id(chat) -> int | None:
    kind = getattr(chat, "type", "")
    access = getattr(chat, "access", "")
    value = getattr(chat, "id", None)
    if (
        str(getattr(kind, "value", kind)).upper() != "CHANNEL"
        or str(getattr(access, "value", access)).upper() in {"PRIVATE", "SECRET"}
        or type(value) is not int or value == 0
    ):
        return None
    return value


class ChannelReactionWorker:
    def __init__(self, database, open_adapter, *, poll_seconds: float = 10):
        self.database = database
        self.open_adapter = open_adapter
        self.poll_seconds = poll_seconds
        self._history_source_offset = 0

    @contextmanager
    def _db(self, *, write: bool = False):
        db = connect(self.database)
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _check(db: sqlite3.Connection, config_id: int, account_id: int, *, use_proxy: bool) -> sqlite3.Row:
        row = db.execute(
            f"SELECT c.*,s.status AS subscription_status FROM channel_reaction_configs c "
            f"JOIN channel_subscriptions s ON s.config_id=c.id JOIN accounts a ON a.id=s.account_id "
            f"WHERE c.id=? AND s.account_id=? AND c.enabled=1 AND c.retired_at_ms IS NULL AND {ACTIVE_ACCOUNT}",
            (config_id, account_id),
        ).fetchone()
        if row is None or (use_proxy and (_stopped(db) or row["subscription_status"] != "subscribed")):
            raise ChannelWorkPaused
        return row

    @asynccontextmanager
    async def _session(self, config_id: int, account_id: int, *, use_proxy: bool):
        def guard():
            with self._db() as db:
                self._check(db, config_id, account_id, use_proxy=use_proxy)

        guard()
        adapter = await self.open_adapter(account_id, use_proxy=use_proxy, before_network_action=guard)
        try:
            yield adapter, guard
        finally:
            try:
                await adapter.close()
            except Exception as exc:
                logger.warning("channel_session_close_failed account_id=%s error_class=%s", account_id, type(exc).__name__)

    async def run_forever(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception as exc:
                logger.warning("channel_worker_cycle_failed error_class=%s", type(exc).__name__)
            await asyncio.sleep(self.poll_seconds)

    async def run_once(self) -> None:
        with self._db() as db:
            config = _current_config(db)
            if config is None or not config["enabled"]:
                return
            config_id = config["id"]
            due = db.execute(
                f"SELECT s.* FROM channel_subscriptions s JOIN accounts a ON a.id=s.account_id "
                f"WHERE s.config_id=? AND s.status IN ('pending','join_uncertain') "
                f"AND s.next_attempt_ms<=? AND {ACTIVE_ACCOUNT} ORDER BY s.next_attempt_ms,s.account_id LIMIT 12",
                (config_id, _now_ms()),
            ).fetchall()
        for subscription in due:
            await self._subscribe(subscription)
        with self._db() as db:
            if _stopped(db):
                return
        history_blocked = await self._discover(config_id)
        await self._dispatch(config_id, allow_partial_history=history_blocked)

    def _subscription_state(self, account_id: int, status: str, error: str | None, *, delay: int = 0) -> None:
        now = _now_ms()
        with self._db(write=True) as db:
            db.execute(
                "UPDATE channel_subscriptions SET status=?,error_code=?,next_attempt_ms=?,joined_at_ms=? "
                "WHERE account_id=?",
                (status, error, now + delay, now if status == "subscribed" else None, account_id),
            )

    def _defer_subscription(self, account_id: int, exc: Exception) -> None:
        reason = getattr(exc, "code", None)
        if reason == "ip_assignment_changed":
            reason = "ip_assignment_unavailable"
        if reason not in {"ip_assignment_unavailable", "account_reauthentication_required"}:
            reason = "channel_subscription_unavailable"
        self._subscription_state(account_id, "pending", reason, delay=RETRY_MS)

    async def _subscribe(self, subscription: sqlite3.Row) -> None:
        account_id, config_id = subscription["account_id"], subscription["config_id"]
        uncertain = subscription["status"] == "join_uncertain"
        try:
            async with self._session(config_id, account_id, use_proxy=False) as (adapter, guard):
                with self._db() as db:
                    config = self._check(db, config_id, account_id, use_proxy=False)
                chat_id = config["chat_id"]
                if uncertain:
                    guard()
                    chat = await adapter.get_chat(chat_id)
                else:
                    guard()
                    chat = await adapter.resolve_channel(config["channel_url"])
                    chat_id = _channel_id(chat)
                    if chat_id is None:
                        self._subscription_state(account_id, "failed", "invalid_channel_destination")
                        return
                    with self._db(write=True) as db:
                        current = self._check(db, config_id, account_id, use_proxy=False)
                        if current["chat_id"] is not None and current["chat_id"] != chat_id:
                            error = "channel_destination_changed"
                        else:
                            db.execute("UPDATE channel_reaction_configs SET chat_id=? WHERE id=?", (chat_id, config_id))
                            error = None
                    if error:
                        self._subscription_state(account_id, "failed", error)
                        return
                if _channel_id(chat) == chat_id and member_proof(chat, str(chat_id)):
                    self._subscription_state(account_id, "subscribed", None)
                    uncertain = False
                    return
                if uncertain:
                    self._subscription_state(account_id, "join_uncertain", "channel_membership_unconfirmed", delay=RETRY_MS)
                    return
                guard()
                with self._db(write=True) as db:
                    self._check(db, config_id, account_id, use_proxy=False)
                    claim = db.execute(
                        "UPDATE channel_subscriptions SET status='joining',error_code=NULL "
                        "WHERE account_id=? AND status='pending'",
                        (account_id,),
                    )
                    if claim.rowcount != 1:
                        return
                try:
                    guard()
                    uncertain = True
                    joined = await adapter.join_channel(config["channel_url"])
                except ChannelWorkPaused:
                    uncertain = False
                    self._subscription_state(account_id, "pending", None)
                    return
                except DispatchPaused as exc:
                    uncertain = False
                    self._defer_subscription(account_id, exc)
                    return
                if _channel_id(joined) != chat_id:
                    self._subscription_state(account_id, "failed", "channel_destination_changed")
                    uncertain = False
                    return
                guard()
                chat = await adapter.get_chat(chat_id)
                if _channel_id(chat) == chat_id and member_proof(chat, str(chat_id)):
                    self._subscription_state(account_id, "subscribed", None)
                    uncertain = False
                    return
                self._subscription_state(account_id, "join_uncertain", "channel_membership_unconfirmed", delay=RETRY_MS)
        except asyncio.CancelledError:
            if uncertain:
                self._subscription_state(account_id, "join_uncertain", "channel_membership_unconfirmed")
            raise
        except ChannelWorkPaused:
            if uncertain:
                self._subscription_state(account_id, "join_uncertain", "channel_membership_unconfirmed", delay=RETRY_MS)
        except Exception as exc:
            if uncertain:
                self._subscription_state(account_id, "join_uncertain", "channel_membership_unconfirmed", delay=RETRY_MS)
            else:
                self._defer_subscription(account_id, exc)

    async def _discover(self, config_id: int) -> bool:
        """Return whether source errors blocked history discovery in this cycle."""
        with self._db() as db:
            sources = db.execute(
                f"SELECT s.account_id FROM channel_subscriptions s JOIN accounts a ON a.id=s.account_id "
                f"WHERE s.config_id=? AND s.status='subscribed' AND {ACTIVE_ACCOUNT} ORDER BY s.account_id",
                (config_id,),
            ).fetchall()
        if not sources:
            return False
        for _ in range(min(8, len(sources))):
            offset = self._history_source_offset % len(sources)
            account_id = sources[offset]["account_id"]
            try:
                async with self._session(config_id, account_id, use_proxy=True) as (adapter, guard):
                    for _ in range(4):
                        if await self._discover_page(config_id, account_id, adapter, guard):
                            break
                return False
            except ChannelWorkPaused:
                return False
            except Exception as exc:
                self._history_source_offset = offset + 1
                logger.info("channel_history_read_failed account_id=%s error_class=%s", account_id, type(exc).__name__)
        return True

    async def _discover_page(self, config_id: int, account_id: int, adapter, guard) -> bool:
        with self._db() as db:
            config = self._check(db, config_id, account_id, use_proxy=True)
            first_join = db.execute(
                "SELECT MIN(s.joined_at_ms) FROM channel_subscriptions s JOIN accounts a ON a.id=s.account_id "
                "WHERE s.config_id=? AND s.status='subscribed' AND a.lifecycle='active'",
                (config_id,),
            ).fetchone()[0]
        before = config["scan_before_ms"] or _now_ms() + 1
        floor = config["scan_floor_ms"] or max(config["history_through_ms"] or 0, first_join)
        page_size = config["scan_page_size"]
        guard()
        posts = await adapter.fetch_channel_posts(config["chat_id"], before_ms=before, limit=page_size)
        oldest = min((post.published_at_ms for post in posts), default=0)
        newest = max(config["scan_newest_ms"] or 0, max((post.published_at_ms for post in posts), default=0))
        complete = len(posts) < page_size or oldest < floor
        next_before, next_size = oldest + 1, HISTORY_PAGE_SIZE
        if not complete and next_before >= before:
            next_before = before
            next_size = min(page_size * 2, MAX_HISTORY_PAGE_SIZE)
            if next_size == page_size:
                raise RuntimeError("channel_history_cursor_stalled")
        with self._db(write=True) as db:
            self._check(db, config_id, account_id, use_proxy=True)
            for post in posts:
                if post.published_at_ms >= floor and getattr(post, "is_publication", True):
                    self._queue_post(db, config_id, config["chat_id"], post)
            if complete:
                db.execute(
                    "UPDATE channel_reaction_configs SET history_through_ms=MAX(COALESCE(history_through_ms,0),?),"
                    "scan_before_ms=NULL,scan_floor_ms=NULL,scan_newest_ms=NULL,scan_page_size=? WHERE id=?",
                    (newest, HISTORY_PAGE_SIZE, config_id),
                )
            else:
                db.execute(
                    "UPDATE channel_reaction_configs SET scan_before_ms=?,scan_floor_ms=?,"
                    "scan_newest_ms=?,scan_page_size=? WHERE id=?",
                    (next_before, floor, newest, next_size, config_id),
                )
        return complete

    @staticmethod
    def _queue_post(db: sqlite3.Connection, config_id: int, chat_id: int, post) -> None:
        stamp = post.published_at_ms
        db.execute(
            "INSERT OR IGNORE INTO channel_reaction_operations(config_id,account_id,chat_id,post_id,published_at_ms) "
            "SELECT s.config_id,s.account_id,?,?,? FROM channel_subscriptions s "
            "JOIN accounts a ON a.id=s.account_id WHERE s.config_id=? AND s.status='subscribed' "
            "AND a.lifecycle='active' AND s.joined_at_ms<? AND NOT EXISTS (SELECT 1 FROM channel_reaction_pauses p "
            "WHERE p.scope IN (0,s.config_id) AND p.started_at_ms<=? AND (p.resumed_at_ms IS NULL OR ?<p.resumed_at_ms))",
            (chat_id, post.id, stamp, config_id, stamp, stamp, stamp),
        )

    async def _dispatch(self, config_id: int, *, allow_partial_history: bool) -> None:
        with self._db() as db:
            rows = db.execute(
                f"SELECT o.* FROM channel_reaction_operations o JOIN accounts a ON a.id=o.account_id "
                f"JOIN channel_reaction_configs c ON c.id=o.config_id WHERE o.config_id=? "
                f"AND c.enabled=1 AND c.retired_at_ms IS NULL AND o.next_attempt_ms<=? AND {ACTIVE_ACCOUNT} "
                "AND ((o.status='queued' AND (c.scan_before_ms IS NULL OR ?) AND NOT EXISTS ("
                "SELECT 1 FROM channel_reaction_operations u WHERE u.account_id=o.account_id AND u.config_id=o.config_id "
                "AND u.status IN ('in_flight','unknown'))) OR (o.status='unknown' AND o.inspect_pending=1)) "
                "ORDER BY o.published_at_ms,o.post_id,o.account_id LIMIT 24",
                (config_id, _now_ms(), allow_partial_history),
            ).fetchall()
        deferred = set()
        for row in rows:
            account_id = row["account_id"]
            if account_id in deferred:
                continue
            try:
                async with self._session(config_id, account_id, use_proxy=True) as (adapter, guard):
                    if row["status"] == "unknown":
                        await self._inspect(row, row["emoji"], adapter, guard)
                    else:
                        blocked = await self._react(row, adapter, guard)
                        if blocked:
                            deferred.add(account_id)
            except ChannelWorkPaused:
                return
            except Exception as exc:
                deferred.add(account_id)
                with self._db(write=True) as db:
                    db.execute(
                        "UPDATE channel_reaction_operations SET next_attempt_ms=? "
                        "WHERE account_id=? AND config_id=? AND status IN ('queued','unknown')",
                        (_now_ms() + RETRY_MS, account_id, config_id),
                    )
                logger.info("channel_reaction_read_failed account_id=%s error_class=%s", account_id, type(exc).__name__)

    async def _inspect(self, row: sqlite3.Row, emoji: str | None, adapter, guard) -> bool:
        guard()
        try:
            observed = await adapter.read_channel_reaction(row["chat_id"], row["post_id"])
        except LookupError as exc:
            if str(exc) != "channel_post_unavailable":
                raise
            observed = None
        with self._db(write=True) as db:
            confirmed = bool(emoji and observed and _emoji_key(observed) == _emoji_key(emoji))
            recorded = db.execute(
                "UPDATE channel_reaction_operations SET status=?,inspect_pending=0 WHERE id=? AND status='unknown'",
                ("confirmed" if confirmed else "unknown", row["id"]),
            )
            if confirmed and recorded.rowcount == 1 and emoji:
                _remember_emoji(db, row["account_id"], emoji)
            return confirmed

    async def _react(self, row: sqlite3.Row, adapter, guard) -> bool:
        """Return whether an uncertain write blocks more work for this account."""
        guard()
        try:
            observed = await adapter.read_channel_reaction(row["chat_id"], row["post_id"])
        except LookupError as exc:
            if str(exc) != "channel_post_unavailable":
                raise
            with self._db(write=True) as db:
                db.execute("UPDATE channel_reaction_operations SET status='post_unavailable' WHERE id=? AND status='queued'",
                           (row["id"],))
            return False
        with self._db(write=True) as db:
            config = self._check(db, row["config_id"], row["account_id"], use_proxy=True)
            if has_unresolved_reactions(db, row["account_id"]):
                return True
            if observed:
                saved = db.execute(
                    "UPDATE channel_reaction_operations SET status='already_reacted',emoji=? WHERE id=? AND status='queued'",
                    (observed, row["id"]),
                )
                if saved.rowcount == 1:
                    _remember_emoji(db, row["account_id"], observed)
                return False
            prior = db.execute(
                "SELECT last_emoji FROM channel_subscriptions WHERE account_id=?", (row["account_id"],),
            ).fetchone()[0]
            choices = json.loads(config["reactions"])
            emoji = random.choice([choice for choice in choices if not prior or _emoji_key(choice) != _emoji_key(prior)])
            claim = db.execute(
                "UPDATE channel_reaction_operations SET status='in_flight',emoji=? WHERE id=? AND status='queued'",
                (emoji, row["id"]),
            )
            if claim.rowcount != 1:
                return False
        try:
            guard()
            confirmed = await adapter.write_channel_reaction(row["chat_id"], row["post_id"], emoji)
        except (ChannelWorkPaused, DispatchPaused):
            # The transport rejects these guards before writing the request.
            with self._db(write=True) as db:
                db.execute(
                    "UPDATE channel_reaction_operations SET emoji=NULL,status=CASE WHEN EXISTS "
                    "(SELECT 1 FROM channel_reaction_configs WHERE id=? AND retired_at_ms IS NULL) "
                    "THEN 'queued' ELSE 'retired' END WHERE id=? AND status='in_flight'",
                    (row["config_id"], row["id"]),
                )
            raise
        except asyncio.CancelledError:
            self._record_write(row, confirmed_emoji=None)
            raise
        except Exception:
            confirmed = None
        matched = bool(confirmed and _emoji_key(confirmed) == _emoji_key(emoji))
        self._record_write(row, confirmed_emoji=emoji if matched else None)
        if matched:
            return False
        return not await self._inspect(row, emoji, adapter, guard)

    def _record_write(self, row: sqlite3.Row, *, confirmed_emoji: str | None) -> None:
        with self._db(write=True) as db:
            recorded = db.execute(
                "UPDATE channel_reaction_operations SET status=?,inspect_pending=? WHERE id=? AND status='in_flight'",
                ("confirmed" if confirmed_emoji else "unknown", not confirmed_emoji, row["id"]),
            )
            if confirmed_emoji and recorded.rowcount == 1:
                _remember_emoji(db, row["account_id"], confirmed_emoji)
