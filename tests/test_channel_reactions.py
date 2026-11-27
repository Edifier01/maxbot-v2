import asyncio
from contextlib import closing
from types import SimpleNamespace

import pytest

from maxbot_v2 import channel_reactions as channels
from maxbot_v2.db import connect, initialize
from maxbot_v2.sender import DispatchPaused


def database(tmp_path):
    path = tmp_path / "channel-reactions.sqlite3"
    with closing(connect(path)) as db:
        initialize(db)
        db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'Test','https://max.ru/join/test')")
    return path


def add_account(db, account_id, *, group_confirmed=True, existing=False):
    db.execute(
        "INSERT INTO accounts(id,group_id,phone,full_name,status,auth_state,ever_authenticated) VALUES(?,1,?,?,?,?,?)",
        (account_id, f"+79990000{account_id:03d}", "Test", "active" if group_confirmed else "needs_membership",
         "authenticated", int(existing)),
    )
    channels.enroll_channel_account(db, account_id)
    db.execute("UPDATE accounts SET ever_authenticated=1 WHERE id=?", (account_id,))


def configure(db, *, channel_url="https://max.ru/test_channel", enabled=True):
    return channels.save_channel_reaction_settings(db, enabled=enabled, channel_url=channel_url, reactions=["👍", "❤️"])


def set_run(db, stopped):
    db.execute("UPDATE settings SET value=? WHERE key='global_stop'", (str(int(stopped)),))
    channels.set_channel_reactions_run(db, stopped=stopped)


class FakeMax:
    def __init__(self):
        self.chat_id = -42
        self.chat_type = "CHANNEL"
        self.chat_access = "PUBLIC"
        self.subscribed = set()
        self.joins = []
        self.history = []
        self.writes = []
        self.reactions = {}
        self.timeout = False
        self.no_proxy_for = set()
        self.join_pause = None
        self.write_pause = None
        self.failed_confirmation = False
        self.unavailable_history_before = 0

    async def open_adapter(self, account_id, *, use_proxy, before_network_action):
        before_network_action()
        if use_proxy and account_id in self.no_proxy_for:
            raise OSError("proxy is gone")
        return FakeAdapter(self, account_id, use_proxy, before_network_action)


class FakeAdapter:
    def __init__(self, max_server, account_id, use_proxy, guard):
        self.max = max_server
        self.account_id = account_id
        self.use_proxy = use_proxy
        self.guard = guard

    async def resolve_channel(self, _url):
        self.guard()
        assert not self.use_proxy
        return self._chat(self.max.chat_id)

    async def get_chat(self, chat_id):
        self.guard()
        if self.max.failed_confirmation:
            raise DispatchPaused("ip_assignment_changed")
        return self._chat(chat_id)

    def _chat(self, chat_id):
        subscribed = self.account_id in self.max.subscribed
        return SimpleNamespace(id=chat_id, type=self.max.chat_type, status="active" if subscribed else "left",
                               join_time=100 if subscribed else 0, access=self.max.chat_access)

    async def join_channel(self, _url):
        self.guard()
        assert not self.use_proxy
        if self.max.join_pause:
            raise self.max.join_pause
        self.max.joins.append(self.account_id)
        self.max.subscribed.add(self.account_id)
        return self._chat(self.max.chat_id)

    async def fetch_channel_posts(self, chat_id, *, before_ms, limit):
        self.guard()
        assert self.use_proxy and chat_id == self.max.chat_id
        if before_ms <= self.max.unavailable_history_before:
            raise OSError("history unavailable")
        return [post for post in reversed(self.max.history) if post.published_at_ms < before_ms][:limit]

    async def read_channel_reaction(self, chat_id, post_id):
        self.guard()
        assert self.use_proxy and chat_id == self.max.chat_id
        return self.max.reactions.get((self.account_id, post_id))

    async def write_channel_reaction(self, chat_id, post_id, emoji):
        self.guard()
        assert self.use_proxy and chat_id == self.max.chat_id
        if self.max.write_pause:
            raise self.max.write_pause
        self.max.writes.append((self.account_id, post_id, emoji))
        if self.max.timeout:
            raise TimeoutError
        self.max.reactions[self.account_id, post_id] = emoji
        return emoji

    async def close(self):
        pass


def post(message_id, stamp, *, is_publication=True):
    return SimpleNamespace(id=message_id, published_at_ms=stamp, is_publication=is_publication)


def test_configuration_and_enrollment_are_additive(tmp_path):
    path = database(tmp_path)
    with closing(connect(path)) as db:
        assert channels.get_channel_reaction_settings(db) == {
            "enabled": False, "channel_url": "", "reactions": [], "stopped": True,
        }
        for url in ("https://other.example/test", "https://max.ru/join/secret", "https://max.ru/test?token=hidden"):
            with pytest.raises(ValueError, match="invalid_channel_url"):
                configure(db, channel_url=url)
        with pytest.raises(ValueError, match="invalid_channel_reactions"):
            channels.save_channel_reaction_settings(db, enabled=True, channel_url="https://max.ru/channel", reactions=["👍", "👍"])
        with pytest.raises(ValueError, match="invalid_channel_reactions"):
            channels.save_channel_reaction_settings(db, enabled=True, channel_url="https://max.ru/channel", reactions=["❤", "❤️"])
        configure(db)
        add_account(db, 1, existing=True)
        add_account(db, 2, group_confirmed=False)
        initialize(db)
        initialize(db)
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert channels.channel_subscription_for_accounts(db, 1) == {
            2: {"channel_subscription_status": "pending", "channel_subscription_error": None},
        }
        configure(db, channel_url="https://max.ru/replacement")
        assert channels.channel_subscription_for_accounts(db, 1)[2]["channel_subscription_status"] == "retired"


def test_settings_accept_separate_joined_emoji_and_reject_concatenated_reactions(tmp_path):
    with closing(connect(database(tmp_path))) as db:
        link = "https://max.ru/test_channel"
        with pytest.raises(ValueError, match="invalid_channel_reactions"):
            channels.save_channel_reaction_settings(db, enabled=True, channel_url=link, reactions=["👍👍", "🔥🔥"])
        reactions = ["👍🏽", "👩🏽‍💻", "🇷🇺"]
        saved = channels.save_channel_reaction_settings(db, enabled=True, channel_url=link, reactions=reactions)
        assert saved["reactions"] == reactions


def test_subscribe_after_group_confirmation_reject_wrong_type_and_preserve_group(tmp_path, monkeypatch):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1, group_confirmed=False)
        asyncio.run(worker.run_once())
        assert not server.joins
        db.execute("UPDATE accounts SET status='active' WHERE id=1")
        asyncio.run(worker.run_once())
        assert server.joins == [1]
        assert channels.channel_subscription_for_accounts(db, 1)[1]["channel_subscription_status"] == "subscribed"
        add_account(db, 2)
        server.chat_type = "CHAT"
        asyncio.run(worker.run_once())
        assert server.joins == [1]
        assert channels.channel_subscription_for_accounts(db, 1)[2] == {
            "channel_subscription_status": "failed", "channel_subscription_error": "invalid_channel_destination",
        }
        assert db.execute("SELECT status FROM accounts WHERE id=2").fetchone()[0] == "active"
        add_account(db, 3)
        server.chat_type, server.chat_access = "CHANNEL", "PRIVATE"
        asyncio.run(worker.run_once())
        assert server.joins == [1]
        assert channels.channel_subscription_for_accounts(db, 1)[3] == {
            "channel_subscription_status": "failed", "channel_subscription_error": "invalid_channel_destination",
        }


def test_new_publications_manual_pause_and_restart(tmp_path, monkeypatch):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1)
        add_account(db, 2)
        asyncio.run(worker.run_once())
        set_run(db, False)
        server.history = [post(1, 900), post(2, 1_100), post(3, 1_200, is_publication=False), post(4, 1_300)]
        server.reactions[2, 2] = "🔥"
        clock = 1_400
        asyncio.run(worker.run_once())
        assert len(server.writes) == 3
        assert {msg for _, msg, _ in server.writes} == {2, 4}
        assert server.reactions[2, 2] == "🔥"
        assert server.reactions[1, 2] != server.reactions[1, 4]

        # A process restart writes the temporary gate but does not open a pause interval.
        db.execute("UPDATE settings SET value='1' WHERE key='global_stop'")
        channels.recover_channel_reactions(db)
        server.history.append(post(5, 1_500))
        clock = 1_600
        asyncio.run(worker.run_once())
        assert len(server.writes) == 3
        set_run(db, False)
        asyncio.run(channels.ChannelReactionWorker(path, server.open_adapter).run_once())
        assert len(server.writes) == 5

        clock = 1_700
        set_run(db, True)
        clock = 1_900
        set_run(db, False)
        server.history.extend([post(6, 1_800), post(7, 2_000)])
        clock = 2_100
        asyncio.run(worker.run_once())
        asyncio.run(worker.run_once())
        assert [msg for _, msg, _ in server.writes] == [2, 4, 4, 5, 5, 7, 7]


def test_unknown_is_never_written_twice_and_can_be_reconciled(tmp_path, monkeypatch):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1)
        asyncio.run(worker.run_once())
        set_run(db, False)
        server.history.extend([post(1, 1_100), post(2, 1_150)])
        clock = 1_200
        server.no_proxy_for.add(1)
        asyncio.run(worker.run_once())
        assert not server.writes
        server.no_proxy_for.clear()
        server.timeout = True
        clock = 100_000
        asyncio.run(worker.run_once())
        assert len(server.writes) == 1
        channels.recover_channel_reactions(db)
        clock = 200_000
        asyncio.run(worker.run_once())
        assert len(server.writes) == 1
        assert channels.has_unresolved_reactions(db, 1)
        [operation] = channels.list_channel_reaction_reviews(db)
        assert operation["post_id"] == "1"
        assert operation["chat_id"] == "-42"
        assert operation["channel_url"] == "https://max.ru/test_channel"
        assert operation["published_at_ms"] == 1_100
        assert channels.reconcile_channel_reaction(db, operation["id"], outcome="not_applied")
        assert not channels.has_unresolved_reactions(db, 1)
        server.timeout = False
        asyncio.run(worker.run_once())
        assert [post_id for _, post_id, _ in server.writes] == [1, 2]


@pytest.mark.parametrize("page_count", [50, 70])
def test_full_history_pages_overlap_and_keep_same_timestamp_publications(tmp_path, monkeypatch, page_count):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1)
        asyncio.run(worker.run_once())
        set_run(db, False)
        server.history = [
            post(message_id, 1_200, is_publication=message_id % 5 == 0)
            for message_id in range(1, page_count + 1)
        ]
        clock = 1_300
        asyncio.run(worker.run_once())
        expected = list(range(5, page_count + 1, 5))
        assert [post_id for _, post_id, _ in server.writes] == expected
        asyncio.run(channels.ChannelReactionWorker(path, server.open_adapter).run_once())
        assert [post_id for _, post_id, _ in server.writes] == expected


def test_interrupted_write_is_verified_by_read_after_restart(tmp_path, monkeypatch):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1)
        asyncio.run(worker.run_once())
        set_run(db, False)
        server.history = [post(1, 1_100), post(2, 1_200)]
        config_id = db.execute("SELECT id FROM channel_reaction_configs").fetchone()[0]
        db.execute(
            "INSERT INTO channel_reaction_operations(config_id,account_id,chat_id,post_id,published_at_ms,status,emoji) "
            "VALUES(?,1,-42,1,1100,'in_flight','❤️')",
            (config_id,),
        )
        server.reactions[1, 1] = "❤"
        channels.recover_channel_reactions(db)
        assert channels.has_unresolved_reactions(db, 1)
        clock = 1_300
        asyncio.run(worker.run_once())
        assert not channels.has_unresolved_reactions(db, 1)
        asyncio.run(worker.run_once())
        assert server.writes == [(1, 2, "👍")]


@pytest.mark.parametrize("preflight_pause", [DispatchPaused("ip_assignment_changed"), channels.ChannelWorkPaused()])
def test_join_and_reaction_preflight_pauses_are_safely_retried(tmp_path, monkeypatch, preflight_pause):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1)
        server.join_pause = preflight_pause
        asyncio.run(worker.run_once())
        assert channels.channel_subscription_for_accounts(db, 1)[1]["channel_subscription_status"] == "pending"
        assert server.joins == []
        server.join_pause = None
        clock = 100_000
        asyncio.run(worker.run_once())
        assert server.joins == [1]

        set_run(db, False)
        clock = 100_200
        server.history.append(post(1, 100_100))
        server.write_pause = preflight_pause
        asyncio.run(worker.run_once())
        assert not channels.has_unresolved_reactions(db, 1)
        assert not server.writes
        assert tuple(db.execute("SELECT status,emoji FROM channel_reaction_operations").fetchone()) == ("queued", None)

        server.write_pause = None
        clock = 200_000
        asyncio.run(worker.run_once())
        assert [post_id for _, post_id, _ in server.writes] == [1]


def test_membership_confirmation_pause_after_sent_join_remains_uncertain(tmp_path, monkeypatch):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1)
        server.failed_confirmation = True
        asyncio.run(worker.run_once())
        assert channels.channel_subscription_for_accounts(db, 1)[1]["channel_subscription_status"] == "join_uncertain"

        server.failed_confirmation = False
        clock = 100_000
        asyncio.run(worker.run_once())
        assert server.joins == [1]
        assert channels.channel_subscription_for_accounts(db, 1)[1]["channel_subscription_status"] == "subscribed"


def test_known_publications_continue_during_history_page_failure(tmp_path, monkeypatch):
    path = database(tmp_path)
    clock = 1_000
    monkeypatch.setattr(channels, "_now_ms", lambda: clock)
    server = FakeMax()
    worker = channels.ChannelReactionWorker(path, server.open_adapter)
    with closing(connect(path)) as db:
        configure(db)
        add_account(db, 1)
        asyncio.run(worker.run_once())
        set_run(db, False)
        clock = 2_000
        server.history = [post(message_id, 1_100 + message_id) for message_id in range(1, 52)]
        server.unavailable_history_before = 1_200

        asyncio.run(worker.run_once())
        assert [post_id for _, post_id, _ in server.writes] == list(range(2, 26))
        assert db.execute("SELECT scan_before_ms FROM channel_reaction_configs").fetchone()[0] == 1_103

        asyncio.run(worker.run_once())
        assert [post_id for _, post_id, _ in server.writes] == list(range(2, 50))
        assert db.execute("SELECT scan_before_ms FROM channel_reaction_configs").fetchone()[0] == 1_103

        server.unavailable_history_before = 0
        asyncio.run(channels.ChannelReactionWorker(path, server.open_adapter).run_once())
        assert [post_id for _, post_id, _ in server.writes] == list(range(2, 50)) + [1, 50, 51]
        assert db.execute("SELECT scan_before_ms FROM channel_reaction_configs").fetchone()[0] is None
