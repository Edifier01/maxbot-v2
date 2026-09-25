from datetime import date

import pytest

from maxbot_v2.db import connect, initialize
from maxbot_v2.scheduling import assign_weekday, monday_of
from maxbot_v2.message_pool import MessagePool


@pytest.fixture
def db(tmp_path):
    connection = connect(tmp_path / "app.db")
    initialize(connection)
    yield connection
    connection.close()


def test_weekday_assignment_balances_and_is_stable(db):
    db.execute("INSERT INTO groups(id, name, invite_link) VALUES (1, 'G', 'https://max.ru/join/a')")
    db.executemany(
        "INSERT INTO accounts(id, group_id, phone, full_name) VALUES (?, 1, ?, 'Name')",
        [(i, f"+700000000{i:02d}") for i in range(1, 9)],
    )
    assert [assign_weekday(db, i) for i in range(1, 9)] == [0, 1, 2, 3, 4, 5, 6, 0]
    assert assign_weekday(db, 1) == 0


def test_week_is_monday_based():
    assert monday_of(date(2026, 9, 27)) == date(2026, 9, 21)


def test_proxy_assignment_uses_least_loaded_and_persists(db):
    db.execute("INSERT INTO groups(id, name, invite_link) VALUES (1, 'G', 'https://max.ru/join/a')")
    db.execute("INSERT INTO proxies(id, group_id, url_ciphertext, label, position) VALUES (1, 1, 'cipher-a', 'a:1', 0), (2, 1, 'cipher-b', 'b:2', 1)")
    db.execute("INSERT INTO accounts(id, group_id, phone, full_name, status) VALUES (1, 1, '+70000000001', 'One', 'active'), (2, 1, '+70000000002', 'Two', 'active'), (3, 1, '+70000000003', 'Three', 'active')")
    from maxbot_v2.scheduling import assign_proxy

    assert assign_proxy(db, 1, 1) == 1
    assert assign_proxy(db, 2, 1) == 2
    assert assign_proxy(db, 3, 1) == 1
    assert assign_proxy(db, 1, 1) == 1


def test_weekly_slot_is_unique_per_account_and_freezes_text(db):
    db.execute("INSERT INTO groups(id, name, invite_link) VALUES (1, 'G', 'https://max.ru/join/a')")
    db.execute("INSERT INTO accounts(id, group_id, phone, full_name, status) VALUES (1, 1, '+70000000001', 'One', 'active')")
    db.execute("INSERT INTO message_versions(id, created_at, checksum) VALUES (1, 'now', 'checksum')")
    from maxbot_v2.scheduling import create_weekly_slot

    first = create_weekly_slot(db, account_id=1, week_start="2026-09-21", scheduled_date="2026-09-21", text="A")
    second = create_weekly_slot(db, account_id=1, week_start="2026-09-21", scheduled_date="2026-09-21", text="B")
    assert first["slot_id"] == second["slot_id"]
    assert second["text"] == "A"


def test_message_pool_draws_without_replacement_then_cycles(db):
    pool = MessagePool(db)
    pool.replace(["one", "two", "three"])
    first_cycle = [pool.draw() for _ in range(3)]
    assert set(first_cycle) == {"one", "two", "three"}
    assert pool.draw() in {"one", "two", "three"}


def test_message_pool_rejects_empty_or_duplicate_entries(db):
    pool = MessagePool(db)
    with pytest.raises(ValueError, match="empty_message_pool"):
        pool.replace(["", "  "])
    with pytest.raises(ValueError, match="duplicate_message"):
        pool.replace(["same", "same"])
