import asyncio

from maxbot_v2.db import connect, initialize
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.planning import prepare_week
from maxbot_v2.workers import GroupWorkerManager
from datetime import date


def test_ten_groups_one_hundred_accounts_and_unique_worker_leases(tmp_path):
    path = tmp_path / "scale.sqlite3"
    db = connect(path)
    initialize(db)
    db.execute("INSERT INTO server_ips(id,address,enabled,available) VALUES(1,'62.109.20.186',1,1)")
    for group_id in range(1, 11):
        db.execute("INSERT INTO groups(id,name,invite_link,chat_id) VALUES(?,?,?,?)", (group_id, f"Group {group_id}", f"https://max.ru/invite/{group_id}", str(group_id)))
        for account_index in range(10):
            account_id = (group_id - 1) * 10 + account_index + 1
            db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status) VALUES(?,?,?,?, 'active')", (account_id, group_id, f"+700000{account_id:05d}", f"Account {account_id}"))
            db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(?,1)", (account_id,))
    replace_message_pool(db, [f"message-{i}" for i in range(100)])
    db.execute("UPDATE settings SET value='00:00-00:01' WHERE key='send_windows_weekday'")
    db.execute("UPDATE settings SET value='00:00-00:01' WHERE key='send_windows_weekend'")
    db.execute("UPDATE settings SET value='1' WHERE key='global_stop'")
    assert prepare_week(db, date(2026, 9, 21)) == 100
    counts = [row[0] for row in db.execute("SELECT COUNT(*) FROM weekly_slots GROUP BY group_id")]
    weekdays = [row[0] for row in db.execute("SELECT COUNT(*) FROM accounts GROUP BY send_weekday")]
    assert counts == [10] * 10
    assert max(weekdays) - min(weekdays) <= 1
    db.close()

    async def no_send(_slot):
        raise AssertionError("window prevents test provider use")

    async def scenario():
        first = GroupWorkerManager(path, no_send, poll_seconds=0.01)
        second = GroupWorkerManager(path, no_send, poll_seconds=0.01)
        await first.start()
        await second.start()
        await asyncio.sleep(0.05)
        check = connect(path)
        try:
            assert check.execute("SELECT COUNT(*) FROM group_worker_leases").fetchone()[0] == 10
            assert check.execute("SELECT COUNT(DISTINCT group_id) FROM group_worker_leases").fetchone()[0] == 10
        finally:
            check.close()
        await first.stop()
        await second.stop()

    asyncio.run(scenario())
