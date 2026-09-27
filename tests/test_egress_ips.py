from concurrent.futures import ThreadPoolExecutor

from maxbot_v2.db import connect, initialize
from maxbot_v2.egress import assign_ip, bootstrap_ips, probe_address, refresh_ips
from maxbot_v2.message_pool import replace_message_pool
from maxbot_v2.scheduling import create_weekly_slot


def test_assignment_uses_enabled_least_loaded_server_ip():
    db = connect(":memory:")
    initialize(db)
    db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'group','link')")
    db.execute("INSERT INTO accounts(id,group_id,phone,full_name) VALUES(1,1,'+79990000001','A')")
    db.execute("INSERT INTO accounts(id,group_id,phone,full_name) VALUES(2,1,'+79990000002','B')")
    db.execute("INSERT INTO server_ips(address,enabled,available) VALUES('62.109.10.109',1,1)")
    db.execute("INSERT INTO server_ips(address,enabled,available) VALUES('62.109.20.186',1,1)")

    assert assign_ip(db, 1) == '62.109.20.186'
    assert assign_ip(db, 2) == '62.109.20.186'


def test_equal_load_ip_assignments_rotate_from_the_least_recently_used_ip():
    db = connect(":memory:")
    initialize(db)
    group_id = db.execute("INSERT INTO groups(name,invite_link) VALUES('group','link')").lastrowid
    db.execute("INSERT INTO server_ips(id,address,enabled,available) VALUES(1,'62.109.20.186',1,1)")
    db.execute("INSERT INTO server_ips(id,address,enabled,available) VALUES(2,'62.109.20.187',1,1)")

    selected = []
    for index in range(3):
        account_id = db.execute(
            "INSERT INTO accounts(group_id,phone,full_name) VALUES(?,?,?)",
            (group_id, f'+7999000000{index}', 'guest'),
        ).lastrowid
        selected.append(assign_ip(db, account_id))

    assert selected == ['62.109.20.186', '62.109.20.187', '62.109.20.186']


def test_ip_bootstrap_does_not_assign_deleted_accounts():
    db = connect(":memory:")
    initialize(db)
    group_id = db.execute("INSERT INTO groups(name,invite_link) VALUES('group','link')").lastrowid
    active_id = db.execute(
        "INSERT INTO accounts(group_id,phone,full_name) VALUES(?, '+79990000001','active')", (group_id,),
    ).lastrowid
    deleted_id = db.execute(
        "INSERT INTO accounts(group_id,phone,full_name,lifecycle) VALUES(?, 'deleted:2','','deleted')", (group_id,),
    ).lastrowid

    bootstrap_ips(db, addresses={"62.109.20.186"}, probe=lambda _address: True)

    assert db.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (active_id,)).fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=?", (deleted_id,)).fetchone()[0] == 0


def test_concurrent_transactions_keep_new_ip_assignments_balanced(tmp_path):
    path = tmp_path / "parallel-ip.db"
    db = connect(path)
    initialize(db)
    group_id = db.execute("INSERT INTO groups(name,invite_link) VALUES('group','https://max.ru/join/test')").lastrowid
    db.executemany(
        "INSERT INTO server_ips(address,enabled,available) VALUES(?,1,1)",
        [("62.109.20.186",), ("62.109.20.187",)],
    )
    db.close()

    def add_account(index):
        connection = connect(path)
        connection.execute("BEGIN IMMEDIATE")
        account_id = connection.execute(
            "INSERT INTO accounts(group_id,phone,full_name,status) VALUES(?,?,?,'pending')",
            (group_id, f"+79990000{index:03d}", "guest"),
        ).lastrowid
        selected = assign_ip(connection, account_id)
        connection.commit()
        connection.close()
        return selected

    with ThreadPoolExecutor(max_workers=8) as pool:
        selected = list(pool.map(add_account, range(8)))

    assert selected.count("62.109.20.186") == 4
    assert selected.count("62.109.20.187") == 4
    db = connect(path)
    assert db.execute("SELECT COUNT(*) FROM ip_assignments").fetchone()[0] == 8
    assert db.execute("SELECT COUNT(*) FROM server_ips WHERE last_assigned_at IS NOT NULL").fetchone()[0] == 2
    db.close()


def test_refresh_excludes_legacy_ip_and_leaves_new_ip_disabled():
    db = connect(":memory:")
    initialize(db)
    rows = refresh_ips(db, addresses={"62.109.10.109", "62.109.20.186", "172.18.0.1"}, probe=lambda _: True)
    assert [(row["address"], row["enabled"]) for row in rows] == [("62.109.20.186", 0)]


def test_refresh_shows_discovered_ip_with_failed_egress_as_unavailable():
    db = connect(":memory:")
    initialize(db)
    rows = refresh_ips(db, addresses={"62.109.20.186"}, probe=lambda _address: False)
    assert [(row["address"], row["enabled"], row["available"]) for row in rows] == [("62.109.20.186", 0, 0)]


def test_probe_binds_source_ip_and_rejects_mismatched_socket(monkeypatch):
    seen = []

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def getsockname(self):
            return ("62.109.20.187", 1234)

    def fake_connect(target, *, timeout, source_address):
        seen.append((target, timeout, source_address))
        return Socket()

    monkeypatch.setattr("maxbot_v2.egress.socket.create_connection", fake_connect)
    assert not probe_address("62.109.20.186")
    assert seen == [(('api2.oneme.ru', 443), 5, ('62.109.20.186', 0))]


def test_bootstrap_preserves_owner_disable_on_restart():
    db = connect(":memory:")
    initialize(db)
    db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'group','link')")
    db.execute("INSERT INTO accounts(id,group_id,phone,full_name) VALUES(1,1,'+79990000001','A')")
    bootstrap_ips(db, addresses={"62.109.20.186"}, probe=lambda _: True)
    assert db.execute("SELECT COUNT(*) FROM ip_assignments").fetchone()[0] == 1
    db.execute("UPDATE server_ips SET enabled=0")
    bootstrap_ips(db, addresses={"62.109.20.186"}, probe=lambda _: True)
    assert db.execute("SELECT enabled FROM server_ips").fetchone()[0] == 0


def test_bootstrap_keeps_legacy_proxy_and_session_metadata():
    db = connect(":memory:")
    initialize(db)
    db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'group','link')")
    db.execute("INSERT INTO accounts(id,group_id,phone,full_name,session_generation) VALUES(1,1,'+79990000001','A',3)")
    db.execute("INSERT INTO proxies(id,group_id,url_ciphertext,label,position) VALUES(1,1,'encrypted','old',0)")
    db.execute("INSERT INTO proxy_assignments(account_id,proxy_id) VALUES(1,1)")
    bootstrap_ips(db, addresses={"62.109.20.186"}, probe=lambda _address: True)
    initialize(db)
    bootstrap_ips(db, addresses={"62.109.20.186"}, probe=lambda _address: True)
    assert db.execute("SELECT session_generation FROM accounts WHERE id=1").fetchone()[0] == 3
    assert db.execute("SELECT proxy_id FROM proxy_assignments WHERE account_id=1").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM ip_assignments WHERE account_id=1").fetchone()[0] == 1


def test_disappeared_ip_blocks_slot_and_restoration_requeues_it():
    db = connect(":memory:")
    initialize(db)
    db.execute("INSERT INTO groups(id,name,invite_link) VALUES(1,'group','link')")
    db.execute("INSERT INTO accounts(id,group_id,phone,full_name,status) VALUES(1,1,'+79990000001','A','active')")
    db.execute("INSERT INTO server_ips(id,address,enabled,available) VALUES(1,'62.109.20.186',1,1)")
    db.execute("INSERT INTO ip_assignments(account_id,ip_id) VALUES(1,1)")
    version = replace_message_pool(db, ["test"])
    create_weekly_slot(db, account_id=1, week_start="2099-01-05", scheduled_date="2099-01-05", text="test", message_version_id=version)
    refresh_ips(db, addresses=set(), probe=lambda _address: True)
    assert db.execute("SELECT status,error_code FROM weekly_slots").fetchone()[:] == ("blocked", "ip_assignment_unavailable")
    refresh_ips(db, addresses={"62.109.20.186"}, probe=lambda _address: True)
    assert db.execute("SELECT status,error_code FROM weekly_slots").fetchone()[:] == ("queued", None)
