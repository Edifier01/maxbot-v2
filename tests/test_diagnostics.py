import logging

from maxbot_v2.app import create_app


def test_safe_onboarding_events_reach_stderr_once(tmp_path, capfd):
    database = tmp_path / "maxbot.sqlite3"
    for _ in range(2):
        create_app(
            db_path=database,
            data_dir=tmp_path,
            owner_password_hash="test-hash",
            secret_key="test-secret",
        )

    logging.getLogger("maxbot_v2.onboarding").info(
        "onboarding_code_request session_id=%s route=direct auth_token_present=%s",
        "test-attempt",
        True,
    )

    output = capfd.readouterr().err
    assert output.count("onboarding_code_request session_id=test-attempt") == 1
