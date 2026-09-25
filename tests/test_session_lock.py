import asyncio

from maxbot_v2.session_lock import AccountSessionLocks


def test_one_account_session_is_serialized_while_other_accounts_run_in_parallel():
    async def scenario():
        locks = AccountSessionLocks()
        active_by_account: dict[int, int] = {}
        peak_by_account: dict[int, int] = {}

        async def use_session(account_id: int):
            async with locks.for_account(account_id):
                active_by_account[account_id] = active_by_account.get(account_id, 0) + 1
                peak_by_account[account_id] = max(peak_by_account.get(account_id, 0), active_by_account[account_id])
                await asyncio.sleep(0.02)
                active_by_account[account_id] -= 1

        await asyncio.gather(use_session(1), use_session(1), use_session(2))
        return peak_by_account

    peak_by_account = asyncio.run(scenario())
    assert peak_by_account[1] == 1
    assert peak_by_account[2] == 1
