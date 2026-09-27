import asyncio

from maxbot_v2.onboarding import WebAuthProviders


def test_web_provider_waits_for_otp_once_and_updates_state():
    updates = []
    provider = WebAuthProviders(lambda state, hint: updates.append((state, hint)), session_id="test", account_id=1, ip_id=2)

    async def run():
        task = asyncio.create_task(provider.get_code("+79990000000"))
        await asyncio.sleep(0)
        assert provider.waiting_for == "code"
        provider.codes.put_nowait("123456")
        assert await task == "123456"

    asyncio.run(run())
    assert updates[0][0] == "waiting_code"
    assert updates[-1][0] == "verifying_code"
