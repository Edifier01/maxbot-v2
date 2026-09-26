import asyncio

from maxbot_v2.max_adapter import ProxyProbeError, probe_proxy


def test_proxy_probe_uses_http_connect_tunnel_to_pymax_host():
    async def run():
        received = []

        async def proxy(reader, writer):
            received.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await reader.read()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(proxy, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            await probe_proxy(f"http://127.0.0.1:{port}", timeout=1)
        finally:
            server.close()
            await server.wait_closed()

        return received[0]

    request = asyncio.run(run())

    assert request.startswith(b"CONNECT api2.oneme.ru:443 HTTP/1.1\r\n")
    assert b"Proxy-Authorization" not in request


def test_proxy_probe_rejects_a_failed_socks5_tunnel_without_echoing_credentials():
    async def run():
        async def proxy(reader, writer):
            greeting = await reader.readexactly(4)
            assert greeting == b"\x05\x02\x00\x02"
            writer.write(b"\x05\x02")
            await writer.drain()
            version, username_length = await reader.readexactly(2)
            assert version == 1
            await reader.readexactly(username_length)
            password_length = (await reader.readexactly(1))[0]
            await reader.readexactly(password_length)
            writer.write(b"\x01\x01")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(proxy, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            try:
                await probe_proxy(f"socks5://private:secret@127.0.0.1:{port}", timeout=1)
            except ProxyProbeError as error:
                assert error.code == "proxy_authentication_failed"
                assert "private" not in str(error)
                assert "secret" not in str(error)
            else:
                raise AssertionError("unavailable proxy authentication must fail")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_proxy_probe_timeout_covers_tunnel_handshake():
    async def run():
        async def silent_proxy(reader, writer):
            await reader.read(1)
            await asyncio.sleep(1)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(silent_proxy, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            try:
                await probe_proxy(f"http://127.0.0.1:{port}", timeout=0.02)
            except ProxyProbeError as error:
                assert error.code == "proxy_check_timeout"
            else:
                raise AssertionError("a stalled tunnel handshake must time out")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())
