# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets==15.0.1"]
# ///
"""uv run e2e/socket-gateway.py (after building csqlite).
Tests the real CP HTTP/WebSocket edge with an in-memory managed actor.
The DP-to-engine path is covered separately by synch-dp's Rust tests.
"""
import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from urllib.error import HTTPError
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed


async def exercise(base, token, cancel):
    headers = {"Authorization": "Bearer " + token}
    path = "/api/orgs/acme/networks/prod/sockets"
    for url, supplied, expected in [
        (base + path, {}, 401),
        (base + path.replace("acme", "other"), headers, 404),
    ]:
        try:
            urllib.request.urlopen(urllib.request.Request(url, headers=supplied))
            raise AssertionError("request unexpectedly authorized")
        except HTTPError as error:
            assert error.code == expected
    with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers)) as response:
        assert json.load(response)["sockets"] == []
    uri = base.replace("http:", "ws:") + path + "/connect?origin=key:test&socket=echo"
    async with connect(uri, additional_headers=headers, max_size=100_000) as ws:
        assert json.loads(await ws.recv())["t"] == "socketopened"
        for data in [b"\0\xffhello", bytes(range(256)) * 256]:
            await ws.send(data)
            assert await ws.recv() == data
            await ws.send('{"t":"ack"}')
            assert json.loads(await ws.recv())["t"] == "credit"
        await ws.send('{"t":"eof"}')
        assert json.loads(await ws.recv())["t"] == "socketeof"
        assert json.loads(await ws.recv())["t"] == "socketclosed"
    async with connect(uri, additional_headers=headers) as ws:
        await ws.recv()
        await ws.send('{"t":"ack"}')
        assert json.loads(await ws.recv())["t"] == "err"
        try:
            await ws.recv()
            raise AssertionError("unsolicited credit did not close connection")
        except ConnectionClosed:
            pass
    async with connect(uri.replace("socket=echo", "socket=refuse"), additional_headers=headers) as ws:
        assert json.loads(await ws.recv())["t"] == "err"
    cancel.unlink(missing_ok=True)
    async with connect(uri, additional_headers=headers) as ws:
        assert json.loads(await ws.recv())["t"] == "socketopened"
    for _ in range(100):
        if cancel.exists():
            break
        await asyncio.sleep(0.02)
    assert cancel.exists(), "client close did not cancel its managed stream"


def main():
    with tempfile.TemporaryDirectory(prefix="socket-gateway-test-") as folder:
        folder = Path(folder)
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        ready, cancel = folder / "ready", folder / "cancel"
        env = dict(os.environ, GATEWAY_TEST_PORT=str(port),
                   GATEWAY_TEST_READY=str(ready), GATEWAY_TEST_CANCEL=str(cancel))
        with (folder / "server.log").open("w+") as log:
            server = subprocess.Popen(["gleam", "run", "-m", "gateway_fixture"],
                                      env=env, stdout=log, stderr=log, start_new_session=True)
            try:
                for _ in range(300):
                    if ready.exists():
                        break
                    if server.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    time.sleep(0.1)
                assert ready.exists(), "fixture startup timed out"
                asyncio.run(asyncio.wait_for(
                    exercise(f"http://127.0.0.1:{port}", json.loads(ready.read_text())["token"], cancel), 30))
                print("socket gateway HTTP/WS integration passed")
            except BaseException:
                log.seek(0)
                print(log.read())
                raise
            finally:
                if server.poll() is None:
                    os.killpg(server.pid, signal.SIGTERM)
                    server.wait(timeout=10)
                if ready.exists():
                    database = json.loads(ready.read_text())["database"]
                    for suffix in ("", "-wal", "-shm"):
                        Path(database + suffix).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
