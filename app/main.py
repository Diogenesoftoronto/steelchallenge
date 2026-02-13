"""
Proxy Server - Steel Challenge Solution

An authenticated HTTP/HTTPS proxy server with bandwidth and site analytics.

Usage:
    uv run python app/main.py [port]

Examples:
    uv run python app/main.py 8002

    curl -x http://localhost:8002 --proxy-user testuser:testpass http://example.com
    curl -x http://localhost:8002 --proxy-user testuser:testpass https://example.com
    curl http://localhost:8002/metrics

Default user: testuser / testpass
"""

import hashlib
import os
import sqlite3
import sys
from asyncio import (
    FIRST_COMPLETED,
    CancelledError,
    Lock,
    Protocol,
    StreamReader,
    create_task,
    gather,
    get_running_loop,
    open_connection,
    wait,
)
from base64 import b64decode
from functools import partial
from json import dumps
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout, web

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(
            password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
        )
        return dk.hex() == dk_hex
    except Exception:
        return False


def format_bytes(n: int) -> str:
    if n < 1000:
        return f"{n}B"
    elif n < 1_000_000:
        return f"{round(n / 1024, 2)}KB"
    elif n < 1_000_000_000:
        return f"{round(n / 1048576, 2)}MB"
    else:
        return f"{round(n / 1073741824, 2)}GB"


def _db_get_metrics(conn) -> dict:
    row = conn.execute("SELECT COALESCE(SUM(total_bytes), 0) FROM bandwidth").fetchone()
    total = row[0] if row else 0
    sites = conn.execute(
        "SELECT site, visits FROM top_sites ORDER BY visits DESC"
    ).fetchall()
    return {
        "bandwidth_usage": format_bytes(total),
        "top_sites": [{"url": s[0], "visits": s[1]} for s in sites],
    }


def _db_authenticate(conn, username: str, password: str) -> bool:
    result = conn.execute(
        "SELECT secret FROM users WHERE username = ?", (username,)
    ).fetchone()
    if result is None:
        return False
    return verify_password(password, result[0])


def _db_track_site(conn, host: str):
    # this 'on conflict' will run every single time a site is visited except the first time, i think this is a slow way to track sites, it is like way faster to just insert and then count.
    conn.execute(
        "INSERT INTO top_sites (site, visits) VALUES (?, 1) "
        "ON CONFLICT (site) DO UPDATE SET visits = top_sites.visits + 1",
        (host,),
    )


def _db_track_bandwidth(conn, incoming: int, outgoing: int):
    conn.execute(
        "INSERT INTO bandwidth VALUES (?, ?, ?)",
        (incoming, outgoing, incoming + outgoing),
    )


async def run_db(app, func, *args):
    loop = get_running_loop()
    async with app["db_lock"]:
        return await loop.run_in_executor(None, partial(func, app["db_conn"], *args))


def proxy_auth_required():
    return web.Response(
        status=407,
        headers={"Proxy-Authenticate": 'Basic realm="Proxy"'},
        text=dumps({"error": "Proxy authentication required"}),
        content_type="application/json",
    )


async def authenticate(app, request):
    proxy_auth = request.headers.get("Proxy-Authorization")
    if not proxy_auth or not proxy_auth.startswith("Basic "):
        return False, proxy_auth_required()

    try:
        credentials = b64decode(proxy_auth[6:]).decode()
        username, password = credentials.split(":", 1)
    except Exception:
        return False, proxy_auth_required()

    if not await run_db(app, _db_authenticate, username, password):
        return False, proxy_auth_required()

    return True, None


async def handle_metrics(request):
    return web.json_response(await run_db(request.app, _db_get_metrics))


class TunnelProtocol(Protocol):
    def __init__(self):
        self.reader = StreamReader()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.reader.feed_data(data)

    def connection_lost(self, exc):
        self.reader.feed_eof()


async def handle_connect(request):
    app = request.app

    success, error = await authenticate(app, request)
    if not success:
        return error

    host_port = request.path_qs
    if host_port.startswith("/"):
        host_port = host_port[1:]
    if not host_port:
        host_port = request.headers.get("Host", "")
    host_port = host_port.strip()

    if host_port.startswith("[") and "]" in host_port:
        host = host_port[1 : host_port.index("]")]
        tail = host_port[host_port.index("]") + 1 :]
        port = int(tail[1:]) if tail.startswith(":") and tail[1:].isdigit() else 443
    elif ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        port = int(port_str) if port_str.isdigit() else 443
    else:
        host = host_port
        port = 443

    await run_db(app, _db_track_site, host)

    try:
        remote_reader, remote_writer = await open_connection(host, port)
    except Exception as e:
        return web.Response(
            status=502,
            text=dumps({"error": f"Cannot connect to {host}:{port}: {e}"}),
            content_type="application/json",
        )

    transport = request.transport
    if transport is None:
        remote_writer.close()
        return web.Response(status=502, text="Transport unavailable")

    transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    tunnel = TunnelProtocol()
    transport.set_protocol(tunnel)
    tunnel.transport = transport

    bytes_up = 0
    bytes_down = 0

    async def pipe_up():
        nonlocal bytes_up
        try:
            while True:
                data = await tunnel.reader.read(65536)
                if not data:
                    break
                bytes_up += len(data)
                remote_writer.write(data)
                await remote_writer.drain()
        except (ConnectionError, CancelledError):
            pass
        finally:
            try:
                remote_writer.close()
            except Exception:
                pass

    async def pipe_down():
        nonlocal bytes_down
        try:
            while True:
                data = await remote_reader.read(65536)
                if not data:
                    break
                bytes_down += len(data)
                transport.write(data)
        except (ConnectionError, CancelledError):
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass

    t1 = create_task(pipe_up())
    t2 = create_task(pipe_down())

    done, pending = await wait({t1, t2}, return_when=FIRST_COMPLETED)
    for p in pending:
        p.cancel()
    await gather(*pending, return_exceptions=True)

    await run_db(app, _db_track_bandwidth, bytes_up, bytes_down)

    raise web.HTTPOk()


HOP_BY_HOP = frozenset(
    {
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
    }
)


async def handle_http(request):
    app = request.app

    raw_target = request.raw_path
    is_proxy = raw_target.startswith("http://") or raw_target.startswith("https://")

    if not is_proxy:
        if request.path == "/metrics":
            return await handle_metrics(request)
        return web.Response(status=404, text="Not found")

    target = raw_target

    success, error = await authenticate(app, request)
    if not success:
        return error

    parsed = urlparse(target)
    site_host = parsed.hostname or parsed.netloc.split(":")[0]

    await run_db(app, _db_track_site, site_host)

    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}

    try:
        sess = app["session"]
        async with sess.request(
            request.method,
            target,
            headers=headers,
            data=await request.read(),
            timeout=ClientTimeout(total=30),
            allow_redirects=False,
        ) as resp:
            content = await resp.read()
            incoming = len(await request.read()) if request.can_read_body else 0
            outgoing = len(content)

            await run_db(app, _db_track_bandwidth, incoming, outgoing)

            resp_headers = {
                k: v
                for k, v in resp.headers.items()
                if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"
            }

            return web.Response(status=resp.status, headers=resp_headers, body=content)
    except Exception as e:
        return web.Response(
            status=502,
            text=dumps({"error": str(e)}),
            content_type="application/json",
        )


@web.middleware
async def connect_middleware(request, handler):
    if request.method == "CONNECT":
        return await handle_connect(request)
    return await handler(request)


async def on_startup(app):
    conn = sqlite3.connect("steel.db", check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS bandwidth "
        "(incoming INTEGER, outgoing INTEGER, total_bytes INTEGER)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS top_sites (site TEXT PRIMARY KEY, visits INTEGER)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, secret TEXT)"
    )
    hashed = hash_password("testpass")
    existing = conn.execute(
        "SELECT secret FROM users WHERE username = 'testuser'"
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO users (username, secret) VALUES ('testuser', ?)", (hashed,)
        )
    elif not existing[0].count(":"):
        conn.execute(
            "UPDATE users SET secret = ? WHERE username = 'testuser'", (hashed,)
        )
    app["db_conn"] = conn
    app["db_lock"] = Lock()
    app["session"] = ClientSession()


async def on_shutdown(app):
    if "session" in app:
        await app["session"].close()
    if "db_conn" in app:
        metrics = _db_get_metrics(app["db_conn"])
        print("\n=== Proxy Server Shutdown Summary ===")
        print(dumps(metrics, indent=2))
        app["db_conn"].close()


def handle_request(request):
    return handle_http(request)


def create_app():
    app = web.Application(middlewares=[connect_middleware])
    app.router.add_get("/metrics", handle_metrics)
    app.router.add_route("*", "/{path:.*}", handle_request)
    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)
    return app


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8002
    app = create_app()
    print(f"Starting proxy server on port {port}")
    web.run_app(app, host="0.0.0.0", port=port, print=None)
