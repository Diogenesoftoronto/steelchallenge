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

import asyncio
import base64
import json
import signal
import sys
from urllib.parse import urlparse

import aiohttp
from aiohttp import web
from duckdb import connect


def format_bytes(n: int) -> str:
    if n < 1000:
        return f"{n}B"
    elif n < 1_000_000:
        return f"{round(n / 1024, 2)}KB"
    elif n < 1_000_000_000:
        return f"{round(n / 1048576, 2)}MB"
    else:
        return f"{round(n / 1073741824, 2)}GB"


def get_metrics(conn) -> dict:
    row = conn.execute("SELECT COALESCE(SUM(total_bytes), 0) FROM bandwidth").fetchone()
    total = row[0] if row else 0
    sites = conn.execute(
        "SELECT site, visits FROM top_sites ORDER BY visits DESC"
    ).fetchall()
    return {
        "bandwidth_usage": format_bytes(total),
        "top_sites": [{"url": s[0], "visits": s[1]} for s in sites],
    }


def proxy_auth_required():
    return web.Response(
        status=407,
        headers={"Proxy-Authenticate": 'Basic realm="Proxy"'},
        text=json.dumps({"error": "Proxy authentication required"}),
        content_type="application/json",
    )


async def authenticate(conn, request):
    proxy_auth = request.headers.get("Proxy-Authorization")
    if not proxy_auth or not proxy_auth.startswith("Basic "):
        return False, proxy_auth_required()

    try:
        credentials = base64.b64decode(proxy_auth[6:]).decode()
        username, password = credentials.split(":", 1)
    except Exception:
        return False, proxy_auth_required()

    result = conn.execute(
        "SELECT secret FROM users WHERE username = ?", (username,)
    ).fetchone()
    if result is None or result[0] != password:
        return False, proxy_auth_required()

    return True, None


async def handle_metrics(request):
    conn = request.app["db_conn"]
    return web.json_response(get_metrics(conn))


async def handle_connect(request):
    app = request.app
    conn = app["db_conn"]
    db_lock = app["db_lock"]

    success, error = await authenticate(conn, request)
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

    async with db_lock:
        conn.execute(
            "INSERT INTO top_sites (site, visits) VALUES (?, 1) "
            "ON CONFLICT (site) DO UPDATE SET visits = top_sites.visits + 1",
            (host,),
        )

    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
    except Exception as e:
        return web.Response(
            status=502,
            text=json.dumps({"error": f"Cannot connect to {host}:{port}: {e}"}),
            content_type="application/json",
        )

    transport = request.transport
    if transport is None:
        remote_writer.close()
        return web.Response(status=502, text="Transport unavailable")

    transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    sock = transport.get_extra_info("socket")
    if sock is None:
        remote_writer.close()
        transport.close()
        return web.Response(status=502, text="Cannot access socket")

    import socket as _socket
    raw_fd = sock.fileno()
    client_sock = _socket.fromfd(raw_fd, sock.family, sock.type, sock.proto)
    client_sock.setblocking(False)

    transport.pause_reading()

    loop = asyncio.get_event_loop()
    client_reader, client_writer = await asyncio.open_connection(sock=client_sock)

    bytes_up = 0
    bytes_down = 0

    async def pipe_up():
        nonlocal bytes_up
        try:
            while True:
                data = await client_reader.read(65536)
                if not data:
                    break
                bytes_up += len(data)
                remote_writer.write(data)
                await remote_writer.drain()
        except (ConnectionError, asyncio.CancelledError):
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
                client_writer.write(data)
                await client_writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                client_writer.close()
            except Exception:
                pass

    t1 = asyncio.create_task(pipe_up())
    t2 = asyncio.create_task(pipe_down())

    done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    for p in pending:
        p.cancel()
    await asyncio.gather(*pending, return_exceptions=True)

    async with db_lock:
        conn.execute(
            "INSERT INTO bandwidth VALUES (?, ?, ?)",
            (bytes_up, bytes_down, bytes_up + bytes_down),
        )

    return web.Response()


HOP_BY_HOP = frozenset({
    "proxy-authorization",
    "proxy-connection",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
})


async def handle_http(request):
    app = request.app
    conn = app["db_conn"]
    db_lock = app["db_lock"]

    raw_target = request.raw_path
    is_proxy = raw_target.startswith("http://") or raw_target.startswith("https://")

    if not is_proxy:
        if request.path == "/metrics":
            return await handle_metrics(request)
        return web.Response(status=404, text="Not found")

    target = raw_target

    success, error = await authenticate(conn, request)
    if not success:
        return error

    parsed = urlparse(target)
    site_host = parsed.hostname or parsed.netloc.split(":")[0]

    async with db_lock:
        conn.execute(
            "INSERT INTO top_sites (site, visits) VALUES (?, 1) "
            "ON CONFLICT (site) DO UPDATE SET visits = top_sites.visits + 1",
            (site_host,),
        )

    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP
    }

    try:
        sess = app["session"]
        async with sess.request(
            request.method,
            target,
            headers=headers,
            data=await request.read(),
            timeout=aiohttp.ClientTimeout(total=30),
            allow_redirects=False,
        ) as resp:
            content = await resp.read()
            incoming = len(await request.read()) if request.can_read_body else 0
            outgoing = len(content)

            async with db_lock:
                conn.execute(
                    "INSERT INTO bandwidth VALUES (?, ?, ?)",
                    (incoming, outgoing, incoming + outgoing),
                )

            resp_headers = {
                k: v
                for k, v in resp.headers.items()
                if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"
            }

            return web.Response(status=resp.status, headers=resp_headers, body=content)
    except Exception as e:
        return web.Response(
            status=502,
            text=json.dumps({"error": str(e)}),
            content_type="application/json",
        )


@web.middleware
async def connect_middleware(request, handler):
    if request.method == "CONNECT":
        return await handle_connect(request)
    return await handler(request)


async def on_startup(app):
    conn = connect("metrics.db")
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
    conn.execute(
        "INSERT INTO users (username, secret) VALUES ('testuser', 'testpass') "
        "ON CONFLICT (username) DO NOTHING"
    )
    app["db_conn"] = conn
    app["db_lock"] = asyncio.Lock()
    app["session"] = aiohttp.ClientSession()


async def on_shutdown(app):
    if "session" in app:
        await app["session"].close()
    if "db_conn" in app:
        metrics = get_metrics(app["db_conn"])
        print("\n=== Proxy Server Shutdown Summary ===")
        print(json.dumps(metrics, indent=2))
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
