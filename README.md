# Proxy Server Challenge (aiohttp + SQLite + uv)

Authenticated HTTP/HTTPS forward proxy with bandwidth and site analytics.

## Features

- HTTP proxying for absolute-form targets (for example, `http://example.com`)
- HTTPS proxying via `CONNECT` tunneling
- Proxy auth via `Proxy-Authorization: Basic ...`
- Metrics endpoint at `GET /metrics` (no auth required)
- SQLite-backed analytics (`steel.db`)
- Shutdown summary printed on `Ctrl+C`

## Run

```bash
uv sync
uv run python app/main.py 8002
```

Default proxy credentials are:

- username: `testuser`
- password: `testpass`

## Proxy Usage

HTTP through proxy:

```bash
curl -x http://localhost:8002 --proxy-user testuser:testpass http://example.com
```

HTTPS through proxy:

```bash
curl -x http://localhost:8002 --proxy-user testuser:testpass https://example.com
```

If credentials are missing or invalid, the proxy returns `407 Proxy Authentication Required`.

## Metrics

`GET /metrics` returns aggregated bandwidth and visited sites.

```bash
curl http://localhost:8002/metrics
```

Example response:

```json
{
  "bandwidth_usage": "125MB",
  "top_sites": [
    {"url": "example.com", "visits": 10},
    {"url": "google.com", "visits": 5}
  ]
}
```

Notes:

- `GET /metrics` is available without proxy auth.
- Other direct local paths (for example, `/nonexistent`) return `404`.

## Test Script

With the proxy running, execute:

```bash
bash tests/test_proxy.sh
```
