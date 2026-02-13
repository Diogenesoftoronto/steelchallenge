# Proxy Server Challenge

Authenticated HTTP/HTTPS proxy with bandwidth and site analytics, built with `aiohttp` + `DuckDB`.

- **Repo**: https://github.com/Diogenesoftoronto/steelchallenge
- **Gist**: https://gist.github.com/Diogenesoftoronto/57cc110671014af38a6160f20d8473de

## Features

- HTTP and HTTPS (CONNECT tunnel) proxy support
- Proxy authentication via `Proxy-Authorization: Basic` header
- Bandwidth tracking for both HTTP and HTTPS traffic
- Real-time `GET /metrics` endpoint
- Shutdown summary printed on `Ctrl+C`

## Run

```bash
uv sync
uv run python app/main.py 8002
```

## Usage

```bash
# HTTP proxy
curl -x http://localhost:8002 --proxy-user testuser:testpass http://example.com

# HTTPS proxy
curl -x http://localhost:8002 --proxy-user testuser:testpass https://example.com

# Metrics (no auth required)
curl http://localhost:8002/metrics
```

## Metrics Response

```json
{
  "bandwidth_usage": "125.00MB",
  "top_sites": [
    {"url": "example.com", "visits": 10},
    {"url": "google.com", "visits": 5}
  ]
}
```

## Tests

Start the server, then run:

```bash
bash tests/test_proxy.sh
```

## Adding Users

```bash
uv run python -c "
from duckdb import connect
conn = connect('metrics.db')
conn.execute(\"INSERT INTO users VALUES ('alice', 'secret123')\")
"
```

Default user: `testuser` / `testpass`
