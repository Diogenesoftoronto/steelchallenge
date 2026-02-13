#!/bin/bash
set -euo pipefail

PROXY_HOST="localhost"
PROXY_PORT="8002"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
METRICS_URL="${PROXY_URL}/metrics"
CREDS="testuser:testpass"

PASS=0
FAIL=0
TOTAL=0

assert_eq() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
        printf "  PASS: %s\n" "$test_name"
    else
        FAIL=$((FAIL + 1))
        printf "  FAIL: %s (expected=%s actual=%s)\n" "$test_name" "$expected" "$actual"
    fi
}

assert_contains() {
    local test_name="$1"
    local needle="$2"
    local haystack="$3"
    TOTAL=$((TOTAL + 1))
    if printf '%s' "$haystack" | grep -q "$needle"; then
        PASS=$((PASS + 1))
        printf "  PASS: %s\n" "$test_name"
    else
        FAIL=$((FAIL + 1))
        printf "  FAIL: %s (expected to contain: %s)\n" "$test_name" "$needle"
    fi
}

assert_not_contains() {
    local test_name="$1"
    local needle="$2"
    local haystack="$3"
    TOTAL=$((TOTAL + 1))
    if printf '%s' "$haystack" | grep -q "$needle"; then
        FAIL=$((FAIL + 1))
        printf "  FAIL: %s (should not contain: %s)\n" "$test_name" "$needle"
    else
        PASS=$((PASS + 1))
        printf "  PASS: %s\n" "$test_name"
    fi
}

# Preflight
printf "Checking server at %s ...\n" "$PROXY_URL"
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$METRICS_URL" || echo "000")
if [ "$CODE" != "200" ]; then
    printf "Server is not running (got %s). Start it first:\n" "$CODE"
    printf "  uv run python app/main.py %s\n" "$PROXY_PORT"
    exit 1
fi
printf "Server is up.\n\n"

# [1] /metrics endpoint returns valid JSON
printf "[1] /metrics endpoint\n"
BODY=$(curl -s -o- --max-time 5 "$METRICS_URL")
assert_contains "bandwidth_usage field present" '"bandwidth_usage"' "$BODY"
assert_contains "top_sites field present"       '"top_sites"'       "$BODY"
printf "\n"

# [2] Authenticated HTTP proxy (google.com)
printf "[2] Authenticated HTTP proxy - google.com\n"
CODE=$(curl -s -x "$PROXY_URL" --proxy-user "$CREDS" -o /dev/null -w "%{http_code}" --max-time 15 "http://google.com")
printf "Status: %s\n" "$CODE"
assert_eq "authenticated proxy returns 200" "200" "$CODE"
printf "\n"

# [3] Authenticated HTTP proxy (example.com)
printf "[3] Authenticated HTTP proxy - example.com\n"
BODY=$(curl -s -x "$PROXY_URL" --proxy-user "$CREDS" -o- --max-time 15 "http://example.com")
assert_contains "proxied response contains Example" "Example" "$BODY"
printf "\n"

# [4] Wrong password returns 407
printf "[4] Wrong password\n"
CODE=$(curl -s -x "$PROXY_URL" --proxy-user testuser:wrongpass -o /dev/null -w "%{http_code}" --max-time 15 "http://google.com")
printf "Status: %s\n" "$CODE"
assert_eq "wrong password returns 407" "407" "$CODE"
printf "\n"

# [5] Unknown user returns 407
printf "[5] Unknown user\n"
CODE=$(curl -s -x "$PROXY_URL" --proxy-user nobody:anything -o /dev/null -w "%{http_code}" --max-time 15 "http://google.com")
printf "Status: %s\n" "$CODE"
assert_eq "unknown user returns 407" "407" "$CODE"
printf "\n"

# [6] Anonymous proxy access returns 407
printf "[6] Anonymous proxy access (no credentials)\n"
CODE=$(curl -s -x "$PROXY_URL" -o /dev/null -w "%{http_code}" --max-time 15 "http://google.com")
printf "Status: %s\n" "$CODE"
assert_eq "anonymous proxy returns 407" "407" "$CODE"
printf "\n"

# [7] Site tracking in /metrics
printf "[7] Site tracking in /metrics\n"
curl -s -x "$PROXY_URL" --proxy-user "$CREDS" -o /dev/null --max-time 15 "http://google.com"
curl -s -x "$PROXY_URL" --proxy-user "$CREDS" -o /dev/null --max-time 15 "http://google.com"
curl -s -x "$PROXY_URL" --proxy-user "$CREDS" -o /dev/null --max-time 15 "http://example.com"
sleep 1
BODY=$(curl -s -o- --max-time 5 "$METRICS_URL")
printf "Metrics: %s\n" "$BODY"
assert_contains "google.com tracked" "google.com" "$BODY"
assert_contains "example.com tracked" "example.com" "$BODY"
printf "\n"

# [8] Bandwidth is non-zero
printf "[8] Bandwidth tracking\n"
BODY=$(curl -s -o- --max-time 5 "$METRICS_URL")
BW=$(printf '%s' "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['bandwidth_usage'])" || echo "0B")
printf "Bandwidth: %s\n" "$BW"
assert_not_contains "bandwidth is not 0B" "^0B$" "$BW"
printf "\n"

# [9] /metrics JSON schema validation
printf "[9] /metrics JSON schema\n"
BODY=$(curl -s -o- --max-time 5 "$METRICS_URL")
RESULT=$(printf '%s' "$BODY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('bandwidth_usage'), str)
assert isinstance(d.get('top_sites'), list)
for e in d['top_sites']:
    assert 'url' in e and 'visits' in e
    assert isinstance(e['visits'], int)
print('ok')
" || echo "fail")
assert_eq "schema is valid" "ok" "$RESULT"
printf "\n"

# [10] /metrics accessible without auth (direct, not proxied)
printf "[10] /metrics without auth\n"
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$METRICS_URL")
assert_eq "/metrics returns 200 without auth" "200" "$CODE"
printf "\n"

# [11] Unknown local path returns 404
printf "[11] Unknown local path\n"
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${PROXY_URL}/nonexistent")
assert_eq "unknown path returns 404" "404" "$CODE"
printf "\n"

# [12] HTTPS proxy via CONNECT tunnel
printf "[12] HTTPS proxy (CONNECT) - example.com\n"
CODE=$(curl -s -x "$PROXY_URL" --proxy-user "$CREDS" -o /dev/null -w "%{http_code}" --max-time 15 "https://example.com" || echo "000")
printf "Status: %s\n" "$CODE"
if [ "$CODE" != "000" ]; then
    TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
    printf "  PASS: HTTPS proxy returned %s\n" "$CODE"
else
    TOTAL=$((TOTAL + 1)); FAIL=$((FAIL + 1))
    printf "  FAIL: HTTPS proxy connection failed\n"
fi
printf "\n"

# [13] HTTPS proxy without auth returns 407
printf "[13] HTTPS proxy without auth\n"
CODE=$(curl -s -x "$PROXY_URL" -o /dev/null -w "%{http_code}" --max-time 15 "https://example.com" || echo "000")
printf "Status: %s\n" "$CODE"
assert_eq "HTTPS without auth returns 407" "407" "$CODE"
printf "\n"

# Summary
printf "=============================\n"
printf "  %d passed, %d failed, %d total\n" "$PASS" "$FAIL" "$TOTAL"
printf "=============================\n"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
