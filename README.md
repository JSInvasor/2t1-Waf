# 2t1-Waf

Custom L7 Web Application Firewall built on top of [Pingora](https://github.com/cloudflare/pingora).

> Status: early. The proxy and detection engine are usable; expect rough edges
> and breaking changes until the first tagged release.

## What it does

- **Reverse proxy** in front of an upstream HTTP service (Pingora 0.8).
- **Detection engine** — SQLi, XSS, path traversal, command injection, LFI,
  and a configurable User-Agent blocklist. Each match adds to a per-request
  bot/anomaly score; thresholds decide *allow / challenge / block*.
- **Sliding-window rate limiting** per client IP, with optional per-route
  stricter limits (regex on path).
- **IP reputation** — static allow / deny CIDRs, plus an in-process auto-ban
  for IPs that repeatedly trip detection rules.
- **JS challenge** — HMAC-signed token + browser-side proof-of-work; on
  success the client gets a `__2t1_clearance` cookie and skips the heavy
  scanning on subsequent requests.
- **Hard limits** — method allowlist, max URI / header / body size,
  Content-Length + Transfer-Encoding smuggling check.
- **Live dashboard** at `127.0.0.1:9090` showing counters, top IPs / paths /
  rules, banned list, and a 60-second per-second chart.

## Build & run

```bash
cargo build --release
./target/release/waf-proxy config/waf.toml
```

The proxy listens on the address from `[server] listen` (defaults to
`0.0.0.0:8080`) and forwards to `[upstream] address`. The admin / dashboard
binds to `[admin] listen` (default `127.0.0.1:9090`).

## Quick test

In one terminal, start something on port 8000:

```bash
python3 -m http.server 8000
```

In another:

```bash
./target/release/waf-proxy config/waf.toml
```

Then:

```bash
curl http://127.0.0.1:8080/                     # 200, forwarded
curl "http://127.0.0.1:8080/x?id=1' OR 1=1--"   # 403 SQLI-01
curl "http://127.0.0.1:8080/a/../etc/passwd"    # 403 LFI-01 / TRAV-01
curl -A "sqlmap/1.6" http://127.0.0.1:8080/     # 403 challenge page
curl -X TRACE http://127.0.0.1:8080/            # 405 METHOD-DENIED
```

Open `http://127.0.0.1:9090/` for the live dashboard.

## Layout

```
crates/
├── waf-core/      # Detection engine, rate limit, reputation, challenge
└── waf-proxy/     # Pingora binary + admin/dashboard server
config/
└── waf.toml       # Runtime configuration
```

The core engine has no Pingora dependency; rules and primitives are unit
tested in isolation (`cargo test -p waf-core`).

## Security note

The default `challenge.hmac_secret` in `config/waf.toml` is a placeholder.
Generate a long random secret before exposing the WAF to the public internet.
