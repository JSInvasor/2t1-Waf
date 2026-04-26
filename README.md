# 2t1-Waf

Custom L7 Web Application Firewall built on [Pingora](https://github.com/cloudflare/pingora), with a Cloudflare-style live dashboard.

## What it does

- **Reverse proxy** (HTTP/1.1 + HTTP/2, TLS terminated via Pingora 0.8) in front of any HTTP origin.
- **L7 anti-DDoS**:
  - Sliding-window rate limiting (per-IP, plus per-route stricter limits).
  - Per-IP concurrent in-flight cap (slowloris / HTTP/2 rapid-reset class).
  - **"Under-attack" mode** — every fresh visitor must pass a JS proof-of-work challenge; the rate limit ceiling is automatically scaled down (configurable basis points).
  - Auto-ban for IPs that repeatedly trip detection rules.
  - Static + runtime IP allow / deny CIDR lists.
  - GeoIP block list (DB hook reserved).
- **Detection rules** — SQLi, XSS, path traversal, command injection, LFI / RFI, and a 50+ entry suspicious-User-Agent list (security scanners, attack toolkits, common malware UAs). Each match contributes to a per-request bot/anomaly score; thresholds decide *allow / challenge / block*.
- **JS proof-of-work challenge** — HMAC-signed token, browser-side SHA-256 PoW; on success the client gets a `__2t1_clearance` cookie (1800 s default) and bypasses heavy scanning.
- **Hard request limits** — method allowlist, max URI / header / body size, Content-Length + Transfer-Encoding smuggling check.
- **Live dashboard** with four pages:
  - **Overview** — KPI counters, 60 s ring chart, top IPs / paths / rules / countries.
  - **Firewall** — toggle individual rule families, edit thresholds and DDoS limits, manage allow / deny / banned lists, country block list.
  - **Live traffic** — streaming request log (last 500), with action / text filters.
  - **Settings** — current runtime state JSON dump.
- **Bearer-token authentication** for the dashboard. Every change made via the UI is persisted to `runtime.json` so it survives restarts.
- **systemd-friendly** — unit file, hardened sandbox, install script.

## Layout

```
crates/
├── waf-core/      # detection engine + primitives (no Pingora dep)
└── waf-proxy/     # Pingora binary + admin/dashboard server
config/
├── waf.toml       # static config (immutable baseline)
└── runtime.json   # runtime overrides (written by the dashboard)
deploy/
├── install.sh         # VPS install script
└── 2t1-waf.service    # systemd unit
```

The core engine has no Pingora dependency; rules and primitives are unit tested in isolation.

```bash
cargo test -p waf-core   # 29 tests, no network needed
```

## Local development

```bash
# Origin to protect
python3 -m http.server 8000 &

# WAF
cargo run --release -p waf-proxy -- config/waf.toml
```

The startup log prints the admin bearer token. Open `http://127.0.0.1:9090/` and paste it when prompted.

Quick sanity check:

```bash
curl http://127.0.0.1:8080/                     # 200, forwarded
curl "http://127.0.0.1:8080/x?id=1' OR 1=1--"   # 403 SQLI-01
curl "http://127.0.0.1:8080/a/../etc/passwd"    # 403 LFI-01 / TRAV-01
curl -A "sqlmap/1.6" http://127.0.0.1:8080/     # 403 challenge page
curl -X TRACE http://127.0.0.1:8080/            # 405 METHOD-DENIED
```

## Deploying to a VPS (e.g. for `2t1.online`)

The repo includes a hardened systemd unit and an install script.

### 1. Set up DNS

Point `2t1.online` (and `www.2t1.online` if you use it) at the VPS IP.

### 2. Get a TLS cert

```bash
apt-get install certbot
certbot certonly --standalone -d 2t1.online -d www.2t1.online
# Files end up in /etc/letsencrypt/live/2t1.online/{fullchain.pem,privkey.pem}
```

### 3. Install

```bash
git clone https://github.com/<you>/2t1-waf
cd 2t1-waf
sudo ./deploy/install.sh
```

The script:
- builds the release binary (installs rustup if needed),
- creates a system user `2t1waf`,
- installs the binary to `/usr/local/bin/waf-proxy`,
- installs `config/waf.toml` to `/etc/2t1-waf/waf.toml`,
- installs and enables the `2t1-waf.service` systemd unit.

### 4. Edit `/etc/2t1-waf/waf.toml`

```toml
[server]
listen     = "0.0.0.0:80"
listen_tls = "0.0.0.0:443"
tls_cert   = "/etc/letsencrypt/live/2t1.online/fullchain.pem"
tls_key    = "/etc/letsencrypt/live/2t1.online/privkey.pem"
redirect_to_https_port = 443

[upstream]
address = "127.0.0.1:8000"   # whatever serves your site locally
sni     = "2t1.online"
tls     = false              # the upstream is on the same machine

[challenge]
hmac_secret = "GENERATE A 32+ BYTE RANDOM STRING HERE"
```

Make sure cert files are readable by the `2t1waf` user (or use `setfacl`/`group`).

### 5. Start

```bash
systemctl start 2t1-waf
systemctl status 2t1-waf
journalctl -u 2t1-waf -f
```

The first line of the log prints the admin bearer token; copy it.

### 6. Reach the dashboard

The admin port (`127.0.0.1:9090`) is bound to localhost on purpose. From your laptop:

```bash
ssh -L 9090:127.0.0.1:9090 user@vps
# then open http://127.0.0.1:9090/ in your browser
```

Paste the bearer token. You can now toggle rules, flip Under-Attack, manage IP lists, and watch live traffic — all changes are written to `/etc/2t1-waf/runtime.json` and survive restarts.

### 7. Renewing certs

```bash
certbot renew
systemctl reload 2t1-waf   # send SIGHUP for graceful reload
```

## Security notes

- `challenge.hmac_secret` must be ≥16 bytes; use 32+ random bytes in production. Treat it like a password — anyone who has it can forge clearance cookies.
- The bearer token in `runtime.json` is auto-generated on first run. To rotate, stop the service, replace the value in `runtime.json`, and restart.
- The admin port is *not* designed to be exposed to the public internet. Keep it on `127.0.0.1`.
- `[reputation].deny_cidrs` and the runtime deny list match before any rule, so they're the cheapest way to block known-bad ASNs.

## Architecture

```
                            ┌──────────────────────────────┐
   client ──── 80/443 ────► │ waf-proxy (Pingora ProxyHttp)│
                            │  ├ request_filter            │
                            │  │  ├ build RequestCtx       │
                            │  │  └ Engine::evaluate       │
                            │  ├ upstream_peer (HTTP/HTTPS)│
                            │  └ logging (decrement conn)  │
                            └───────────┬──────────────────┘
                                        │
                                        ▼
                            ┌──────────────────────────────┐
                            │ Engine (waf-core)            │
                            │  ├ runtime overrides         │
                            │  ├ reputation + auto-ban     │
                            │  ├ connection tracker        │
                            │  ├ rate limiter (adaptive)   │
                            │  ├ rules (sqli/xss/…)        │
                            │  ├ challenger (HMAC + PoW)   │
                            │  └ events ring               │
                            └───────────┬──────────────────┘
                                        │
                            ┌───────────▼──────────────────┐
                            │ admin (bound to 127.0.0.1)   │
                            │  ├ bearer auth               │
                            │  ├ /api/state /api/events    │
                            │  ├ /api/runtime /api/ip/…    │
                            │  ├ /api/stream  (SSE)        │
                            │  └ /  (Cloudflare-like SPA)  │
                            └──────────────────────────────┘
```
