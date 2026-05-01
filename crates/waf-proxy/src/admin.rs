//! Admin / dashboard HTTP server. Bound to localhost by default; the operator
//! tunnels (`ssh -L 9090:127.0.0.1:9090`) or fronts it with their own TLS
//! reverse-proxy.
//!
//! Auth: every `/api/*` endpoint requires `Authorization: Bearer <token>`
//! where `<token>` is the runtime token (printed at startup, persisted in
//! `runtime.json`). The static dashboard at `/` is unauthenticated.
//!
//! Endpoints:
//!   GET  /healthz                           liveness
//!   GET  /api/state                         metrics + runtime config
//!   GET  /api/events?since=ms&limit=N       recent decisions
//!   GET  /api/banned                        currently banned IPs
//!   POST /api/runtime                       update runtime overrides (JSON)
//!   POST /api/under_attack?on=true|false    toggle "under attack" mode
//!   POST /api/ip/allow?cidr=…               add to allow list
//!   POST /api/ip/deny?cidr=…                add to deny list
//!   POST /api/ip/unallow?cidr=…             remove from allow list
//!   POST /api/ip/undeny?cidr=…              remove from deny list
//!   POST /api/unban?ip=…                    lift an auto-ban
//!   GET  /                                  dashboard HTML
//!   GET  /static/dashboard.js               dashboard JS

use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::Service;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use waf_core::Engine;

mod assets;

pub fn admin_service(engine: Arc<Engine>, listen: String) -> AdminService {
    AdminService { engine, listen }
}

pub struct AdminService {
    engine: Arc<Engine>,
    listen: String,
}

/// Open the SQLite event store and attach its sink to the engine.
/// Wrapped as a Pingora Service so the open + writer task share the
/// same tokio runtime as the rest of the admin plumbing. Service exits
/// immediately after attach — the writer task it spawned keeps running.
pub fn storage_service(engine: Arc<Engine>, db_path: std::path::PathBuf) -> StorageService {
    StorageService { engine, db_path }
}

pub struct StorageService {
    engine: Arc<Engine>,
    db_path: std::path::PathBuf,
}

#[async_trait]
impl Service for StorageService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora_core::server::ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        match waf_core::storage::Storage::open(&self.db_path) {
            Ok(storage) => {
                tracing::info!(path = %self.db_path.display(), "storage opened");
                self.engine.set_storage_path(storage.path.clone());
                self.engine.attach_storage(storage.sink.clone());
                // Keep `storage` alive — its writer task lives on the
                // shared tokio runtime, but the Sink/Storage clone here
                // owns the rusqlite Connection used during queries.
                let _ = shutdown.changed().await;
                drop(storage);
            }
            Err(e) => {
                tracing::error!(%e, "failed to open event storage; events will only stay in the in-memory ring");
                let _ = shutdown.changed().await;
            }
        }
    }
    fn name(&self) -> &str { "2t1-storage" }
    fn threads(&self) -> Option<usize> { Some(1) }
}

/// Background loop that adjusts `runtime.uam_level` based on the per-second
/// block rate. Activated when `runtime.auto_uam_enabled = true`.
pub fn auto_uam_service(engine: Arc<Engine>) -> AutoUamService {
    AutoUamService { engine }
}

pub struct AutoUamService {
    engine: Arc<Engine>,
}

#[async_trait]
impl Service for AutoUamService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora_core::server::ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut gc_tick = tokio::time::interval(Duration::from_secs(60));
        let mut prev_blocks: u64 = self.engine.metrics.blocked.load(Ordering::Relaxed);
        let mut last_change: u64 = 0;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = gc_tick.tick() => {
                    // Sweep stale entries from all unbounded DashMaps.
                    // Without this, ConnTracker / RateLimiter / Reputations
                    // grow indefinitely and eventually OOM-kill the process.
                    self.engine.conns.gc();
                    self.engine.rate_limiter.gc(120);
                    self.engine.reputations.gc();
                    // Best-effort persist of auto-bans so they survive restarts.
                    let _ = self.engine.reputations.persist();
                    tracing::debug!(
                        conn_tracked = self.engine.conns.total(),
                        subnets = self.engine.subnets.tracked(),
                        "gc sweep completed"
                    );
                }
                _ = interval.tick() => {
                    if !self.engine.runtime.auto_uam_enabled.load(Ordering::Relaxed) {
                        prev_blocks = self.engine.metrics.blocked.load(Ordering::Relaxed);
                        continue;
                    }
                    let now_blocks = self.engine.metrics.blocked.load(Ordering::Relaxed);
                    let delta = now_blocks.saturating_sub(prev_blocks);
                    let bps = (delta / 5) as u32; // blocks per second
                    prev_blocks = now_blocks;
                    let now_s = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0);
                    // Don't oscillate — wait 30 s between level changes.
                    if now_s.saturating_sub(last_change) < 30 { continue; }

                    let cur = self.engine.runtime.uam_level.load(Ordering::Relaxed);
                    let thresh = self.engine.runtime.auto_uam_threshold.load(Ordering::Relaxed);
                    let escalate_at = thresh;
                    let de_escalate_at = thresh / 4;

                    let next = if bps >= escalate_at && cur < 4 {
                        cur + 1
                    } else if bps <= de_escalate_at && cur > 0 {
                        cur - 1
                    } else { cur };

                    if next != cur {
                        self.engine.runtime.uam_level.store(next, Ordering::Relaxed);
                        let _ = self.engine.runtime.persist();
                        last_change = now_s;
                        tracing::warn!(blocks_per_sec = bps, prev = cur, new = next,
                            "auto-UAM level changed");
                    }
                }
            }
        }
    }

    fn name(&self) -> &str { "2t1-auto-uam" }
    fn threads(&self) -> Option<usize> { Some(1) }
}

#[async_trait]
impl Service for AdminService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora_core::server::ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let listener = match TcpListener::bind(&self.listen).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(listen = %self.listen, %e, "admin bind failed");
                return;
            }
        };
        tracing::info!(listen = %self.listen, "admin server up");
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("admin shutting down");
                    return;
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let engine = self.engine.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle(stream, engine).await {
                                    tracing::debug!(%e, "admin conn error");
                                }
                            });
                        }
                        Err(e) => tracing::warn!(%e, "admin accept error"),
                    }
                }
            }
        }
    }

    fn name(&self) -> &str { "2t1-admin" }
    fn threads(&self) -> Option<usize> { Some(1) }
}

struct ParsedReq {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn handle(mut s: TcpStream, engine: Arc<Engine>) -> std::io::Result<()> {
    let req = match read_request(&mut s).await? {
        Some(r) => r, None => return Ok(()),
    };

    let (status, ctype, body) = if req.path == "/api/stream" && req.method == "GET" {
        if !auth_ok(&req, &engine) {
            return write_response(&mut s, 401, "application/json", br#"{"error":"unauthorized"}"#).await;
        }
        return stream_events(s, engine).await;
    } else if (req.path == "/api/events/range" || req.path == "/api/events/series")
        && req.method == "GET"
    {
        if !auth_ok(&req, &engine) {
            (401, "application/json", br#"{"error":"unauthorized"}"#.to_vec())
        } else {
            route_timeframe(&req, &engine).await
        }
    } else if req.path.starts_with("/api/") {
        if !auth_ok(&req, &engine) {
            (401, "application/json", br#"{"error":"unauthorized"}"#.to_vec())
        } else {
            route_api(&req, &engine)
        }
    } else {
        route_static(&req)
    };

    write_response(&mut s, status, ctype, &body).await
}

async fn read_request(s: &mut TcpStream) -> std::io::Result<Option<ParsedReq>> {
    let mut buf = vec![0u8; 0];
    let mut tmp = [0u8; 4096];
    let mut header_end = None;
    while header_end.is_none() {
        let n = s.read(&mut tmp).await?;
        if n == 0 { return Ok(None); }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = find_double_crlf(&buf) { header_end = Some(p); }
        if buf.len() > 64 * 1024 { return Ok(None); } // header bomb defence
    }
    let header_end = header_end.unwrap();
    let head = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
    let mut lines = head.split("\r\n");
    let line = lines.next().unwrap_or("");
    let mut it = line.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("/");
    let (path, query_str) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };

    let mut headers = HashMap::new();
    let mut content_length: usize = 0;
    for h in lines {
        if let Some((k, v)) = h.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_string();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0).min(1 << 20);
            }
            headers.insert(k, v);
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let need = content_length - body.len();
        let mut chunk = vec![0u8; need.min(8192)];
        let n = s.read(&mut chunk).await?;
        if n == 0 { break; }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    Ok(Some(ParsedReq { method, path, query: parse_query(&query_str), headers, body }))
}

fn parse_range(q: &HashMap<String, String>, now_ms: u64) -> (u64, u64) {
    if let (Some(s), Some(u)) = (
        q.get("since").and_then(|x| x.parse::<u64>().ok()),
        q.get("until").and_then(|x| x.parse::<u64>().ok()),
    ) {
        return (s, u.max(s));
    }
    let span_ms: u64 = match q.get("range").map(|s| s.as_str()) {
        Some("30m") => 30 * 60 * 1000,
        Some("6h")  => 6 * 3600 * 1000,
        Some("24h") => 24 * 3600 * 1000,
        Some("1h")  => 3600 * 1000,
        _           => 30 * 60 * 1000,
    };
    (now_ms.saturating_sub(span_ms), now_ms)
}

fn parse_query(s: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for kv in s.split('&') {
        if kv.is_empty() { continue; }
        if let Some((k, v)) = kv.split_once('=') {
            m.insert(percent_decode(k), percent_decode(v));
        } else {
            m.insert(percent_decode(kv), String::new());
        }
    }
    m
}

fn percent_decode(s: &str) -> String {
    use percent_encoding::percent_decode_str;
    percent_decode_str(s).decode_utf8_lossy().to_string()
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn auth_ok(req: &ParsedReq, engine: &Engine) -> bool {
    let token = engine.runtime.auth_token.read().clone();
    if token.is_empty() { return true; }
    let header = req.headers.get("authorization").map(|s| s.as_str()).unwrap_or("");
    if let Some(rest) = header.strip_prefix("Bearer ") {
        return rest == token;
    }
    if let Some(rest) = header.strip_prefix("bearer ") {
        return rest == token;
    }
    // Allow ?token=… as a fallback for browser EventSource (which can't set headers).
    req.query.get("token").map(|t| t == &token).unwrap_or(false)
}

fn route_api(req: &ParsedReq, engine: &Engine) -> (u16, &'static str, Vec<u8>) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/state") => {
            let snap = engine.metrics.snapshot();
            let mut runtime = engine.runtime.snapshot();
            // Honeypots live outside Runtime; merge them into the snapshot.
            runtime.honeypot_paths = Some(engine.honeypots.snapshot());
            let body = serde_json::json!({
                "metrics": snap,
                "runtime": runtime,
                "in_flight_total": engine.conns.total(),
                "subnets_tracked": engine.subnets.tracked(),
                "version": env!("CARGO_PKG_VERSION"),
            });
            ok_json(serde_json::to_vec(&body).unwrap_or_default())
        }
        ("GET", "/api/events") => {
            let since = req.query.get("since").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let limit = req.query.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(100).min(500);
            let evs = if since > 0 {
                engine.events.since(since, limit)
            } else {
                engine.events.recent(limit)
            };
            ok_json(serde_json::to_vec(&evs).unwrap_or_default())
        }
        ("GET", "/api/goodbots") => {
            ok_json(serde_json::to_vec(&engine.goodbot.snapshot()).unwrap_or_default())
        }
        ("GET", "/api/banned") => {
            let banned: Vec<serde_json::Value> = engine.reputations.banned().into_iter()
                .map(|(ip, ttl)| serde_json::json!({"ip": ip.to_string(), "expires_in": ttl}))
                .collect();
            ok_json(serde_json::to_vec(&banned).unwrap_or_default())
        }
        ("POST", "/api/runtime") => {
            #[derive(Deserialize)]
            struct Patch {
                #[serde(default)] under_attack: Option<bool>,
                #[serde(default)] uam_level: Option<u8>,
                #[serde(default)] challenge_mode: Option<u8>,
                #[serde(default)] auto_uam_enabled: Option<bool>,
                #[serde(default)] auto_uam_threshold: Option<u32>,
                #[serde(default)] challenge_threshold: Option<u32>,
                #[serde(default)] block_threshold: Option<u32>,
                #[serde(default)] max_concurrent_per_ip: Option<u32>,
                #[serde(default)] rpm_under_attack_bps: Option<u32>,
                #[serde(default)] subnet_rpm:  Option<u32>,
                #[serde(default)] subnet_conn: Option<u32>,
                #[serde(default)] global_inflight_cap: Option<u32>,
                #[serde(default)] tarpit_score:        Option<u32>,
                #[serde(default)] datacenter_block:    Option<bool>,
                #[serde(default)] rules: Option<RulesPatch>,
                #[serde(default)] defenses: Option<DefensesPatch>,
                #[serde(default)] blocked_countries: Option<Vec<String>>,
                #[serde(default)] honeypot_paths:    Option<Vec<String>>,
                #[serde(default)] turnstile_provider: Option<String>,
                #[serde(default)] turnstile_site_key: Option<String>,
                #[serde(default)] turnstile_secret:   Option<String>,
            }
            #[derive(Deserialize)]
            struct RulesPatch {
                #[serde(default)] sqli: Option<bool>,
                #[serde(default)] xss: Option<bool>,
                #[serde(default)] traversal: Option<bool>,
                #[serde(default)] cmdi: Option<bool>,
                #[serde(default)] lfi: Option<bool>,
                #[serde(default)] bot_ua: Option<bool>,
                #[serde(default)] rate_limit: Option<bool>,
            }
            #[derive(Deserialize)]
            struct DefensesPatch {
                #[serde(default)] bot_score: Option<bool>,
                #[serde(default)] behavior:  Option<bool>,
                #[serde(default)] ddos:      Option<bool>,
                #[serde(default)] honeypots: Option<bool>,
                #[serde(default)] subnet:    Option<bool>,
                #[serde(default)] replay:    Option<bool>,
                #[serde(default)] dist_ua:   Option<bool>,
                #[serde(default)] goodbot:   Option<bool>,
                #[serde(default)] bic:       Option<bool>,
            }
            let patch: Patch = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(e) => return bad_request(&format!("invalid json: {e}")),
            };
            let r = &engine.runtime;
            use std::sync::atomic::Ordering;
            if let Some(v) = patch.under_attack { r.under_attack.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.uam_level    { r.uam_level.store(v.min(4), Ordering::Relaxed); }
            if let Some(v) = patch.challenge_mode { r.challenge_mode.store(v.min(2), Ordering::Relaxed); }
            if let Some(v) = patch.auto_uam_enabled  { r.auto_uam_enabled.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.auto_uam_threshold{ r.auto_uam_threshold.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.challenge_threshold { r.challenge_threshold.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.block_threshold     { r.block_threshold.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.max_concurrent_per_ip { r.max_concurrent_per_ip.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.rpm_under_attack_bps  { r.rpm_under_attack_bps.store(v, Ordering::Relaxed); }
            if let Some(rp) = patch.rules {
                if let Some(v) = rp.sqli      { r.rules.sqli.store(v, Ordering::Relaxed); }
                if let Some(v) = rp.xss       { r.rules.xss.store(v, Ordering::Relaxed); }
                if let Some(v) = rp.traversal { r.rules.traversal.store(v, Ordering::Relaxed); }
                if let Some(v) = rp.cmdi      { r.rules.cmdi.store(v, Ordering::Relaxed); }
                if let Some(v) = rp.lfi       { r.rules.lfi.store(v, Ordering::Relaxed); }
                if let Some(v) = rp.bot_ua    { r.rules.bot_ua.store(v, Ordering::Relaxed); }
                if let Some(v) = rp.rate_limit{ r.rules.rate_limit.store(v, Ordering::Relaxed); }
            }
            if let Some(dp) = patch.defenses {
                if let Some(v) = dp.bot_score { r.defenses.bot_score.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.behavior  { r.defenses.behavior.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.ddos      { r.defenses.ddos.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.honeypots { r.defenses.honeypots.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.subnet    { r.defenses.subnet.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.replay    { r.defenses.replay.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.dist_ua   { r.defenses.dist_ua.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.goodbot   { r.defenses.goodbot.store(v, Ordering::Relaxed); }
                if let Some(v) = dp.bic       { r.defenses.bic.store(v, Ordering::Relaxed); }
            }
            if let Some(v) = patch.subnet_rpm  { r.subnet_rpm.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.subnet_conn { r.subnet_conn.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.global_inflight_cap { r.global_inflight_cap.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.tarpit_score        { r.tarpit_score.store(v, Ordering::Relaxed); }
            if let Some(v) = patch.datacenter_block    { r.datacenter_block.store(v, Ordering::Relaxed); }
            if let Some(paths) = patch.honeypot_paths {
                engine.honeypots.replace(paths);
            }
            if let Some(s) = patch.turnstile_provider { *r.turnstile_provider.write() = s.to_lowercase(); }
            if let Some(s) = patch.turnstile_site_key { *r.turnstile_site_key.write() = s; }
            if let Some(s) = patch.turnstile_secret   {
                if !s.is_empty() { *r.turnstile_secret.write() = s; }
            }
            if let Some(c) = patch.blocked_countries {
                *r.blocked_countries.write() = c.into_iter().map(|s| s.to_ascii_uppercase()).collect();
            }
            let _ = r.persist();
            ok_json(serde_json::to_vec(&r.snapshot()).unwrap_or_default())
        }
        ("POST", "/api/uam") => {
            // Quick-set UAM level: ?level=0..4 or ?panic=true (sets to 4).
            let level = if req.query.get("panic").map(|v| v == "true").unwrap_or(false) {
                4u8
            } else {
                req.query.get("level").and_then(|s| s.parse::<u8>().ok()).unwrap_or(0).min(4)
            };
            engine.runtime.uam_level.store(level, std::sync::atomic::Ordering::Relaxed);
            let _ = engine.runtime.persist();
            ok_json(format!(r#"{{"uam_level":{level}}}"#).into_bytes())
        }
        ("POST", "/api/under_attack") => {
            let on = req.query.get("on").map(|v| v == "true").unwrap_or(false);
            engine.runtime.under_attack.store(on, std::sync::atomic::Ordering::Relaxed);
            let _ = engine.runtime.persist();
            ok_json(format!(r#"{{"under_attack":{on}}}"#).into_bytes())
        }
        ("POST", "/api/ip/allow") => with_cidr(req, |c| engine.runtime.add_allow(c)),
        ("POST", "/api/ip/deny")  => with_cidr(req, |c| engine.runtime.add_deny(c)),
        ("POST", "/api/ip/unallow") => with_cidr(req, |c| engine.runtime.remove_allow(c)),
        ("POST", "/api/ip/undeny")  => with_cidr(req, |c| engine.runtime.remove_deny(c)),
        ("POST", "/api/unban") => {
            let ip = req.query.get("ip").and_then(|s| s.parse::<IpAddr>().ok());
            match ip {
                Some(addr) => { engine.reputations.unban(addr); (204, "text/plain", vec![]) }
                None => bad_request("missing ip"),
            }
        }
        _ => (404, "application/json", br#"{"error":"not found"}"#.to_vec()),
    }
}

/// Persisted timeframe lookups. `?range=30m|1h|6h|24h` (default 30m)
/// or `?since=ms&until=ms`. Falls back to the in-memory ring when SQLite
/// isn't open yet.
async fn route_timeframe(req: &ParsedReq, engine: &Engine) -> (u16, &'static str, Vec<u8>) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64).unwrap_or(0);
    let (since, until) = parse_range(&req.query, now_ms);
    let limit = req.query.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(500).min(5000);
    let path = engine.storage_path();

    if req.path == "/api/events/range" {
        let body = match path {
            Some(p) => waf_core::storage::query_readonly(&p, since, until, limit)
                .await.unwrap_or_else(|_| engine.events.recent(limit)),
            None => engine.events.recent(limit),
        };
        return ok_json(serde_json::to_vec(&body).unwrap_or_default());
    }
    // /api/events/series
    let buckets = match path {
        Some(p) => waf_core::storage::series_readonly(&p, since, until)
            .await.unwrap_or_default(),
        None => Vec::new(),
    };
    ok_json(serde_json::to_vec(&buckets).unwrap_or_default())
}

fn route_static(req: &ParsedReq) -> (u16, &'static str, Vec<u8>) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/healthz") => (200, "text/plain", b"ok\n".to_vec()),
        ("GET", "/" | "/index.html" | "/firewall" | "/traffic" | "/settings") =>
            (200, "text/html; charset=utf-8", assets::DASHBOARD_HTML.as_bytes().to_vec()),
        ("GET", "/static/dashboard.js") =>
            (200, "application/javascript; charset=utf-8", assets::DASHBOARD_JS.as_bytes().to_vec()),
        ("GET", "/static/dashboard.css") =>
            (200, "text/css; charset=utf-8", assets::DASHBOARD_CSS.as_bytes().to_vec()),
        _ => (404, "application/json", br#"{"error":"not found"}"#.to_vec()),
    }
}

fn with_cidr<F>(req: &ParsedReq, f: F) -> (u16, &'static str, Vec<u8>)
where F: FnOnce(&str) -> anyhow::Result<()>,
{
    let cidr = match req.query.get("cidr") { Some(c) => c.as_str(), None => return bad_request("missing cidr") };
    match f(cidr) {
        Ok(()) => (204, "text/plain", vec![]),
        Err(e) => bad_request(&format!("{e}")),
    }
}

fn ok_json(body: Vec<u8>) -> (u16, &'static str, Vec<u8>) { (200, "application/json", body) }
fn bad_request(msg: &str) -> (u16, &'static str, Vec<u8>) {
    (400, "application/json",
     serde_json::to_vec(&serde_json::json!({"error": msg})).unwrap_or_default())
}

async fn write_response(s: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         content-type: {ctype}\r\n\
         content-length: {len}\r\n\
         cache-control: no-store\r\n\
         x-content-type-options: nosniff\r\n\
         connection: close\r\n\r\n",
        status = status, reason = reason(status), ctype = ctype, len = body.len(),
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    Ok(())
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK", 201 => "Created", 204 => "No Content",
        301 => "Moved Permanently",
        400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden",
        404 => "Not Found", 405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

/// Server-Sent Events stream of new dashboard data. Writes one JSON snapshot
/// per second. The connection is kept open until the client disconnects.
async fn stream_events(mut s: TcpStream, engine: Arc<Engine>) -> std::io::Result<()> {
    let head = "HTTP/1.1 200 OK\r\n\
                content-type: text/event-stream\r\n\
                cache-control: no-store\r\n\
                connection: keep-alive\r\n\
                x-accel-buffering: no\r\n\r\n";
    s.write_all(head.as_bytes()).await?;

    let mut last_event_ts: u64 = 0;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        let snap = engine.metrics.snapshot();
        let evs = engine.events.since(last_event_ts, 200);
        if let Some(last) = evs.last() { last_event_ts = last.ts_ms; }
        let payload = serde_json::json!({
            "metrics": snap,
            "runtime": engine.runtime.snapshot(),
            "in_flight_total": engine.conns.total(),
            "events": evs,
            "ts_ms": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64).unwrap_or(0),
        });
        let line = format!("data: {}\n\n", serde_json::to_string(&payload).unwrap_or_default());
        if s.write_all(line.as_bytes()).await.is_err() { return Ok(()); }
        // Heartbeat is implicit because we always send something each second.
    }
}
