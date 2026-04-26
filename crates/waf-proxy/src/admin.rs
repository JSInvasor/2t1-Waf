//! Tiny admin / metrics HTTP server bound to localhost. The dashboard frontend
//! polls these JSON endpoints. Implemented as a Pingora `Service` so it shares
//! the same shutdown plumbing as the proxy.
//!
//! Endpoints:
//!   GET  /api/metrics         summary counters + per-second ring + top-N tables
//!   GET  /api/banned          currently banned IPs
//!   POST /api/unban?ip=<ip>   lift an auto-ban
//!   GET  /healthz             liveness
//!   GET  /                    minimal HTML dashboard

use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::Service;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use waf_core::Engine;

pub fn admin_service(engine: Arc<Engine>, listen: String) -> AdminService {
    AdminService { engine, listen }
}

pub struct AdminService {
    engine: Arc<Engine>,
    listen: String,
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

async fn handle(mut s: tokio::net::TcpStream, engine: Arc<Engine>) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = s.read(&mut buf).await?;
    if n == 0 { return Ok(()); }
    let req = &buf[..n];

    // Parse "METHOD PATH HTTP/1.1\r\n..." minimally.
    let line_end = req.windows(2).position(|w| w == b"\r\n").unwrap_or(req.len());
    let line = std::str::from_utf8(&req[..line_end]).unwrap_or("");
    let mut it = line.split_whitespace();
    let method = it.next().unwrap_or("");
    let target = it.next().unwrap_or("/");

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    let (status, ctype, body) = route(method, path, query, &engine);
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         content-type: {ctype}\r\n\
         content-length: {len}\r\n\
         cache-control: no-store\r\n\
         connection: close\r\n\r\n",
        status = status,
        reason = reason(status),
        ctype = ctype,
        len = body.len(),
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(&body).await?;
    Ok(())
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK", 204 => "No Content",
        400 => "Bad Request", 404 => "Not Found", 405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn route(method: &str, path: &str, query: &str, engine: &Engine) -> (u16, &'static str, Vec<u8>) {
    match (method, path) {
        ("GET", "/healthz") => (200, "text/plain", b"ok\n".to_vec()),
        ("GET", "/api/metrics") => {
            let snap = engine.metrics.snapshot();
            (200, "application/json", serde_json::to_vec(&snap).unwrap_or_default())
        }
        ("GET", "/api/banned") => {
            let banned: Vec<serde_json::Value> = engine.reputations.banned().into_iter()
                .map(|(ip, ttl)| serde_json::json!({"ip": ip.to_string(), "expires_in": ttl}))
                .collect();
            (200, "application/json", serde_json::to_vec(&banned).unwrap_or_default())
        }
        ("POST", "/api/unban") => {
            let ip = query.split('&').find_map(|kv| kv.strip_prefix("ip="));
            match ip.and_then(|s| s.parse::<IpAddr>().ok()) {
                Some(addr) => { engine.reputations.unban(addr); (204, "text/plain", vec![]) }
                None => (400, "application/json", br#"{"error":"missing ip"}"#.to_vec()),
            }
        }
        ("GET", "/" | "/index.html") => (200, "text/html; charset=utf-8", DASHBOARD.as_bytes().to_vec()),
        _ => (404, "application/json", br#"{"error":"not found"}"#.to_vec()),
    }
}

/// Minimal dashboard served by the admin port. The "real" dashboard can grow
/// here over time; this is enough to verify the WAF is doing something useful.
const DASHBOARD: &str = r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>2t1-Waf · live</title>
<style>
:root{color-scheme:dark;--bg:#0b0d12;--card:#11141b;--border:#1c2030;--mut:#8a8f9c;--fg:#e6e7ea;--ok:#3ddc97;--warn:#f7b500;--bad:#ff5470;--accent:#3a86ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
header h1{margin:0;font-size:16px;font-weight:600;letter-spacing:.3px}
header .pulse{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);display:inline-block;margin-right:8px}
main{padding:24px;display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
.card h2{margin:0 0 8px;font-size:12px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.7px}
.kpi{font-size:28px;font-weight:600}
.kpi .lbl{font-size:11px;color:var(--mut);margin-left:6px;text-transform:uppercase}
.row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px dashed var(--border);font-variant-numeric:tabular-nums}
.row:last-child{border-bottom:0}
.row .v{color:var(--mut)}
canvas{width:100%;height:120px;display:block}
.footer{padding:12px 24px;color:var(--mut);font-size:11px;border-top:1px solid var(--border)}
.full{grid-column:1/-1}
.tag{display:inline-block;padding:2px 6px;border-radius:4px;background:#1c2030;color:var(--mut);font-size:11px;margin-left:6px}
.bad{color:var(--bad)} .warn{color:var(--warn)} .ok{color:var(--ok)}
</style></head><body>
<header>
  <h1><span class="pulse"></span>2t1-Waf · live</h1>
  <div class="mut" id="upd">—</div>
</header>
<main>
  <section class="card"><h2>Allowed</h2><div class="kpi ok"><span id="allowed">0</span><span class="lbl">requests</span></div></section>
  <section class="card"><h2>Challenged</h2><div class="kpi warn"><span id="challenged">0</span><span class="lbl">requests</span></div></section>
  <section class="card"><h2>Blocked</h2><div class="kpi bad"><span id="blocked">0</span><span class="lbl">requests</span></div></section>
  <section class="card"><h2>Rate-limited</h2><div class="kpi"><span id="rate_limited">0</span><span class="lbl">hits</span></div></section>

  <section class="card full"><h2>Last 60 seconds</h2><canvas id="chart" width="600" height="120"></canvas></section>

  <section class="card"><h2>Top IPs</h2><div id="top_ips"></div></section>
  <section class="card"><h2>Top paths</h2><div id="top_paths"></div></section>
  <section class="card"><h2>Top rules</h2><div id="top_rules"></div></section>
  <section class="card"><h2>Top countries</h2><div id="top_countries"></div></section>
  <section class="card full"><h2>Currently banned</h2><div id="banned"></div></section>
</main>
<div class="footer">2t1-Waf · admin · refresh 2s</div>
<script>
const $ = id => document.getElementById(id);
function rows(el, items){
  el.innerHTML = items.length ? items.map(([k,v]) =>
    `<div class="row"><span>${escapeHtml(k)}</span><span class="v">${v}</span></div>`
  ).join("") : '<div class="row"><span class="v">no data</span></div>';
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function drawChart(buckets){
  const c = $("chart"), ctx = c.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = c.clientHeight;
  c.width = w*dpr; c.height = h*dpr; ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,w,h);
  const max = Math.max(1, ...buckets.flatMap(b => [b.allowed,b.challenged,b.blocked]));
  const bw = w / buckets.length;
  buckets.forEach((b,i)=>{
    const x = i*bw, all = b.allowed+b.challenged+b.blocked;
    const ya = h - (b.allowed/max)*h;
    const yc = ya - (b.challenged/max)*h;
    const yb = yc - (b.blocked/max)*h;
    ctx.fillStyle = "#3ddc97"; ctx.fillRect(x, ya, Math.max(1,bw-1), h-ya);
    ctx.fillStyle = "#f7b500"; ctx.fillRect(x, yc, Math.max(1,bw-1), ya-yc);
    ctx.fillStyle = "#ff5470"; ctx.fillRect(x, yb, Math.max(1,bw-1), yc-yb);
  });
}
async function tick(){
  try {
    const [m, b] = await Promise.all([
      fetch("/api/metrics").then(r=>r.json()),
      fetch("/api/banned").then(r=>r.json()),
    ]);
    $("allowed").textContent = m.allowed;
    $("challenged").textContent = m.challenged;
    $("blocked").textContent = m.blocked;
    $("rate_limited").textContent = m.rate_limited;
    rows($("top_ips"), m.top_ips);
    rows($("top_paths"), m.top_paths);
    rows($("top_rules"), m.top_rules);
    rows($("top_countries"), m.top_countries);
    rows($("banned"), b.map(x => [x.ip, x.expires_in + "s"]));
    drawChart(m.ring);
    $("upd").textContent = new Date().toLocaleTimeString();
  } catch (e) { /* keep polling */ }
}
tick(); setInterval(tick, 2000);
</script>
</body></html>"##;
