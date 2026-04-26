//! Pingora `ProxyHttp` impl that runs `waf-core` in front of an upstream.

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use waf_core::config::UpstreamCfg;
use waf_core::request::{parse_cookie_header, RequestCtx};
use waf_core::{Action, Decision, Engine};

pub struct WafProxy {
    pub engine: Arc<Engine>,
    pub upstream: UpstreamCfg,
}

impl WafProxy {
    pub fn new(engine: Arc<Engine>, upstream: UpstreamCfg) -> Self {
        Self { engine, upstream }
    }
}

#[derive(Default)]
pub struct WafCtx {
    pub decision: Option<Decision>,
    pub handled_locally: bool,
    pub request_id: String,
    pub client_ip: String,
    /// IP that was tracked in the conn-tracker so `logging` decrements it.
    pub tracked_ip: Option<IpAddr>,
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = WafCtx;
    fn new_ctx(&self) -> Self::CTX { WafCtx::default() }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = build_request_ctx(session, &self.engine);
        ctx.request_id = req.request_id.clone();
        ctx.client_ip = req.client_ip.to_string();
        ctx.tracked_ip = Some(req.client_ip);
        self.engine.conns.inc(req.client_ip);

        // Reserved internal endpoints.
        if req.path == "/__2t1/verify" && req.method.eq_ignore_ascii_case("POST") {
            ctx.handled_locally = true;
            handle_verify(session, &self.engine).await;
            return Ok(true);
        }
        if req.path == "/__2t1/healthz" {
            ctx.handled_locally = true;
            respond_text(session, 200, "ok\n", &[]).await;
            return Ok(true);
        }

        let decision = self.engine.evaluate(&req);

        let path = req.path.clone();
        let country = req.country.clone();
        let primary_rule = decision.reasons.first().map(|r| r.rule_id.to_string());
        self.engine.metrics.record(
            decision.action,
            &ctx.client_ip, &path,
            country.as_deref(),
            primary_rule.as_deref(),
        );

        match decision.action {
            Action::Allow => {
                ctx.decision = Some(decision);
                Ok(false) // continue to upstream
            }
            Action::Block => {
                ctx.decision = Some(decision.clone());
                ctx.handled_locally = true;
                serve_block(session, &decision).await;
                Ok(true)
            }
            Action::Challenge => {
                ctx.decision = Some(decision.clone());
                ctx.handled_locally = true;
                serve_challenge(session, &self.engine, &decision).await;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(
            self.upstream.address.as_str(),
            self.upstream.tls,
            self.upstream.sni.clone(),
        );
        peer.options.connection_timeout = Some(Duration::from_millis(self.upstream.connect_timeout_ms));
        peer.options.read_timeout = Some(Duration::from_millis(self.upstream.read_timeout_ms));
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self, _session: &mut Session, upstream_request: &mut RequestHeader, ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Stamp identifiers so the origin can correlate WAF logs with upstream logs.
        let _ = upstream_request.insert_header("x-waf-request-id", ctx.request_id.as_str());
        let _ = upstream_request.insert_header("x-real-ip", ctx.client_ip.as_str());
        // Replace any client-supplied X-Forwarded-For with our own attested chain.
        let xff = format!("{}", ctx.client_ip);
        let _ = upstream_request.insert_header("x-forwarded-for", xff);
        let _ = upstream_request.insert_header("x-forwarded-proto",
            if self.upstream.tls { "https" } else { "http" });
        Ok(())
    }

    async fn response_filter(
        &self, _session: &mut Session, upstream_response: &mut ResponseHeader, _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let _ = upstream_response.insert_header("x-waf", "2t1");
        let _ = upstream_response.insert_header("x-content-type-options", "nosniff");
        let _ = upstream_response.insert_header("referrer-policy", "strict-origin-when-cross-origin");
        Ok(())
    }

    async fn logging(&self, _session: &mut Session, e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        if let Some(ip) = ctx.tracked_ip { self.engine.conns.dec(ip); }
        if let Some(err) = e {
            self.engine.metrics.upstream_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(request_id = %ctx.request_id, ip = %ctx.client_ip, err = %err, "request failed");
        } else if let Some(d) = &ctx.decision {
            tracing::info!(
                request_id = %ctx.request_id, ip = %ctx.client_ip,
                action = ?d.action, score = d.score, status = d.status,
                handled_locally = ctx.handled_locally,
                "request"
            );
        }
    }
}

fn build_request_ctx(session: &Session, engine: &Engine) -> RequestCtx {
    let req = session.req_header();
    let client_ip = resolve_client_ip(session, engine.cfg.server.trusted_proxy_hops);

    let method = req.method.as_str().to_string();
    let uri = req.uri.to_string();
    let path = req.uri.path().to_string();
    let query = req.uri.query().unwrap_or("").to_string();

    let mut headers = std::collections::HashMap::with_capacity(req.headers.len());
    for (k, v) in req.headers.iter() {
        if let Ok(vs) = v.to_str() {
            headers.entry(k.as_str().to_ascii_lowercase()).or_insert_with(|| vs.to_string());
        }
    }

    let host = headers.get("host").cloned().unwrap_or_default();
    let user_agent = headers.get("user-agent").cloned().unwrap_or_default();
    let content_length = headers.get("content-length").and_then(|s| s.parse().ok());
    let cookies = headers.get("cookie").map(|c| parse_cookie_header(c)).unwrap_or_default();

    RequestCtx {
        request_id: gen_request_id(),
        client_ip,
        method, uri, path, query, host, user_agent,
        headers, cookies,
        body_preview: Vec::new(),
        content_length,
        country: None,
    }
}

fn resolve_client_ip(session: &Session, trusted_hops: u8) -> IpAddr {
    let socket_ip = session.client_addr()
        .and_then(|a| a.as_inet())
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([0,0,0,0]));
    if trusted_hops == 0 { return socket_ip; }
    let req = session.req_header();
    let xff = req.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let Some(xff) = xff else { return socket_ip; };
    // Take the (trusted_hops)th from the right.
    let parts: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
    if parts.is_empty() { return socket_ip; }
    let want = parts.len().saturating_sub(trusted_hops as usize);
    parts.get(want).and_then(|s| s.parse().ok()).unwrap_or(socket_ip)
}

fn gen_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    // Tiny xorshift over (nanos | thread_id_hash) to make it unique enough for logs.
    let tid = std::thread::current().id();
    let mut h: u64 = (nanos as u64).wrapping_mul(2862933555777941757).wrapping_add(3037000493);
    h ^= format!("{tid:?}").len() as u64;
    format!("{:016x}", h)
}

async fn serve_block(session: &mut Session, d: &Decision) {
    let body = serde_json::to_vec(&serde_json::json!({
        "error": "blocked",
        "request_id": d.request_id,
        "rule": d.reasons.first().map(|r| r.rule_id),
    })).unwrap_or_else(|_| b"{\"error\":\"blocked\"}".to_vec());
    let extra = if d.status == 429 { vec![("retry-after", "10")] } else { vec![] };
    write_response(session, d.status, "application/json", &body, &extra).await;
}

async fn serve_challenge(session: &mut Session, engine: &Engine, d: &Decision) {
    let token = engine.challenger.issue();
    let body = engine.challenger.render_page(&token, &d.request_id);
    let extra: Vec<(&str, &str)> = vec![
        ("cache-control", "no-store, private"),
        ("x-waf-action", "challenge"),
    ];
    write_response(session, 403, "text/html; charset=utf-8", body.as_bytes(), &extra).await;
}

async fn handle_verify(session: &mut Session, engine: &Engine) {
    // Read up to 4 KiB of body.
    let mut buf = Vec::with_capacity(512);
    while buf.len() < 4096 {
        match session.as_mut().read_request_body().await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    #[derive(serde::Deserialize)]
    struct Submit { c: String, n: String, s: String, e: u64 }

    let ok = serde_json::from_slice::<Submit>(&buf).ok().map(|s| {
        engine.challenger.verify(&s.c, &s.n, &s.s, s.e).is_ok()
    }).unwrap_or(false);

    if ok {
        let cookie_value = engine.challenger.mint_clearance();
        let cookie = format!(
            "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
            engine.challenger.cookie_name(), cookie_value, engine.challenger.cookie_ttl(),
        );
        write_response(session, 204, "text/plain", b"", &[("set-cookie", cookie.as_str())]).await;
    } else {
        write_response(session, 400, "application/json",
            br#"{"error":"verification failed"}"#, &[]).await;
    }
}

async fn write_response(session: &mut Session, status: u16, ctype: &str, body: &[u8], extra: &[(&str, &str)]) {
    let mut resp = match ResponseHeader::build(status, Some(8)) {
        Ok(r) => r, Err(_) => return,
    };
    let _ = resp.insert_header("content-type", ctype);
    let _ = resp.insert_header("content-length", body.len().to_string());
    let _ = resp.insert_header("x-waf", "2t1");
    let _ = resp.insert_header("cache-control", "no-store, private");
    // Names need 'static; cheapest portable workaround is to clone into String.
    for (k, v) in extra { let _ = resp.insert_header(k.to_string(), *v); }
    if session.write_response_header(Box::new(resp), body.is_empty()).await.is_err() {
        return;
    }
    if !body.is_empty() {
        let _ = session.write_response_body(Some(Bytes::copy_from_slice(body)), true).await;
    }
}

async fn respond_text(session: &mut Session, status: u16, body: &str, extra: &[(&str, &str)]) {
    write_response(session, status, "text/plain; charset=utf-8", body.as_bytes(), extra).await;
}
