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
use waf_core::fingerprint;
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
        // Crisis valve. If global in-flight is already at the configured
        // ceiling, drop the connection here without parsing or scoring —
        // this is the line that keeps the proxy alive under L7 flood and
        // the upstream from receiving the spillover.
        if self.engine.at_capacity() {
            self.engine.metrics.upstream_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // 503 with a tiny body, connection: close — minimal cost path.
            write_response(session, 503, "text/plain", b"overloaded\n",
                &[("connection", "close"), ("retry-after", "5")]).await;
            return Ok(true);
        }

        let req = build_request_ctx(session, &self.engine);
        ctx.request_id = req.request_id.clone();
        ctx.client_ip = req.client_ip.to_string();
        ctx.tracked_ip = Some(req.client_ip);
        self.engine.conns.inc(req.client_ip);
        self.engine.subnets.inc_inflight(req.client_ip);

        // Reserved internal endpoints.
        if req.path == "/__2t1/verify" && req.method.eq_ignore_ascii_case("POST") {
            ctx.handled_locally = true;
            handle_verify(session, &self.engine).await;
            return Ok(true);
        }
        if req.path == "/__2t1/bic-verify" && req.method.eq_ignore_ascii_case("POST") {
            ctx.handled_locally = true;
            handle_bic_verify(session, &self.engine, req.client_ip).await;
            return Ok(true);
        }
        if req.path == "/__2t1/turnstile-verify" && req.method.eq_ignore_ascii_case("POST") {
            ctx.handled_locally = true;
            handle_turnstile_verify(session, &self.engine, req.client_ip).await;
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
        let primary_rule = decision.reasons.first().map(|r| r.rule_id.clone());
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
            Action::Tarpit => {
                ctx.decision = Some(decision.clone());
                ctx.handled_locally = true;
                serve_tarpit(session).await;
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
        if let Some(ip) = ctx.tracked_ip {
            self.engine.conns.dec(ip);
            self.engine.subnets.dec_inflight(ip);
        }
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
    let http_version = format!("{:?}", req.version);

    // Preserve header arrival order — http::HeaderMap iterates in insertion
    // order, which Pingora populates from the wire frame.
    let mut header_order: Vec<String> = Vec::with_capacity(req.headers.len());
    let mut headers = std::collections::HashMap::with_capacity(req.headers.len());
    for (k, v) in req.headers.iter() {
        if let Ok(vs) = v.to_str() {
            let name = k.as_str().to_ascii_lowercase();
            if !header_order.iter().any(|h| h == &name) {
                header_order.push(name.clone());
            }
            headers.entry(name).or_insert_with(|| vs.to_string());
        }
    }

    let host = headers.get("host").cloned().unwrap_or_default();
    let user_agent = headers.get("user-agent").cloned().unwrap_or_default();
    let content_length = headers.get("content-length").and_then(|s| s.parse().ok());

    let (cookies, cookie_order) = headers.get("cookie")
        .map(|c| {
            let m = parse_cookie_header(c);
            // Preserve cookie order from the header.
            let order: Vec<String> = c.split(';')
                .filter_map(|p| p.split_once('='))
                .map(|(k, _)| k.trim().to_ascii_lowercase())
                .collect();
            (m, order)
        })
        .unwrap_or_default();

    let ja4h = fingerprint::compute(
        &method, &http_version, &header_order, &headers, &cookie_order, &cookies,
    );

    RequestCtx {
        request_id: gen_request_id(),
        client_ip,
        method, uri, path, query, host, user_agent,
        http_version,
        headers, header_order,
        cookie_order, cookies,
        body_preview: Vec::new(),
        content_length,
        country: None,
        ja4h,
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
        "rule": d.reasons.first().map(|r| r.rule_id.clone()),
    })).unwrap_or_else(|_| b"{\"error\":\"blocked\"}".to_vec());
    let extra = if d.status == 429 { vec![("retry-after", "10")] } else { vec![] };
    write_response(session, d.status, "application/json", &body, &extra).await;
}

/// Hold the attacker's connection open and drip-feed bytes to burn
/// their socket budget. Total spend per attacker connection: ~120s
/// blocking only one tokio task slot — much cheaper than the equivalent
/// nginx worker on the upstream side.
async fn serve_tarpit(session: &mut Session) {
    use bytes::Bytes;
    use tokio::time::{sleep, Duration};
    let mut resp = match ResponseHeader::build(200, Some(4)) {
        Ok(r) => r, Err(_) => return,
    };
    let _ = resp.insert_header("content-type", "text/plain; charset=utf-8");
    let _ = resp.insert_header("connection", "close");
    let _ = resp.insert_header("x-waf", "2t1");
    if session.write_response_header(Box::new(resp), false).await.is_err() {
        return;
    }
    // Drip 1 byte every 4s for ~30 chunks (~2 minutes).
    let payload: &[u8] = b"please-wait-please-wait-please\n";
    for &b in payload.iter() {
        sleep(Duration::from_millis(4000)).await;
        if session.write_response_body(Some(Bytes::copy_from_slice(&[b])), false).await.is_err() {
            return;
        }
    }
    let _ = session.write_response_body(Some(Bytes::new()), true).await;
}

async fn serve_challenge(session: &mut Session, engine: &Engine, d: &Decision) {
    // If BIC is enabled and this client doesn't already have a valid BIC
    // cookie, serve the silent integrity check first. Real browsers pass
    // it in <100 ms with no friction; bots that don't run JS get stuck.
    let bic_on = engine.runtime.defenses.bic.load(std::sync::atomic::Ordering::Relaxed);
    let req = session.req_header();
    let cookie_hdr = req.headers.get("cookie")
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    let cookies = waf_core::request::parse_cookie_header(cookie_hdr);
    let bic_present = cookies.get(engine.bic.cookie_name())
        .map(|c| {
            let ip = session.client_addr().and_then(|a| a.as_inet())
                .map(|a| a.ip())
                .unwrap_or_else(|| std::net::IpAddr::from([0,0,0,0]));
            engine.bic.verify_cookie(c, ip)
        })
        .unwrap_or(false);

    if bic_on && !bic_present {
        let token = engine.bic.issue();
        let original = req.uri.path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let body = engine.bic.render_page(&token, &d.request_id, &original);
        let extra: Vec<(&str, &str)> = vec![
            ("cache-control", "no-store, private"),
            ("x-waf-action", "bic"),
        ];
        write_response(session, 200, "text/html; charset=utf-8", body.as_bytes(), &extra).await;
        return;
    }

    // After BIC (if any), pick PoW vs interactive captcha based on the
    // operator-selected ChallengeMode.
    let mode = engine.runtime.challenge_mode_v();
    if matches!(mode, waf_core::runtime::ChallengeMode::Interactive
                    | waf_core::runtime::ChallengeMode::Combined) {
        let site_key = engine.runtime.turnstile_site_key.read().clone();
        let provider_name = engine.runtime.turnstile_provider.read().clone();
        if !site_key.is_empty() {
            let provider = waf_core::turnstile::Provider::from_str(&provider_name);
            let original = req.uri.path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".into());
            let body = waf_core::turnstile::render_page(provider, &site_key, &d.request_id, &original);
            let extra: Vec<(&str, &str)> = vec![
                ("cache-control", "no-store, private"),
                ("x-waf-action", "captcha"),
            ];
            write_response(session, 403, "text/html; charset=utf-8", body.as_bytes(), &extra).await;
            return;
        }
        // Site key not configured — fall back to PoW so we never serve
        // a broken captcha widget.
    }

    // Fall through to the heavyweight PoW challenge. The difficulty scales
    // up under heavy UAM levels (and is bound into the token signature).
    let token = engine.challenger.issue_with(engine.pow_difficulty_for_uam());
    let body = engine.challenger.render_page(&token, &d.request_id);
    let extra: Vec<(&str, &str)> = vec![
        ("cache-control", "no-store, private"),
        ("x-waf-action", "challenge"),
    ];
    write_response(session, 403, "text/html; charset=utf-8", body.as_bytes(), &extra).await;
}

async fn handle_turnstile_verify(session: &mut Session, engine: &Engine, client_ip: std::net::IpAddr) {
    use waf_core::turnstile::{verify, Provider};

    // Read up to 8 KiB of body — JSON `{"token": "..."}`.
    let mut buf = Vec::with_capacity(512);
    while buf.len() < 8192 {
        match session.as_mut().read_request_body().await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
            _ => break,
        }
    }
    #[derive(serde::Deserialize)]
    struct Submit { token: String }

    let token = serde_json::from_slice::<Submit>(&buf).ok().map(|s| s.token).unwrap_or_default();
    let secret   = engine.runtime.turnstile_secret.read().clone();
    let provider = Provider::from_str(&engine.runtime.turnstile_provider.read());

    if secret.is_empty() {
        write_response(session, 503, "application/json",
            br#"{"error":"captcha not configured"}"#, &[]).await;
        return;
    }
    let ok = verify(provider, &secret, &token, &client_ip.to_string()).await;
    if ok {
        // Reuse the PoW Challenger's clearance cookie — same downstream
        // semantics, so once the visitor passes a captcha they enjoy
        // the full PoW-cleared trust window.
        let cookie_value = engine.challenger.mint_clearance();
        let cookie = format!(
            "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
            engine.challenger.cookie_name(), cookie_value, engine.challenger.cookie_ttl(),
        );
        write_response(session, 204, "text/plain", b"", &[("set-cookie", cookie.as_str())]).await;
    } else {
        write_response(session, 403, "application/json",
            br#"{"error":"captcha verification failed"}"#, &[]).await;
    }
}

async fn handle_bic_verify(session: &mut Session, engine: &Engine, client_ip: std::net::IpAddr) {
    let mut buf = Vec::with_capacity(256);
    while buf.len() < 1024 {
        match session.as_mut().read_request_body().await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
            _ => break,
        }
    }
    #[derive(serde::Deserialize)]
    struct Submit { c: String, e: u64, s: String, p: String }

    let ok = serde_json::from_slice::<Submit>(&buf).ok().map(|s| {
        engine.bic.verify_proof(&s.c, s.e, &s.s, &s.p).is_ok()
    }).unwrap_or(false);

    if ok {
        let (name, value) = engine.bic.mint(client_ip);
        let cookie = format!(
            "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
            name, value, engine.bic.ttl(),
        );
        write_response(session, 204, "text/plain", b"", &[("set-cookie", cookie.as_str())]).await;
    } else {
        write_response(session, 400, "application/json",
            br#"{"error":"bic verification failed"}"#, &[]).await;
    }
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
    struct Submit { c: String, n: String, s: String, e: u64, #[serde(default)] d: u8 }

    let ok = serde_json::from_slice::<Submit>(&buf).ok().map(|s| {
        engine.challenger.verify(&s.c, &s.n, &s.s, s.e, s.d).is_ok()
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
