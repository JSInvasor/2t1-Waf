//! The orchestrator that turns a `RequestCtx` into a `Decision` by running
//! every check in a sensible order. Checks are short-circuited as soon as the
//! score crosses the block threshold so a clearly malicious request does the
//! minimum work.

use crate::behavior::BehaviorTracker;
use crate::bot_score;
use crate::challenge::Challenger;
use crate::config::Config;
use crate::connections::ConnTracker;
use crate::ddos;
use crate::decision::{Decision, DecisionReason};
use crate::events::EventLog;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::reputation::{Reputation, Reputations};
use crate::request::RequestCtx;
use crate::rules::{self, Surface};
use crate::runtime::{Runtime, UamLevel};
use crate::score::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub struct Engine {
    pub cfg: Arc<Config>,
    pub rate_limiter: RateLimiter,
    pub reputations: Reputations,
    pub challenger: Challenger,
    pub ua_scanner: rules::ua::UaScanner,
    pub metrics: Arc<Metrics>,
    pub runtime: Arc<Runtime>,
    pub events: Arc<EventLog>,
    pub conns: Arc<ConnTracker>,
    pub behavior: Arc<BehaviorTracker>,
}

/// Per-UAM level scaling. Returned by `Engine::uam_params`.
#[derive(Debug, Clone, Copy)]
pub struct UamParams {
    /// Force every fresh request through the JS challenge.
    pub force_challenge: bool,
    /// Multiply rate-limit RPM ceiling by this basis-points value.
    pub rpm_scale_bps: u32,
    /// Subtract this from the challenge threshold (lower = more challenges).
    pub challenge_drop: u32,
    /// Subtract this from the block threshold.
    pub block_drop: u32,
    /// Lower the per-IP concurrent cap by this (0 = leave alone).
    pub conn_cap_clamp: u32,
}

impl Engine {
    pub fn build(cfg: Config) -> anyhow::Result<Arc<Self>> {
        let rate_limiter = RateLimiter::new(&cfg.rate_limit)?;
        let reputations = Reputations::new(&cfg.reputation)?;
        let ua_scanner = rules::ua::UaScanner::new(&cfg.detection.suspicious_user_agents)?;
        let challenger = Challenger::new(
            &cfg.challenge.hmac_secret,
            &cfg.challenge.cookie_name,
            cfg.challenge.cookie_ttl_secs,
            cfg.challenge.pow_difficulty,
        );
        let runtime = Arc::new(Runtime::from_config(&cfg));
        Ok(Arc::new(Self {
            cfg: Arc::new(cfg),
            rate_limiter,
            reputations,
            challenger,
            ua_scanner,
            metrics: Arc::new(Metrics::default()),
            runtime,
            events: Arc::new(EventLog::default()),
            conns: Arc::new(ConnTracker::default()),
            behavior: Arc::new(BehaviorTracker::default()),
        }))
    }

    /// Translate the runtime UAM level into engine-side scaling parameters.
    pub fn uam_params(&self) -> UamParams {
        // Legacy `under_attack` flag forces medium if level is still 0.
        let mut lvl = self.runtime.uam();
        if matches!(lvl, UamLevel::Off) && self.runtime.under_attack.load(Ordering::Relaxed) {
            lvl = UamLevel::Medium;
        }
        match lvl {
            UamLevel::Off     => UamParams { force_challenge: false, rpm_scale_bps: 10_000,
                challenge_drop: 0,  block_drop: 0,  conn_cap_clamp: 0 },
            UamLevel::Low     => UamParams { force_challenge: false, rpm_scale_bps:  7_500,
                challenge_drop: 5,  block_drop: 5,  conn_cap_clamp: 0 },
            UamLevel::Medium  => UamParams { force_challenge: true,  rpm_scale_bps:  5_000,
                challenge_drop: 10, block_drop: 10, conn_cap_clamp: 0 },
            UamLevel::High    => UamParams { force_challenge: true,  rpm_scale_bps:  2_500,
                challenge_drop: 15, block_drop: 15, conn_cap_clamp: 50 },
            UamLevel::Extreme => UamParams { force_challenge: true,  rpm_scale_bps:  1_000,
                challenge_drop: 20, block_drop: 20, conn_cap_clamp: 25 },
        }
    }

    pub fn evaluate(&self, ctx: &RequestCtx) -> Decision {
        let req_id = ctx.request_id.clone();
        let uam = self.uam_params();

        // 1. Clearance cookie short-circuits everything except the always-on
        //    deny-list / connection-cap / rate-limit checks.
        let cleared = ctx.cookie(self.challenger.cookie_name())
            .map(|v| self.challenger.verify_clearance(v))
            .unwrap_or(false);

        // 2. Static + runtime IP reputation. Allow always wins.
        let ip = ctx.client_ip;
        let runtime_allow = self.runtime.allow.read();
        if runtime_allow.iter().any(|n| n.contains(&ip)) {
            drop(runtime_allow);
            return self.finalize(ctx, Decision::allow(req_id));
        }
        drop(runtime_allow);

        match self.reputations.classify(ip) {
            Reputation::Allow => return self.finalize(ctx, Decision::allow(req_id)),
            Reputation::Deny => {
                let r = DecisionReason {
                    rule_id: "REP-DENY", category: "reputation",
                    score: SCORE_DENY_REPUTATION,
                    detail: "ip on deny list or auto-banned".into(),
                };
                self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
                return self.finalize(ctx, Decision::block(req_id, 403, r));
            }
            Reputation::Unknown => {}
        }
        if self.runtime.deny.read().iter().any(|n| n.contains(&ip)) {
            let r = DecisionReason {
                rule_id: "REP-DENY-RT", category: "reputation",
                score: SCORE_DENY_REPUTATION,
                detail: "ip on runtime deny list".into(),
            };
            self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
            return self.finalize(ctx, Decision::block(req_id, 403, r));
        }

        // 3. Per-IP concurrent request cap (UAM clamps this further).
        let in_flight = self.conns.current(ip);
        let mut cap = self.runtime.max_concurrent_per_ip.load(Ordering::Relaxed) as i64;
        if uam.conn_cap_clamp > 0 {
            cap = cap.min(uam.conn_cap_clamp as i64);
        }
        if cap > 0 && in_flight > cap {
            let r = DecisionReason {
                rule_id: "CONN-CAP", category: "ddos",
                score: SCORE_DENY_REPUTATION,
                detail: format!("{} concurrent > cap {}", in_flight, cap),
            };
            self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
            return self.finalize(ctx, Decision::block(req_id, 429, r));
        }

        // 4. Hard absolute limits.
        if let Some(d) = self.hard_limits(&req_id, ctx) {
            return self.finalize(ctx, d);
        }

        // 5. Rate limit (UAM tightens the ceiling adaptively).
        if self.runtime.rules.rate_limit.load(Ordering::Relaxed) {
            // The legacy `under_attack` toggle keeps using `rpm_under_attack_bps`;
            // UAM levels above Off override it with their own scale.
            let scale_bps = if uam.rpm_scale_bps < 10_000 {
                uam.rpm_scale_bps
            } else if self.runtime.under_attack.load(Ordering::Relaxed) {
                self.runtime.rpm_under_attack_bps.load(Ordering::Relaxed)
            } else { 10_000 };
            if let Err(l) = self.rate_limiter.check_scaled(&ctx.client_ip.to_string(), &ctx.path, scale_bps) {
                let r = DecisionReason {
                    rule_id: "RL-01", category: "rate_limit",
                    score: SCORE_RL_HIT,
                    detail: format!("scope={} retry_after={}s path={}", l.scope, l.retry_after, l.path),
                };
                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
                return self.finalize(ctx, Decision::block(req_id, 429, r));
            }
        }

        if cleared {
            return self.finalize(ctx, Decision::allow(req_id));
        }

        // 6. UAM force-challenge for fresh visitors (Medium and up).
        if uam.force_challenge {
            self.metrics.challenged.fetch_add(1, Ordering::Relaxed);
            let r = DecisionReason {
                rule_id: "UAM-FORCE", category: "anti_ddos",
                score: 100,
                detail: format!("uam={:?} forcing challenge", self.runtime.uam()),
            };
            return self.finalize(ctx, Decision::challenge(req_id, 100, vec![r]));
        }

        // 7. Scoring signals.
        let mut decision = Decision::allow(req_id.clone());

        if let Some(r) = self.geoip_reason(ctx) { decision.add_reason(r); }
        for r in self.header_reasons(ctx)      { decision.add_reason(r); }

        // Browser/bot heuristics (header completeness, UA consistency).
        if self.runtime.defenses.bot_score.load(Ordering::Relaxed) {
            for r in bot_score::score(ctx) { decision.add_reason(r); }
        }

        // Per-IP behaviour fingerprint (URL diversity, interval regularity, …).
        if self.runtime.defenses.behavior.load(Ordering::Relaxed) {
            for r in self.behavior.observe(ctx.client_ip, &ctx.path, &ctx.method, &ctx.user_agent) {
                decision.add_reason(r);
            }
        }

        // DDoS-flavoured request anomalies.
        if self.runtime.defenses.ddos.load(Ordering::Relaxed) {
            for r in ddos::score(ctx) { decision.add_reason(r); }
        }

        if self.runtime.rules.bot_ua.load(Ordering::Relaxed)
            && !ctx.user_agent.is_empty()
            && self.ua_scanner.is_suspicious(&ctx.user_agent)
        {
            decision.add_reason(DecisionReason {
                rule_id: "UA-SUSPICIOUS", category: "ua",
                score: SCORE_BAD_UA,
                detail: rules::excerpt(&ctx.user_agent),
            });
        }

        let surface = Surface::from(ctx);
        if self.runtime.rules.sqli.load(Ordering::Relaxed) {
            if let Some(h) = rules::sqli::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_SQLI_HIGH));
            }
        }
        if self.runtime.rules.xss.load(Ordering::Relaxed) {
            if let Some(h) = rules::xss::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_XSS_HIGH));
            }
        }
        if self.runtime.rules.traversal.load(Ordering::Relaxed) {
            if let Some(h) = rules::traversal::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_TRAVERSAL));
            }
        }
        if self.runtime.rules.cmdi.load(Ordering::Relaxed) {
            if let Some(h) = rules::cmdi::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_CMDI));
            }
        }
        if self.runtime.rules.lfi.load(Ordering::Relaxed) {
            if let Some(h) = rules::lfi::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_LFI));
            }
        }

        // 8. Threshold decision (UAM lowers both thresholds adaptively).
        let block_t = self.runtime.block_threshold.load(Ordering::Relaxed)
            .saturating_sub(uam.block_drop);
        let chal_t  = self.runtime.challenge_threshold.load(Ordering::Relaxed)
            .saturating_sub(uam.challenge_drop);
        if decision.score >= block_t {
            let primary = decision.reasons.first().cloned().unwrap_or(DecisionReason {
                rule_id: "ANOMALY", category: "anomaly",
                score: decision.score, detail: "score over threshold".into(),
            });
            let new_ban = self.reputations.record_offence(ctx.client_ip);
            tracing::warn!(
                request_id = %req_id, ip = %ctx.client_ip, path = %ctx.path,
                score = decision.score, banned = new_ban,
                "blocked by score threshold"
            );
            self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
            return self.finalize(ctx, Decision::block(req_id, 403, primary));
        }
        if decision.score >= chal_t {
            self.metrics.challenged.fetch_add(1, Ordering::Relaxed);
            return self.finalize(ctx, Decision::challenge(req_id, decision.score, decision.reasons));
        }

        self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
        self.finalize(ctx, Decision::allow(req_id))
    }

    fn finalize(&self, ctx: &RequestCtx, d: Decision) -> Decision {
        self.events.record(ctx, &d);
        d
    }

    fn hard_limits(&self, req_id: &str, ctx: &RequestCtx) -> Option<Decision> {
        let l = &self.cfg.limits;
        if !l.allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(&ctx.method)) {
            return Some(Decision::block(
                req_id.to_string(), 405,
                DecisionReason {
                    rule_id: "METHOD-DENIED", category: "method",
                    score: SCORE_BAD_METHOD,
                    detail: ctx.method.clone(),
                }));
        }
        if ctx.uri.len() > l.max_uri_bytes {
            return Some(Decision::block(
                req_id.to_string(), 414,
                DecisionReason {
                    rule_id: "URI-TOO-LONG", category: "limit",
                    score: SCORE_OVERSIZE_URI,
                    detail: format!("uri={}B max={}B", ctx.uri.len(), l.max_uri_bytes),
                }));
        }
        if ctx.headers.len() > l.max_headers {
            return Some(Decision::block(
                req_id.to_string(), 431,
                DecisionReason {
                    rule_id: "TOO-MANY-HEADERS", category: "limit",
                    score: SCORE_OVERSIZE_HEAD,
                    detail: format!("count={}", ctx.headers.len()),
                }));
        }
        if let Some(too_big) = ctx.headers.values().find(|v| v.len() > l.max_header_value_bytes) {
            return Some(Decision::block(
                req_id.to_string(), 431,
                DecisionReason {
                    rule_id: "HEADER-TOO-LONG", category: "limit",
                    score: SCORE_OVERSIZE_HEAD,
                    detail: format!("len={}B", too_big.len()),
                }));
        }
        if let Some(cl) = ctx.content_length {
            if cl as usize > l.max_body_bytes {
                return Some(Decision::block(
                    req_id.to_string(), 413,
                    DecisionReason {
                        rule_id: "BODY-TOO-LARGE", category: "limit",
                        score: SCORE_OVERSIZE_BODY,
                        detail: format!("len={}B max={}B", cl, l.max_body_bytes),
                    }));
            }
        }
        None
    }

    fn header_reasons(&self, ctx: &RequestCtx) -> Vec<DecisionReason> {
        let mut out = Vec::new();
        if ctx.host.is_empty() {
            out.push(DecisionReason {
                rule_id: "HDR-NO-HOST", category: "headers",
                score: SCORE_MISSING_HOST,
                detail: "Host header missing".into(),
            });
        }
        if ctx.user_agent.is_empty() {
            out.push(DecisionReason {
                rule_id: "HDR-NO-UA", category: "headers",
                score: SCORE_MISSING_UA,
                detail: "User-Agent missing".into(),
            });
        }
        if ctx.headers.len() < 3 {
            out.push(DecisionReason {
                rule_id: "HDR-MINIMAL", category: "headers",
                score: SCORE_HEADERLESS,
                detail: format!("only {} headers present", ctx.headers.len()),
            });
        }
        let has_cl = ctx.headers.contains_key("content-length");
        let has_te = ctx.headers.get("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);
        if has_cl && has_te {
            out.push(DecisionReason {
                rule_id: "HDR-CL-TE", category: "smuggling",
                score: SCORE_SUSPICIOUS_HEADER,
                detail: "Content-Length + Transfer-Encoding: chunked".into(),
            });
        }
        out
    }

    fn geoip_reason(&self, ctx: &RequestCtx) -> Option<DecisionReason> {
        let country = ctx.country.as_deref()?;
        let cc = country.to_ascii_uppercase();
        let runtime_blocked = self.runtime.blocked_countries.read();
        if runtime_blocked.iter().any(|c| c.eq_ignore_ascii_case(&cc))
            || self.cfg.geoip.block_countries.iter().any(|c| c.eq_ignore_ascii_case(&cc))
        {
            return Some(DecisionReason {
                rule_id: "GEO-BLOCKED", category: "geoip",
                score: SCORE_GEO_BLOCKED,
                detail: format!("country={cc}"),
            });
        }
        if self.cfg.geoip.suspicious_countries.iter().any(|c| c.eq_ignore_ascii_case(&cc)) {
            return Some(DecisionReason {
                rule_id: "GEO-SUSPICIOUS", category: "geoip",
                score: SCORE_GEO_SUSPICIOUS,
                detail: format!("country={cc}"),
            });
        }
        None
    }
}

fn hit_to_reason(h: rules::Hit, score: u32) -> DecisionReason {
    DecisionReason {
        rule_id: h.rule_id,
        category: h.category,
        score,
        detail: format!("field={} excerpt={:?}", h.matched_field, h.matched_excerpt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Action;
    use crate::config::*;
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn cfg() -> Config {
        toml::from_str(r##"
[server]
listen = "0.0.0.0:8080"
[upstream]
address = "127.0.0.1:8000"
[limits]
max_body_bytes = 1024
max_headers = 100
max_header_value_bytes = 8192
max_uri_bytes = 8192
allowed_methods = ["GET","POST"]
[rate_limit]
enabled = false
requests_per_minute = 9999
[reputation]
[detection]
suspicious_user_agents = ["sqlmap"]
challenge_threshold = 40
block_threshold = 70
[challenge]
hmac_secret = "a-very-secret-key-of-some-length"
"##).unwrap()
    }

    fn req(uri: &str, query: &str) -> RequestCtx {
        let mut h = HashMap::new();
        h.insert("host".into(), "h".into());
        h.insert("user-agent".into(), "Mozilla/5.0".into());
        h.insert("accept".into(), "*/*".into());
        RequestCtx {
            request_id: "t".into(),
            client_ip: IpAddr::from([1,2,3,4]),
            method: "GET".into(),
            uri: uri.into(), path: uri.split('?').next().unwrap().into(),
            query: query.into(), host: "h".into(),
            user_agent: "Mozilla/5.0".into(),
            headers: h, cookies: HashMap::new(),
            body_preview: vec![], content_length: None, country: None,
        }
    }

    fn quiet_engine() -> std::sync::Arc<Engine> {
        // Disable the heuristic defenses for tests that exercise just the
        // routing / threshold logic. Each defense module has its own tests.
        let e = Engine::build(cfg()).unwrap();
        e.runtime.defenses.bot_score.store(false, Ordering::Relaxed);
        e.runtime.defenses.behavior.store(false,  Ordering::Relaxed);
        e.runtime.defenses.ddos.store(false,      Ordering::Relaxed);
        e
    }

    #[test]
    fn benign_passes() {
        let e = quiet_engine();
        let d = e.evaluate(&req("/x", ""));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn sqli_blocks() {
        let e = quiet_engine();
        let d = e.evaluate(&req("/x?id=1' OR 1=1--", "id=1' OR 1=1--"));
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn under_attack_forces_challenge() {
        let e = quiet_engine();
        e.runtime.under_attack.store(true, Ordering::Relaxed);
        let d = e.evaluate(&req("/x", ""));
        assert_eq!(d.action, Action::Challenge);
    }

    #[test]
    fn uam_medium_forces_challenge() {
        let e = quiet_engine();
        e.runtime.uam_level.store(2, Ordering::Relaxed);
        let d = e.evaluate(&req("/x", ""));
        assert_eq!(d.action, Action::Challenge);
        assert_eq!(d.reasons.first().map(|r| r.rule_id), Some("UAM-FORCE"));
    }

    #[test]
    fn runtime_deny_blocks() {
        let e = quiet_engine();
        e.runtime.add_deny("1.2.3.4").unwrap();
        let d = e.evaluate(&req("/x", ""));
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn runtime_allow_overrides_rule() {
        let e = quiet_engine();
        e.runtime.add_allow("1.2.3.4").unwrap();
        let d = e.evaluate(&req("/x?id=1' OR 1=1--", "id=1' OR 1=1--"));
        assert_eq!(d.action, Action::Allow);
    }
}
