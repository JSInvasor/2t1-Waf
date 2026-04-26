//! The orchestrator that turns a `RequestCtx` into a `Decision` by running
//! every check in a sensible order. Checks are short-circuited as soon as the
//! score crosses the block threshold so a clearly malicious request does the
//! minimum work.

use crate::challenge::Challenger;
use crate::config::Config;
use crate::decision::{Decision, DecisionReason};
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::reputation::{Reputation, Reputations};
use crate::request::RequestCtx;
use crate::rules::{self, Surface};
use crate::score::*;
use std::sync::Arc;

pub struct Engine {
    pub cfg: Arc<Config>,
    pub rate_limiter: RateLimiter,
    pub reputations: Reputations,
    pub challenger: Challenger,
    pub ua_scanner: rules::ua::UaScanner,
    pub metrics: Arc<Metrics>,
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
        Ok(Arc::new(Self {
            cfg: Arc::new(cfg),
            rate_limiter,
            reputations,
            challenger,
            ua_scanner,
            metrics: Arc::new(Metrics::default()),
        }))
    }

    pub fn evaluate(&self, ctx: &RequestCtx) -> Decision {
        let req_id = ctx.request_id.clone();

        // 1. A valid clearance cookie short-circuits everything but the IP
        //    deny / rate limit checks (still cheap).
        let cleared = ctx.cookie(self.challenger.cookie_name())
            .map(|v| self.challenger.verify_clearance(v))
            .unwrap_or(false);

        // 2. IP reputation.
        match self.reputations.classify(ctx.client_ip) {
            Reputation::Allow => {
                return Decision::allow(req_id);
            }
            Reputation::Deny => {
                let r = DecisionReason {
                    rule_id: "REP-DENY", category: "reputation",
                    score: SCORE_DENY_REPUTATION,
                    detail: "ip on deny list or auto-banned".into(),
                };
                self.metrics.blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Decision::block(req_id, 403, r);
            }
            Reputation::Unknown => {}
        }

        // 3. Hard limits — these are absolute, no scoring.
        if let Some(d) = self.hard_limits(&req_id, ctx) { return d; }

        // 4. Rate limit.
        if let Err(l) = self.rate_limiter.check(&ctx.client_ip.to_string(), &ctx.path) {
            let r = DecisionReason {
                rule_id: "RL-01", category: "rate_limit",
                score: SCORE_RL_HIT,
                detail: format!("scope={} retry_after={}s path={}", l.scope, l.retry_after, l.path),
            };
            self.metrics.rate_limited.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics.blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Decision::block(req_id, 429, r);
        }

        if cleared {
            // Trusted browser — skip the heavyweight scanning.
            return Decision::allow(req_id);
        }

        // 5. Scoring signals. Run cheap header checks first, then the regex
        //    surface scans.
        let mut decision = Decision::allow(req_id.clone());

        if let Some(r) = self.geoip_reason(ctx) { decision.add_reason(r); }
        for r in self.header_reasons(ctx) { decision.add_reason(r); }

        if !ctx.user_agent.is_empty() && self.ua_scanner.is_suspicious(&ctx.user_agent) {
            decision.add_reason(DecisionReason {
                rule_id: "UA-SUSPICIOUS", category: "ua",
                score: SCORE_BAD_UA,
                detail: rules::excerpt(&ctx.user_agent),
            });
        }

        // Detection rules over the request surface.
        let surface = Surface::from(ctx);
        if self.cfg.detection.sqli {
            if let Some(h) = rules::sqli::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_SQLI_HIGH));
            }
        }
        if self.cfg.detection.xss {
            if let Some(h) = rules::xss::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_XSS_HIGH));
            }
        }
        if self.cfg.detection.traversal {
            if let Some(h) = rules::traversal::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_TRAVERSAL));
            }
        }
        if self.cfg.detection.cmdi {
            if let Some(h) = rules::cmdi::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_CMDI));
            }
        }
        if self.cfg.detection.lfi {
            if let Some(h) = rules::lfi::scan(&surface) {
                decision.add_reason(hit_to_reason(h, SCORE_LFI));
            }
        }

        // 6. Threshold decision.
        let block_t = self.cfg.detection.block_threshold;
        let chal_t  = self.cfg.detection.challenge_threshold;
        if decision.score >= block_t {
            // Promote to block + register an offence (auto-ban).
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
            self.metrics.blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Decision::block(req_id, 403, primary);
        }
        if decision.score >= chal_t {
            self.metrics.challenged.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Decision::challenge(req_id, decision.score, decision.reasons);
        }

        self.metrics.allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Decision::allow(req_id)
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
        // Smuggling-style header-pair anomalies.
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
        if self.cfg.geoip.block_countries.iter().any(|c| c.eq_ignore_ascii_case(&cc)) {
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

    #[test]
    fn benign_passes() {
        let e = Engine::build(cfg()).unwrap();
        let d = e.evaluate(&req("/x", ""));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn sqli_blocks() {
        let e = Engine::build(cfg()).unwrap();
        let d = e.evaluate(&req("/x?id=1' OR 1=1--", "id=1' OR 1=1--"));
        assert_eq!(d.action, Action::Block);
    }
}
