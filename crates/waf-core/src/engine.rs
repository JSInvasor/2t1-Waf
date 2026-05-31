//! The orchestrator that turns a `RequestCtx` into a `Decision` by running
//! every check in a sensible order. Checks are short-circuited as soon as the
//! score crosses the block threshold so a clearly malicious request does the
//! minimum work.

use crate::behavior::BehaviorTracker;
use crate::bic::Bic;
use crate::bot_score;
use crate::challenge::Challenger;
use crate::config::Config;
use crate::connections::ConnTracker;
use crate::datacenter;
use crate::ddos;
use crate::decision::{Action, Decision, DecisionReason};
use crate::events::EventLog;
use crate::goodbot::{GoodBotVerifier, Verdict};
use crate::honeypots::Honeypots;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::reputation::{Reputation, Reputations};
use crate::request::RequestCtx;
use crate::rules::{self, Surface};
use crate::runtime::{Runtime, UamLevel};
use crate::score::*;
use crate::signature::{DistributedUa, RequestReplay};
use crate::storage::Sink;
use crate::subnet::SubnetTracker;
use parking_lot::RwLock;
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
    pub subnets:  Arc<SubnetTracker>,
    pub honeypots: Arc<Honeypots>,
    pub replay:   Arc<RequestReplay>,
    pub dist_ua:  Arc<DistributedUa>,
    pub goodbot:  Arc<GoodBotVerifier>,
    pub bic:      Arc<Bic>,
    /// Optional persistent event sink. None = in-memory ring only.
    pub storage_sink: RwLock<Option<Sink>>,
    pub storage_path: RwLock<Option<std::path::PathBuf>>,
}

const W_DATACENTER: u32 = 25;

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
        let _bic_secret_clone = cfg.challenge.hmac_secret.clone();
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
            subnets:  Arc::new(SubnetTracker::default()),
            honeypots: Arc::new(Honeypots::default()),
            replay:   Arc::new(RequestReplay::default()),
            dist_ua:  Arc::new(DistributedUa::default()),
            goodbot:  Arc::new(GoodBotVerifier::default()),
            bic:      Arc::new(Bic::new(&_bic_secret_clone)),
            storage_sink: RwLock::new(None),
            storage_path: RwLock::new(None),
        }))
    }

    /// Bind a persistent event sink. Called by the proxy crate after
    /// `Storage::open` succeeds. Optional — if no sink is bound, events
    /// only land in the in-memory ring.
    pub fn attach_storage(&self, sink: Sink) {
        *self.storage_sink.write() = Some(sink);
    }

    /// Path the storage writer is using; the admin layer needs it to
    /// open short-lived read connections for timeframe queries.
    pub fn storage_path(&self) -> Option<std::path::PathBuf> {
        self.storage_path.read().clone()
    }
    pub fn set_storage_path(&self, p: std::path::PathBuf) {
        *self.storage_path.write() = Some(p);
    }

    /// Convenience for the admin range endpoints.
    pub fn runtime_state_db_path(&self) -> Option<std::path::PathBuf> {
        self.storage_path()
    }

    /// True when the global in-flight count is at or above the hard
    /// ceiling. The proxy uses this to short-circuit at the door without
    /// running any of the rule pipeline.
    pub fn at_capacity(&self) -> bool {
        let cap = self.runtime.global_inflight_cap.load(Ordering::Relaxed) as i64;
        if cap == 0 { return false; }
        self.conns.total() >= cap
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

    /// PoW difficulty for a freshly issued challenge. Scaled up by one step
    /// under the heavy UAM levels (High / Extreme) so automated solvers pay
    /// noticeably more per request during an attack, while a real browser still
    /// clears it in about a second. Deliberately capped at `base + 1` and an
    /// absolute ceiling of 5 leading hex zeroes: each extra digit is 16× the
    /// work, so this is the most we can add without risking a slow mobile
    /// client timing out — keeping the no-false-positive guarantee even for the
    /// few genuine visitors who hit a challenge mid-attack. For a strictly
    /// stronger gate under heavy attack, switch ChallengeMode to the
    /// interactive captcha, which costs a human nothing.
    pub fn pow_difficulty_for_uam(&self) -> u8 {
        let base = self.challenger.base_difficulty();
        let bump = match self.runtime.uam() {
            UamLevel::High | UamLevel::Extreme => 1,
            _ => 0,
        };
        base.saturating_add(bump).min(5)
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
                    rule_id: "REP-DENY".to_string(), category: "reputation".to_string(),
                    score: SCORE_DENY_REPUTATION,
                    detail: "ip on deny list or auto-banned".into(),
                };
                return self.finalize(ctx, Decision::block(req_id, 403, r));
            }
            Reputation::Unknown => {}
        }
        if self.runtime.deny.read().iter().any(|n| n.contains(&ip)) {
            let r = DecisionReason {
                rule_id: "REP-DENY-RT".to_string(), category: "reputation".to_string(),
                score: SCORE_DENY_REPUTATION,
                detail: "ip on runtime deny list".into(),
            };
            return self.finalize(ctx, Decision::block(req_id, 403, r));
        }

        // 2.4 Verified good-bot whitelist. Real Googlebot / Bingbot etc.
        // bypass everything; UA spoofers get a heavy +score that rides
        // them into challenge / block territory naturally. Pending bots
        // (UA matches but reverse-DNS lookup is in flight) get a lenient
        // pass — bot_score is skipped for that one request so SEO doesn't
        // break on the very first hit.
        let mut goodbot_pending = false;
        let mut goodbot_spoof: Option<DecisionReason> = None;
        if self.runtime.defenses.goodbot.load(Ordering::Relaxed) {
            match self.goodbot.classify(ip, &ctx.user_agent) {
                Verdict::GoodBotVerified(_) => {
                    return self.finalize(ctx, Decision::allow(req_id));
                }
                Verdict::GoodBotSpoofed(name) => {
                    goodbot_spoof = Some(crate::goodbot::spoof_reason(name));
                }
                Verdict::GoodBotPending  => goodbot_pending = true,
                Verdict::NotABot         => {}
            }
        }

        // 2.5 Honeypot trip — any request to a trap path is malicious by
        //     definition. Force-ban immediately and short-circuit.
        if self.runtime.defenses.honeypots.load(Ordering::Relaxed) {
            if let Some(r) = self.honeypots.check(&ctx.path) {
                self.reputations.force_ban(ip, self.cfg.reputation.auto_ban_duration_secs);
                return self.finalize(ctx, Decision::block(req_id, 403, r));
            }
        }

        // 3. Per-IP concurrent request cap (UAM clamps this further).
        let in_flight = self.conns.current(ip);
        let mut cap = self.runtime.max_concurrent_per_ip.load(Ordering::Relaxed) as i64;
        if uam.conn_cap_clamp > 0 {
            cap = cap.min(uam.conn_cap_clamp as i64);
        }
        if cap > 0 && in_flight > cap {
            let r = DecisionReason {
                rule_id: "CONN-CAP".to_string(), category: "ddos".to_string(),
                score: SCORE_DENY_REPUTATION,
                detail: format!("{} concurrent > cap {}", in_flight, cap),
            };
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
            if let Err(l) = self.rate_limiter.check_scaled(ctx.client_ip, &ctx.path, scale_bps) {
                let r = DecisionReason {
                    rule_id: "RL-01".to_string(), category: "rate_limit".to_string(),
                    score: SCORE_RL_HIT,
                    detail: format!("scope={} retry_after={}s path={}", l.scope, l.retry_after, l.path),
                };
                // rate_limited is a separate counter (not derived from action),
                // so it's still incremented here. action counters live in
                // metrics::record() called by the proxy layer.
                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                return self.finalize(ctx, Decision::block(req_id, 429, r));
            }
        }

        if cleared {
            return self.finalize(ctx, Decision::allow(req_id));
        }

        // 6. Under-Attack Lockdown — hard default-deny. When lockdown is active
        //    (operator switch, or auto once auto-UAM reaches High/Extreme) and
        //    the browser-integrity check is enabled, a request must positively
        //    prove it is a real, modern browser. The verdict is authoritative
        //    and replaces the softer UAM force-challenge:
        //      * Forged   → an *impossible* browser fingerprint → immediate 403,
        //                   no challenge page is even served, and the offence is
        //                   recorded toward an auto-ban.
        //      * Unverified → can't be vouched for → invisible challenge (silent
        //                   BIC → PoW/Turnstile). A client that already cleared
        //                   the silent probe (valid BIC cookie) is let through.
        //      * Trusted  → complete, internally-consistent modern browser →
        //                   falls through to normal scoring (no forced friction).
        //    Verified good bots and clients holding a clearance cookie already
        //    returned above, so they never reach this gate.
        let browser_integrity = self.runtime.defenses.browser_integrity.load(Ordering::Relaxed);
        if self.runtime.lockdown_active() && browser_integrity {
            use crate::browser_check::{verify, BrowserVerdict};
            match verify(ctx) {
                BrowserVerdict::Forged(reason) => {
                    let r = DecisionReason {
                        rule_id: "LOCKDOWN-FORGED".to_string(), category: "lockdown".to_string(),
                        score: SCORE_DENY_REPUTATION,
                        detail: format!("forged browser fingerprint: {reason}"),
                    };
                    let new_ban = self.reputations.record_offence(ctx.client_ip);
                    tracing::warn!(
                        request_id = %req_id, ip = %ctx.client_ip, path = %ctx.path,
                        reason = %reason, banned = new_ban,
                        "lockdown: blocked forged browser fingerprint"
                    );
                    return self.finalize(ctx, Decision::block(req_id, 403, r));
                }
                BrowserVerdict::Unverified => {
                    // Already cleared the silent probe this lockdown? Let it on.
                    let has_bic = self.runtime.defenses.bic.load(Ordering::Relaxed)
                        && ctx.cookie(self.bic.cookie_name())
                            .map(|v| self.bic.verify_cookie(v, ctx.client_ip))
                            .unwrap_or(false);
                    if !has_bic {
                        let r = DecisionReason {
                            rule_id: "LOCKDOWN-UNVERIFIED".to_string(), category: "lockdown".to_string(),
                            score: 100,
                            detail: "client could not prove it is a real browser".into(),
                        };
                        return self.finalize(ctx, Decision::challenge(req_id, 100, vec![r]));
                    }
                }
                BrowserVerdict::Trusted => { /* fall through to normal scoring */ }
            }
        } else if uam.force_challenge {
            // Softer UAM force-challenge for fresh visitors (Medium and up),
            // used whenever lockdown is not enforcing the hard verdict.
            let r = DecisionReason {
                rule_id: "UAM-FORCE".to_string(), category: "anti_ddos".to_string(),
                score: 100,
                detail: format!("uam={:?} forcing challenge", self.runtime.uam()),
            };
            return self.finalize(ctx, Decision::challenge(req_id, 100, vec![r]));
        }

        // 7. Scoring signals.
        let mut decision = Decision::allow(req_id.clone());

        // Apply the goodbot spoof score before any other signal so the
        // dashboard's "primary reason" surfaces the spoof clearly.
        if let Some(r) = goodbot_spoof.take() { decision.add_reason(r); }

        if let Some(r) = self.geoip_reason(ctx) { decision.add_reason(r); }
        for r in self.header_reasons(ctx)      { decision.add_reason(r); }

        // Silent BIC cookie acts like a lower-strength clearance: when
        // present and valid, we skip bot_score (the layer most prone to
        // false positives on minor UA quirks) but still run every DDoS
        // pattern / behaviour / subnet check.
        let has_bic = self.runtime.defenses.bic.load(Ordering::Relaxed)
            && ctx.cookie(self.bic.cookie_name())
                .map(|v| self.bic.verify_cookie(v, ctx.client_ip))
                .unwrap_or(false);

        // Browser/bot heuristics (header completeness, UA consistency).
        // Skipped while a good-bot verification is in flight so the very
        // first request from an SEO crawler isn't bounced through the
        // challenge before its PTR record is checked. Also skipped when
        // a valid BIC cookie is present.
        if !goodbot_pending && !has_bic && self.runtime.defenses.bot_score.load(Ordering::Relaxed) {
            for r in bot_score::score(ctx) { decision.add_reason(r); }
        }

        // "This is a genuine modern browser navigation or XHR" hint. A real
        // browser sets the forbidden `sec-fetch-*` headers on every fetch and
        // always sends `accept-language`; headless flood/scan tooling forges
        // neither. We use it to suppress the anomaly signals that overlap with
        // perfectly normal browser behaviour (single-endpoint polling, fixed-
        // interval timers, popular shared User-Agents, identical repeat
        // requests) so real users are never caught by them — while the same
        // signals stay fully active for non-browser clients, and the volume-
        // based defences (rate limit, subnet, conn-cap, global valve) protect
        // against floods regardless of how the client presents itself.
        let browserish = ctx.headers.keys().any(|k| k.starts_with("sec-fetch-"))
            && ctx.headers.contains_key("accept-language");

        // Per-IP behaviour fingerprint (URL diversity, interval regularity, …).
        if self.runtime.defenses.behavior.load(Ordering::Relaxed) {
            for r in self.behavior.observe(ctx.client_ip, &ctx.path, &ctx.method, &ctx.user_agent, browserish) {
                decision.add_reason(r);
            }
        }

        // DDoS-flavoured request anomalies.
        if self.runtime.defenses.ddos.load(Ordering::Relaxed) {
            for r in ddos::score(ctx) { decision.add_reason(r); }
        }

        // Source IP from a known datacenter / cloud ASN range.
        if self.runtime.datacenter_block.load(Ordering::Relaxed)
            && datacenter::is_datacenter(ctx.client_ip)
        {
            decision.add_reason(DecisionReason {
                rule_id: "DC-RANGE".to_string(), category: "asn".to_string(),
                score: W_DATACENTER,
                detail: "source ip within hosting/cloud CIDR".into(),
            });
        }

        // Per-subnet rate / concurrent ceiling (catches /24 botnets).
        if self.runtime.defenses.subnet.load(Ordering::Relaxed) {
            let rpm  = self.runtime.subnet_rpm.load(Ordering::Relaxed);
            let conn = self.runtime.subnet_conn.load(Ordering::Relaxed) as i64;
            for r in self.subnets.observe(ip, rpm, conn) { decision.add_reason(r); }
        }

        // Identical-request replay flood from a single IP. Skipped for real
        // browsers: a legitimate SPA polling one endpoint on a timer produces
        // the same (method, path, UA) signature repeatedly and would otherwise
        // be mistaken for a replay flood. Non-browser clients are still
        // checked, and browserish floods are caught by the rate/conn limits.
        if self.runtime.defenses.replay.load(Ordering::Relaxed) && !browserish {
            if let Some(r) = self.replay.observe(ip, &ctx.method, &ctx.path, &ctx.user_agent) {
                decision.add_reason(r);
            }
        }

        // Same UA shared by many distinct IPs in a short window (botnet UA).
        // Skipped for real browsers: a popular User-Agent (e.g. the current
        // Chrome release) is legitimately shared by many visitors at once, so
        // counting browserish clients here would false-positive on normal
        // traffic to any busy site. Only non-browser clients sharing a UA —
        // the actual botnet-toolkit signature — are counted.
        if self.runtime.defenses.dist_ua.load(Ordering::Relaxed)
            && !browserish && !ctx.user_agent.is_empty()
        {
            if let Some(r) = self.dist_ua.observe(ip, &ctx.user_agent) {
                decision.add_reason(r);
            }
        }

        if self.runtime.rules.bot_ua.load(Ordering::Relaxed)
            && !ctx.user_agent.is_empty()
            && self.ua_scanner.is_suspicious(&ctx.user_agent)
        {
            decision.add_reason(DecisionReason {
                rule_id: "UA-SUSPICIOUS".to_string(), category: "ua".to_string(),
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

        // 8. Threshold decision. UAM lowers both thresholds adaptively.
        // tarpit_t is an absolute "egregious" line above which the
        // decision is upgraded from block → tarpit so the attacker's
        // socket gets held open instead of freed.
        let block_t = self.runtime.block_threshold.load(Ordering::Relaxed)
            .saturating_sub(uam.block_drop);
        let chal_t  = self.runtime.challenge_threshold.load(Ordering::Relaxed)
            .saturating_sub(uam.challenge_drop);
        let tarpit_t = self.runtime.tarpit_score.load(Ordering::Relaxed);
        if decision.score >= block_t {
            let primary = decision.reasons.first().cloned().unwrap_or(DecisionReason {
                rule_id: "ANOMALY".to_string(), category: "anomaly".to_string(),
                score: decision.score, detail: "score over threshold".into(),
            });
            let new_ban = self.reputations.record_offence(ctx.client_ip);
            tracing::warn!(
                request_id = %req_id, ip = %ctx.client_ip, path = %ctx.path,
                score = decision.score, banned = new_ban,
                "blocked by score threshold"
            );
            // Score is egregiously high → tarpit instead of block to
            // burn the attacker's socket and slow their re-cycle rate.
            if tarpit_t > 0 && decision.score >= tarpit_t {
                return self.finalize(ctx, Decision::tarpit(req_id, decision.score, decision.reasons));
            }
            return self.finalize(ctx, Decision::block(req_id, 403, primary));
        }
        if decision.score >= chal_t {
            return self.finalize(ctx, Decision::challenge(req_id, decision.score, decision.reasons));
        }

        self.finalize(ctx, Decision::allow(req_id))
    }

    fn finalize(&self, ctx: &RequestCtx, d: Decision) -> Decision {
        self.events.record(ctx, &d);
        // Mirror to persistent storage if attached. The submit() is
        // non-blocking; on overload the sink drops with a counter.
        if let Some(sink) = self.storage_sink.read().as_ref() {
            // Build an Event the same way EventLog does so the schema matches.
            let primary = d.reasons.first();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_millis() as u64).unwrap_or(0);
            let headers: Vec<(String, String)> = ctx.header_order.iter()
                .filter_map(|n| ctx.headers.get(n).map(|v| (n.clone(), redact(n, v))))
                .collect();
            let ev = crate::events::Event {
                ts_ms: now_ms,
                request_id: d.request_id.clone(),
                ip: ctx.client_ip.to_string(),
                method: ctx.method.clone(),
                host: ctx.host.clone(),
                path: ctx.path.clone(),
                query: trim(&ctx.query, 192),
                user_agent: trim(&ctx.user_agent, 192),
                country: ctx.country.clone(),
                action: d.action,
                status: d.status,
                score: d.score,
                rule_id: primary.map(|r| r.rule_id.to_string()),
                category: primary.map(|r| r.category.to_string()),
                http_version: ctx.http_version.clone(),
                ja4h: ctx.ja4h.clone(),
                reasons: d.reasons.clone(),
                header_order: ctx.header_order.clone(),
                headers,
            };
            sink.submit(ev);
        }
        d
    }

    fn hard_limits(&self, req_id: &str, ctx: &RequestCtx) -> Option<Decision> {
        let l = &self.cfg.limits;
        if !l.allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(&ctx.method)) {
            return Some(Decision::block(
                req_id.to_string(), 405,
                DecisionReason {
                    rule_id: "METHOD-DENIED".to_string(), category: "method".to_string(),
                    score: SCORE_BAD_METHOD,
                    detail: ctx.method.clone(),
                }));
        }
        if ctx.uri.len() > l.max_uri_bytes {
            return Some(Decision::block(
                req_id.to_string(), 414,
                DecisionReason {
                    rule_id: "URI-TOO-LONG".to_string(), category: "limit".to_string(),
                    score: SCORE_OVERSIZE_URI,
                    detail: format!("uri={}B max={}B", ctx.uri.len(), l.max_uri_bytes),
                }));
        }
        if ctx.headers.len() > l.max_headers {
            return Some(Decision::block(
                req_id.to_string(), 431,
                DecisionReason {
                    rule_id: "TOO-MANY-HEADERS".to_string(), category: "limit".to_string(),
                    score: SCORE_OVERSIZE_HEAD,
                    detail: format!("count={}", ctx.headers.len()),
                }));
        }
        if let Some(too_big) = ctx.headers.values().find(|v| v.len() > l.max_header_value_bytes) {
            return Some(Decision::block(
                req_id.to_string(), 431,
                DecisionReason {
                    rule_id: "HEADER-TOO-LONG".to_string(), category: "limit".to_string(),
                    score: SCORE_OVERSIZE_HEAD,
                    detail: format!("len={}B", too_big.len()),
                }));
        }
        if let Some(cl) = ctx.content_length {
            if cl as usize > l.max_body_bytes {
                return Some(Decision::block(
                    req_id.to_string(), 413,
                    DecisionReason {
                        rule_id: "BODY-TOO-LARGE".to_string(), category: "limit".to_string(),
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
                rule_id: "HDR-NO-HOST".to_string(), category: "headers".to_string(),
                score: SCORE_MISSING_HOST,
                detail: "Host header missing".into(),
            });
        }
        if ctx.user_agent.is_empty() {
            out.push(DecisionReason {
                rule_id: "HDR-NO-UA".to_string(), category: "headers".to_string(),
                score: SCORE_MISSING_UA,
                detail: "User-Agent missing".into(),
            });
        }
        if ctx.headers.len() < 3 {
            out.push(DecisionReason {
                rule_id: "HDR-MINIMAL".to_string(), category: "headers".to_string(),
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
                rule_id: "HDR-CL-TE".to_string(), category: "smuggling".to_string(),
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
                rule_id: "GEO-BLOCKED".to_string(), category: "geoip".to_string(),
                score: SCORE_GEO_BLOCKED,
                detail: format!("country={cc}"),
            });
        }
        if self.cfg.geoip.suspicious_countries.iter().any(|c| c.eq_ignore_ascii_case(&cc)) {
            return Some(DecisionReason {
                rule_id: "GEO-SUSPICIOUS".to_string(), category: "geoip".to_string(),
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

/// Same-shape helpers the events module uses, duplicated here so the
/// storage-sink mirror keeps the schema 1:1 without making them pub.
fn redact(name: &str, value: &str) -> String {
    match name {
        "cookie" | "authorization" | "proxy-authorization"
        | "x-api-key" | "x-auth-token" => "•••".to_string(),
        _ => trim(value, 256),
    }
}
fn trim(s: &str, n: usize) -> String { s.chars().take(n).collect() }

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
            http_version: "HTTP/1.1".into(),
            headers: h,
            header_order: vec!["host".into(), "user-agent".into(), "accept".into()],
            cookie_order: vec![],
            cookies: HashMap::new(),
            body_preview: vec![], content_length: None, country: None,
            ja4h: String::new(),
            ja3: String::new(),
            ja4: String::new(),
        }
    }

    /// Build a request with an explicit User-Agent and header set, for the
    /// lockdown / browser-integrity gate tests.
    fn req_h(uri: &str, ua: &str, ver: &str, headers: &[(&str, &str)]) -> RequestCtx {
        let mut h = HashMap::new();
        h.insert("host".into(), "h".into());
        if !ua.is_empty() { h.insert("user-agent".into(), ua.into()); }
        let mut order: Vec<String> = vec!["host".into(), "user-agent".into()];
        for (k, v) in headers {
            h.insert(k.to_string(), v.to_string());
            order.push(k.to_string());
        }
        RequestCtx {
            request_id: "t".into(),
            client_ip: IpAddr::from([1, 2, 3, 4]),
            method: "GET".into(),
            uri: uri.into(), path: uri.split('?').next().unwrap().into(),
            query: "".into(), host: "h".into(),
            user_agent: ua.into(),
            http_version: ver.into(),
            headers: h,
            header_order: order,
            cookie_order: vec![],
            cookies: HashMap::new(),
            body_preview: vec![], content_length: None, country: None,
            ja4h: String::new(), ja3: String::new(), ja4: String::new(),
        }
    }

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36";

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
        assert_eq!(d.reasons.first().map(|r| r.rule_id.as_str()), Some("UAM-FORCE"));
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

    #[test]
    fn lockdown_blocks_forged_browser() {
        // A Chrome UA with no Client Hints / Fetch-Metadata at all is an
        // impossible-for-Chrome fingerprint → blocked outright, no challenge.
        let e = quiet_engine();
        e.runtime.lockdown.store(true, Ordering::Relaxed);
        let d = e.evaluate(&req_h("/x", CHROME_UA, "HTTP/2.0", &[("accept", "*/*")]));
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.status, 403);
        assert_eq!(d.reasons.first().map(|r| r.rule_id.as_str()), Some("LOCKDOWN-FORGED"));
    }

    #[test]
    fn lockdown_challenges_unverified() {
        // A bare "Mozilla/5.0" claims to be a browser but presents none of the
        // tells we need to vouch for it → invisible challenge, not a block.
        let e = quiet_engine();
        e.runtime.lockdown.store(true, Ordering::Relaxed);
        let d = e.evaluate(&req("/x", ""));
        assert_eq!(d.action, Action::Challenge);
        assert_eq!(d.reasons.first().map(|r| r.rule_id.as_str()), Some("LOCKDOWN-UNVERIFIED"));
    }

    #[test]
    fn lockdown_allows_trusted_browser() {
        // A complete, internally-consistent Chrome fingerprint sails through
        // the lockdown gate and (with a benign request) is allowed.
        let e = quiet_engine();
        e.runtime.lockdown.store(true, Ordering::Relaxed);
        let d = e.evaluate(&req_h("/x", CHROME_UA, "HTTP/2.0", &[
            ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
            ("accept-language", "en-US,en;q=0.9"),
            ("accept-encoding", "gzip, deflate, br"),
            ("sec-fetch-dest", "document"),
            ("sec-fetch-mode", "navigate"),
            ("sec-ch-ua", "\"Chromium\";v=\"123\", \"Not?A_Brand\";v=\"24\""),
            ("sec-ch-ua-mobile", "?0"),
        ]));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn auto_lockdown_engages_at_high_uam_when_enabled() {
        // auto_lockdown is OFF by default (so a UAM spike never silently walls
        // off the site), but once an operator opts in, UAM High/Extreme enforces
        // the hard verdict: a forged fingerprint is blocked rather than merely
        // soft force-challenged.
        let e = quiet_engine();
        assert!(!e.runtime.lockdown_active());
        e.runtime.uam_level.store(3, Ordering::Relaxed); // High
        assert!(!e.runtime.lockdown_active(), "UAM alone must not engage lockdown");
        e.runtime.auto_lockdown.store(true, Ordering::Relaxed); // operator opt-in
        assert!(e.runtime.lockdown_active());
        let d = e.evaluate(&req_h("/x", CHROME_UA, "HTTP/2.0", &[("accept", "*/*")]));
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.reasons.first().map(|r| r.rule_id.as_str()), Some("LOCKDOWN-FORGED"));
    }
}
