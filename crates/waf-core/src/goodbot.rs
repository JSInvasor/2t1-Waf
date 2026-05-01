//! Verified good-bot whitelist via reverse-DNS handshake.
//!
//! Real Googlebot / Bingbot / Yandex / etc. ship from IPs whose PTR
//! record ends with a vendor-specific suffix and forward-resolves back
//! to the same IP. UA spoofers fail one of those two checks, so a
//! simple two-step lookup separates "actual SEO crawler" from
//! "DDoS toolkit pretending to be Googlebot".
//!
//! Architecture:
//!  - In-memory cache of (IP → state) with separate positive (1h) and
//!    negative (5min) TTLs, keyed on IP not on UA so an attacker can't
//!    flush our cache by rotating User-Agent strings.
//!  - First request from a claimed-bot IP returns `Pending` and
//!    triggers an async lookup task. The engine treats Pending as
//!    "skip bot_score for this request" so we don't break SEO on the
//!    first hit. Subsequent requests get the verified verdict.
//!  - DNS work runs on `spawn_blocking` so the proxy runtime never
//!    stalls on a slow resolver.

use crate::decision::DecisionReason;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const POSITIVE_TTL_SECS: u64 = 3600;
const NEGATIVE_TTL_SECS: u64 = 300;
const PENDING_TTL_SECS:  u64 = 30;

const W_GOODBOT_SPOOF: u32 = 60;

/// (UA token to look for, expected reverse-DNS suffix list, friendly name).
/// UA matching is `contains` on the lower-cased UA string. The first
/// match wins.
pub const KNOWN_BOTS: &[(&str, &[&str], &str)] = &[
    ("googlebot",            &[".googlebot.com", ".google.com"], "Googlebot"),
    ("google-inspectiontool",&[".google.com"],                   "Google InspectionTool"),
    ("adsbot-google",        &[".googlebot.com", ".google.com"], "AdsBot-Google"),
    ("apis-google",          &[".google.com"],                   "APIs-Google"),
    ("googleother",          &[".googlebot.com", ".google.com"], "GoogleOther"),
    ("mediapartners-google", &[".google.com"],                   "Mediapartners"),
    ("bingbot",              &[".search.msn.com"],               "Bingbot"),
    ("adidxbot",             &[".search.msn.com"],               "AdIdxBot"),
    ("msnbot",               &[".search.msn.com"],               "MSNBot"),
    ("duckduckbot",          &[".duckduckgo.com"],               "DuckDuckBot"),
    ("yandexbot",            &[".yandex.com", ".yandex.net", ".yandex.ru"], "YandexBot"),
    ("yandeximages",         &[".yandex.com", ".yandex.net", ".yandex.ru"], "YandexImages"),
    ("baiduspider",          &[".baidu.com", ".baidu.jp"],       "Baiduspider"),
    ("applebot",             &[".applebot.apple.com", ".apple.com"], "Applebot"),
    ("facebookexternalhit",  &[".facebook.com", ".fbsv.net"],    "FacebookBot"),
    ("meta-externalagent",   &[".facebook.com", ".fbsv.net"],    "MetaBot"),
    ("linkedinbot",          &[".linkedin.com"],                 "LinkedInBot"),
    ("twitterbot",           &[".twttr.com", ".twitter.com"],    "Twitterbot"),
    ("discordbot",           &[".discordapp.com", ".discord.com"], "Discordbot"),
];

#[derive(Debug, Clone)]
struct CacheEntry {
    state: State,
    expires_at: u64,
    /// PTR record observed during verification, kept for the dashboard.
    ptr: Option<String>,
}

#[derive(Debug, Clone)]
enum State {
    Pending,
    Verified(&'static str),
    Rejected,
}

#[derive(Debug, Clone, Copy)]
pub enum Verdict {
    /// UA didn't match any known bot prefix.
    NotABot,
    /// UA + PTR + forward-resolve all checked out.
    GoodBotVerified(&'static str),
    /// UA matches a bot prefix; verification is in flight. Treat the
    /// current request leniently (no bot_score) so we don't break SEO.
    GoodBotPending,
    /// UA matches a bot prefix but reverse-DNS contradicted it. This is
    /// a spoofer pretending to be a search crawler.
    GoodBotSpoofed(&'static str),
}

#[derive(Default)]
pub struct GoodBotVerifier {
    cache: Arc<DashMap<IpAddr, CacheEntry>>,
}

impl GoodBotVerifier {
    /// Synchronous classification. Spawns the async lookup if the IP
    /// hasn't been verified yet — must be called from inside a tokio
    /// runtime (the request handler is, so this is safe).
    pub fn classify(&self, ip: IpAddr, ua: &str) -> Verdict {
        if ua.is_empty() { return Verdict::NotABot; }
        let lower = ua.to_ascii_lowercase();
        let bot = KNOWN_BOTS.iter()
            .find(|(prefix, _, _)| lower.contains(prefix));
        let Some(&(_, suffixes, name)) = bot else { return Verdict::NotABot; };

        let now = now_secs();
        if let Some(e) = self.cache.get(&ip) {
            if e.expires_at > now {
                return match &e.state {
                    State::Verified(n) => Verdict::GoodBotVerified(n),
                    State::Rejected    => Verdict::GoodBotSpoofed(name),
                    State::Pending     => Verdict::GoodBotPending,
                };
            }
        }

        // Insert pending entry and fire the verifier. The cache entry
        // doubles as a "lookup in flight" guard so a flood of requests
        // from the same claimed-bot IP only triggers one DNS dance.
        self.cache.insert(ip, CacheEntry {
            state: State::Pending,
            expires_at: now + PENDING_TTL_SECS,
            ptr: None,
        });
        spawn_verify(self.cache.clone(), ip, suffixes, name);
        Verdict::GoodBotPending
    }

    /// Render a snapshot of currently-cached verifications for the
    /// dashboard. Sorted newest first (longest TTL).
    pub fn snapshot(&self) -> Vec<VerifyEntry> {
        let now = now_secs();
        let mut out: Vec<VerifyEntry> = self.cache.iter()
            .filter(|e| e.value().expires_at > now)
            .map(|e| {
                let v = e.value();
                VerifyEntry {
                    ip: e.key().to_string(),
                    state: match v.state {
                        State::Verified(n) => format!("verified · {}", n),
                        State::Rejected    => "spoofed".to_string(),
                        State::Pending     => "pending".to_string(),
                    },
                    ptr: v.ptr.clone(),
                    ttl: v.expires_at.saturating_sub(now),
                }
            })
            .collect();
        out.sort_by(|a, b| b.ttl.cmp(&a.ttl));
        out.truncate(200);
        out
    }
}

#[derive(Debug, serde::Serialize)]
pub struct VerifyEntry {
    pub ip: String,
    pub state: String,
    pub ptr: Option<String>,
    pub ttl: u64,
}

fn spawn_verify(
    cache: Arc<DashMap<IpAddr, CacheEntry>>,
    ip: IpAddr,
    suffixes: &'static [&'static str],
    name: &'static str,
) {
    tokio::spawn(async move {
        let outcome = tokio::task::spawn_blocking(move || verify_blocking(ip, suffixes)).await;
        let now = now_secs();
        let entry = match outcome {
            Ok((true, ptr)) => CacheEntry {
                state: State::Verified(name),
                expires_at: now + POSITIVE_TTL_SECS,
                ptr: Some(ptr),
            },
            Ok((false, ptr)) => CacheEntry {
                state: State::Rejected,
                expires_at: now + NEGATIVE_TTL_SECS,
                ptr: if ptr.is_empty() { None } else { Some(ptr) },
            },
            Err(_) => CacheEntry {
                state: State::Rejected,
                expires_at: now + NEGATIVE_TTL_SECS,
                ptr: None,
            },
        };
        cache.insert(ip, entry);
    });
}

/// Two-step verification. Returns (passed, ptr_record).
fn verify_blocking(ip: IpAddr, suffixes: &[&str]) -> (bool, String) {
    // 1. Reverse DNS.
    let ptr = match dns_lookup::lookup_addr(&ip) {
        Ok(p) => p.to_ascii_lowercase(),
        Err(_) => return (false, String::new()),
    };
    // 2. Suffix match.
    if !suffixes.iter().any(|s| ptr.ends_with(*s)) {
        return (false, ptr);
    }
    // 3. Forward DNS the PTR result; require it to map back to the
    //    original IP. This is what stops `*.googlebot.com` PTR-pointing
    //    on attacker-controlled IPs from succeeding.
    let resolved: Vec<IpAddr> = match dns_lookup::lookup_host(&ptr) {
        Ok(v) => v,
        Err(_) => return (false, ptr),
    };
    (resolved.contains(&ip), ptr)
}

/// Build a `DecisionReason` for a spoofed bot UA. Caller adds it to
/// the running decision so the score can ride up to challenge / block
/// territory naturally.
pub fn spoof_reason(name: &str) -> DecisionReason {
    DecisionReason {
        rule_id: "GOODBOT-SPOOF".to_string(),
        category: "bot".to_string(),
        score: W_GOODBOT_SPOOF,
        detail: format!("UA claims {name} but reverse-DNS contradicted it"),
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
