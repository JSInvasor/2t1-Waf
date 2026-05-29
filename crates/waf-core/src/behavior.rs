//! Per-IP behavioural fingerprinting.
//!
//! Tracks four signals per IP across a sliding window:
//!  1. *URL diversity*  — bots that hammer one path are easy to spot.
//!  2. *Inter-arrival regularity* — extremely regular intervals are robotic.
//!  3. *Method bias* — only OPTIONS / HEAD / unusual mixes are suspicious.
//!  4. *UA churn* — a single IP cycling through many UAs is botnet-like.
//!
//! All bookkeeping is in-process; an IP is forgotten after `idle_secs`.

use crate::decision::DecisionReason;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const WINDOW_SECS:  u64 = 60;
const PATHS_CAP:    usize = 32;
const INTERVAL_CAP: usize = 16;
const UA_CAP:       usize = 8;

const W_LOW_DIVERSITY:   u32 = 30;
const W_REGULAR_INTERVAL:u32 = 35;
const W_METHOD_FLOOD:    u32 = 25;
const W_UA_CHURN:        u32 = 30;

#[derive(Default)]
pub struct BehaviorTracker {
    by_ip: DashMap<IpAddr, Mutex<State>>,
    last_gc: AtomicU64,
}

#[derive(Default)]
struct State {
    first_seen:    u64,
    last_seen:     u64,
    request_count: u32,
    /// Bounded set; we only need the count of distinct entries.
    paths:        Vec<u64>,
    /// Last N inter-arrival deltas (ms) — newest at the back.
    intervals:    VecDeque<u32>,
    /// Method counters: 0=GET 1=POST 2=PUT 3=DELETE 4=PATCH 5=OPTIONS 6=HEAD 7=other
    methods:      [u32; 8],
    /// Bounded set of distinct User-Agent hashes seen.
    uas:          Vec<u64>,
}

impl BehaviorTracker {
    /// Record one request and return the behavioural anomaly reasons it tripped.
    ///
    /// `browserish` is the engine's "this is a real, modern browser navigation
    /// or XHR" hint (genuine `sec-fetch-*` + `accept-language`). It exists to
    /// kill the dominant source of false positives: legitimate single-page
    /// apps and mobile clients **poll one endpoint on a fixed timer**, which is
    /// indistinguishable from a flood by the URL-diversity and interval-
    /// regularity signals alone. Those two signals are therefore only treated
    /// as abuse for non-browser clients, or — for browser clients — at request
    /// volumes a human/SPA never legitimately produces. Headless flood scripts
    /// (python/go/curl) are not `browserish`, so flood detection is unchanged.
    pub fn observe(&self, ip: IpAddr, path: &str, method: &str, ua: &str, browserish: bool) -> Vec<DecisionReason> {
        let now_ms = now_ms();
        let now_s  = now_ms / 1000;

        // GC every 30 s.
        let last = self.last_gc.load(Ordering::Relaxed);
        if now_s.saturating_sub(last) > 30 {
            if self.last_gc.compare_exchange(last, now_s, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                self.gc(now_s);
            }
        }

        let entry = self.by_ip.entry(ip).or_default();
        let mut s = entry.lock();
        // Reset window if the IP went idle for the full window.
        if now_s.saturating_sub(s.last_seen) > WINDOW_SECS {
            *s = State::default();
        }
        if s.first_seen == 0 { s.first_seen = now_s; }

        // --- update ---
        if s.last_seen != 0 {
            let delta = now_ms.saturating_sub(s.last_seen * 1000) as u32;
            if s.intervals.len() == INTERVAL_CAP { s.intervals.pop_front(); }
            s.intervals.push_back(delta);
        }
        s.last_seen = now_s;
        s.request_count = s.request_count.saturating_add(1);

        let p = fnv64(path.as_bytes());
        if !s.paths.contains(&p) {
            if s.paths.len() == PATHS_CAP { s.paths.remove(0); }
            s.paths.push(p);
        }

        let mi = method_index(method);
        s.methods[mi] = s.methods[mi].saturating_add(1);

        if !ua.is_empty() {
            let h = fnv64(ua.as_bytes());
            if !s.uas.contains(&h) {
                if s.uas.len() == UA_CAP { s.uas.remove(0); }
                s.uas.push(h);
            }
        }

        // --- score ---
        let mut out = Vec::new();
        let count = s.request_count;
        let unique_paths = s.paths.len() as u32;

        // Low diversity: one endpoint hammered. For a non-browser client this
        // is a textbook single-target flood. Real browser/XHR traffic *does*
        // legitimately sit on one endpoint (SPA route, polling widget), so for
        // browserish clients we only flag it at a volume (≥ 180 req/min, i.e.
        // sustained ≥ 3 req/s on a single path) that a human or SPA timer never
        // reaches — and even then it lands as a recoverable challenge, never a
        // standalone hard block.
        let (lowdiv_min, lowdiv_paths) = if browserish { (180u32, 2u32) } else { (30u32, 3u32) };
        if count >= lowdiv_min && unique_paths < lowdiv_paths {
            out.push(DecisionReason {
                rule_id: "BHV-LOWDIV".to_string(), category: "behavior".to_string(),
                score: W_LOW_DIVERSITY,
                detail: format!("{} requests on {} unique paths in window", count, unique_paths),
            });
        }

        // Regular intervals: ≥ 8 samples, std-dev / mean < 0.15. Perfectly
        // regular request spacing is the *definition* of a legitimate timer-
        // driven SPA / mobile / monitoring client, so on its own it is a
        // notoriously false-positive-prone signal. We only treat it as a bot
        // tell for clients that don't present genuine browser fetch metadata.
        if !browserish && s.intervals.len() >= 8 {
            let mean = s.intervals.iter().map(|&v| v as f32).sum::<f32>() / s.intervals.len() as f32;
            if mean > 5.0 {  // ignore micro-burst noise
                let var = s.intervals.iter()
                    .map(|&v| (v as f32 - mean).powi(2)).sum::<f32>() / s.intervals.len() as f32;
                let std_dev = var.sqrt();
                let cv = std_dev / mean;
                if cv < 0.15 && count >= 15 {
                    out.push(DecisionReason {
                        rule_id: "BHV-REGULAR".to_string(), category: "behavior".to_string(),
                        score: W_REGULAR_INTERVAL,
                        detail: format!("interval cv={:.2} mean={:.0}ms n={}", cv, mean, s.intervals.len()),
                    });
                }
            }
        }

        // Method flood: ≥ 25 requests, ≥ 90% are OPTIONS or HEAD. Safe for real
        // users — browsers never sustain a 90% OPTIONS/HEAD mix — so it stays
        // on regardless of the browserish hint.
        if count >= 25 {
            let opt = s.methods[5] + s.methods[6];
            if (opt as f32 / count as f32) >= 0.9 {
                out.push(DecisionReason {
                    rule_id: "BHV-METHOD-BIAS".to_string(), category: "behavior".to_string(),
                    score: W_METHOD_FLOOD,
                    detail: format!("{}% OPTIONS+HEAD of {} requests",
                        (opt * 100) / count.max(1), count),
                });
            }
        }

        // UA churn: a single IP cycling through many User-Agents is botnet-like.
        // The old "≥ 3 distinct UAs" bar false-positived on shared egress IPs
        // (CGNAT / mobile carriers / office NAT) where many real users sit
        // behind one address. Require both a higher distinct-UA count and a
        // meaningful request volume so genuine NAT browsing stays clear while a
        // single host rotating UAs to dodge fingerprinting still trips it.
        if s.uas.len() >= 5 && count >= 20 {
            out.push(DecisionReason {
                rule_id: "BHV-UA-CHURN".to_string(), category: "behavior".to_string(),
                score: W_UA_CHURN,
                detail: format!("{} distinct User-Agents from same IP over {} requests", s.uas.len(), count),
            });
        }

        out
    }

    fn gc(&self, now_s: u64) {
        self.by_ip.retain(|_, v| {
            let s = v.lock();
            now_s.saturating_sub(s.last_seen) <= WINDOW_SECS * 2
        });
    }

    pub fn tracked_ips(&self) -> usize { self.by_ip.len() }
}

fn method_index(m: &str) -> usize {
    match m.to_ascii_uppercase().as_str() {
        "GET" => 0, "POST" => 1, "PUT" => 2, "DELETE" => 3,
        "PATCH" => 4, "OPTIONS" => 5, "HEAD" => 6, _ => 7,
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)) }

    fn fired(rs: &[DecisionReason], id: &str) -> bool {
        rs.iter().any(|r| r.rule_id == id)
    }

    // A non-browser flood script hammering one path is a single-target flood
    // and must be caught. Doubles as a 1:1-counting check: the rule fires at
    // exactly the 30th request (so each observe counts as exactly one).
    #[test]
    fn nonbrowser_single_path_flood_is_flagged() {
        let t = BehaviorTracker::default();
        let mut last = Vec::new();
        for i in 1..=30 {
            last = t.observe(ip(1), "/api/x", "GET", "curl/8", false);
            // The 29th request must NOT yet trip BHV-LOWDIV; only the 30th does.
            if i == 29 { assert!(!fired(&last, "BHV-LOWDIV"), "fired too early — double counting?"); }
        }
        assert!(fired(&last, "BHV-LOWDIV"), "single-target flood must be flagged");
    }

    // A real browser/XHR client polling one endpoint (the canonical false
    // positive) at the same volume must be left completely alone.
    #[test]
    fn browserish_single_path_polling_is_clean() {
        let t = BehaviorTracker::default();
        let mut last = Vec::new();
        for _ in 0..120 {
            last = t.observe(ip(2), "/api/notifications", "GET", "Mozilla/5.0", true);
        }
        assert!(!fired(&last, "BHV-LOWDIV"), "legit SPA polling must not be flagged");
        assert!(!fired(&last, "BHV-REGULAR"), "legit timer polling must not be flagged");
    }

    // Two or three real users behind one shared/NAT egress IP must not be
    // mistaken for a UA-rotating bot.
    #[test]
    fn small_ua_churn_behind_nat_is_clean() {
        let t = BehaviorTracker::default();
        let uas = ["Mozilla/5.0 A", "Mozilla/5.0 B", "Mozilla/5.0 C"];
        let mut last = Vec::new();
        for (i, ua) in uas.iter().cycle().take(15).enumerate() {
            last = t.observe(ip(3), &format!("/p{}", i % 6), "GET", ua, true);
        }
        assert!(!fired(&last, "BHV-UA-CHURN"), "3 UAs from a NAT must not trip churn");
    }
}
