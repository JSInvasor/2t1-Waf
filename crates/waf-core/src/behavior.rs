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
const UA_CAP:       usize = 4;

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
    pub fn observe(&self, ip: IpAddr, path: &str, method: &str, ua: &str) -> Vec<DecisionReason> {
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

        // Low diversity: ≥ 30 requests, < 3 distinct paths.
        if count >= 30 && unique_paths < 3 {
            out.push(DecisionReason {
                rule_id: "BHV-LOWDIV", category: "behavior",
                score: W_LOW_DIVERSITY,
                detail: format!("{} requests on {} unique paths in window", count, unique_paths),
            });
        }

        // Regular intervals: ≥ 8 samples, std-dev / mean < 0.15.
        if s.intervals.len() >= 8 {
            let mean = s.intervals.iter().map(|&v| v as f32).sum::<f32>() / s.intervals.len() as f32;
            if mean > 5.0 {  // ignore micro-burst noise
                let var = s.intervals.iter()
                    .map(|&v| (v as f32 - mean).powi(2)).sum::<f32>() / s.intervals.len() as f32;
                let std_dev = var.sqrt();
                let cv = std_dev / mean;
                if cv < 0.15 && count >= 15 {
                    out.push(DecisionReason {
                        rule_id: "BHV-REGULAR", category: "behavior",
                        score: W_REGULAR_INTERVAL,
                        detail: format!("interval cv={:.2} mean={:.0}ms n={}", cv, mean, s.intervals.len()),
                    });
                }
            }
        }

        // Method flood: ≥ 25 requests, ≥ 90% are OPTIONS or HEAD.
        if count >= 25 {
            let opt = s.methods[5] + s.methods[6];
            if (opt as f32 / count as f32) >= 0.9 {
                out.push(DecisionReason {
                    rule_id: "BHV-METHOD-BIAS", category: "behavior",
                    score: W_METHOD_FLOOD,
                    detail: format!("{}% OPTIONS+HEAD of {} requests",
                        (opt * 100) / count.max(1), count),
                });
            }
        }

        // UA churn: same IP, ≥ 3 distinct UAs in the window.
        if s.uas.len() >= 3 {
            out.push(DecisionReason {
                rule_id: "BHV-UA-CHURN", category: "behavior",
                score: W_UA_CHURN,
                detail: format!("{} distinct User-Agents from same IP", s.uas.len()),
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
