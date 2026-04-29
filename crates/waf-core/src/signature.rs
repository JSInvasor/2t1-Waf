//! Two complementary "anti-replay" signals:
//!
//!  * `RequestReplay` — per-IP, count occurrences of the same
//!    (method, path, UA) triple in a short window. Floods that hammer a
//!    single endpoint produce huge counts here even when the per-IP rate
//!    limit is below threshold.
//!
//!  * `DistributedUa` — global, count distinct IPs that share the same
//!    User-Agent string in a short window. A botnet using a shared
//!    DDoS-toolkit UA lights this up immediately.

use crate::decision::DecisionReason;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const REPLAY_WINDOW_SECS: u64 = 30;
const REPLAY_THRESHOLD:   u32 = 25;
const W_REPLAY:           u32 = 60;

const UA_WINDOW_SECS:  u64 = 60;
const UA_THRESHOLD_IP: usize = 8;
const W_DIST_UA:       u32 = 50;

#[derive(Default)]
pub struct RequestReplay {
    by_ip: DashMap<IpAddr, Mutex<ReplayState>>,
    last_gc: AtomicU64,
}

#[derive(Default)]
struct ReplayState {
    last_hash: u64,
    count: u32,
    first_secs: u64,
}

impl RequestReplay {
    pub fn observe(&self, ip: IpAddr, method: &str, path: &str, ua: &str) -> Option<DecisionReason> {
        let now = now_secs();
        self.maybe_gc(now);

        let h = sig_hash(method, path, ua);
        let entry = self.by_ip.entry(ip).or_default();
        let mut s = entry.lock();
        if s.last_hash != h || now.saturating_sub(s.first_secs) > REPLAY_WINDOW_SECS {
            s.last_hash = h;
            s.count = 1;
            s.first_secs = now;
            return None;
        }
        s.count = s.count.saturating_add(1);
        if s.count >= REPLAY_THRESHOLD {
            return Some(DecisionReason {
                rule_id: "REPLAY", category: "ddos",
                score: W_REPLAY,
                detail: format!("{} repeats of same signature in {}s", s.count, REPLAY_WINDOW_SECS),
            });
        }
        None
    }

    fn maybe_gc(&self, now: u64) {
        let last = self.last_gc.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 30 { return; }
        if self.last_gc.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            return;
        }
        self.by_ip.retain(|_, v| {
            let s = v.lock();
            now.saturating_sub(s.first_secs) < REPLAY_WINDOW_SECS * 2
        });
    }
}

#[derive(Default)]
pub struct DistributedUa {
    /// UA hash → bucket of distinct IPs in the window.
    by_ua: DashMap<u64, Mutex<UaBucket>>,
    last_gc: AtomicU64,
}

#[derive(Default)]
struct UaBucket {
    ips: HashSet<IpAddr>,
    first_secs: u64,
}

impl DistributedUa {
    pub fn observe(&self, ip: IpAddr, ua: &str) -> Option<DecisionReason> {
        if ua.is_empty() { return None; }
        let now = now_secs();
        self.maybe_gc(now);

        let h = fnv64(ua.as_bytes());
        let entry = self.by_ua.entry(h).or_default();
        let mut b = entry.lock();
        if b.first_secs == 0 || now.saturating_sub(b.first_secs) > UA_WINDOW_SECS {
            b.ips.clear();
            b.first_secs = now;
        }
        if b.ips.len() < 256 { b.ips.insert(ip); }

        if b.ips.len() >= UA_THRESHOLD_IP {
            return Some(DecisionReason {
                rule_id: "DIST-UA", category: "ddos",
                score: W_DIST_UA,
                detail: format!("UA shared by {} distinct IPs in {}s", b.ips.len(), UA_WINDOW_SECS),
            });
        }
        None
    }

    fn maybe_gc(&self, now: u64) {
        let last = self.last_gc.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 60 { return; }
        if self.last_gc.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            return;
        }
        self.by_ua.retain(|_, v| {
            let b = v.lock();
            now.saturating_sub(b.first_secs) < UA_WINDOW_SECS * 2
        });
    }
}

fn sig_hash(method: &str, path: &str, ua: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in method.as_bytes() { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    for &b in path.as_bytes()   { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    for &b in ua.as_bytes()     { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    h
}
fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    h
}
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
