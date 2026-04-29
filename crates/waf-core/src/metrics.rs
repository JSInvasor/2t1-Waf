//! Lightweight in-process counters. The proxy/admin server reads them out for
//! the dashboard. Designed to stay allocation-free in the hot path.

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const RING_BUCKETS: usize = 60; // 60 seconds of history.

/// Hard cap on each top-N tracker. Top-N by count is computed off the
/// live map at snapshot time; once the map size exceeds this, the entry
/// with the smallest count is evicted on the next observation. This is
/// the difference between OOM during a flood and a steady ~1 MB ceiling.
const PER_KEY_CAP: usize = 4096;

#[derive(Debug, Default)]
pub struct Metrics {
    pub allowed:    AtomicU64,
    pub challenged: AtomicU64,
    pub blocked:    AtomicU64,
    pub tarpit:     AtomicU64,
    pub rate_limited: AtomicU64,
    pub upstream_errors: AtomicU64,

    /// Top-N counters keyed by string. Bounded by a periodic sweep.
    pub by_ip:        DashMap<String, AtomicU64>,
    pub by_path:      DashMap<String, AtomicU64>,
    pub by_country:   DashMap<String, AtomicU64>,
    pub by_rule:      DashMap<String, AtomicU64>,

    /// Per-second ring buffer for the dashboard live chart.
    pub ring: Mutex<Ring>,
}

#[derive(Debug)]
pub struct Ring {
    pub buckets: [Bucket; RING_BUCKETS],
    pub head_secs: u64,
}

impl Default for Ring {
    fn default() -> Self {
        Self { buckets: std::array::from_fn(|_| Bucket::default()), head_secs: 0 }
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Bucket {
    pub allowed: u32,
    pub challenged: u32,
    pub blocked: u32,
}

impl Metrics {
    pub fn record(&self, action: crate::Action, ip: &str, path: &str, country: Option<&str>, rule: Option<&str>) {
        match action {
            crate::Action::Allow     => self.allowed.fetch_add(1, Ordering::Relaxed),
            crate::Action::Challenge => self.challenged.fetch_add(1, Ordering::Relaxed),
            crate::Action::Block     => self.blocked.fetch_add(1, Ordering::Relaxed),
            crate::Action::Tarpit    => self.tarpit.fetch_add(1, Ordering::Relaxed),
        };
        bump(&self.by_ip, ip);
        bump(&self.by_path, path);
        if let Some(c) = country { bump(&self.by_country, c); }
        if let Some(r) = rule    { bump(&self.by_rule, r);    }

        let now = now_secs();
        let mut ring = self.ring.lock();
        if ring.head_secs == 0 { ring.head_secs = now; }
        let drift = now.saturating_sub(ring.head_secs) as usize;
        if drift >= RING_BUCKETS {
            for b in ring.buckets.iter_mut() { *b = Bucket::default(); }
        } else {
            for i in 0..drift {
                let idx = ((ring.head_secs as usize) + i + 1) % RING_BUCKETS;
                ring.buckets[idx] = Bucket::default();
            }
        }
        ring.head_secs = now;
        let idx = (now as usize) % RING_BUCKETS;
        let b = &mut ring.buckets[idx];
        match action {
            crate::Action::Allow     => b.allowed    = b.allowed.saturating_add(1),
            crate::Action::Challenge => b.challenged = b.challenged.saturating_add(1),
            // Tarpit is operationally a "blocked but holding" state, so
            // we put it on the same chart band to keep the visual stable.
            crate::Action::Block | crate::Action::Tarpit
                                     => b.blocked    = b.blocked.saturating_add(1),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let ring = self.ring.lock().buckets;
        Snapshot {
            allowed: self.allowed.load(Ordering::Relaxed),
            challenged: self.challenged.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            tarpit:  self.tarpit.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            unique_ips: self.by_ip.len() as u64,
            unique_paths: self.by_path.len() as u64,
            unique_countries: self.by_country.len() as u64,
            top_ips: top_n(&self.by_ip, 20),
            top_paths: top_n(&self.by_path, 20),
            top_countries: top_n(&self.by_country, 20),
            top_rules: top_n(&self.by_rule, 20),
            ring: ring.to_vec(),
        }
    }
}

fn bump(map: &DashMap<String, AtomicU64>, key: &str) {
    if let Some(v) = map.get(key) {
        v.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // Cap eviction: when the table is full, drop the least-hit entry to
    // make room. This is approximate (we scan up to 32 entries) but it
    // keeps memory bounded under flood conditions.
    if map.len() >= PER_KEY_CAP {
        let mut min_key: Option<String> = None;
        let mut min_count: u64 = u64::MAX;
        for entry in map.iter().take(32) {
            let c = entry.value().load(Ordering::Relaxed);
            if c < min_count { min_count = c; min_key = Some(entry.key().clone()); }
        }
        if let Some(k) = min_key { map.remove(&k); }
    }
    map.entry(key.to_string()).or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

fn top_n(map: &DashMap<String, AtomicU64>, n: usize) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = map.iter()
        .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(n);
    v
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub allowed: u64,
    pub challenged: u64,
    pub blocked: u64,
    pub tarpit: u64,
    pub rate_limited: u64,
    pub upstream_errors: u64,
    pub unique_ips: u64,
    pub unique_paths: u64,
    pub unique_countries: u64,
    pub top_ips: Vec<(String, u64)>,
    pub top_paths: Vec<(String, u64)>,
    pub top_countries: Vec<(String, u64)>,
    pub top_rules: Vec<(String, u64)>,
    pub ring: Vec<Bucket>,
}
