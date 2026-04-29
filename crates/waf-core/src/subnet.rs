//! Per-subnet rate limiting. Tracks request rate and in-flight count by
//! /24 (IPv4) and /64 (IPv6), so a botnet that spreads load across many
//! IPs in the same allocation still trips a single counter.

use crate::decision::DecisionReason;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const BUCKETS: usize = 6;
const BUCKET_SECS: u64 = 10;

const W_SUBNET_FLOOD: u32 = 80;
const W_SUBNET_CONN:  u32 = 70;

#[derive(Default)]
pub struct SubnetTracker {
    counters:    DashMap<u128, Mutex<Counter>>,
    in_flight:   DashMap<u128, AtomicI64>,
    last_gc:     AtomicU64,
}

#[derive(Default)]
struct Counter {
    buckets: [u32; BUCKETS],
    head_secs: u64,
}

impl Counter {
    fn hit(&mut self, now: u64) -> u32 {
        let head_b = self.head_secs / BUCKET_SECS;
        let now_b  = now / BUCKET_SECS;
        let drift = now_b.saturating_sub(head_b) as usize;
        if drift >= BUCKETS {
            self.buckets = [0; BUCKETS];
        } else {
            for i in 0..drift {
                let idx = ((head_b as usize) + i + 1) % BUCKETS;
                self.buckets[idx] = 0;
            }
        }
        self.head_secs = now;
        let idx = (now_b as usize) % BUCKETS;
        self.buckets[idx] = self.buckets[idx].saturating_add(1);
        self.buckets.iter().sum()
    }
    fn current(&self) -> u32 { self.buckets.iter().sum() }
}

impl SubnetTracker {
    /// Record one request from `ip`, return the score reasons it triggered.
    /// `rpm_cap` is the per-subnet ceiling (RPM); `conn_cap` the concurrent
    /// in-flight ceiling for the whole subnet.
    pub fn observe(&self, ip: IpAddr, rpm_cap: u32, conn_cap: i64) -> Vec<DecisionReason> {
        let key = subnet_key(ip);
        let now = now_secs();
        self.maybe_gc(now);

        // request rate
        let entry = self.counters.entry(key).or_default();
        let count = entry.lock().hit(now);
        drop(entry);

        let mut out = Vec::new();
        if rpm_cap > 0 && count > rpm_cap {
            out.push(DecisionReason {
                rule_id: "SUBNET-RPM".to_string(), category: "ddos".to_string(),
                score: W_SUBNET_FLOOD,
                detail: format!("subnet rpm={} cap={}", count, rpm_cap),
            });
        }
        if conn_cap > 0 {
            let cur = self.in_flight.get(&key).map(|v| v.load(Ordering::Relaxed)).unwrap_or(0);
            if cur > conn_cap {
                out.push(DecisionReason {
                    rule_id: "SUBNET-CONN".to_string(), category: "ddos".to_string(),
                    score: W_SUBNET_CONN,
                    detail: format!("subnet inflight={} cap={}", cur, conn_cap),
                });
            }
        }
        out
    }

    pub fn inc_inflight(&self, ip: IpAddr) {
        let key = subnet_key(ip);
        self.in_flight.entry(key).or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn dec_inflight(&self, ip: IpAddr) {
        let key = subnet_key(ip);
        if let Some(v) = self.in_flight.get(&key) {
            let prev = v.fetch_sub(1, Ordering::Relaxed);
            if prev <= 0 { v.store(0, Ordering::Relaxed); }
        }
    }

    fn maybe_gc(&self, now: u64) {
        let last = self.last_gc.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 60 { return; }
        if self.last_gc.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            return;
        }
        self.counters.retain(|_, v| {
            let c = v.lock();
            now.saturating_sub(c.head_secs) < 60 && c.current() > 0
        });
        self.in_flight.retain(|_, v| v.load(Ordering::Relaxed) > 0);
    }

    pub fn tracked(&self) -> usize { self.counters.len() }
}

/// Map an IP to its 64-bit subnet key. IPv4 → /24, IPv6 → /64.
/// Stored as u128 with a high bit indicating the family.
fn subnet_key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let prefix24 = ((octets[0] as u32) << 16) | ((octets[1] as u32) << 8) | (octets[2] as u32);
            (prefix24 as u128) | (1u128 << 127)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let mut acc: u128 = 0;
            for s in &segs[..4] { acc = (acc << 16) | (*s as u128); }
            acc
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// keep imports tidy when only some variants are used in feature combos
#[allow(dead_code)] type _Suppress = (Ipv4Addr, Ipv6Addr);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn same_24_collides() {
        assert_eq!(subnet_key(IpAddr::V4(Ipv4Addr::new(1,2,3,4))),
                   subnet_key(IpAddr::V4(Ipv4Addr::new(1,2,3,250))));
        assert_ne!(subnet_key(IpAddr::V4(Ipv4Addr::new(1,2,3,4))),
                   subnet_key(IpAddr::V4(Ipv4Addr::new(1,2,4,4))));
    }
    #[test]
    fn rpm_cap_triggers() {
        let s = SubnetTracker::default();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let mut tripped = false;
        for _ in 0..50 {
            let r = s.observe(ip, 30, 0);
            if !r.is_empty() { tripped = true; break; }
        }
        assert!(tripped);
    }
}
