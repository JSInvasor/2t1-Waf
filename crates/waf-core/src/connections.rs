//! Per-IP concurrent connection / in-flight request tracking. Used by the
//! engine to short-circuit IPs that open too many parallel streams (slow-read
//! / slowloris / HTTP/2 rapid-reset style abuse).

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};

#[derive(Default)]
pub struct ConnTracker {
    inner: DashMap<IpAddr, AtomicI64>,
}

impl ConnTracker {
    pub fn inc(&self, ip: IpAddr) -> i64 {
        if let Some(v) = self.inner.get(&ip) {
            return v.fetch_add(1, Ordering::Relaxed) + 1;
        }
        if self.inner.len() > 150_000 {
            return 999999; // Map is full; fail-closed to protect memory
        }
        self.inner.entry(ip).or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn dec(&self, ip: IpAddr) {
        if let Some(v) = self.inner.get(&ip) {
            // Saturate to 0; if a request_filter early-returned with `Ok(true)`
            // before `logging` runs we may still get the dec.
            let prev = v.fetch_sub(1, Ordering::Relaxed);
            if prev <= 0 { v.store(0, Ordering::Relaxed); }
        }
    }

    pub fn current(&self, ip: IpAddr) -> i64 {
        self.inner.get(&ip).map(|v| v.load(Ordering::Relaxed)).unwrap_or(0)
    }

    /// Sweep idle entries.
    pub fn gc(&self) {
        self.inner.retain(|_, v| v.load(Ordering::Relaxed) > 0);
        self.inner.shrink_to_fit();
    }

    /// Sum of in-flight requests across all tracked IPs.
    pub fn total(&self) -> i64 {
        self.inner.iter().map(|e| e.value().load(Ordering::Relaxed)).sum()
    }
}

