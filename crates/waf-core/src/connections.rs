//! Per-IP concurrent connection / in-flight request tracking. Used by the
//! engine to short-circuit IPs that open too many parallel streams (slow-read
//! / slowloris / HTTP/2 rapid-reset style abuse).

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};

#[derive(Default)]
pub struct ConnTracker {
    inner: DashMap<IpAddr, AtomicI64>,
    /// Running sum of all per-IP in-flight counters. Kept in lock-step with the
    /// map so `total()` (called on every request via `at_capacity`) is O(1)
    /// instead of summing a map that can hold up to 150k entries under flood.
    global: AtomicI64,
}

impl ConnTracker {
    pub fn inc(&self, ip: IpAddr) -> i64 {
        if let Some(v) = self.inner.get(&ip) {
            let n = v.fetch_add(1, Ordering::Relaxed) + 1;
            self.global.fetch_add(1, Ordering::Relaxed);
            return n;
        }
        if self.inner.len() > 150_000 {
            return 999999; // Map is full; fail-closed to protect memory
        }
        let n = self.inner.entry(ip).or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed) + 1;
        self.global.fetch_add(1, Ordering::Relaxed);
        n
    }

    pub fn dec(&self, ip: IpAddr) {
        if let Some(v) = self.inner.get(&ip) {
            // Saturate to 0; if a request_filter early-returned with `Ok(true)`
            // before `logging` runs we may still get the dec. Only mirror the
            // decrement into `global` when we actually removed an in-flight
            // request (prev > 0), so `global` never drifts negative.
            let prev = v.fetch_sub(1, Ordering::Relaxed);
            if prev <= 0 {
                v.store(0, Ordering::Relaxed);
            } else {
                self.global.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    pub fn current(&self, ip: IpAddr) -> i64 {
        self.inner.get(&ip).map(|v| v.load(Ordering::Relaxed)).unwrap_or(0)
    }

    /// Sweep idle entries. Only entries at 0 in-flight are dropped, so the
    /// `global` running sum is unaffected by the sweep.
    pub fn gc(&self) {
        self.inner.retain(|_, v| v.load(Ordering::Relaxed) > 0);
        self.inner.shrink_to_fit();
    }

    /// Sum of in-flight requests across all tracked IPs. O(1): reads the
    /// maintained running total rather than scanning the map.
    pub fn total(&self) -> i64 {
        self.global.load(Ordering::Relaxed).max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr { IpAddr::from([10, 0, 0, n]) }

    #[test]
    fn total_tracks_inc_dec() {
        let c = ConnTracker::default();
        assert_eq!(c.total(), 0);
        c.inc(ip(1));
        c.inc(ip(1));
        c.inc(ip(2));
        assert_eq!(c.total(), 3);
        assert_eq!(c.current(ip(1)), 2);
        c.dec(ip(1));
        c.dec(ip(2));
        assert_eq!(c.total(), 1);
    }

    #[test]
    fn over_dec_never_goes_negative() {
        let c = ConnTracker::default();
        c.inc(ip(1));
        c.dec(ip(1));
        c.dec(ip(1)); // spurious extra dec
        c.dec(ip(1));
        assert_eq!(c.total(), 0, "global must floor at 0");
    }

    #[test]
    fn gc_drops_idle_without_disturbing_total() {
        let c = ConnTracker::default();
        c.inc(ip(1)); // idle after dec
        c.dec(ip(1));
        c.inc(ip(2)); // still in-flight
        c.gc();
        assert_eq!(c.current(ip(1)), 0, "idle entry swept");
        assert_eq!(c.total(), 1, "in-flight total preserved across gc");
    }
}
