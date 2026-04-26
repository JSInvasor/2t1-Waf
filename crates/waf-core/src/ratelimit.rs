//! Sliding-window rate limiter with optional per-route overrides.
//!
//! The window is split into 6 buckets of 10 seconds; the count is the sum of
//! the bucket the request falls into and the previous five. This is much
//! cheaper than a true sliding log and accurate enough for HTTP traffic.

use crate::config::{RateLimitCfg, RouteRateLimit};
use dashmap::DashMap;
use parking_lot::Mutex;
use regex::Regex;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const BUCKETS: usize = 6;
const BUCKET_SECS: u64 = 10;

#[derive(Debug, Default)]
struct Counter {
    buckets: [u32; BUCKETS],
    head_secs: u64,
}

impl Counter {
    fn hit(&mut self, now: u64) -> u32 {
        let head_bucket = self.head_secs / BUCKET_SECS;
        let now_bucket = now / BUCKET_SECS;
        let drift = now_bucket.saturating_sub(head_bucket) as usize;
        if drift >= BUCKETS {
            self.buckets = [0; BUCKETS];
        } else {
            for i in 0..drift {
                let idx = ((head_bucket as usize) + i + 1) % BUCKETS;
                self.buckets[idx] = 0;
            }
        }
        self.head_secs = now;
        let idx = (now_bucket as usize) % BUCKETS;
        self.buckets[idx] = self.buckets[idx].saturating_add(1);
        self.buckets.iter().sum()
    }
}

struct CompiledRoute {
    re: Regex,
    rpm: u32,
    burst: u32,
}

pub struct RateLimiter {
    enabled: bool,
    global_rpm: u32,
    global_burst: u32,
    routes: Vec<CompiledRoute>,
    /// Keyed by `route_id|ip` so global and per-route counts are independent.
    counters: DashMap<String, Arc<Mutex<Counter>>>,
}

impl RateLimiter {
    pub fn new(cfg: &RateLimitCfg) -> anyhow::Result<Self> {
        let routes = cfg.routes.iter()
            .map(|r: &RouteRateLimit| {
                let re = Regex::new(&r.pattern)
                    .map_err(|e| anyhow::anyhow!("rate_limit.routes pattern {:?}: {e}", r.pattern))?;
                Ok(CompiledRoute { re, rpm: r.requests_per_minute, burst: r.burst })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            enabled: cfg.enabled,
            global_rpm: cfg.requests_per_minute,
            global_burst: cfg.burst,
            routes,
            counters: DashMap::with_capacity(4096),
        })
    }

    /// Returns Ok(()) when allowed, Err(Limited) when limited.
    pub fn check(&self, ip: &str, path: &str) -> Result<(), Limited> {
        self.check_scaled(ip, path, 10_000)
    }

    /// Like `check` but applies a basis-points multiplier to the RPM ceiling
    /// (10000 = 100%). Used to clamp during "under attack" mode.
    pub fn check_scaled(&self, ip: &str, path: &str, scale_bps: u32) -> Result<(), Limited> {
        if !self.enabled { return Ok(()); }
        let now = now_secs();
        let scale = scale_bps.max(100);

        for (idx, r) in self.routes.iter().enumerate() {
            if r.re.is_match(path) {
                let key = format!("r{idx}|{ip}");
                let count = self.bump(&key, now);
                let rpm = scale_rpm(r.rpm, scale);
                if exceeds(count, rpm, r.burst) {
                    return Err(Limited { retry_after: BUCKET_SECS, scope: "route", path: path.to_string() });
                }
                break;
            }
        }

        let key = format!("g|{ip}");
        let count = self.bump(&key, now);
        let rpm = scale_rpm(self.global_rpm, scale);
        if exceeds(count, rpm, self.global_burst) {
            return Err(Limited { retry_after: BUCKET_SECS, scope: "global", path: path.to_string() });
        }
        Ok(())
    }

    fn bump(&self, key: &str, now: u64) -> u32 {
        let entry = self.counters
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(Counter::default())))
            .clone();
        let mut c = entry.lock();
        c.hit(now)
    }

    /// Sweep cold counters. Caller decides cadence.
    pub fn gc(&self, max_age_secs: u64) {
        let now = now_secs();
        self.counters.retain(|_, v| {
            let c = v.lock();
            now.saturating_sub(c.head_secs) < max_age_secs
        });
    }
}

fn exceeds(count: u32, rpm: u32, burst: u32) -> bool {
    // The window is BUCKETS * BUCKET_SECS = 60s, so `count` over a 60s window
    // is directly comparable to rpm. Burst is added as a one-off allowance.
    count > rpm.saturating_add(burst)
}

fn scale_rpm(rpm: u32, scale_bps: u32) -> u32 {
    // basis points: 10_000 = 100%, 5000 = 50%, etc.
    ((rpm as u64) * (scale_bps as u64) / 10_000) as u32
}

#[derive(Debug)]
pub struct Limited {
    pub retry_after: u64,
    pub scope: &'static str,
    pub path: String,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rpm: u32, burst: u32) -> RateLimitCfg {
        RateLimitCfg { enabled: true, requests_per_minute: rpm, burst, routes: vec![] }
    }

    #[test]
    fn under_limit_passes() {
        let rl = RateLimiter::new(&cfg(100, 10)).unwrap();
        for _ in 0..50 { rl.check("1.2.3.4", "/x").unwrap(); }
    }

    #[test]
    fn over_limit_blocks() {
        let rl = RateLimiter::new(&cfg(10, 0)).unwrap();
        let mut blocked = false;
        for _ in 0..30 {
            if rl.check("1.2.3.4", "/x").is_err() { blocked = true; break; }
        }
        assert!(blocked);
    }
}
