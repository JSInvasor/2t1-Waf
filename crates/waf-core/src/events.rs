//! Bounded ring buffer of recent decisions for the live-traffic page.
//!
//! Lock-strategy: a single Mutex<VecDeque>. Writes happen once per request;
//! reads happen when the dashboard polls. Both are cheap relative to the rest
//! of the request path, so the simplicity buys more than a more complex
//! lock-free ring would.

use crate::decision::DecisionReason;
use crate::{Action, Decision};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CAP: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts_ms: u64,
    pub request_id: String,
    pub ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub user_agent: String,
    pub country: Option<String>,
    pub action: Action,
    pub status: u16,
    pub score: u32,
    pub rule_id: Option<String>,
    pub category: Option<String>,
    /// HTTP version stamp.
    pub http_version: String,
    /// JA4H fingerprint of the request.
    pub ja4h: String,
    /// Every triggered DecisionReason in the order they fired.
    pub reasons: Vec<DecisionReason>,
    /// Lower-cased header names in arrival order — useful for Cloudflare-
    /// like deep-inspection in the dashboard.
    pub header_order: Vec<String>,
    /// Snapshot of headers (lower-case → value). Cookie / Authorization
    /// values are redacted before storing.
    pub headers: Vec<(String, String)>,
}

pub struct EventLog {
    inner: Mutex<VecDeque<Event>>,
    cap: usize,
}

impl Default for EventLog {
    fn default() -> Self { Self::with_capacity(DEFAULT_CAP) }
}

impl EventLog {
    pub fn with_capacity(cap: usize) -> Self {
        Self { inner: Mutex::new(VecDeque::with_capacity(cap.min(8192))), cap }
    }

    pub fn record(&self, ctx: &crate::RequestCtx, d: &Decision) {
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        let primary = d.reasons.first();
        let headers: Vec<(String, String)> = ctx.header_order.iter()
            .filter_map(|n| ctx.headers.get(n).map(|v| (n.clone(), redact_header(n, v))))
            .collect();
        let ev = Event {
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
        let mut q = self.inner.lock();
        if q.len() == self.cap { q.pop_front(); }
        q.push_back(ev);
    }

    /// Return the most recent `n` events newest-first.
    pub fn recent(&self, n: usize) -> Vec<Event> {
        let q = self.inner.lock();
        q.iter().rev().take(n).cloned().collect()
    }

    /// Events newer than `since_ms`, oldest-first (suitable for SSE catch-up).
    pub fn since(&self, since_ms: u64, max: usize) -> Vec<Event> {
        let q = self.inner.lock();
        q.iter().filter(|e| e.ts_ms > since_ms).take(max).cloned().collect()
    }
}

/// Cookie / Authorization values are sensitive — keep the name but blank
/// the value so the dashboard can show "what was sent" without leaking
/// session credentials.
fn redact_header(name: &str, value: &str) -> String {
    match name {
        "cookie" | "authorization" | "proxy-authorization"
        | "x-api-key" | "x-auth-token" => "•••".to_string(),
        _ => trim(value, 256),
    }
}

fn trim(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
