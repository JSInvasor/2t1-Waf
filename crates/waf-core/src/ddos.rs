//! DDoS-flavoured request anomalies — patterns that shouldn't appear in
//! normal browser traffic but show up constantly in flood scripts and
//! stress-tester output.

use crate::decision::DecisionReason;
use crate::request::RequestCtx;

const W_GET_WITH_BODY:   u32 = 25;
const W_EMPTY_CONNECTION:u32 = 18;
const W_CACHE_BUSTER:    u32 = 20;
const W_DUP_HEADERS:     u32 = 18;
const W_OPTIONS_NOORIG:  u32 = 22;
const W_NULLBYTE:        u32 = 100;
const W_QUERY_BLOAT:     u32 = 25;

const SUSPECT_BUSTER_KEYS: &[&str] = &[
    "_t", "_ts", "_r", "_rand", "rand", "nocache", "cb", "cachebust", "_=",
];

pub fn score(ctx: &RequestCtx) -> Vec<DecisionReason> {
    let mut out = Vec::new();

    // GET / HEAD with a body is malformed-ish and a flood-script favourite.
    if (ctx.method.eq_ignore_ascii_case("GET") || ctx.method.eq_ignore_ascii_case("HEAD"))
        && ctx.content_length.unwrap_or(0) > 0
    {
        out.push(DecisionReason {
            rule_id: "DDOS-GET-BODY", category: "ddos",
            score: W_GET_WITH_BODY,
            detail: format!("{} with content-length={}", ctx.method, ctx.content_length.unwrap()),
        });
    }

    // Empty Connection header — real clients send "keep-alive" or "close".
    if let Some(c) = ctx.headers.get("connection") {
        if c.trim().is_empty() {
            out.push(DecisionReason {
                rule_id: "DDOS-EMPTY-CONN", category: "ddos",
                score: W_EMPTY_CONNECTION,
                detail: "empty Connection header".into(),
            });
        }
    }

    // CORS preflight without Origin / Access-Control-Request-Method is
    // almost always a flood toolkit "browser-impersonation" footgun.
    if ctx.method.eq_ignore_ascii_case("OPTIONS")
        && !ctx.headers.contains_key("origin")
        && !ctx.headers.contains_key("access-control-request-method")
    {
        out.push(DecisionReason {
            rule_id: "DDOS-OPTIONS-NOORIG", category: "ddos",
            score: W_OPTIONS_NOORIG,
            detail: "OPTIONS without CORS preflight headers".into(),
        });
    }

    // NUL byte anywhere in the path/query is hostile by definition.
    if ctx.uri.contains('\0') {
        out.push(DecisionReason {
            rule_id: "DDOS-NUL", category: "ddos",
            score: W_NULLBYTE,
            detail: "NUL byte in URI".into(),
        });
    }

    // Pathological query string (huge / many params).
    if ctx.query.len() > 2048 || ctx.query.matches('&').count() > 64 {
        out.push(DecisionReason {
            rule_id: "DDOS-QUERY-BLOAT", category: "ddos",
            score: W_QUERY_BLOAT,
            detail: format!("query={}B params={}", ctx.query.len(), ctx.query.matches('&').count() + 1),
        });
    }

    // Cache-busting query soup (`?_t=…&_r=…&nocache=…`) — flood toolkits
    // generate one per request to defeat upstream caches.
    let buster_hits = SUSPECT_BUSTER_KEYS.iter()
        .filter(|k| {
            let needle = format!("{}=", k);
            ctx.query.contains(&needle)
        })
        .count();
    if buster_hits >= 2 {
        out.push(DecisionReason {
            rule_id: "DDOS-CACHEBUST", category: "ddos",
            score: W_CACHE_BUSTER,
            detail: format!("{} cache-buster keys in query", buster_hits),
        });
    }

    // Duplicated single-value headers (Host, Content-Length, Authorization …)
    // The proxy pre-collapses headers, so we can detect duplicates only when
    // the upstream stamped a marker. Best effort: x-duplicated-headers count.
    if let Some(d) = ctx.headers.get("x-duplicated-headers") {
        if d != "0" {
            out.push(DecisionReason {
                rule_id: "DDOS-DUP-HDR", category: "ddos",
                score: W_DUP_HEADERS,
                detail: format!("{} duplicated singleton headers", d),
            });
        }
    }

    out
}
