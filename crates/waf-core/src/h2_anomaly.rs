//! HTTP/2 (and HTTP/3) protocol-level anomalies. Pingora abstracts
//! away the pseudo-header parsing so we can't see the literal frame
//! layout, but we still get full visibility into the *named* headers
//! the client sent — and h2 has a tighter spec than h1, so several
//! header shapes that are merely odd on h1 are outright illegal on h2
//! and overwhelmingly indicate a flood toolkit that didn't bother to
//! emulate the protocol correctly.
//!
//! References: RFC 7540 §8.1.2.{1,2}, RFC 9113 §8.2.

use crate::decision::DecisionReason;
use crate::request::RequestCtx;

const W_FORBIDDEN_HDR: u32 = 70;
const W_TE_INVALID:    u32 = 60;
const W_NO_UA_H2:      u32 = 25;
const W_MIN_HDRS_H2:   u32 = 30;
const W_BAD_PATH:      u32 = 20;

/// Headers RFC 9113 §8.2 forbids on HTTP/2 (and h3 by inheritance).
const FORBIDDEN_H2: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

pub fn score(ctx: &RequestCtx) -> Vec<DecisionReason> {
    // Only relevant for HTTP/2+. http::Version's Debug renders as
    // "HTTP/2.0", "HTTP/3.0", "HTTP/1.1", etc.
    let v = ctx.http_version.as_str();
    let is_h2_or_h3 = v.contains("/2") || v.contains("/3");
    if !is_h2_or_h3 { return Vec::new(); }

    let mut out = Vec::new();

    // Forbidden hop-by-hop headers leaking into the h2 frame are a
    // dead-giveaway for an h1 toolkit that translates to h2 by stuffing
    // the same byte stream into a frame.
    for &name in FORBIDDEN_H2 {
        if ctx.headers.contains_key(name) {
            out.push(DecisionReason {
                rule_id: "H2-FORBIDDEN-HDR".to_string(),
                category: "h2".to_string(),
                score: W_FORBIDDEN_HDR,
                detail: format!("HTTP/2 request carries forbidden header `{name}`"),
            });
        }
    }

    // The TE header MAY appear on h2 but its only legal value is
    // "trailers" (RFC 9113 §8.2.2). Anything else is malformed.
    if let Some(te) = ctx.headers.get("te") {
        if !te.eq_ignore_ascii_case("trailers") {
            out.push(DecisionReason {
                rule_id: "H2-TE-INVALID".to_string(),
                category: "h2".to_string(),
                score: W_TE_INVALID,
                detail: format!("HTTP/2 TE header has illegal value: {:?}", te),
            });
        }
    }

    // Missing User-Agent on h2 is much rarer than on h1 (every modern
    // browser sends it, and h2 is browser-driven) — give it more weight.
    if !ctx.headers.contains_key("user-agent") {
        out.push(DecisionReason {
            rule_id: "H2-NO-UA".to_string(),
            category: "h2".to_string(),
            score: W_NO_UA_H2,
            detail: "HTTP/2 request without User-Agent".into(),
        });
    }

    // Real browsers cannot help but send Accept, Accept-Encoding,
    // Accept-Language, sec-fetch-* on h2 navigations — the named-header
    // count is consistently >= 6. h2 floods often ship 2-3.
    if ctx.headers.len() < 4 {
        out.push(DecisionReason {
            rule_id: "H2-MIN-HDRS".to_string(),
            category: "h2".to_string(),
            score: W_MIN_HDRS_H2,
            detail: format!("HTTP/2 request with only {} named headers", ctx.headers.len()),
        });
    }

    // h2 paths must start with `/` (or be `*` for OPTIONS). Anything
    // else is a malformed :path pseudo-header.
    if !ctx.path.is_empty() && !ctx.path.starts_with('/') && ctx.path != "*" {
        out.push(DecisionReason {
            rule_id: "H2-BAD-PATH".to_string(),
            category: "h2".to_string(),
            score: W_BAD_PATH,
            detail: format!("HTTP/2 :path doesn't start with /: {:?}",
                ctx.path.chars().take(48).collect::<String>()),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn ctx(version: &str, headers: &[(&str, &str)]) -> RequestCtx {
        let mut h = HashMap::new();
        for (k, v) in headers { h.insert(k.to_string(), v.to_string()); }
        RequestCtx {
            request_id: "t".into(),
            client_ip: IpAddr::from([1,2,3,4]),
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query: "".into(), host: "h".into(), user_agent: "".into(),
            headers: h, cookies: HashMap::new(),
            http_version: version.into(),
            header_order: vec![],
            cookie_order: vec![],
            body_preview: vec![], content_length: None, country: None,
            ja4h: String::new(),
        }
    }

    #[test]
    fn h1_request_gets_no_score() {
        let r = score(&ctx("HTTP/1.1", &[("connection", "close")]));
        assert!(r.is_empty());
    }

    #[test]
    fn h2_with_connection_header_blocks() {
        let r = score(&ctx("HTTP/2.0", &[
            ("user-agent", "ua"), ("connection", "close"),
            ("accept", "*/*"), ("accept-language", "en"),
        ]));
        assert!(r.iter().any(|x| x.rule_id == "H2-FORBIDDEN-HDR"));
    }

    #[test]
    fn h2_te_must_be_trailers() {
        let r = score(&ctx("HTTP/2.0", &[
            ("user-agent", "ua"), ("te", "gzip"),
            ("accept", "*/*"), ("accept-language", "en"),
        ]));
        assert!(r.iter().any(|x| x.rule_id == "H2-TE-INVALID"));
        let ok = score(&ctx("HTTP/2.0", &[
            ("user-agent", "ua"), ("te", "trailers"),
            ("accept", "*/*"), ("accept-language", "en"),
        ]));
        assert!(!ok.iter().any(|x| x.rule_id == "H2-TE-INVALID"));
    }

    #[test]
    fn h2_minimal_headers_flagged() {
        let r = score(&ctx("HTTP/2.0", &[("user-agent", "ua")]));
        assert!(r.iter().any(|x| x.rule_id == "H2-MIN-HDRS"));
    }
}
