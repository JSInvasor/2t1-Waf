//! Reflected/stored XSS patterns.

use super::{Hit, Surface, excerpt};
use once_cell::sync::Lazy;
use regex::RegexSet;

static PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        r"(?i)<script\b[^>]*>",
        r"(?i)</\s*script\s*>",
        r"(?i)\bjavascript\s*:",
        r"(?i)\bdata\s*:\s*text/html",
        r#"(?i)on(?:load|error|click|mouseover|focus|submit|toggle|animationstart)\s*=\s*["']?[^"'>]+"#,
        r"(?i)<\s*(iframe|object|embed|svg|math|video|audio)\b",
        r"(?i)\bsrcdoc\s*=",
        r"(?i)expression\s*\(",
        r"(?i)<\s*img[^>]+\bonerror\s*=",
        r"(?i)\beval\s*\(\s*atob\s*\(",
        r"(?i)\bdocument\.cookie\b",
        r#"(?i)<\s*meta\s+http-equiv\s*=\s*["']?refresh"#,
    ]).expect("static XSS regex set compiles")
});

pub fn scan(s: &Surface) -> Option<Hit> {
    for (field_name, field) in [
        ("query", &s.query_decoded),
        ("path",  &s.path_decoded),
        ("body",  &s.body_preview),
        ("headers", &s.headers_concat),
        ("uri-raw", &s.uri),
    ] {
        if PATTERNS.is_match(field) {
            return Some(Hit {
                rule_id: "XSS-01".to_string(),
                category: "xss".to_string(),
                matched_field: field_name,
                matched_excerpt: excerpt(field),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::RequestCtx;
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn ctx_with_body(body: &str) -> RequestCtx {
        RequestCtx {
            request_id: "t".into(),
            client_ip: IpAddr::from([1,2,3,4]),
            method: "POST".into(),
            uri: "/x".into(), path: "/x".into(), query: "".into(),
            host: "h".into(), user_agent: "".into(),
            headers: HashMap::new(), cookies: HashMap::new(),
            http_version: "HTTP/1.1".into(), header_order: vec![], cookie_order: vec![], body_preview: body.as_bytes().to_vec(),
            content_length: None, country: None, ja4h: String::new(), ja3: String::new(), ja4: String::new(),
        }
    }

    #[test]
    fn detects_script_tag() {
        let s = Surface::from(&ctx_with_body("comment=<script>alert(1)</script>"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn detects_event_handler() {
        let s = Surface::from(&ctx_with_body("<img src=x onerror=alert(1)>"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn benign_html_passes() {
        let s = Surface::from(&ctx_with_body("Bold text using <b>tag</b> is fine."));
        assert!(scan(&s).is_none());
    }
}
