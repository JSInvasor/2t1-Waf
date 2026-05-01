//! Path-traversal patterns. Detects `..`-style segments after URL decoding.

use super::{Hit, Surface, excerpt};
use once_cell::sync::Lazy;
use regex::RegexSet;

static PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        // Decoded.
        r"(?i)\.\.[/\\]",
        r"(?i)[/\\]\.\.[/\\]",
        // Common encodings still surviving after one decode pass.
        r"(?i)%2e%2e[%2f%5c/\\]",
        r"(?i)\.\.%(2f|5c)",
        // Backslash variant on Windows targets.
        r"(?i)\.\.%5c",
        // Triple-decode hint (Apache historic CVE-2021-41773 style).
        r"(?i)%c0%2e%c0%2e",
    ]).expect("static traversal regex set compiles")
});

pub fn scan(s: &Surface) -> Option<Hit> {
    for (field_name, field) in [
        ("path",  &s.path_decoded),
        ("query", &s.query_decoded),
        ("uri-raw", &s.uri),
        ("body",  &s.body_preview),
    ] {
        if PATTERNS.is_match(field) {
            return Some(Hit {
                rule_id: "TRAV-01".to_string(),
                category: "traversal".to_string(),
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

    fn ctx(uri: &str, path: &str) -> RequestCtx {
        RequestCtx {
            request_id: "t".into(), client_ip: IpAddr::from([1,2,3,4]),
            method: "GET".into(), uri: uri.into(), path: path.into(),
            query: "".into(), host: "h".into(), user_agent: "".into(),
            headers: HashMap::new(), cookies: HashMap::new(),
            http_version: "HTTP/1.1".into(), header_order: vec![], cookie_order: vec![], body_preview: vec![], content_length: None, country: None, ja4h: String::new(),
        }
    }

    #[test]
    fn classic_traversal() {
        let s = Surface::from(&ctx("/a/../etc/passwd", "/a/../etc/passwd"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn encoded_traversal() {
        let s = Surface::from(&ctx("/a/%2e%2e/passwd", "/a/%2e%2e/passwd"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn benign_path() {
        let s = Surface::from(&ctx("/files/report.pdf", "/files/report.pdf"));
        assert!(scan(&s).is_none());
    }
}
