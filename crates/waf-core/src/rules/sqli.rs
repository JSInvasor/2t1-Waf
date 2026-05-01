//! SQL injection patterns. The goal is high recall for *unambiguous* injection
//! signatures — keyword-only matches (e.g. a blog post containing the word
//! `select`) must not trip these.

use super::{Hit, Surface, excerpt};
use once_cell::sync::Lazy;
use regex::RegexSet;

static PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        // Classic boolean / tautology injections.
        r"(?i)\b(or|and)\s+\d+\s*=\s*\d+",
        r"(?i)'\s*(or|and)\s*'?\s*\d+\s*=\s*\d+",
        r"(?i)'\s*(or|and)\s+'\w+'\s*=\s*'\w+",
        // UNION based.
        r"(?i)\bunion\s+(all\s+)?select\b",
        // Stacked queries.
        r";\s*(drop|alter|truncate|create|update|delete|insert|exec|execute)\s+",
        // Common attack functions.
        r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay|extractvalue|updatexml|load_file)\s*\(",
        // Information schema probing.
        r"(?i)\binformation_schema\.\w+",
        // Comment-based truncation.
        r"(?:--|#)\s*$",
        r"/\*.*?\*/",
        // Hex / char obfuscation.
        r"(?i)\b(0x[0-9a-f]{6,}|char\s*\(\s*\d+(\s*,\s*\d+){2,}\s*\))",
        // Out-of-band exfiltration via DNS.
        r"(?i)\bload_file\s*\(\s*concat\s*\(",
    ]).expect("static SQLi regex set compiles")
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
                rule_id: "SQLI-01".to_string(),
                category: "sqli".to_string(),
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

    fn ctx(query: &str) -> RequestCtx {
        RequestCtx {
            request_id: "t".into(),
            client_ip: IpAddr::from([1,2,3,4]),
            method: "GET".into(),
            uri: format!("/x?{query}"),
            path: "/x".into(),
            query: query.into(),
            host: "h".into(), user_agent: "".into(),
            headers: HashMap::new(), cookies: HashMap::new(),
            http_version: "HTTP/1.1".into(), header_order: vec![], cookie_order: vec![], body_preview: vec![], content_length: None, country: None, ja4h: String::new(),
        }
    }

    #[test]
    fn classic_or_1_eq_1() {
        let s = Surface::from(&ctx("id=1' or 1=1--"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn union_select() {
        let s = Surface::from(&ctx("id=1 UNION SELECT 1,2,3"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn benign_passes() {
        let s = Surface::from(&ctx("q=hello world"));
        assert!(scan(&s).is_none());
        let s = Surface::from(&ctx("q=select+a+book"));
        assert!(scan(&s).is_none());
    }
}
