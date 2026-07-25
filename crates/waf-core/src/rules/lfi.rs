//! Local / remote file inclusion patterns.

use super::{Hit, Surface, excerpt};
use once_cell::sync::Lazy;
use regex::RegexSet;

static PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        // Sensitive Unix files referenced as a value.
        r"(?i)(?:^|[=/])/etc/(?:passwd|shadow|hosts|hostname|self/environ|crontab)\b",
        r"(?i)/proc/self/(?:environ|cmdline|maps|stat)\b",
        // Windows system files.
        r"(?i)(?:^|[=/\\])(?:c:[\\/])?windows[\\/]system32[\\/]drivers[\\/]etc[\\/]hosts\b",
        r"(?i)(?:^|[=/])(?:boot\.ini|win\.ini)\b",
        // PHP wrappers.
        r"(?i)\bphp://(?:filter|input|expect|stdin)\b",
        r"(?i)\bzip://|phar://",
        // Remote inclusion → http(s)://...?something=
        r"(?i)\b(?:include|require|page|file|template)\s*=\s*https?://",
    ]).expect("static lfi regex set compiles")
});

pub fn scan(s: &Surface) -> Option<Hit> {
    for (field_name, field) in [
        ("query", &s.query_decoded),
        ("path",  &s.path_decoded),
        ("body",  &s.body_preview),
        ("uri-raw", &s.uri),
    ] {
        if PATTERNS.is_match(field) {
            return Some(Hit {
                rule_id: "LFI-01".to_string(),
                category: "lfi".to_string(),
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
            request_id: "t".into(), client_ip: IpAddr::from([1,2,3,4]),
            method: "GET".into(), uri: format!("/x?{query}"), path: "/x".into(),
            query: query.into(), host: "h".into(), user_agent: "".into(),
            headers: HashMap::new(), cookies: HashMap::new(),
            http_version: "HTTP/1.1".into(), header_order: vec![], cookie_order: vec![], body_preview: vec![], content_length: None, country: None, ja4h: String::new(), ja3: String::new(), ja4: String::new(),
        }
    }

    #[test]
    fn etc_passwd() {
        let s = Surface::from(&ctx("page=/etc/passwd"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn php_wrapper() {
        let s = Surface::from(&ctx("file=php://filter/convert.base64-encode/resource=index.php"));
        assert!(scan(&s).is_some());
    }
}
