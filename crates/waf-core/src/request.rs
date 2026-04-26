//! Protocol-agnostic view of an incoming HTTP request, populated by the proxy
//! crate from Pingora's `Session` and handed to the engine.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub method: String,
    pub uri: String,
    pub path: String,
    pub query: String,
    pub host: String,
    pub user_agent: String,
    /// Lower-cased header names → values.
    pub headers: HashMap<String, String>,
    /// Cookie name → value.
    pub cookies: HashMap<String, String>,
    /// The first chunk of the body the proxy has buffered (may be empty).
    pub body_preview: Vec<u8>,
    pub content_length: Option<u64>,
    /// ISO 3166-1 alpha-2, populated if a GeoIP DB is configured.
    pub country: Option<String>,
}

impl RequestCtx {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(|s| s.as_str())
    }
}

/// Parse a Cookie header into a name→value map (last value wins, RFC 6265 §5.4).
pub fn parse_cookie_header(header: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some((k, v)) = part.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_split() {
        let m = parse_cookie_header("a=1; b=hello; c=\"x y\"");
        assert_eq!(m.get("a").unwrap(), "1");
        assert_eq!(m.get("b").unwrap(), "hello");
        assert_eq!(m.get("c").unwrap(), "x y");
    }
}
