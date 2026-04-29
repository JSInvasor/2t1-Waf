//! JA4H — HTTP-layer client fingerprint, the analogue of JA3 / JA4 that
//! works without TLS handshake access. Composition (FoxIO / John Althouse):
//!
//!   ja4h_a (12 chars):
//!     <method:2> <ver:2> <cookie:1> <referer:1> <nheaders:2> <lang:4>
//!
//!   ja4h_b (12 hex):  sha256(",".join(header_names_in_order)) [..12]
//!     Header names are lower-case, Cookie/Referer + most pseudo-headers
//!     excluded by spec.
//!
//!   ja4h_c (12 hex):  sha256(",".join(cookie_names_sorted)) [..12]
//!   ja4h_d (12 hex):  sha256(",".join("name=value")) [..12]
//!
//! Final form: "ja4h_a_ja4h_b_ja4h_c_ja4h_d"  (or "_000000000000" if none).
//!
//! This is enough to spot common DDoS toolkits even when their
//! User-Agent is a real-looking Chrome string.

use sha2::{Digest, Sha256};

/// Headers that are excluded from the ja4h_b digest by the spec.
const EXCLUDED: &[&str] = &[
    "cookie", "referer",
    // Pseudo-headers, not sent on the wire as named headers.
    ":method", ":path", ":scheme", ":authority",
];

pub fn compute(
    method: &str,
    http_version: &str,
    header_order: &[String],
    headers: &std::collections::HashMap<String, String>,
    cookie_order: &[String],
    cookies: &std::collections::HashMap<String, String>,
) -> String {
    let m2 = method_two(method);
    let v2 = version_two(http_version);
    let cookie_byte  = if cookies.is_empty()       { 'n' } else { 'c' };
    let referer_byte = if headers.contains_key("referer") { 'r' } else { 'n' };

    let included: Vec<&str> = header_order.iter()
        .map(|h| h.as_str())
        .filter(|h| !EXCLUDED.contains(h) && !h.starts_with(':'))
        .collect();
    let nheaders = included.len().min(99);

    let lang = headers.get("accept-language")
        .map(|s| s.as_str())
        .unwrap_or("");
    let lang4 = ja4_lang(lang);

    let a = format!("{m2}{v2}{cookie_byte}{referer_byte}{nheaders:02}{lang4}");

    let b = if included.is_empty() {
        "000000000000".to_string()
    } else {
        let joined = included.join(",");
        sha_12hex(joined.as_bytes())
    };

    let c = if cookie_order.is_empty() {
        "000000000000".to_string()
    } else {
        let mut names: Vec<&str> = cookie_order.iter().map(|s| s.as_str()).collect();
        names.sort();
        names.dedup();
        sha_12hex(names.join(",").as_bytes())
    };

    let d = if cookies.is_empty() {
        "000000000000".to_string()
    } else {
        let mut pairs: Vec<String> = cookies.iter()
            .map(|(k, v)| format!("{k}={v}")).collect();
        pairs.sort();
        sha_12hex(pairs.join(",").as_bytes())
    };

    format!("{a}_{b}_{c}_{d}")
}

fn method_two(m: &str) -> String {
    let s: String = m.chars().take(2).collect::<String>().to_ascii_lowercase();
    let mut out = s;
    while out.len() < 2 { out.push('0'); }
    out
}

fn version_two(v: &str) -> &'static str {
    if v.contains("3") { "30" }
    else if v.contains("2") { "20" }
    else if v.contains("1.0") { "10" }
    else { "11" }
}

fn ja4_lang(lang: &str) -> String {
    // Take the primary language tag (before ',' / ';'), pull alpha chars,
    // lowercase, pad to 4 with '0'. Examples: "en-US,en;q=0.9" → "enus".
    let primary = lang.split(|c: char| c == ',' || c == ';').next().unwrap_or("");
    let cleaned: String = primary.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(4)
        .collect::<String>()
        .to_ascii_lowercase();
    let mut out = cleaned;
    while out.len() < 4 { out.push('0'); }
    out
}

fn sha_12hex(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    let digest = h.finalize();
    let mut s = String::with_capacity(12);
    for b in &digest[..6] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_ja4h_shape() {
        let mut h = HashMap::new();
        h.insert("user-agent".into(), "x".into());
        let out = compute("GET", "HTTP/1.1", &["user-agent".into()], &h, &[], &HashMap::new());
        // ja4h_a: "ge" + "11" + "n" + "n" + "01" + "0000" = "ge11nn010000"
        assert!(out.starts_with("ge11nn010000_"));
        assert!(out.ends_with("_000000000000_000000000000"));
    }

    #[test]
    fn lang_extracted() {
        let mut h = HashMap::new();
        h.insert("accept-language".into(), "tr-TR,en;q=0.9".into());
        let out = compute("POST", "HTTP/2.0", &["accept-language".into()], &h, &[], &HashMap::new());
        // method "po", ver "20", cookie "n", referer "n", nheaders "01", lang "trtr"
        assert!(out.starts_with("po20nn01trtr_"));
    }

    #[test]
    fn cookies_change_d() {
        let mut h = HashMap::new();
        h.insert("cookie".into(), "a=1; b=2".into());
        let mut c = HashMap::new();
        c.insert("a".into(), "1".into());
        c.insert("b".into(), "2".into());
        let out1 = compute("GET", "HTTP/1.1", &["cookie".into()], &h, &["a".into(), "b".into()], &c);
        c.insert("b".into(), "3".into()); // change a value
        let out2 = compute("GET", "HTTP/1.1", &["cookie".into()], &h, &["a".into(), "b".into()], &c);
        assert_ne!(out1, out2, "ja4h_d should differ when cookie values change");
    }
}
