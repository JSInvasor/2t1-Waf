//! Hard browser-integrity verification — the core of "Under-Attack lockdown".
//!
//! `bot_score` produces *soft* weighted points that nudge a request toward the
//! challenge/block thresholds. This module produces a *hard verdict*: it answers
//! the single question the lockdown gate cares about — **"could this plausibly
//! be a real, modern browser?"** — by cross-checking every browser tell against
//! every other one. A real Chrome/Firefox/Safari is internally consistent
//! across its User-Agent, Client Hints (`sec-ch-ua*`), Fetch Metadata
//! (`sec-fetch-*`), `Accept*` headers, HTTP version, **and** — when a TLS front
//! layer forwards it — its JA3/JA4 TLS fingerprint. Spoofing tools (curl,
//! python-requests, go-http, even headless automation that forges the UA
//! string) almost always break at least one of these cross-checks, because the
//! checks are mutually reinforcing: faking the UA convincingly means *also*
//! faking the exact header set, ordering, client hints and TLS stack of the
//! claimed browser/version, which off-the-shelf flood tooling does not do.
//!
//! The verdict is deliberately conservative about `Forged`: we only return it
//! when a combination is *impossible* for the browser the client claims to be,
//! never for a merely-incomplete request. That keeps the no-false-positive
//! guarantee — a forged verdict in lockdown is an immediate 403, so it must be
//! certain. Everything merely suspicious lands in `Unverified`, which under
//! lockdown still has to clear the invisible challenge.

use crate::request::RequestCtx;

/// Outcome of the hard browser-integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserVerdict {
    /// Presents a complete, internally consistent modern-browser fingerprint.
    /// Under lockdown this client is allowed straight through to normal scoring.
    Trusted,
    /// Not obviously forged, but missing enough browser tells that we can't
    /// vouch for it. Under lockdown it must pass the invisible challenge.
    Unverified,
    /// Claims to be a browser but presents a combination that is *impossible*
    /// for that browser — a positive forgery signal. Blocked outright under
    /// lockdown (no challenge page is even served). Carries a short reason.
    Forged(&'static str),
}

/// A UA family we can reason about precisely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Chromium, // Chrome / Edge / Opera / Brave / modern Chromium
    Firefox,
    Safari, // real Safari / iOS WebKit (NOT Chrome's "Safari" token)
    Other,  // claims a browser token we can't pin down precisely
    NonBrowser, // does not claim to be a browser at all (curl, python, …)
}

fn family(ua: &str) -> Family {
    let ua = ua.to_ascii_lowercase();
    let chromium = ua.contains("chrome/")
        || ua.contains("chromium/")
        || ua.contains("edg/")
        || ua.contains("edga/")
        || ua.contains("edgios/")
        || ua.contains("opr/")
        || ua.contains("samsungbrowser/");
    if chromium {
        return Family::Chromium;
    }
    if ua.contains("firefox/") || ua.contains("fxios/") {
        return Family::Firefox;
    }
    // Real Safari carries "version/<n>" + "safari/" and NO chrome token.
    if ua.contains("safari/") && ua.contains("version/") {
        return Family::Safari;
    }
    if ua.contains("mozilla/") {
        return Family::Other;
    }
    Family::NonBrowser
}

/// Run the hard browser-integrity verdict for a request.
///
/// `ja3` / `ja4` are the TLS fingerprints if a front layer forwarded them
/// (empty otherwise). They sharpen the verdict but are never *required* — the
/// header/hint cross-checks stand on their own when TLS data is absent.
pub fn verify(ctx: &RequestCtx) -> BrowserVerdict {
    let ua_raw = ctx.user_agent.trim();
    let fam = family(ua_raw);

    // No browser claim at all → never Trusted. It's not "forged" (it isn't
    // lying about being a browser), so it lands in Unverified and must clear
    // the invisible challenge under lockdown.
    if fam == Family::NonBrowser || ua_raw.is_empty() {
        return BrowserVerdict::Unverified;
    }

    let has = |k: &str| ctx.headers.contains_key(k);
    let has_sec_fetch = ctx.headers.keys().any(|k| k.starts_with("sec-fetch-"));
    let has_sec_ch_ua = has("sec-ch-ua");
    let accept = ctx.headers.get("accept").map(|s| s.as_str()).unwrap_or("");
    let ua_l = ua_raw.to_ascii_lowercase();

    // ---- IMPOSSIBLE combinations → Forged (certain) -------------------------

    // 1. HTTP/2 or HTTP/3 with an HTTP/1.0 client is impossible; and a modern
    //    browser never speaks 1.0. A "Mozilla" UA on HTTP/1.0 is flood tooling.
    if ctx.http_version.contains("1.0") {
        return BrowserVerdict::Forged("modern browser UA over HTTP/1.0");
    }

    // 2. Chromium ≥ 89 ALWAYS sends both sec-ch-ua and sec-fetch-* on a
    //    top-level navigation. A Chrome UA with neither is categorically a
    //    forged UA string (the single most common DDoS-tool signature).
    if fam == Family::Chromium {
        if !has_sec_ch_ua && !has_sec_fetch {
            return BrowserVerdict::Forged("Chrome UA without any sec-ch-ua / sec-fetch headers");
        }
        // sec-ch-ua must mention a Chromium-ish brand. A spoofer that sends a
        // hand-rolled sec-ch-ua often gets the brand wrong or leaves it empty.
        if has_sec_ch_ua {
            let v = ctx.headers.get("sec-ch-ua").map(|s| s.to_ascii_lowercase()).unwrap_or_default();
            let brand_ok = v.contains("chromium")
                || v.contains("chrome")
                || v.contains("edge")
                || v.contains("opera")
                || v.contains("brave")
                || v.contains("not")   // the deliberate "Not?A_Brand" GREASE entry
                || v.contains("brand");
            if !brand_ok {
                return BrowserVerdict::Forged("sec-ch-ua present but lists no Chromium brand");
            }
        }
        // sec-ch-ua-mobile, when present, must be the strict "?0"/"?1" form.
        if let Some(m) = ctx.headers.get("sec-ch-ua-mobile") {
            let m = m.trim();
            if m != "?0" && m != "?1" {
                return BrowserVerdict::Forged("malformed sec-ch-ua-mobile");
            }
        }
    }

    // 3. Any real browser sends an Accept header on a document navigation, and
    //    it is never literally "*/*" for the top-level document (that's the
    //    curl/library default). Browser-claiming UA + Accept:*/* on a GET HTML
    //    navigation is a library wearing a costume.
    if matches!(fam, Family::Chromium | Family::Firefox | Family::Safari)
        && ctx.method.eq_ignore_ascii_case("GET")
        && has_sec_fetch_dest_document(ctx)
        && accept == "*/*"
    {
        return BrowserVerdict::Forged("browser document navigation with Accept: */*");
    }

    // 4. TLS-layer contradiction: a forwarded JA3/JA4 that decodes to a
    //    non-browser TLS stack while the UA claims a browser. We keep this
    //    intentionally narrow — only well-known scripting-stack fingerprints —
    //    so a legitimate-but-unusual TLS stack is never mistaken for forgery.
    if let Some(reason) = tls_contradicts_browser(&ctx.ja3, &ctx.ja4, fam) {
        return BrowserVerdict::Forged(reason);
    }

    // ---- POSITIVE trust: complete & consistent modern-browser fingerprint ---

    let accept_lang = has("accept-language");
    let accept_enc = has("accept-encoding");
    let accept_ok = !accept.is_empty() && accept != "*/*";

    let trusted = match fam {
        Family::Chromium => {
            has_sec_ch_ua && has_sec_fetch && accept_lang && accept_enc && accept_ok
        }
        Family::Firefox | Family::Safari => {
            // WebKit/Gecko don't send Client Hints, but always send the
            // Fetch-Metadata set on navigations plus the Accept* trio.
            has_sec_fetch && accept_lang && accept_enc && accept_ok
        }
        _ => false,
    };
    // When a trustworthy TLS fingerprint is forwarded and agrees with the UA
    // family, that alone is strong enough to keep Trusted even if Client Hints
    // are stripped by a privacy extension.
    let tls_agrees = tls_agrees_with_browser(&ctx.ja3, &ctx.ja4, fam);

    if trusted || (tls_agrees && accept_lang && accept_enc) {
        return BrowserVerdict::Trusted;
    }

    BrowserVerdict::Unverified
}

fn has_sec_fetch_dest_document(ctx: &RequestCtx) -> bool {
    ctx.headers
        .get("sec-fetch-dest")
        .map(|v| v.eq_ignore_ascii_case("document"))
        .unwrap_or(false)
}

/// Known scripting/automation TLS fingerprints that flatly contradict a
/// browser UA. Returns Some(reason) only for a *certain* contradiction.
/// Empty fingerprints (no TLS front layer) always return None.
fn tls_contradicts_browser(ja3: &str, ja4: &str, fam: Family) -> Option<&'static str> {
    if matches!(fam, Family::NonBrowser | Family::Other) {
        return None;
    }
    let ja4 = ja4.to_ascii_lowercase();
    // JA4 starts with the TLS-library class. Browsers negotiate TLS 1.3 (t13)
    // with a rich cipher list; common scripting stacks present a distinctly
    // thin ClientHello. We only flag the unambiguous library prefixes.
    // (e.g. python/urllib, go default transport, curl without --ciphers.)
    for sig in ["t13d1517h2", "t13d1516h2"] {
        // placeholder browser-ish prefixes are intentionally NOT here.
        let _ = sig;
    }
    for bad in BAD_JA4_PREFIXES {
        if ja4.starts_with(bad) {
            return Some("TLS fingerprint is a known scripting stack, UA claims a browser");
        }
    }
    for bad in BAD_JA3_HASHES {
        if ja3.eq_ignore_ascii_case(bad) {
            return Some("TLS JA3 is a known scripting stack, UA claims a browser");
        }
    }
    None
}

/// True when a forwarded TLS fingerprint positively matches the claimed family.
fn tls_agrees_with_browser(ja3: &str, ja4: &str, fam: Family) -> bool {
    if ja3.is_empty() && ja4.is_empty() {
        return false;
    }
    let ja4 = ja4.to_ascii_lowercase();
    match fam {
        // All modern browsers negotiate TLS 1.3; JA4 encodes that as a "t13"
        // class prefix. A scripting stack that forged the UA would have to also
        // forge a full browser TLS stack to land here.
        Family::Chromium | Family::Firefox | Family::Safari => ja4.starts_with("t13"),
        _ => false,
    }
}

/// JA4 prefixes for well-known non-browser TLS stacks. Conservative list:
/// only fingerprints that are *never* produced by a real browser.
const BAD_JA4_PREFIXES: &[&str] = &[
    "t13d190900", // common Go default transport shape
    "t10d",       // TLS 1.0-only ClientHello — no modern browser does this
    "t11d",       // TLS 1.1-only ClientHello
];

/// Specific JA3 MD5 hashes of common attack/scripting libraries. Extend via
/// ops as new toolkits appear; an empty match set simply means "no JA3 rule".
const BAD_JA3_HASHES: &[&str] = &[
    // python-requests / urllib3 default contexts and curl default builds vary
    // by OpenSSL version, so we keep this list short and exact to avoid any
    // chance of a browser collision. Operators append their own observed ones.
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn ctx(headers: &[(&str, &str)], ua: &str, method: &str, ver: &str, ja3: &str, ja4: &str) -> RequestCtx {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert(k.to_string(), v.to_string());
        }
        RequestCtx {
            request_id: "t".into(),
            client_ip: IpAddr::from([1, 2, 3, 4]),
            method: method.into(),
            uri: "/".into(),
            path: "/".into(),
            query: "".into(),
            host: "h".into(),
            user_agent: ua.into(),
            http_version: ver.into(),
            headers: h,
            header_order: vec![],
            cookie_order: vec![],
            cookies: HashMap::new(),
            body_preview: vec![],
            content_length: None,
            country: None,
            ja4h: String::new(),
            ja3: ja3.into(),
            ja4: ja4.into(),
        }
    }

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36";

    #[test]
    fn real_chrome_is_trusted() {
        let v = verify(&ctx(
            &[
                ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
                ("accept-language", "en-US,en;q=0.9"),
                ("accept-encoding", "gzip, deflate, br"),
                ("sec-fetch-dest", "document"),
                ("sec-fetch-mode", "navigate"),
                ("sec-ch-ua", "\"Chromium\";v=\"123\", \"Not?A_Brand\";v=\"24\""),
                ("sec-ch-ua-mobile", "?0"),
            ],
            CHROME_UA, "GET", "HTTP/2.0", "", "",
        ));
        assert_eq!(v, BrowserVerdict::Trusted, "real Chrome must be trusted");
    }

    #[test]
    fn chrome_ua_without_client_hints_is_forged() {
        // The classic DDoS tool signature: a copy-pasted Chrome UA, nothing else.
        let v = verify(&ctx(&[("accept", "*/*")], CHROME_UA, "GET", "HTTP/1.1", "", ""));
        assert!(matches!(v, BrowserVerdict::Forged(_)), "bare Chrome UA must be forged, got {:?}", v);
    }

    #[test]
    fn chrome_ua_over_http10_is_forged() {
        let v = verify(&ctx(&[("accept", "text/html")], CHROME_UA, "GET", "HTTP/1.0", "", ""));
        assert!(matches!(v, BrowserVerdict::Forged(_)));
    }

    #[test]
    fn curl_is_unverified_not_forged() {
        // Honest non-browser: doesn't claim to be a browser, so it isn't
        // "forged" — it just can't be vouched for and must pass the challenge.
        let v = verify(&ctx(&[("accept", "*/*")], "curl/8.4.0", "GET", "HTTP/1.1", "", ""));
        assert_eq!(v, BrowserVerdict::Unverified);
    }

    #[test]
    fn empty_ua_is_unverified() {
        let v = verify(&ctx(&[], "", "GET", "HTTP/1.1", "", ""));
        assert_eq!(v, BrowserVerdict::Unverified);
    }

    #[test]
    fn fake_sec_ch_ua_brand_is_forged() {
        let v = verify(&ctx(
            &[
                ("accept", "text/html"),
                ("sec-fetch-mode", "navigate"),
                ("sec-ch-ua", "\"definitely\";v=\"1\""),
                ("accept-language", "en"),
                ("accept-encoding", "gzip"),
            ],
            CHROME_UA, "GET", "HTTP/2.0", "", "",
        ));
        assert!(matches!(v, BrowserVerdict::Forged(_)), "bogus sec-ch-ua brand must be forged, got {:?}", v);
    }

    #[test]
    fn real_firefox_is_trusted_without_client_hints() {
        let ff = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0";
        let v = verify(&ctx(
            &[
                ("accept", "text/html,application/xhtml+xml"),
                ("accept-language", "en-US,en;q=0.5"),
                ("accept-encoding", "gzip, deflate, br"),
                ("sec-fetch-dest", "document"),
                ("sec-fetch-mode", "navigate"),
            ],
            ff, "GET", "HTTP/2.0", "", "",
        ));
        assert_eq!(v, BrowserVerdict::Trusted);
    }

    #[test]
    fn tls_fingerprint_rescues_hint_stripped_chrome() {
        // Privacy extension stripped Client Hints, but a browser TLS 1.3
        // fingerprint was forwarded → still Trusted.
        let v = verify(&ctx(
            &[
                ("accept", "text/html,*/*;q=0.8"),
                ("accept-language", "en-US"),
                ("accept-encoding", "gzip, deflate, br"),
                ("sec-fetch-mode", "navigate"),
            ],
            CHROME_UA, "GET", "HTTP/2.0", "", "t13d1516h2_8daaf6152771_b186095e22b6",
        ));
        assert_eq!(v, BrowserVerdict::Trusted);
    }

    #[test]
    fn browser_ua_with_scripting_tls_is_forged() {
        let v = verify(&ctx(
            &[
                ("accept", "text/html"),
                ("accept-language", "en"),
                ("accept-encoding", "gzip"),
                ("sec-fetch-mode", "navigate"),
                ("sec-ch-ua", "\"Chromium\";v=\"123\""),
                ("sec-ch-ua-mobile", "?0"),
            ],
            CHROME_UA, "GET", "HTTP/2.0", "", "t10d000000_aaaaaaaaaaaa_bbbbbbbbbbbb",
        ));
        assert!(matches!(v, BrowserVerdict::Forged(_)), "TLS 1.0 stack + Chrome UA must be forged, got {:?}", v);
    }
}
