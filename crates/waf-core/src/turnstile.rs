//! Cloudflare Turnstile / hCaptcha verification.
//!
//! When `challenge_mode == Interactive` (or Combined), the proxy serves
//! a real captcha widget instead of the home-grown PoW. The visitor's
//! token is POSTed to /__2t1/turnstile-verify, the verifier opens an
//! outbound TLS connection to the provider's siteverify endpoint, and
//! on a positive response a regular `__2t1_clearance` cookie is minted
//! using the existing PoW Challenger HMAC. So upstream code paths
//! treat a captcha-cleared visitor the same as a PoW-cleared one.
//!
//! Implementation notes:
//!  - We deliberately avoid pulling in `reqwest`. The dep cost (extra
//!    90s of compile time on a fresh build, additional TLS plumbing)
//!    isn't worth it when openssl is already wired in via Pingora.
//!  - One TLS handshake per verification call. Operators expect single-
//!    digit verifications per second; we don't bother pooling.
//!  - 5s end-to-end timeout — siteverify is normally <300ms.
//!  - JSON parsing via `serde_json` already in deps.

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use serde::Deserialize;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_openssl::SslStream;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Captcha provider — selected via runtime config. Both have the same
/// REST shape (POST `secret` + `response` form fields, get back a JSON
/// object with `success: bool`), they just live on different hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider { Turnstile, Hcaptcha }

impl Provider {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "hcaptcha" => Self::Hcaptcha,
            _          => Self::Turnstile,
        }
    }
    pub fn host(&self) -> &'static str {
        match self {
            Self::Turnstile => "challenges.cloudflare.com",
            Self::Hcaptcha  => "hcaptcha.com",
        }
    }
    pub fn path(&self) -> &'static str {
        match self {
            Self::Turnstile => "/turnstile/v0/siteverify",
            Self::Hcaptcha  => "/siteverify",
        }
    }
    /// JS asset URL for the widget.
    pub fn script_src(&self) -> &'static str {
        match self {
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/api.js",
            Self::Hcaptcha  => "https://js.hcaptcha.com/1/api.js",
        }
    }
    /// HTML class the JS auto-renders against.
    pub fn widget_class(&self) -> &'static str {
        match self {
            Self::Turnstile => "cf-turnstile",
            Self::Hcaptcha  => "h-captcha",
        }
    }
    /// Token field the widget injects into form submission.
    pub fn token_field(&self) -> &'static str {
        match self {
            Self::Turnstile => "cf-turnstile-response",
            Self::Hcaptcha  => "h-captcha-response",
        }
    }
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    success: bool,
    #[serde(default, rename = "error-codes")]
    _error_codes: Vec<String>,
}

/// POST the token to the provider's siteverify endpoint and return
/// `Ok(true)` only on a verified response. Network / TLS / timeout
/// errors return `Ok(false)` — we fail closed, since the captcha is
/// the gate to a clearance cookie.
pub async fn verify(provider: Provider, secret: &str, token: &str, remote_ip: &str) -> bool {
    if secret.is_empty() || token.is_empty() { return false; }
    match timeout(VERIFY_TIMEOUT, do_verify(provider, secret, token, remote_ip)).await {
        Ok(Ok(v))  => v,
        Ok(Err(e)) => { tracing::warn!(provider = ?provider, %e, "captcha verify failed"); false }
        Err(_)     => { tracing::warn!(provider = ?provider, "captcha verify timed out"); false }
    }
}

async fn do_verify(provider: Provider, secret: &str, token: &str, remote_ip: &str) -> io::Result<bool> {
    // 1. Open TCP, then upgrade to TLS with SNI = provider host.
    let host = provider.host();
    let addr = format!("{host}:443");
    let tcp = TcpStream::connect(&addr).await?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    builder.set_verify(SslVerifyMode::PEER);
    let connector = builder.build();
    let ssl = connector.configure()
        .and_then(|c| c.into_ssl(host))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut tls = SslStream::new(ssl, tcp)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    std::pin::Pin::new(&mut tls).connect().await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls handshake: {e}")))?;

    // 2. Build form-urlencoded body.
    let body = format!(
        "secret={}&response={}&remoteip={}",
        urlenc(secret), urlenc(token), urlenc(remote_ip),
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: 2t1-waf\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         Accept: application/json\r\n\r\n\
         {body}",
        path = provider.path(),
        host = host,
        len = body.len(),
        body = body,
    );
    tls.write_all(req.as_bytes()).await?;

    // 3. Read until EOF (Connection: close), cap at 16 KiB.
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        let n = tls.read(&mut chunk).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 16 * 1024 { break; }
    }
    let _ = tls.shutdown().await;

    // 4. Split headers / body, parse JSON.
    let split_at = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let json_bytes = match split_at {
        Some(i) => &buf[i + 4..],
        None    => return Err(io::Error::new(io::ErrorKind::InvalidData, "no headers/body split")),
    };
    let resp: VerifyResponse = serde_json::from_slice(json_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad json: {e}")))?;
    Ok(resp.success)
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Render the captcha challenge HTML in the I-Waf cream theme. The
/// widget posts the token to /__2t1/turnstile-verify, which on success
/// reloads `original` from the same origin.
pub fn render_page(provider: Provider, site_key: &str, request_id: &str, original: &str) -> String {
    let original_safe: String = original.chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\'').collect();
    format!(
r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check · 2t1</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=Outfit:wght@200;300;400;500;600&display=swap" rel="stylesheet">
<script src="{script_src}" async defer></script>
<style>
  :root{{--bg:#0f0f0f;--paper:#181818;--ink:#e8e8e8;--ink2:#fff;--muted:#6b6b6b;--accent:#8B1A1A;--accent2:#a82020;--hair:rgba(255,255,255,.08);--glow:rgba(139,26,26,.15);}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  html,body{{height:100%}}
  body{{background:var(--bg);color:var(--ink);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px;display:grid;place-items:center;-webkit-font-smoothing:antialiased;overflow:hidden}}
  body::before{{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(ellipse 600px 400px at 50% 30%,var(--glow),transparent)}}
  .card{{width:min(440px,92vw);background:var(--paper);border:1px solid var(--hair);border-radius:16px;padding:36px 38px;position:relative;z-index:2;box-shadow:0 20px 60px rgba(0,0,0,.4),0 0 0 1px rgba(255,255,255,.03) inset;text-align:center}}
  .logo{{margin:0 auto 20px;width:72px;height:72px}}
  .logo svg{{width:100%;height:100%;filter:drop-shadow(0 4px 12px rgba(139,26,26,.3))}}
  .badge{{display:inline-flex;align-items:center;gap:6px;font-family:'Outfit',sans-serif;font-weight:500;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent2);background:rgba(139,26,26,.1);border:1px solid rgba(139,26,26,.15);padding:4px 12px;border-radius:20px;margin-bottom:18px}}
  .badge .dot{{width:6px;height:6px;border-radius:50%;background:var(--accent2);animation:pulse 2s ease infinite}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
  h1{{font-family:'Outfit',sans-serif;font-weight:400;font-size:20px;margin:0 0 6px;color:var(--ink2)}}
  .sub{{font-family:'Outfit',sans-serif;font-weight:300;color:var(--muted);margin:6px 0 24px;font-size:13px;line-height:1.6}}
  .captcha-wrap{{margin:0 auto;display:inline-block;border-radius:12px;overflow:hidden;max-height:70px;position:relative}}
  .captcha-wrap [class*="turnstile"],.captcha-wrap [class*="captcha"]{{transform:scale(1.02);transform-origin:top center}}
  .foot{{margin-top:24px;padding-top:16px;border-top:1px solid var(--hair);display:flex;justify-content:space-between;align-items:center;font-family:'Outfit',sans-serif;font-weight:300;font-size:11px;color:var(--muted)}}
  .foot code{{background:rgba(255,255,255,.06);padding:2px 8px;border-radius:4px;color:var(--ink);font-size:10px;font-family:'JetBrains Mono',monospace}}
  .brand{{font-weight:500;color:var(--accent2);letter-spacing:.04em}}
  .err{{color:#e84057;margin-top:14px;font-size:12px;font-family:'Outfit',sans-serif}}
</style></head><body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <polygon fill="#8B1A1A" points="100,8 110,45 131,14 128,51 159,30 143,64 180,54 153,81 191,84 156,100 191,116 153,119 180,146 143,136 159,170 128,149 131,186 110,155 100,192 90,155 69,186 72,149 41,170 57,136 20,146 47,119 9,116 44,100 9,84 47,81 20,54 57,64 41,30 72,51 69,14 90,45"/>
      <ellipse cx="80" cy="96" rx="16" ry="19" fill="#fff"/>
      <ellipse cx="120" cy="96" rx="16" ry="19" fill="#fff"/>
      <ellipse cx="83" cy="100" rx="9" ry="11" fill="#1a1a1a"/>
      <ellipse cx="123" cy="100" rx="9" ry="11" fill="#1a1a1a"/>
      <circle cx="78" cy="93" r="3.5" fill="#fff"/>
      <circle cx="118" cy="93" r="3.5" fill="#fff"/>
    </svg>
  </div>
  <div class="badge"><span class="dot"></span>security check</div>
  <h1>Verify you're human</h1>
  <p class="sub">Complete the verification below to continue.<br>This usually takes a couple of seconds.</p>
  <form id="f" method="POST" action="/__2t1/turnstile-verify">
    <div class="captcha-wrap"><div class="{widget_class}" data-sitekey="{site_key}" data-callback="onCaptcha" data-theme="dark"></div></div>
    <p class="err" id="err" hidden>Verification failed. Please refresh and try again.</p>
  </form>
  <div class="foot"><span>ref · <code>{request_id}</code></span><span class="brand">2t1 Protection</span></div>
</div>
<script>
  const T = "{original_safe}";
  function onCaptcha(token) {{
    fetch("/__2t1/turnstile-verify", {{
      method:"POST",
      headers:{{"content-type":"application/json"}},
      body: JSON.stringify({{ token: token }}),
      credentials:"same-origin",
    }}).then(r => {{
      if (r.ok) {{ location.replace(T || "/"); }}
      else      {{ document.getElementById("err").hidden = false; }}
    }}).catch(() => {{ document.getElementById("err").hidden = false; }});
  }}
</script>
</body></html>
"##,
        script_src = provider.script_src(),
        widget_class = provider.widget_class(),
        site_key = site_key,
        request_id = request_id,
        original_safe = original_safe,
    )
}
