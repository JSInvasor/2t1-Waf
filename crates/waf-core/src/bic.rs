//! Silent Browser Integrity Check (BIC).
//!
//! Lightweight, invisible filter served before the full PoW challenge.
//! Real browsers complete it in <100 ms with a tiny inline script and
//! immediately get a signed cookie that lets them bypass `bot_score`
//! on subsequent requests. Dumb HTTP scripts that don't execute JS
//! never get the cookie and remain in the slow path.
//!
//! The cookie is HMAC-signed and tied to the source IP's /24 (or /64
//! for IPv6) subnet, so a botnet can't lift one cookie and reuse it
//! across many unrelated IPs.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const BIC_COOKIE_NAME: &str = "__2t1_bic";
const COOKIE_TTL_SECS:  u64 = 1800;
const TOKEN_TTL_SECS:   u64 = 60;

pub struct Bic { secret: Vec<u8> }

#[derive(Debug)]
pub struct Token {
    pub challenge: String,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BicError {
    #[error("token format invalid")]   BadFormat,
    #[error("token expired")]          Expired,
    #[error("signature mismatch")]     BadSig,
    #[error("integrity proof invalid")] BadProof,
}

impl Bic {
    pub fn new(secret: &str) -> Self { Self { secret: secret.as_bytes().to_vec() } }

    /// Issue a fresh challenge token (called when serving the BIC page).
    pub fn issue(&self) -> Token {
        let now = now_secs();
        let expires_at = now + TOKEN_TTL_SECS;
        let mut chal = [0u8; 12];
        getrandom_bytes(&mut chal);
        let challenge = hex::encode(chal);
        let signature = self.sign(&challenge, expires_at);
        Token { challenge, expires_at, signature }
    }

    /// Verify the proof submitted by the BIC JS.
    /// `proof` must equal SHA-256(challenge | "2t1bic")[..16] in hex.
    pub fn verify_proof(&self, challenge: &str, exp: u64, sig: &str, proof: &str) -> Result<(), BicError> {
        if now_secs() > exp { return Err(BicError::Expired); }
        let expect = self.sign(challenge, exp);
        if !ct_eq(expect.as_bytes(), sig.as_bytes()) {
            return Err(BicError::BadSig);
        }
        let mut h = Sha256::new();
        h.update(challenge.as_bytes());
        h.update(b"2t1bic");
        let want = hex::encode(&h.finalize()[..8]); // 16 hex chars
        if !ct_eq(want.as_bytes(), proof.as_bytes()) {
            return Err(BicError::BadProof);
        }
        Ok(())
    }

    /// After a successful verify, mint a clearance cookie value.
    /// Format: `<exp>.<subnet>.<sig>` where sig binds the subnet, so
    /// lifting the cookie onto an unrelated IP family fails.
    pub fn mint(&self, ip: IpAddr) -> (String, String) {
        let exp = now_secs() + COOKIE_TTL_SECS;
        let subnet = subnet_marker(ip);
        let payload = format!("bic|{exp}|{subnet}");
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac key");
        mac.update(payload.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let cookie = format!("{exp}.{subnet}.{sig}");
        (BIC_COOKIE_NAME.to_string(), cookie)
    }

    /// Validate a previously-minted cookie against the source IP.
    pub fn verify_cookie(&self, value: &str, ip: IpAddr) -> bool {
        let mut parts = value.splitn(3, '.');
        let exp_s = match parts.next() { Some(p) => p, None => return false };
        let subnet = match parts.next() { Some(p) => p, None => return false };
        let sig = match parts.next() { Some(p) => p, None => return false };
        let exp: u64 = match exp_s.parse() { Ok(n) => n, Err(_) => return false };
        if exp <= now_secs() { return false; }
        if subnet != subnet_marker(ip) { return false; }
        let payload = format!("bic|{exp}|{subnet}");
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac key");
        mac.update(payload.as_bytes());
        let expect = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        ct_eq(expect.as_bytes(), sig.as_bytes())
    }

    pub fn cookie_name(&self) -> &str { BIC_COOKIE_NAME }
    pub fn ttl(&self) -> u64 { COOKIE_TTL_SECS }

    fn sign(&self, challenge: &str, exp: u64) -> String {
        let payload = format!("{challenge}|{exp}");
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac key");
        mac.update(payload.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Minimal HTML page. Inline JS computes the integrity proof and
    /// posts it to /__2t1/bic-verify, then redirects back to the URL
    /// the user originally tried to visit.
    pub fn render_page(&self, token: &Token, request_id: &str, original: &str) -> String {
        let Token { challenge, expires_at, signature } = token;
        let original_safe: String = original.chars().filter(|c| !c.is_control() && *c != '"' && *c != '\'').collect();
        format!(
r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying…</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400&family=Outfit:wght@300;400&display=swap" rel="stylesheet">
<style>
  :root{{--bg:#f4f3ee;--paper:#fafaf6;--ink:#111;--muted:#8b8a84;--hair:rgba(17,17,17,.12);}}
  *{{box-sizing:border-box}}html,body{{margin:0;padding:0;height:100%}}
  body{{background:var(--bg);color:var(--ink);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px;display:grid;place-items:center;-webkit-font-smoothing:antialiased;overflow:hidden}}
  body::before{{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(circle at 20% 10%,rgba(17,17,17,.025),transparent 40%),radial-gradient(circle at 80% 80%,rgba(17,17,17,.02),transparent 50%)}}
  .box{{width:min(380px,92vw);background:var(--paper);border:1px solid var(--hair);border-radius:10px;padding:24px 28px;position:relative;z-index:2;box-shadow:0 8px 24px rgba(17,17,17,.05)}}
  .tag{{font-family:'Outfit',sans-serif;font-weight:400;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:8px}}
  h1{{font-family:'Outfit',sans-serif;font-weight:300;font-size:15px;margin:0 0 6px}}
  .caret{{display:inline-block;width:1.5px;height:.95em;background:var(--ink);margin-left:4px;vertical-align:text-bottom;color:transparent;animation:b 1.1s steps(2) infinite}}
  @keyframes b{{50%{{opacity:0}}}}
  .sub{{font-family:'Outfit',sans-serif;font-weight:300;color:var(--muted);margin:8px 0 14px;font-size:12px}}
  .bar{{height:2px;background:rgba(17,17,17,.08);border-radius:999px;overflow:hidden}}
  .bar>div{{height:100%;width:0;background:var(--ink);transition:width .15s ease}}
  .foot{{margin-top:14px;display:flex;justify-content:space-between;font-family:'Outfit',sans-serif;font-weight:300;font-size:10.5px;color:var(--muted)}}
  code{{background:rgba(17,17,17,.04);padding:1px 5px;border-radius:3px;color:var(--ink);font-size:10px}}
</style></head><body>
<div class="box">
  <div class="tag">i-waf · integrity</div>
  <h1>Verifying browser<span class="caret"></span></h1>
  <p class="sub">One moment — silent integrity check (no captcha).</p>
  <div class="bar"><div id="p"></div></div>
  <div class="foot"><span>ref · <code>{request_id}</code></span><span>I-Waf</span></div>
</div>
<script>
(async () => {{
  const C="{challenge}", E={expires_at}, S="{signature}", T="{original_safe}";
  const bar=document.getElementById("p");
  // Quick integrity probe: features that headless minimal HTTP libs lack.
  const probe = !!(window.crypto && crypto.subtle && navigator && document.body
                   && new Date().getTimezoneOffset !== undefined);
  bar.style.width="40%";
  if (!probe) {{ document.querySelector("h1").textContent="Browser unsupported"; return; }}
  // Compute SHA-256(challenge + "2t1bic"), keep first 16 hex chars.
  const enc=new TextEncoder();
  const buf=await crypto.subtle.digest("SHA-256", enc.encode(C+"2t1bic"));
  const hex=Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
  const proof=hex.slice(0,16);
  bar.style.width="80%";
  const r=await fetch("/__2t1/bic-verify",{{
    method:"POST",
    headers:{{"content-type":"application/json"}},
    body:JSON.stringify({{c:C,e:E,s:S,p:proof}}),
    credentials:"same-origin",
  }});
  bar.style.width="100%";
  if (r.ok) {{ location.replace(T||"/"); }}
  else      {{ document.querySelector("h1").textContent="Verification failed."; }}
}})();
</script>
</body></html>
"##)
    }
}

/// First-three-octet (IPv4) or first-four-segment (IPv6) marker. Embedded
/// in the cookie so cross-IP-family lifts of the cookie are rejected.
fn subnet_marker(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("4{:02x}{:02x}{:02x}", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("6{:04x}{:04x}{:04x}{:04x}", s[0], s[1], s[2], s[3])
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
    diff == 0
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn getrandom_bytes(buf: &mut [u8]) {
    let mut h = Sha256::new();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0).to_le_bytes();
    h.update(nanos);
    h.update(std::process::id().to_le_bytes());
    h.update((buf.as_ptr() as usize).to_le_bytes());
    let digest = h.finalize();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = digest[i % digest.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cookie_roundtrip_same_subnet() {
        let b = Bic::new("a-very-secret-key-of-some-length");
        let ip: IpAddr = "1.2.3.99".parse().unwrap();
        let (_, v) = b.mint(ip);
        assert!(b.verify_cookie(&v, ip));
        assert!(b.verify_cookie(&v, "1.2.3.10".parse().unwrap()));
        assert!(!b.verify_cookie(&v, "1.2.4.10".parse().unwrap()));
        assert!(!b.verify_cookie("garbage", ip));
    }
    #[test]
    fn proof_check() {
        let b = Bic::new("a-very-secret-key-of-some-length");
        let t = b.issue();
        let mut h = Sha256::new();
        h.update(t.challenge.as_bytes());
        h.update(b"2t1bic");
        let proof = hex::encode(&h.finalize()[..8]);
        b.verify_proof(&t.challenge, t.expires_at, &t.signature, &proof).unwrap();
        assert!(b.verify_proof(&t.challenge, t.expires_at, &t.signature, "deadbeef00112233").is_err());
    }
}
