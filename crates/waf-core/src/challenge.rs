//! JS challenge with HMAC-signed proof-of-work.
//!
//! Flow:
//!  1. Engine returns `Action::Challenge`.
//!  2. The proxy serves `render_page()` containing a 16-byte hex challenge
//!     `c` and difficulty `d` signed with the server HMAC secret as
//!     `t = HMAC_SHA256(secret, c|exp)|exp` (base64-url).
//!  3. The browser finds a nonce `n` such that
//!     `sha256(c | n)` starts with `d` leading hex zeroes, then submits
//!     `c, n, t` to `/__2t1/verify`.
//!  4. Server verifies `t`, recomputes the PoW, then issues a
//!     `__2t1_clearance` cookie that `verify_clearance()` accepts.
//!
//! Real bots can solve PoWs too, but doing so for every request multiplies
//! their cost by orders of magnitude — which is the goal.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub struct Challenger {
    secret: Vec<u8>,
    cookie_name: String,
    cookie_ttl: u64,
    pow_difficulty: u8,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub challenge: String, // hex
    pub expires_at: u64,
    pub signature: String, // base64-url
    pub difficulty: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("token format invalid")]
    BadFormat,
    #[error("token expired")]
    Expired,
    #[error("signature mismatch")]
    BadSig,
    #[error("proof of work invalid")]
    BadPow,
}

impl Challenger {
    pub fn new(secret: &str, cookie_name: &str, cookie_ttl: u64, pow_difficulty: u8) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
            cookie_name: cookie_name.to_string(),
            cookie_ttl,
            pow_difficulty: pow_difficulty.clamp(1, 8),
        }
    }

    /// Create a fresh challenge token (called when serving the challenge page).
    pub fn issue(&self) -> Token {
        let now = now_secs();
        let expires_at = now + 120; // 2 minute solve budget
        let mut chal = [0u8; 16];
        getrandom_bytes(&mut chal);
        let challenge = hex::encode(chal);
        let signature = self.sign(&challenge, expires_at);
        Token { challenge, expires_at, signature, difficulty: self.pow_difficulty }
    }

    /// Verify a `(challenge, nonce, signature, expires_at)` quadruple.
    pub fn verify(&self, challenge: &str, nonce: &str, signature: &str, expires_at: u64) -> Result<(), ChallengeError> {
        if now_secs() > expires_at { return Err(ChallengeError::Expired); }
        let expect = self.sign(challenge, expires_at);
        if !ct_eq(expect.as_bytes(), signature.as_bytes()) {
            return Err(ChallengeError::BadSig);
        }
        if !verify_pow(challenge, nonce, self.pow_difficulty) {
            return Err(ChallengeError::BadPow);
        }
        Ok(())
    }

    /// After a successful verify, mint a clearance cookie value.
    /// Format: `<exp>.<sig>` where sig = HMAC(secret, "clr|"+exp).
    pub fn mint_clearance(&self) -> String {
        let exp = now_secs() + self.cookie_ttl;
        let payload = format!("clr|{exp}");
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac key");
        mac.update(payload.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{exp}.{sig}")
    }

    /// Validate a clearance cookie value previously minted by us.
    pub fn verify_clearance(&self, value: &str) -> bool {
        let (exp_s, sig) = match value.split_once('.') {
            Some(p) => p, None => return false,
        };
        let exp: u64 = match exp_s.parse() { Ok(n) => n, Err(_) => return false };
        if exp <= now_secs() { return false; }
        let payload = format!("clr|{exp}");
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac key");
        mac.update(payload.as_bytes());
        let expect = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        ct_eq(expect.as_bytes(), sig.as_bytes())
    }

    pub fn cookie_name(&self) -> &str { &self.cookie_name }
    pub fn cookie_ttl(&self) -> u64 { self.cookie_ttl }

    fn sign(&self, challenge: &str, exp: u64) -> String {
        let payload = format!("{challenge}|{exp}");
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac key");
        mac.update(payload.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Render an HTML challenge page. The browser solves a SHA-256 PoW in JS.
    pub fn render_page(&self, token: &Token, request_id: &str) -> String {
        let Token { challenge, expires_at, signature, difficulty } = token;
        let logo_b64 = include_str!("logo.b64").trim();
        format!(
r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check · Project Aretuze</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=Outfit:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  :root{{--bg:#f5f6fa;--paper:#ffffff;--ink:#2f3640;--ink2:#111111;--muted:#7f8fa6;--accent:#e84118;--accent2:#c23616;--hair:rgba(0,0,0,.08);--glow:rgba(232,65,24,.1);}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  html,body{{height:100%}}
  body{{background:var(--bg);color:var(--ink);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px;display:grid;place-items:center;-webkit-font-smoothing:antialiased;overflow:hidden}}
  body::before{{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(ellipse 600px 400px at 50% 30%,var(--glow),transparent)}}
  .card{{width:min(440px,92vw);background:var(--paper);border:1px solid var(--hair);border-radius:16px;padding:36px 38px;position:relative;z-index:2;box-shadow:0 15px 35px rgba(0,0,0,.05),0 0 0 1px rgba(255,255,255,.5) inset}}
  .logo{{width:80px;height:80px;margin:0 auto 18px}}
  .logo img{{width:100%;height:100%;object-fit:contain;filter:drop-shadow(0 4px 12px rgba(232,65,24,.2))}}
  .badge{{display:inline-flex;align-items:center;gap:6px;font-family:'Outfit',sans-serif;font-weight:500;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent2);background:rgba(232,65,24,.08);border:1px solid rgba(232,65,24,.15);padding:4px 12px;border-radius:20px;margin-bottom:16px;margin-left:auto;margin-right:auto;display:flex;width:max-content}}
  .badge .dot{{width:6px;height:6px;border-radius:50%;background:var(--accent2);animation:pulse 2s ease infinite}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
  h1{{font-family:'Outfit',sans-serif;font-weight:500;font-size:20px;margin:0 0 4px;color:var(--ink2);text-align:center}}
  .caret{{display:inline-block;width:1.5px;height:.95em;background:var(--accent2);margin-left:5px;vertical-align:text-bottom;color:transparent;animation:blink 1.1s steps(2) infinite}}
  @keyframes blink{{50%{{opacity:0}}}}
  p.sub{{font-family:'Outfit',sans-serif;font-weight:300;color:var(--muted);margin:12px 0 24px;font-size:13px;line-height:1.6;text-align:center}}
  .progress{{height:4px;background:rgba(0,0,0,.06);border-radius:999px;overflow:hidden}}
  .progress > div{{height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width .15s ease}}
  .meta{{margin-top:10px;font-size:10.5px;color:var(--muted);display:flex;justify-content:space-between;align-items:center;letter-spacing:.02em}}
  .meta .nonce{{font-variant-numeric:tabular-nums}}
  .foot{{margin-top:24px;padding-top:16px;border-top:1px solid var(--hair);display:flex;justify-content:space-between;align-items:center;font-family:'Outfit',sans-serif;font-weight:300;font-size:11px;color:var(--muted)}}
  .foot code{{background:rgba(0,0,0,.04);padding:2px 8px;border-radius:4px;color:var(--ink);font-size:10px;font-family:'JetBrains Mono',monospace}}
  .brand{{font-weight:600;color:var(--accent2);letter-spacing:.04em;text-transform:uppercase;font-size:10px}}
</style></head><body>
<div class="card">
  <div class="logo">
    <img src="data:image/webp;base64,{logo_b64}" alt="Project Aretuze">
  </div>
  <div class="badge"><span class="dot"></span>security check</div>
  <h1>Checking your browser<span class="caret"></span></h1>
  <p class="sub">A one-time browser proof is required before you continue.<br>This usually takes less than a second.</p>

  <div class="progress"><div id="p"></div></div>
  <div class="meta">
    <span id="status">solving proof of work…</span>
    <span class="nonce" id="nonce">0</span>
  </div>

  <div class="foot">
    <span>ref · <code>{request_id}</code></span>
    <span class="brand">Project Aretuze</span>
  </div>
</div>
<script>
(async () => {{
  const C = "{challenge}", S = "{signature}", E = {expires_at}, D = {difficulty};
  const enc = new TextEncoder();
  const target = "0".repeat(D);
  const bar = document.getElementById("p");
  const nonceLbl = document.getElementById("nonce");
  const status = document.getElementById("status");
  let nonce = 0;
  const start = performance.now();
  while (true) {{
    const dig = await crypto.subtle.digest("SHA-256", enc.encode(C + nonce));
    const hex = Array.from(new Uint8Array(dig)).map(b => b.toString(16).padStart(2,"0")).join("");
    if (hex.startsWith(target)) break;
    if ((nonce & 0xfff) === 0) {{
      bar.style.width = Math.min(95, (performance.now()-start)/30) + "%";
      nonceLbl.textContent = nonce.toLocaleString();
      await new Promise(r => setTimeout(r, 0));
    }}
    nonce++;
  }}
  bar.style.width = "100%";
  nonceLbl.textContent = nonce.toLocaleString();
  status.textContent = "submitting…";
  const r = await fetch("/__2t1/verify", {{
    method: "POST",
    headers: {{ "content-type": "application/json" }},
    body: JSON.stringify({{ c: C, n: String(nonce), s: S, e: E }}),
    credentials: "same-origin",
  }});
  if (r.ok) {{
    status.textContent = "verified · redirecting…";
    setTimeout(() => location.reload(), 250);
  }} else {{
    document.querySelector("h1").textContent = "Verification failed.";
    status.textContent = "please refresh and try again";
  }}
}})();
</script>
</body></html>
"##,
        challenge = challenge,
        expires_at = expires_at,
        signature = signature,
        difficulty = difficulty,
        request_id = request_id,
        logo_b64 = logo_b64,
        )
    }
}

fn verify_pow(challenge: &str, nonce: &str, difficulty: u8) -> bool {
    let mut h = Sha256::new();
    h.update(challenge.as_bytes());
    h.update(nonce.as_bytes());
    let digest = h.finalize();
    let need = difficulty as usize;
    // Compare leading hex zeroes without allocating the full hex string.
    let full_bytes = need / 2;
    for i in 0..full_bytes {
        if digest[i] != 0 { return false; }
    }
    if need % 2 == 1 {
        if (digest[full_bytes] >> 4) != 0 { return false; }
    }
    true
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
    // Avoid pulling in `getrandom` as a direct dep; SystemTime + a hash gives
    // adequate entropy here because the value is signed by HMAC anyway.
    use sha2::{Digest, Sha256};
    let mut seed = [0u8; 16];
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0).to_le_bytes();
    seed[..nanos.len().min(16)].copy_from_slice(&nanos[..nanos.len().min(16)]);
    let mut h = Sha256::new();
    h.update(seed);
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
    fn clearance_roundtrip() {
        let c = Challenger::new("a-very-secret-key-of-some-length", "ck", 60, 4);
        let v = c.mint_clearance();
        assert!(c.verify_clearance(&v));
        assert!(!c.verify_clearance("garbage"));
        assert!(!c.verify_clearance("123.abc"));
    }

    #[test]
    fn pow_check() {
        // Find any nonce manually for difficulty 1 to test the verifier end-to-end.
        let challenge = "abcd";
        let mut found = None;
        for n in 0..10_000u64 {
            if verify_pow(challenge, &n.to_string(), 1) { found = Some(n); break; }
        }
        assert!(found.is_some());
    }

    #[test]
    fn token_signature_check() {
        let c = Challenger::new("a-very-secret-key-of-some-length", "ck", 60, 1);
        let t = c.issue();
        // Find a valid nonce for difficulty 1.
        let mut nonce = String::from("0");
        for n in 0..100_000u64 {
            let cand = n.to_string();
            if verify_pow(&t.challenge, &cand, t.difficulty) { nonce = cand; break; }
        }
        c.verify(&t.challenge, &nonce, &t.signature, t.expires_at).unwrap();
    }
}
