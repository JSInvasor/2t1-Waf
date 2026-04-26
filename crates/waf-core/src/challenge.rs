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
        format!(
r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying your browser…</title>
<style>
:root {{ color-scheme: dark; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
  background: #0b0d12; color: #e6e7ea; font: 14px/1.5 system-ui, sans-serif; }}
.box {{ width: min(420px, 92vw); padding: 32px; background: #11141b;
  border: 1px solid #1c2030; border-radius: 12px; box-shadow: 0 10px 30px #0007; }}
h1 {{ margin: 0 0 8px; font-size: 16px; font-weight: 600; }}
.sub {{ color: #8a8f9c; margin: 0 0 24px; }}
.bar {{ height: 6px; background: #1c2030; border-radius: 999px; overflow: hidden; }}
.bar > div {{ height: 100%; width: 0; background: linear-gradient(90deg,#3a86ff,#8338ec);
  transition: width .15s ease; }}
.foot {{ margin-top: 18px; font-size: 11px; color: #5a6071; }}
code {{ font-family: ui-monospace, monospace; color: #8a8f9c; }}
</style></head><body>
<div class="box">
  <h1>Checking your connection</h1>
  <p class="sub">A one-time browser proof is required before you can continue.</p>
  <div class="bar"><div id="p"></div></div>
  <p class="foot">Ref <code>{request_id}</code> · 2t1-Waf</p>
</div>
<script>
(async () => {{
  const C = "{challenge}", S = "{signature}", E = {expires_at}, D = {difficulty};
  const enc = new TextEncoder();
  const target = "0".repeat(D);
  const bar = document.getElementById("p");
  let nonce = 0;
  const start = performance.now();
  while (true) {{
    const buf = enc.encode(C + nonce);
    const dig = await crypto.subtle.digest("SHA-256", buf);
    const hex = Array.from(new Uint8Array(dig)).map(b => b.toString(16).padStart(2,"0")).join("");
    if (hex.startsWith(target)) break;
    if ((nonce & 0xfff) === 0) {{
      bar.style.width = Math.min(95, (performance.now()-start)/30) + "%";
      await new Promise(r => setTimeout(r, 0));
    }}
    nonce++;
  }}
  bar.style.width = "100%";
  const r = await fetch("/__2t1/verify", {{
    method: "POST",
    headers: {{ "content-type": "application/json" }},
    body: JSON.stringify({{ c: C, n: String(nonce), s: S, e: E }}),
    credentials: "same-origin",
  }});
  if (r.ok) {{ location.reload(); }}
  else {{ document.querySelector("h1").textContent = "Verification failed."; }}
}})();
</script>
</body></html>
"##)
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
