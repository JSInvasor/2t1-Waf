//! Mutable runtime state. Anything the dashboard can change at runtime lives
//! here behind atomics / RwLocks so the hot path stays lock-free for reads.
//!
//! Persisted to `runtime.json` next to the main config so changes survive
//! restarts. Static config (`waf.toml`) is the immutable baseline; runtime
//! state is the override layer.

use ipnet::IpNet;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[derive(Debug)]
pub struct Runtime {
    pub under_attack: AtomicBool,
    pub challenge_threshold: AtomicU32,
    pub block_threshold: AtomicU32,
    /// Per-IP concurrent connection cap; 0 disables.
    pub max_concurrent_per_ip: AtomicU32,
    /// Multiplier (basis points) applied to global RPM when under attack.
    /// 5000 = 50% of configured RPM.
    pub rpm_under_attack_bps: AtomicU32,

    pub rules: RuleToggles,

    /// Hot-swappable IP lists. CIDR format, parsed at write time.
    pub allow: RwLock<Vec<IpNet>>,
    pub deny: RwLock<Vec<IpNet>>,
    /// ISO 3166-1 alpha-2 codes blocked at runtime.
    pub blocked_countries: RwLock<Vec<String>>,

    pub auth_token: RwLock<String>,

    persist_path: RwLock<Option<PathBuf>>,
}

#[derive(Debug)]
pub struct RuleToggles {
    pub sqli: AtomicBool,
    pub xss: AtomicBool,
    pub traversal: AtomicBool,
    pub cmdi: AtomicBool,
    pub lfi: AtomicBool,
    pub bot_ua: AtomicBool,
    pub rate_limit: AtomicBool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PersistedRuntime {
    #[serde(default)] pub under_attack: bool,
    #[serde(default)] pub challenge_threshold: Option<u32>,
    #[serde(default)] pub block_threshold: Option<u32>,
    #[serde(default)] pub max_concurrent_per_ip: Option<u32>,
    #[serde(default)] pub rpm_under_attack_bps: Option<u32>,
    #[serde(default)] pub allow: Vec<String>,
    #[serde(default)] pub deny: Vec<String>,
    #[serde(default)] pub blocked_countries: Vec<String>,
    #[serde(default)] pub rules: PersistedToggles,
    #[serde(default)] pub auth_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PersistedToggles {
    #[serde(default)] pub sqli: Option<bool>,
    #[serde(default)] pub xss: Option<bool>,
    #[serde(default)] pub traversal: Option<bool>,
    #[serde(default)] pub cmdi: Option<bool>,
    #[serde(default)] pub lfi: Option<bool>,
    #[serde(default)] pub bot_ua: Option<bool>,
    #[serde(default)] pub rate_limit: Option<bool>,
}

impl Runtime {
    pub fn from_config(cfg: &crate::Config) -> Self {
        Self {
            under_attack: AtomicBool::new(false),
            challenge_threshold: AtomicU32::new(cfg.detection.challenge_threshold),
            block_threshold: AtomicU32::new(cfg.detection.block_threshold),
            max_concurrent_per_ip: AtomicU32::new(200),
            rpm_under_attack_bps: AtomicU32::new(2000), // 20% of normal
            rules: RuleToggles {
                sqli: AtomicBool::new(cfg.detection.sqli),
                xss: AtomicBool::new(cfg.detection.xss),
                traversal: AtomicBool::new(cfg.detection.traversal),
                cmdi: AtomicBool::new(cfg.detection.cmdi),
                lfi: AtomicBool::new(cfg.detection.lfi),
                bot_ua: AtomicBool::new(true),
                rate_limit: AtomicBool::new(cfg.rate_limit.enabled),
            },
            allow: RwLock::new(Vec::new()),
            deny: RwLock::new(Vec::new()),
            blocked_countries: RwLock::new(cfg.geoip.block_countries.clone()),
            auth_token: RwLock::new(generate_token()),
            persist_path: RwLock::new(None),
        }
    }

    /// Set the file used to persist runtime state and load any existing data.
    pub fn bind_persist_file(&self, path: PathBuf) -> anyhow::Result<()> {
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let p: PersistedRuntime = serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("parse runtime.json: {e}"))?;
            self.apply_persisted(p)?;
        }
        *self.persist_path.write() = Some(path);
        Ok(())
    }

    pub fn apply_persisted(&self, p: PersistedRuntime) -> anyhow::Result<()> {
        self.under_attack.store(p.under_attack, Ordering::Relaxed);
        if let Some(v) = p.challenge_threshold { self.challenge_threshold.store(v, Ordering::Relaxed); }
        if let Some(v) = p.block_threshold     { self.block_threshold.store(v, Ordering::Relaxed); }
        if let Some(v) = p.max_concurrent_per_ip { self.max_concurrent_per_ip.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rpm_under_attack_bps { self.rpm_under_attack_bps.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rules.sqli      { self.rules.sqli.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rules.xss       { self.rules.xss.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rules.traversal { self.rules.traversal.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rules.cmdi      { self.rules.cmdi.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rules.lfi       { self.rules.lfi.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rules.bot_ua    { self.rules.bot_ua.store(v, Ordering::Relaxed); }
        if let Some(v) = p.rules.rate_limit{ self.rules.rate_limit.store(v, Ordering::Relaxed); }

        let allow: Vec<IpNet> = p.allow.iter().filter_map(|s| parse_net(s).ok()).collect();
        let deny:  Vec<IpNet> = p.deny.iter().filter_map(|s| parse_net(s).ok()).collect();
        *self.allow.write() = allow;
        *self.deny.write()  = deny;
        *self.blocked_countries.write() = p.blocked_countries.into_iter()
            .map(|c| c.to_ascii_uppercase()).collect();

        if let Some(t) = p.auth_token { if !t.is_empty() { *self.auth_token.write() = t; } }
        Ok(())
    }

    pub fn snapshot(&self) -> PersistedRuntime {
        PersistedRuntime {
            under_attack: self.under_attack.load(Ordering::Relaxed),
            challenge_threshold: Some(self.challenge_threshold.load(Ordering::Relaxed)),
            block_threshold: Some(self.block_threshold.load(Ordering::Relaxed)),
            max_concurrent_per_ip: Some(self.max_concurrent_per_ip.load(Ordering::Relaxed)),
            rpm_under_attack_bps: Some(self.rpm_under_attack_bps.load(Ordering::Relaxed)),
            allow: self.allow.read().iter().map(|n| n.to_string()).collect(),
            deny:  self.deny.read().iter().map(|n| n.to_string()).collect(),
            blocked_countries: self.blocked_countries.read().clone(),
            rules: PersistedToggles {
                sqli: Some(self.rules.sqli.load(Ordering::Relaxed)),
                xss: Some(self.rules.xss.load(Ordering::Relaxed)),
                traversal: Some(self.rules.traversal.load(Ordering::Relaxed)),
                cmdi: Some(self.rules.cmdi.load(Ordering::Relaxed)),
                lfi: Some(self.rules.lfi.load(Ordering::Relaxed)),
                bot_ua: Some(self.rules.bot_ua.load(Ordering::Relaxed)),
                rate_limit: Some(self.rules.rate_limit.load(Ordering::Relaxed)),
            },
            auth_token: Some(self.auth_token.read().clone()),
        }
    }

    pub fn persist(&self) -> anyhow::Result<()> {
        let path = match self.persist_path.read().clone() {
            Some(p) => p, None => return Ok(()),
        };
        let snap = self.snapshot();
        let json = serde_json::to_vec_pretty(&snap)?;
        // Write-then-rename for atomicity.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn add_allow(&self, cidr: &str) -> anyhow::Result<()> {
        let net = parse_net(cidr)?;
        let mut g = self.allow.write();
        if !g.iter().any(|n| *n == net) { g.push(net); }
        drop(g); let _ = self.persist(); Ok(())
    }

    pub fn add_deny(&self, cidr: &str) -> anyhow::Result<()> {
        let net = parse_net(cidr)?;
        let mut g = self.deny.write();
        if !g.iter().any(|n| *n == net) { g.push(net); }
        drop(g); let _ = self.persist(); Ok(())
    }

    pub fn remove_allow(&self, cidr: &str) -> anyhow::Result<()> {
        let net = parse_net(cidr)?;
        self.allow.write().retain(|n| *n != net);
        let _ = self.persist(); Ok(())
    }

    pub fn remove_deny(&self, cidr: &str) -> anyhow::Result<()> {
        let net = parse_net(cidr)?;
        self.deny.write().retain(|n| *n != net);
        let _ = self.persist(); Ok(())
    }
}

pub fn parse_net(s: &str) -> anyhow::Result<IpNet> {
    if let Ok(ip) = std::net::IpAddr::from_str(s) {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNet::new(ip, prefix).map_err(|e| anyhow::anyhow!("{s}: {e}"));
    }
    s.parse().map_err(|e| anyhow::anyhow!("{s}: {e}"))
}

fn generate_token() -> String {
    // 32-byte token derived from time + pid, base64-url. Not cryptographic
    // randomness but adequate for the dashboard until persistence imports
    // a user-supplied one.
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut h = Sha256::new();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(format!("{:?}", std::thread::current().id()).as_bytes());
    let bytes = h.finalize();
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parse_bare_ip() {
        let n = parse_net("8.8.8.8").unwrap();
        assert_eq!(n.prefix_len(), 32);
        let n = parse_net("10.0.0.0/24").unwrap();
        assert_eq!(n.prefix_len(), 24);
    }
}
