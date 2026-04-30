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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

#[derive(Debug)]
pub struct Runtime {
    pub under_attack: AtomicBool,
    /// 0=off, 1=low, 2=medium, 3=high, 4=extreme. See `UamLevel`.
    pub uam_level: AtomicU8,
    /// 0=pow, 1=interactive, 2=combined.
    pub challenge_mode: AtomicU8,
    pub auto_uam_enabled: AtomicBool,
    /// Block rate (per second) above which auto-UAM escalates one level.
    pub auto_uam_threshold: AtomicU32,
    pub challenge_threshold: AtomicU32,
    pub block_threshold: AtomicU32,
    pub max_concurrent_per_ip: AtomicU32,
    pub rpm_under_attack_bps: AtomicU32,
    pub subnet_rpm: AtomicU32,
    pub subnet_conn: AtomicU32,
    /// Hard upper bound on global in-flight requests across the whole
    /// process. When exceeded, new requests are dropped at the door
    /// without entering the rest of the pipeline. 0 disables the check
    /// (NOT recommended in production — this is the last line before OOM).
    pub global_inflight_cap: AtomicU32,
    /// Score at or above which `evaluate()` returns Action::Tarpit
    /// instead of Block. Connection is held open writing one byte at
    /// a time to burn the attacker's socket.
    pub tarpit_score: AtomicU32,
    /// When ON, requests originating from a built-in cloud / hosting
    /// provider CIDR list (OVH, Hetzner, DO, Vultr, Linode, AWS, GCP,
    /// Azure ranges) are dropped or scored as suspicious depending on
    /// UAM level.
    pub datacenter_block: AtomicBool,

    pub rules: RuleToggles,
    pub defenses: DefenseToggles,

    pub allow: RwLock<Vec<IpNet>>,
    pub deny: RwLock<Vec<IpNet>>,
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

#[derive(Debug)]
pub struct DefenseToggles {
    pub bot_score: AtomicBool,
    pub behavior:  AtomicBool,
    pub ddos:      AtomicBool,
    pub honeypots: AtomicBool,
    pub subnet:    AtomicBool,
    pub replay:    AtomicBool,
    pub dist_ua:   AtomicBool,
    /// Reverse-DNS verified good-bot whitelist (Googlebot, Bingbot, …).
    pub goodbot:   AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UamLevel {
    Off     = 0,
    Low     = 1,
    Medium  = 2,
    High    = 3,
    Extreme = 4,
}
impl UamLevel {
    pub fn from_u8(n: u8) -> Self {
        match n { 1 => Self::Low, 2 => Self::Medium, 3 => Self::High, 4 => Self::Extreme, _ => Self::Off }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChallengeMode { Pow = 0, Interactive = 1, Combined = 2 }
impl ChallengeMode {
    pub fn from_u8(n: u8) -> Self {
        match n { 1 => Self::Interactive, 2 => Self::Combined, _ => Self::Pow }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PersistedRuntime {
    #[serde(default)] pub under_attack: bool,
    #[serde(default)] pub uam_level: Option<u8>,
    #[serde(default)] pub challenge_mode: Option<u8>,
    #[serde(default)] pub auto_uam_enabled: Option<bool>,
    #[serde(default)] pub auto_uam_threshold: Option<u32>,
    #[serde(default)] pub challenge_threshold: Option<u32>,
    #[serde(default)] pub block_threshold: Option<u32>,
    #[serde(default)] pub max_concurrent_per_ip: Option<u32>,
    #[serde(default)] pub rpm_under_attack_bps: Option<u32>,
    #[serde(default)] pub subnet_rpm:  Option<u32>,
    #[serde(default)] pub subnet_conn: Option<u32>,
    #[serde(default)] pub global_inflight_cap: Option<u32>,
    #[serde(default)] pub tarpit_score:        Option<u32>,
    #[serde(default)] pub datacenter_block:    Option<bool>,
    #[serde(default)] pub allow: Vec<String>,
    #[serde(default)] pub deny: Vec<String>,
    #[serde(default)] pub blocked_countries: Vec<String>,
    #[serde(default)] pub rules: PersistedToggles,
    #[serde(default)] pub defenses: PersistedDefenses,
    #[serde(default)] pub honeypot_paths: Option<Vec<String>>,
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

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PersistedDefenses {
    #[serde(default)] pub bot_score: Option<bool>,
    #[serde(default)] pub behavior:  Option<bool>,
    #[serde(default)] pub ddos:      Option<bool>,
    #[serde(default)] pub honeypots: Option<bool>,
    #[serde(default)] pub subnet:    Option<bool>,
    #[serde(default)] pub replay:    Option<bool>,
    #[serde(default)] pub dist_ua:   Option<bool>,
    #[serde(default)] pub goodbot:   Option<bool>,
}

impl Runtime {
    pub fn from_config(cfg: &crate::Config) -> Self {
        Self {
            under_attack: AtomicBool::new(false),
            uam_level: AtomicU8::new(0),
            challenge_mode: AtomicU8::new(0),
            auto_uam_enabled: AtomicBool::new(false),
            auto_uam_threshold: AtomicU32::new(50), // blocks/sec
            challenge_threshold: AtomicU32::new(cfg.detection.challenge_threshold),
            block_threshold: AtomicU32::new(cfg.detection.block_threshold),
            max_concurrent_per_ip: AtomicU32::new(200),
            rpm_under_attack_bps: AtomicU32::new(2000),
            rules: RuleToggles {
                sqli: AtomicBool::new(cfg.detection.sqli),
                xss: AtomicBool::new(cfg.detection.xss),
                traversal: AtomicBool::new(cfg.detection.traversal),
                cmdi: AtomicBool::new(cfg.detection.cmdi),
                lfi: AtomicBool::new(cfg.detection.lfi),
                bot_ua: AtomicBool::new(true),
                rate_limit: AtomicBool::new(cfg.rate_limit.enabled),
            },
            defenses: DefenseToggles {
                bot_score: AtomicBool::new(true),
                behavior:  AtomicBool::new(true),
                ddos:      AtomicBool::new(true),
                honeypots: AtomicBool::new(true),
                subnet:    AtomicBool::new(true),
                replay:    AtomicBool::new(true),
                dist_ua:   AtomicBool::new(true),
                goodbot:   AtomicBool::new(true),
            },
            subnet_rpm:  AtomicU32::new(2400),
            subnet_conn: AtomicU32::new(800),
            global_inflight_cap: AtomicU32::new(20_000),
            tarpit_score:        AtomicU32::new(150),
            datacenter_block:    AtomicBool::new(false),
            allow: RwLock::new(Vec::new()),
            deny: RwLock::new(Vec::new()),
            blocked_countries: RwLock::new(cfg.geoip.block_countries.clone()),
            auth_token: RwLock::new(generate_token()),
            persist_path: RwLock::new(None),
        }
    }

    pub fn uam(&self) -> UamLevel { UamLevel::from_u8(self.uam_level.load(Ordering::Relaxed)) }
    pub fn challenge_mode_v(&self) -> ChallengeMode {
        ChallengeMode::from_u8(self.challenge_mode.load(Ordering::Relaxed))
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
        if let Some(v) = p.uam_level          { self.uam_level.store(v.min(4), Ordering::Relaxed); }
        if let Some(v) = p.challenge_mode     { self.challenge_mode.store(v.min(2), Ordering::Relaxed); }
        if let Some(v) = p.auto_uam_enabled   { self.auto_uam_enabled.store(v, Ordering::Relaxed); }
        if let Some(v) = p.auto_uam_threshold { self.auto_uam_threshold.store(v, Ordering::Relaxed); }
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
        if let Some(v) = p.defenses.bot_score { self.defenses.bot_score.store(v, Ordering::Relaxed); }
        if let Some(v) = p.defenses.behavior  { self.defenses.behavior.store(v, Ordering::Relaxed); }
        if let Some(v) = p.defenses.ddos      { self.defenses.ddos.store(v, Ordering::Relaxed); }
        if let Some(v) = p.defenses.honeypots { self.defenses.honeypots.store(v, Ordering::Relaxed); }
        if let Some(v) = p.defenses.subnet    { self.defenses.subnet.store(v, Ordering::Relaxed); }
        if let Some(v) = p.defenses.replay    { self.defenses.replay.store(v, Ordering::Relaxed); }
        if let Some(v) = p.defenses.dist_ua   { self.defenses.dist_ua.store(v, Ordering::Relaxed); }
        if let Some(v) = p.defenses.goodbot   { self.defenses.goodbot.store(v, Ordering::Relaxed); }
        if let Some(v) = p.subnet_rpm  { self.subnet_rpm.store(v, Ordering::Relaxed); }
        if let Some(v) = p.subnet_conn { self.subnet_conn.store(v, Ordering::Relaxed); }
        if let Some(v) = p.global_inflight_cap { self.global_inflight_cap.store(v, Ordering::Relaxed); }
        if let Some(v) = p.tarpit_score        { self.tarpit_score.store(v, Ordering::Relaxed); }
        if let Some(v) = p.datacenter_block    { self.datacenter_block.store(v, Ordering::Relaxed); }

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
            uam_level: Some(self.uam_level.load(Ordering::Relaxed)),
            challenge_mode: Some(self.challenge_mode.load(Ordering::Relaxed)),
            auto_uam_enabled: Some(self.auto_uam_enabled.load(Ordering::Relaxed)),
            auto_uam_threshold: Some(self.auto_uam_threshold.load(Ordering::Relaxed)),
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
            defenses: PersistedDefenses {
                bot_score: Some(self.defenses.bot_score.load(Ordering::Relaxed)),
                behavior:  Some(self.defenses.behavior.load(Ordering::Relaxed)),
                ddos:      Some(self.defenses.ddos.load(Ordering::Relaxed)),
                honeypots: Some(self.defenses.honeypots.load(Ordering::Relaxed)),
                subnet:    Some(self.defenses.subnet.load(Ordering::Relaxed)),
                replay:    Some(self.defenses.replay.load(Ordering::Relaxed)),
                dist_ua:   Some(self.defenses.dist_ua.load(Ordering::Relaxed)),
                goodbot:   Some(self.defenses.goodbot.load(Ordering::Relaxed)),
            },
            subnet_rpm:  Some(self.subnet_rpm.load(Ordering::Relaxed)),
            subnet_conn: Some(self.subnet_conn.load(Ordering::Relaxed)),
            global_inflight_cap: Some(self.global_inflight_cap.load(Ordering::Relaxed)),
            tarpit_score:        Some(self.tarpit_score.load(Ordering::Relaxed)),
            datacenter_block:    Some(self.datacenter_block.load(Ordering::Relaxed)),
            honeypot_paths: None, // filled in by Engine which owns the Honeypots store
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
