//! Static CIDR allow/deny lists + dynamic auto-ban for IPs that repeatedly
//! trip detection rules. The auto-ban is in-process; persistent state belongs
//! in a separate store (Redis, sled) and can be added later.

use crate::config::ReputationCfg;
use dashmap::DashMap;
use ipnet::IpNet;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reputation {
    Allow,
    Deny,
    Unknown,
}

pub struct Reputations {
    allow: Vec<IpNet>,
    deny:  Vec<IpNet>,
    auto_ban_threshold: u32,
    window_secs: u64,
    duration_secs: u64,
    /// IP → (hit_count, first_hit_secs, ban_until_secs)
    state: DashMap<IpAddr, Mutex<HitState>>,
    persist_path: parking_lot::RwLock<Option<PathBuf>>,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
struct HitState {
    hits: u32,
    first_hit: u64,
    ban_until: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedBan {
    ip: IpAddr,
    ban_until: u64,
    hits: u32,
}

impl Reputations {
    pub fn new(cfg: &ReputationCfg) -> anyhow::Result<Self> {
        let allow = cfg.allow_cidrs.iter().map(|s| parse_net(s, "allow")).collect::<anyhow::Result<Vec<_>>>()?;
        let deny  = cfg.deny_cidrs.iter().map(|s| parse_net(s, "deny")).collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            allow, deny,
            auto_ban_threshold: cfg.auto_ban_threshold_hits,
            window_secs: cfg.auto_ban_window_secs,
            duration_secs: cfg.auto_ban_duration_secs,
            state: DashMap::with_capacity(4096),
            persist_path: parking_lot::RwLock::new(None),
        })
    }

    /// Bind a path that will receive ban dumps (one JSON line per ban).
    /// Existing bans are reloaded immediately.
    pub fn bind_persist_file(&self, path: PathBuf) -> anyhow::Result<()> {
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let bans: Vec<PersistedBan> = serde_json::from_str(&raw).unwrap_or_default();
            let now = now_secs();
            for b in bans {
                if b.ban_until > now {
                    self.state.insert(b.ip, Mutex::new(HitState {
                        hits: b.hits, first_hit: now, ban_until: b.ban_until,
                    }));
                }
            }
        }
        *self.persist_path.write() = Some(path);
        Ok(())
    }

    pub fn persist(&self) -> anyhow::Result<()> {
        let path = match self.persist_path.read().clone() {
            Some(p) => p, None => return Ok(()),
        };
        let now = now_secs();
        let dump: Vec<PersistedBan> = self.state.iter()
            .filter_map(|e| {
                let s = e.value().lock();
                if s.ban_until > now {
                    Some(PersistedBan { ip: *e.key(), ban_until: s.ban_until, hits: s.hits })
                } else { None }
            })
            .collect();
        let json = serde_json::to_vec_pretty(&dump)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn classify(&self, ip: IpAddr) -> Reputation {
        // Allow always wins.
        if self.allow.iter().any(|n| n.contains(&ip)) { return Reputation::Allow; }
        if self.deny.iter().any(|n| n.contains(&ip))  { return Reputation::Deny;  }
        if self.is_banned(ip) { return Reputation::Deny; }
        Reputation::Unknown
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let now = now_secs();
        if let Some(s) = self.state.get(&ip) {
            return s.lock().ban_until > now;
        }
        false
    }

    /// Record one offence and return true if the IP just transitioned to banned.
    pub fn record_offence(&self, ip: IpAddr) -> bool {
        if self.allow.iter().any(|n| n.contains(&ip)) { return false; }
        let now = now_secs();
        let entry = self.state.entry(ip).or_insert_with(|| Mutex::new(HitState::default()));
        let mut s = entry.lock();
        if s.first_hit == 0 || now.saturating_sub(s.first_hit) > self.window_secs {
            s.first_hit = now;
            s.hits = 0;
        }
        s.hits = s.hits.saturating_add(1);
        if s.hits >= self.auto_ban_threshold && s.ban_until <= now {
            s.ban_until = now + self.duration_secs;
            drop(s);
            // Best-effort flush; ignore I/O errors here so the request path
            // never blocks on disk.
            let _ = self.persist();
            return true;
        }
        false
    }

    /// Force an immediate ban for a single offence (used for honeypot hits).
    pub fn force_ban(&self, ip: IpAddr, secs: u64) -> bool {
        if self.allow.iter().any(|n| n.contains(&ip)) { return false; }
        let now = now_secs();
        let entry = self.state.entry(ip).or_insert_with(|| Mutex::new(HitState::default()));
        let mut s = entry.lock();
        let until = now + secs;
        if s.ban_until < until { s.ban_until = until; }
        s.hits = s.hits.saturating_add(self.auto_ban_threshold);
        drop(s);
        let _ = self.persist();
        true
    }

    pub fn unban(&self, ip: IpAddr) {
        if let Some(s) = self.state.get(&ip) {
            let mut s = s.lock();
            s.ban_until = 0;
            s.hits = 0;
        }
    }

    /// Remove expired bans and idle entries. Caller decides cadence.
    pub fn gc(&self) {
        let now = now_secs();
        self.state.retain(|_, v| {
            let s = v.lock();
            // Keep entries that are still banned or had recent activity.
            s.ban_until > now || now.saturating_sub(s.first_hit) < self.window_secs * 2
        });
    }

    /// Snapshot of currently banned IPs for the dashboard.
    pub fn banned(&self) -> Vec<(IpAddr, u64)> {
        let now = now_secs();
        let mut out = Vec::new();
        for entry in self.state.iter() {
            let s = entry.value().lock();
            if s.ban_until > now {
                out.push((*entry.key(), s.ban_until - now));
            }
        }
        out
    }
}

fn parse_net(s: &str, label: &str) -> anyhow::Result<IpNet> {
    // Bare IP → /32 or /128.
    if let Ok(ip) = IpAddr::from_str(s) {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNet::new(ip, prefix).map_err(|e| anyhow::anyhow!("{label} {s}: {e}"));
    }
    s.parse().map_err(|e| anyhow::anyhow!("{label} {s}: {e}"))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_cidr_classifies() {
        let cfg = ReputationCfg {
            allow_cidrs: vec![],
            deny_cidrs: vec!["10.0.0.0/8".into()],
            auto_ban_threshold_hits: 5,
            auto_ban_window_secs: 60,
            auto_ban_duration_secs: 60,
        };
        let r = Reputations::new(&cfg).unwrap();
        assert_eq!(r.classify("10.1.2.3".parse().unwrap()), Reputation::Deny);
        assert_eq!(r.classify("8.8.8.8".parse().unwrap()), Reputation::Unknown);
    }

    #[test]
    fn auto_ban_kicks_in() {
        let cfg = ReputationCfg {
            allow_cidrs: vec![],
            deny_cidrs: vec![],
            auto_ban_threshold_hits: 3,
            auto_ban_window_secs: 60,
            auto_ban_duration_secs: 60,
        };
        let r = Reputations::new(&cfg).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!r.record_offence(ip));
        assert!(!r.record_offence(ip));
        assert!(r.record_offence(ip));
        assert!(r.is_banned(ip));
    }
}
