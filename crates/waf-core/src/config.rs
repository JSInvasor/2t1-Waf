//! Configuration loaded from `waf.toml` at startup (and on SIGHUP).

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerCfg,
    pub upstream: UpstreamCfg,
    pub limits: LimitsCfg,
    pub rate_limit: RateLimitCfg,
    pub reputation: ReputationCfg,
    #[serde(default)]
    pub geoip: GeoIpCfg,
    pub detection: DetectionCfg,
    pub challenge: ChallengeCfg,
    #[serde(default)]
    pub logging: LoggingCfg,
    #[serde(default)]
    pub admin: AdminCfg,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerCfg {
    pub listen: String,
    #[serde(default)]
    pub threads: usize,
    #[serde(default)]
    pub trusted_proxy_hops: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamCfg {
    pub address: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_ms: u64,
}

fn default_connect_timeout() -> u64 { 2000 }
fn default_read_timeout() -> u64 { 30_000 }

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsCfg {
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default = "default_max_header_value")]
    pub max_header_value_bytes: usize,
    #[serde(default = "default_max_uri")]
    pub max_uri_bytes: usize,
    #[serde(default = "default_methods")]
    pub allowed_methods: Vec<String>,
}

fn default_max_body() -> usize { 1024 * 1024 }
fn default_max_headers() -> usize { 100 }
fn default_max_header_value() -> usize { 8192 }
fn default_max_uri() -> usize { 8192 }
fn default_methods() -> Vec<String> {
    ["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]
        .iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub requests_per_minute: u32,
    #[serde(default)]
    pub burst: u32,
    #[serde(default)]
    pub routes: Vec<RouteRateLimit>,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Deserialize)]
pub struct RouteRateLimit {
    pub pattern: String,
    pub requests_per_minute: u32,
    #[serde(default)]
    pub burst: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReputationCfg {
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    #[serde(default = "default_auto_ban_hits")]
    pub auto_ban_threshold_hits: u32,
    #[serde(default = "default_auto_ban_window")]
    pub auto_ban_window_secs: u64,
    #[serde(default = "default_auto_ban_duration")]
    pub auto_ban_duration_secs: u64,
}

fn default_auto_ban_hits() -> u32 { 5 }
fn default_auto_ban_window() -> u64 { 60 }
fn default_auto_ban_duration() -> u64 { 3600 }

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GeoIpCfg {
    #[serde(default)]
    pub mmdb_path: String,
    #[serde(default)]
    pub block_countries: Vec<String>,
    #[serde(default)]
    pub suspicious_countries: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectionCfg {
    #[serde(default = "default_challenge_threshold")]
    pub challenge_threshold: u32,
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u32,
    #[serde(default = "default_true")]
    pub sqli: bool,
    #[serde(default = "default_true")]
    pub xss: bool,
    #[serde(default = "default_true")]
    pub traversal: bool,
    #[serde(default = "default_true")]
    pub cmdi: bool,
    #[serde(default = "default_true")]
    pub lfi: bool,
    #[serde(default)]
    pub suspicious_user_agents: Vec<String>,
}

fn default_challenge_threshold() -> u32 { 40 }
fn default_block_threshold() -> u32 { 70 }

#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeCfg {
    pub hmac_secret: String,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_cookie_ttl")]
    pub cookie_ttl_secs: u64,
    #[serde(default = "default_pow_difficulty")]
    pub pow_difficulty: u8,
}

fn default_cookie_name() -> String { "__2t1_clearance".to_string() }
fn default_cookie_ttl() -> u64 { 1800 }
fn default_pow_difficulty() -> u8 { 4 }

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingCfg {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingCfg {
    fn default() -> Self {
        Self { format: default_log_format(), level: default_log_level() }
    }
}

fn default_log_format() -> String { "json".to_string() }
fn default_log_level() -> String { "info".to_string() }

#[derive(Debug, Clone, Deserialize)]
pub struct AdminCfg {
    #[serde(default = "default_admin_listen")]
    pub listen: String,
}

impl Default for AdminCfg {
    fn default() -> Self { Self { listen: default_admin_listen() } }
}

fn default_admin_listen() -> String { "127.0.0.1:9090".to_string() }

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.challenge.hmac_secret.len() < 16 {
            anyhow::bail!("challenge.hmac_secret must be at least 16 bytes");
        }
        if self.detection.challenge_threshold >= self.detection.block_threshold {
            anyhow::bail!(
                "detection.challenge_threshold ({}) must be < block_threshold ({})",
                self.detection.challenge_threshold, self.detection.block_threshold
            );
        }
        Ok(())
    }
}
