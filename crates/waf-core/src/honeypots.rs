//! Honeypot path detector. Any request to one of these paths is by definition
//! malicious — legitimate browsers never request `.env`, `wp-config.php`, etc.
//! On a hit the engine instantly blocks AND records an offence so the IP
//! gets auto-banned for the full ban duration.

use crate::decision::DecisionReason;
use parking_lot::RwLock;

const W_HONEYPOT: u32 = 100;

/// Default trap list, drawn from the most common scanner / vuln-checker
/// payloads observed on public hosts. The operator can rewrite this set
/// from the dashboard.
pub const DEFAULT_TRAPS: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.dev",
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.gitignore",
    "/.svn/wc.db",
    "/.hg/store",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/.ssh/authorized_keys",
    "/.dockerignore",
    "/.docker/config.json",
    "/.npmrc",
    "/.bash_history",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.bak",
    "/wp-config.txt",
    "/wp-admin/setup-config.php",
    "/wp-admin/install.php",
    "/wp-content/debug.log",
    "/xmlrpc.php",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/phpmyadmin/",
    "/pma/",
    "/myadmin/",
    "/server-status",
    "/server-info",
    "/console",
    "/manager/html",
    "/manager/status",
    "/admin.php",
    "/setup.php",
    "/.well-known/security.txt.bak",
    "/cgi-bin/luci",
    "/cgi-bin/php-cgi",
    "/HNAP1/",
    "/Autodiscover/Autodiscover.xml",
    "/owa/auth/logon.aspx",
    "/ews/exchange.asmx",
    "/boaform/admin/formLogin",
    "/cgi-bin/.%2e/",
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/prometheus",
    "/api/v1/cluster/info",
    "/druid/indexer/v1/sampler",
    "/struts2-rest-showcase/orders/3",
    "/_ignition/execute-solution",
];

pub struct Honeypots {
    paths: RwLock<Vec<String>>,
}

impl Default for Honeypots {
    fn default() -> Self {
        Self::new(DEFAULT_TRAPS.iter().map(|s| s.to_string()).collect())
    }
}

impl Honeypots {
    pub fn new(paths: Vec<String>) -> Self {
        Self { paths: RwLock::new(paths) }
    }
    pub fn replace(&self, paths: Vec<String>) {
        *self.paths.write() = paths;
    }
    pub fn snapshot(&self) -> Vec<String> {
        self.paths.read().clone()
    }
    pub fn is_trap(&self, path: &str) -> bool {
        let g = self.paths.read();
        g.iter().any(|p| {
            if p.ends_with('/') { path.starts_with(p.as_str()) }
            else                { path == p.as_str() || path.starts_with(&format!("{}?", p)) }
        })
    }
    pub fn check(&self, path: &str) -> Option<DecisionReason> {
        if self.is_trap(path) {
            Some(DecisionReason {
                rule_id: "HONEYPOT", category: "honeypot",
                score: W_HONEYPOT,
                detail: format!("trap path {}", path.chars().take(64).collect::<String>()),
            })
        } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_default_trap() {
        let h = Honeypots::default();
        assert!(h.is_trap("/.env"));
        assert!(h.is_trap("/wp-config.php"));
        assert!(h.is_trap("/phpmyadmin/index.php"));
        assert!(!h.is_trap("/index.html"));
        assert!(!h.is_trap("/api/users"));
    }
}
