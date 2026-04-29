//! 2t1-Waf Pingora binary. Wires `waf-core` into Pingora's proxy pipeline.

mod proxy;
mod redirect;
mod admin;

use std::path::PathBuf;
use std::sync::Arc;

use pingora_core::server::configuration::ServerConf;
use pingora_core::server::Server;
use pingora_proxy::http_proxy_service;
use waf_core::{Config, Engine};

fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg_path = std::env::args().nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/waf.toml"));
    tracing::info!(path = %cfg_path.display(), "loading config");
    let cfg = Config::load(&cfg_path)?;

    let listen = cfg.server.listen.clone();
    let listen_tls = cfg.server.listen_tls.clone();
    let tls_cert = cfg.server.tls_cert.clone();
    let tls_key  = cfg.server.tls_key.clone();
    let redirect_port = cfg.server.redirect_to_https_port;
    let admin_listen = cfg.admin.listen.clone();
    let runtime_state_path = cfg.admin.runtime_state_path.clone();
    let threads = if cfg.server.threads == 0 { num_cpus() } else { cfg.server.threads };
    let upstream = cfg.upstream.clone();

    let engine = Engine::build(cfg)?;

    // Persist runtime overrides if a path is configured.
    if !runtime_state_path.is_empty() {
        let path = PathBuf::from(&runtime_state_path);
        if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
        if let Err(e) = engine.runtime.bind_persist_file(path.clone()) {
            tracing::error!(%e, "failed to load runtime state");
        }
        // Persist auto-bans alongside runtime state so they survive restarts.
        let bans_path = path.with_file_name("bans.json");
        if let Err(e) = engine.reputations.bind_persist_file(bans_path) {
            tracing::error!(%e, "failed to load persisted bans");
        }
    }

    let mut server_conf = ServerConf::default();
    server_conf.threads = threads;
    let mut server = Server::new_with_opt_and_conf(None, server_conf);
    server.bootstrap();

    // Plain HTTP listener: either WAF or 301-redirect to HTTPS.
    if !listen.is_empty() {
        if redirect_port > 0 && !listen_tls.is_empty() {
            let svc = redirect::HttpsRedirect::new(redirect_port);
            let mut s = http_proxy_service(&server.configuration, svc);
            s.add_tcp(&listen);
            server.add_service(s);
            tracing::info!(%listen, redirect_port, "http listener up (redirecting)");
        } else {
            let svc = proxy::WafProxy::new(engine.clone(), upstream.clone());
            let mut s = http_proxy_service(&server.configuration, svc);
            s.add_tcp(&listen);
            server.add_service(s);
            tracing::info!(%listen, "http listener up");
        }
    }

    // HTTPS listener.
    if !listen_tls.is_empty() {
        let svc = proxy::WafProxy::new(engine.clone(), upstream);
        let mut s = http_proxy_service(&server.configuration, svc);
        s.add_tls(&listen_tls, &tls_cert, &tls_key)
            .map_err(|e| anyhow::anyhow!("add_tls({listen_tls}): {e}"))?;
        server.add_service(s);
        tracing::info!(%listen_tls, "https listener up");
    }

    // Local admin / metrics service for the dashboard.
    server.add_service(admin::admin_service(engine.clone(), admin_listen.clone()));

    // Auto-UAM watchdog: monitors block rate and escalates / de-escalates the
    // UAM level on its own when enabled.
    server.add_service(admin::auto_uam_service(engine.clone()));

    tracing::info!(%admin_listen, token = %engine.runtime.auth_token.read(), "admin token (use as Bearer)");

    tracing::info!(threads, "2t1-waf running");
    server.run_forever();
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,pingora_core=warn,pingora_proxy=warn"));
    let _ = fmt().with_env_filter(filter).json().try_init();
    let _ = Arc::new(()); // keep std::sync::Arc imported for downstream
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2)
}
