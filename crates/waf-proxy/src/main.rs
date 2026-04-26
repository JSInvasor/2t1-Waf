//! 2t1-Waf Pingora binary. Wires `waf-core` into Pingora's proxy pipeline.

mod proxy;
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
    let admin_listen = cfg.admin.listen.clone();
    let threads = if cfg.server.threads == 0 { num_cpus() } else { cfg.server.threads };
    let upstream = cfg.upstream.clone();

    let engine = Engine::build(cfg)?;

    // Bootstrap the Pingora server.
    let mut server_conf = ServerConf::default();
    server_conf.threads = threads;
    let mut server = Server::new_with_opt_and_conf(None, server_conf);
    server.bootstrap();

    // The HTTP proxy service.
    let svc = proxy::WafProxy::new(engine.clone(), upstream);
    let mut http = http_proxy_service(&server.configuration, svc);
    http.add_tcp(&listen);
    server.add_service(http);

    // Local admin / metrics service for the dashboard.
    server.add_service(admin::admin_service(engine.clone(), admin_listen));

    tracing::info!(%listen, threads, "2t1-waf running");
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
