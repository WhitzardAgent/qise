//! Qise Proxy — high-performance HTTP reverse proxy for AI agent security.
//!
//! Intercepts Agent↔LLM traffic, calls Python Bridge for guard analysis,
//! and forwards requests to the upstream LLM API.

mod config;
mod decision;
mod guard_client;
mod parser;
mod proxy;
mod streaming;

use axum::Router;
use axum::routing::any;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qise_proxy=info".into()),
        )
        .init();

    // Load config from environment
    let config = config::ProxyConfig::from_env();
    info!("Qise proxy starting...");
    info!("  Listen: {}:{}", config.listen_host, config.listen_port);
    info!("  Upstream: {}", config.upstream_base_url);
    info!("  Bridge: {}", config.bridge_url);

    // Create shared state
    let state = Arc::new(proxy::AppState::new(config.clone()));

    // Check bridge availability
    let bridge_ok = state.guard_client.health_check().await;
    if !bridge_ok {
        info!("Bridge not available — running in observe-only mode (degrade to pass)");
    }

    // Build axum router — catch-all handler for all paths
    let app = Router::new()
        // Use a wildcard catch-all path
        .route("/{*path}", any(proxy::handle_request))
        .with_state(state);

    // Start server
    let addr = format!("{}:{}", config.listen_host, config.listen_port);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("failed to bind");
    info!("Qise proxy listening on {}", addr);

    axum::serve(listener, app).await.expect("server error");
}
