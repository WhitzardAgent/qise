//! ProxyConfig — reads configuration from environment variables.

use std::env;

/// Proxy server configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Port to listen on.
    pub listen_port: u16,
    /// Host to bind to.
    pub listen_host: String,
    /// Upstream LLM API base URL (e.g. https://api.openai.com/v1).
    pub upstream_base_url: String,
    /// Upstream API key for Authorization header.
    pub upstream_api_key: String,
    /// Python Bridge base URL (e.g. http://127.0.0.1:8823).
    pub bridge_url: String,
    /// Request timeout in seconds.
    pub request_timeout_s: u64,
    /// Bridge request timeout in seconds.
    pub bridge_timeout_s: u64,
    /// Whether to block on guard block decisions.
    pub block_on_guard_block: bool,
    /// Whether to inject security context.
    pub inject_security_context: bool,
    /// Paths to intercept for guard analysis.
    pub intercept_paths: Vec<String>,
    /// Paths to pass through without interception.
    pub passthrough_paths: Vec<String>,
}

impl ProxyConfig {
    /// Load configuration from environment variables with defaults.
    pub fn from_env() -> Self {
        Self {
            listen_port: env::var("QISE_PROXY_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8822),
            listen_host: env::var("QISE_PROXY_HOST")
                .unwrap_or_else(|_| "127.0.0.1".into()),
            upstream_base_url: env::var("QISE_PROXY_UPSTREAM_URL")
                .unwrap_or_else(|_| "".into()),
            upstream_api_key: env::var("QISE_PROXY_UPSTREAM_API_KEY")
                .unwrap_or_else(|_| "".into()),
            bridge_url: env::var("QISE_BRIDGE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8823".into()),
            request_timeout_s: env::var("QISE_PROXY_TIMEOUT_S")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            bridge_timeout_s: env::var("QISE_BRIDGE_TIMEOUT_S")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(35),
            block_on_guard_block: env::var("QISE_BLOCK_ON_GUARD_BLOCK")
                .ok()
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            inject_security_context: env::var("QISE_INJECT_SECURITY_CONTEXT")
                .ok()
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            intercept_paths: vec![
                "/v1/chat/completions".into(),
            ],
            passthrough_paths: vec![
                "/v1/models".into(),
            ],
        }
    }
}
