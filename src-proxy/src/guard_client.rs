//! GuardClient — HTTP client for calling the Python Bridge.

use crate::config::ProxyConfig;
use crate::decision::{GuardCheckRequest, GuardCheckResponse};
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// HTTP client for the Python Bridge guard check API.
#[derive(Clone)]
pub struct GuardClient {
    base_url: String,
    client: Client,
    timeout: Duration,
}

impl GuardClient {
    /// Create a new GuardClient from proxy config.
    pub fn new(config: &ProxyConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.bridge_timeout_s))
            .build()
            .expect("failed to build reqwest client");

        Self {
            base_url: config.bridge_url.trim_end_matches('/').to_string(),
            client,
            timeout: Duration::from_secs(config.bridge_timeout_s),
        }
    }

    /// Check if the bridge is available via health check.
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/v1/bridge/health", self.base_url);
        match self.client.get(&url).timeout(Duration::from_secs(5)).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Bridge health check OK");
                true
            }
            Ok(resp) => {
                warn!("Bridge health check returned status {}", resp.status());
                false
            }
            Err(e) => {
                warn!("Bridge health check failed: {}", e);
                false
            }
        }
    }

    /// Send a guard check request to the Python Bridge.
    pub async fn check(&self, request: &GuardCheckRequest) -> Result<GuardCheckResponse, String> {
        let url = format!("{}/v1/guard/check", self.base_url);
        debug!("Sending guard check: type={}", request.r#type);

        match self.client.post(&url).timeout(self.timeout).json(request).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    match resp.json::<GuardCheckResponse>().await {
                        Ok(guard_resp) => {
                            info!(
                                "Guard check response: action={}, warnings={}, block_reason={}",
                                guard_resp.action,
                                guard_resp.warnings.len(),
                                guard_resp.block_reason,
                            );
                            Ok(guard_resp)
                        }
                        Err(e) => {
                            error!("Failed to parse guard check response: {}", e);
                            Err(format!("Parse error: {}", e))
                        }
                    }
                } else {
                    let body = resp.text().await.unwrap_or_else(|_| "(no body)".into());
                    error!("Guard check returned status {}: {}", status, body);
                    Err(format!("Bridge returned status {}: {}", status, body))
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    warn!("Guard check timed out after {:?}", self.timeout);
                    Err("Bridge timeout".into())
                } else {
                    error!("Guard check request failed: {}", e);
                    Err(format!("Bridge request failed: {}", e))
                }
            }
        }
    }
}
