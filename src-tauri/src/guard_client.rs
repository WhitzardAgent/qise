//! GuardClient — HTTP client for calling the Python Bridge.

use crate::decision::{GuardCheckRequest, GuardCheckResponse};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// HTTP client for the Python Bridge guard check API.
#[derive(Clone)]
pub struct GuardClient {
    base_url: String,
    client: Client,
    timeout: Duration,
    /// Whether the bridge was reachable at last check.
    bridge_available: Arc<std::sync::atomic::AtomicBool>,
}

#[allow(dead_code)]
impl GuardClient {
    /// Create a new GuardClient pointing at the given bridge URL.
    pub fn new(bridge_url: &str, bridge_timeout_s: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(bridge_timeout_s))
            .build()
            .expect("failed to build reqwest client");

        Self {
            base_url: bridge_url.trim_end_matches('/').to_string(),
            client,
            timeout: Duration::from_secs(bridge_timeout_s),
            bridge_available: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Check if the bridge is available via health check (returns bool only).
    pub async fn health_check(&self) -> bool {
        let result = self.health_detail().await;
        result.is_ok()
    }

    /// Check bridge health and return the full JSON response.
    pub async fn health_detail(&self) -> Result<serde_json::Value, String> {
        let url = format!("{}/v1/bridge/health", self.base_url);
        match self.client.get(&url).timeout(Duration::from_secs(5)).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Bridge health check OK");
                self.bridge_available.store(true, std::sync::atomic::Ordering::Relaxed);
                resp.json::<serde_json::Value>().await.map_err(|e| format!("Parse error: {}", e))
            }
            Ok(resp) => {
                warn!("Bridge health check returned status {}", resp.status());
                self.bridge_available.store(false, std::sync::atomic::Ordering::Relaxed);
                Err(format!("Bridge returned status {}", resp.status()))
            }
            Err(e) => {
                warn!("Bridge health check failed: {}", e);
                self.bridge_available.store(false, std::sync::atomic::Ordering::Relaxed);
                Err(format!("Bridge request failed: {}", e))
            }
        }
    }

    /// Whether the bridge was reachable at last health check.
    pub fn is_available(&self) -> bool {
        self.bridge_available.load(std::sync::atomic::Ordering::Relaxed)
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
                            self.bridge_available.store(true, std::sync::atomic::Ordering::Relaxed);
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
                    self.bridge_available.store(false, std::sync::atomic::Ordering::Relaxed);
                    Err(format!("Bridge request failed: {}", e))
                }
            }
        }
    }

    /// Get the list of guards from the Bridge.
    pub async fn get_guards(&self) -> Result<Vec<serde_json::Value>, String> {
        let url = format!("{}/v1/bridge/guards", self.base_url);
        match self.client.get(&url).timeout(self.timeout).send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<Vec<serde_json::Value>>().await.map_err(|e| format!("Parse error: {}", e))
            }
            Ok(resp) => {
                let status = resp.status();
                Err(format!("Bridge returned status {}", status))
            }
            Err(e) => Err(format!("Bridge request failed: {}", e)),
        }
    }

    /// Get recent security events from the Bridge.
    pub async fn get_events(&self, limit: usize) -> Result<Vec<serde_json::Value>, String> {
        let url = format!("{}/v1/bridge/events?limit={}", self.base_url, limit);
        match self.client.get(&url).timeout(self.timeout).send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<Vec<serde_json::Value>>().await.map_err(|e| format!("Parse error: {}", e))
            }
            Ok(resp) => {
                let status = resp.status();
                Err(format!("Bridge returned status {}", status))
            }
            Err(e) => Err(format!("Bridge request failed: {}", e)),
        }
    }

    /// Set a guard's mode via the Bridge.
    pub async fn set_guard_mode(&self, guard_name: &str, mode: &str) -> Result<(), String> {
        let url = format!("{}/v1/bridge/guard/mode", self.base_url);
        let body = serde_json::json!({
            "guard_name": guard_name,
            "mode": mode,
        });
        match self.client.post(&url).timeout(self.timeout).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(format!("Bridge returned status {}", resp.status())),
            Err(e) => Err(format!("Bridge request failed: {}", e)),
        }
    }
}
