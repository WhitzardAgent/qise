//! GuardClient — HTTP client for calling the Python Bridge.

use reqwest::Client;
use std::time::Duration;

/// HTTP client for the Python Bridge management API.
#[derive(Clone)]
pub struct GuardClient {
    base_url: String,
    client: Client,
    timeout: Duration,
}

impl GuardClient {
    /// Create a new GuardClient pointing at the given bridge URL.
    pub fn new(bridge_url: &str, bridge_timeout_s: u64) -> Self {
        Self {
            base_url: bridge_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            timeout: Duration::from_secs(bridge_timeout_s),
        }
    }

    /// Get the list of guards from the Bridge.
    pub async fn get_guards(&self) -> Result<Vec<serde_json::Value>, String> {
        let url = format!("{}/v1/bridge/guards", self.base_url);
        match self.client.get(&url).timeout(self.timeout).send().await {
            Ok(resp) if resp.status().is_success() => resp
                .json::<Vec<serde_json::Value>>()
                .await
                .map_err(|e| format!("Parse error: {}", e)),
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
        match self
            .client
            .post(&url)
            .timeout(self.timeout)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(format!("Bridge returned status {}", resp.status())),
            Err(e) => Err(format!("Bridge request failed: {}", e)),
        }
    }
}
