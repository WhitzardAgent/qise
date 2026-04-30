//! Tauri IPC commands — called from the React frontend.

use serde::Serialize;
use tauri::State;

use crate::SharedState;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AppStatus {
    protection_enabled: bool,
    proxy_port: u16,
    bridge_port: u16,
    blocked_count: u64,
    warning_count: u64,
    slm_status: String,       // "local" / "cloud" / "unavailable"
    slm_latency_ms: u64,      // most recent SLM call latency
}

#[derive(Serialize, Clone)]
pub struct SecurityEvent {
    timestamp: String,
    guard_name: String,
    verdict: String,
    message: String,
}

#[derive(Serialize)]
pub struct GuardInfo {
    name: String,
    mode: String,
    pipeline: String,
    primary_strategy: String,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn toggle_protection(
    enable: bool,
    state: State<'_, SharedState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    if enable {
        // --- Enable: start bridge, then proxy ---
        let (bridge_port, proxy_port, config_path, upstream_url, upstream_api_key) = {
            let s = state.lock().await;
            (
                s.bridge_port,
                s.proxy_port,
                s.config_path.clone(),
                s.upstream_url.clone(),
                s.upstream_api_key.clone(),
            )
        };

        // Use a default config path if not set
        let config = if config_path.is_empty() {
            let home = dirs_home()?;
            format!("{}/.qise/shield.yaml", home)
        } else {
            config_path
        };

        // Start Bridge first
        let bridge_handle = crate::bridge::start_bridge(bridge_port, &config).await?;

        // Start Proxy (depends on bridge being up)
        let bridge_url = format!("http://127.0.0.1:{}", bridge_port);
        let proxy_handle = crate::proxy::start_proxy(
            bridge_url,
            upstream_url,
            upstream_api_key,
            proxy_port,
            app.clone(),
        ).await?;

        let mut s = state.lock().await;
        s.protection_enabled = true;
        s.proxy_handle = Some(proxy_handle);
        s.bridge_handle = Some(bridge_handle);
        tracing::info!("Protection enabled — proxy on {}, bridge on {}", proxy_port, bridge_port);

        // Update tray menu text
        crate::tray::update_tray_menu(&app, true);
    } else {
        // --- Disable: stop proxy, then bridge ---
        let mut s = state.lock().await;

        if let Some(handle) = s.proxy_handle.take() {
            crate::proxy::stop_proxy(handle).await?;
        }

        if let Some(handle) = s.bridge_handle.take() {
            crate::bridge::stop_bridge(handle).await?;
        }

        s.protection_enabled = false;
        tracing::info!("Protection disabled — proxy + bridge stopped");

        // Update tray menu text
        crate::tray::update_tray_menu(&app, false);
    }

    Ok(())
}

#[tauri::command]
pub async fn get_status(state: State<'_, SharedState>) -> Result<AppStatus, String> {
    let s = state.lock().await;

    // Try to get SLM status from Bridge health endpoint
    let (slm_status, slm_latency_ms) = if s.protection_enabled {
        if let Some(ref _bridge_handle) = s.bridge_handle {
            let bridge_url = format!("http://127.0.0.1:{}", s.bridge_port);
            let client = crate::guard_client::GuardClient::new(&bridge_url, 3);
            if let Ok(data) = client.health_detail().await {
                let mode = data.get("slm_mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unavailable")
                    .to_string();
                let lat = data.get("slm_latency_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                (mode, lat)
            } else {
                ("unavailable".to_string(), 0)
            }
        } else {
            ("unavailable".to_string(), 0)
        }
    } else {
        ("unavailable".to_string(), 0)
    };

    Ok(AppStatus {
        protection_enabled: s.protection_enabled,
        proxy_port: s.proxy_port,
        bridge_port: s.bridge_port,
        blocked_count: s.blocked_count,
        warning_count: s.warning_count,
        slm_status,
        slm_latency_ms,
    })
}

#[tauri::command]
pub async fn get_events(
    limit: usize,
    state: State<'_, SharedState>,
) -> Result<Vec<SecurityEvent>, String> {
    let s = state.lock().await;

    // If bridge is running, try to get events from it
    if s.protection_enabled {
        if let Some(ref _bridge_handle) = s.bridge_handle {
            let bridge_url = format!("http://127.0.0.1:{}", s.bridge_port);
            let client = crate::guard_client::GuardClient::new(&bridge_url, 5);
            if let Ok(events) = client.get_events(limit).await {
                return Ok(events
                    .into_iter()
                    .filter_map(|v| {
                        Some(SecurityEvent {
                            timestamp: v.get("timestamp")?.as_str()?.to_string(),
                            guard_name: v.get("guard_name")?.as_str()?.to_string(),
                            verdict: v.get("verdict")?.as_str()?.to_string(),
                            message: v.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string(),
                        })
                    })
                    .collect());
            }
        }
    }

    Ok(vec![])
}

#[tauri::command]
pub async fn get_guards(state: State<'_, SharedState>) -> Result<Vec<GuardInfo>, String> {
    let s = state.lock().await;

    // If bridge is running, try to get guards from it
    if s.protection_enabled {
        if let Some(ref _bridge_handle) = s.bridge_handle {
            let bridge_url = format!("http://127.0.0.1:{}", s.bridge_port);
            let client = crate::guard_client::GuardClient::new(&bridge_url, 5);
            if let Ok(guards) = client.get_guards().await {
                return Ok(guards
                    .into_iter()
                    .filter_map(|v| {
                        Some(GuardInfo {
                            name: v.get("name")?.as_str()?.to_string(),
                            mode: v.get("mode").and_then(|m| m.as_str()).unwrap_or("observe").to_string(),
                            pipeline: v.get("pipeline").and_then(|p| p.as_str()).unwrap_or("").to_string(),
                            primary_strategy: v.get("primary_strategy").and_then(|p| p.as_str()).unwrap_or("rules").to_string(),
                        })
                    })
                    .collect());
            }
        }
    }

    // Fallback: hardcoded guard list (when bridge is not running)
    Ok(vec![
        GuardInfo { name: "prompt".into(), mode: "observe".into(), pipeline: "ingress".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "command".into(), mode: "enforce".into(), pipeline: "egress".into(), primary_strategy: "rules".into() },
        GuardInfo { name: "filesystem".into(), mode: "enforce".into(), pipeline: "egress".into(), primary_strategy: "rules".into() },
        GuardInfo { name: "network".into(), mode: "enforce".into(), pipeline: "egress".into(), primary_strategy: "rules".into() },
        GuardInfo { name: "credential".into(), mode: "enforce".into(), pipeline: "output".into(), primary_strategy: "rules".into() },
        GuardInfo { name: "exfil".into(), mode: "observe".into(), pipeline: "egress".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "reasoning".into(), mode: "observe".into(), pipeline: "egress".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "tool_sanity".into(), mode: "observe".into(), pipeline: "ingress".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "context".into(), mode: "observe".into(), pipeline: "ingress".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "supply_chain".into(), mode: "observe".into(), pipeline: "ingress".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "resource".into(), mode: "enforce".into(), pipeline: "egress".into(), primary_strategy: "rules".into() },
        GuardInfo { name: "audit".into(), mode: "observe".into(), pipeline: "output".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "output".into(), mode: "observe".into(), pipeline: "output".into(), primary_strategy: "ai".into() },
        GuardInfo { name: "tool_policy".into(), mode: "enforce".into(), pipeline: "egress".into(), primary_strategy: "rules".into() },
    ])
}

#[tauri::command]
pub async fn set_guard_mode(
    guard_name: String,
    mode: String,
    state: State<'_, SharedState>,
) -> Result<(), String> {
    let s = state.lock().await;

    // If bridge is running, forward mode change
    if s.protection_enabled {
        if let Some(ref _bridge_handle) = s.bridge_handle {
            let bridge_url = format!("http://127.0.0.1:{}", s.bridge_port);
            let client = crate::guard_client::GuardClient::new(&bridge_url, 5);
            return client.set_guard_mode(&guard_name, &mode).await;
        }
    }

    tracing::info!("Setting guard '{}' to mode '{}' (bridge not running, no-op)", guard_name, mode);
    Ok(())
}

/// Get the user's home directory.
fn dirs_home() -> Result<String, String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "Cannot determine home directory".into())
}

// ---------------------------------------------------------------------------
// Takeover Commands
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AgentInfoResponse {
    pub agent_type: String,
    pub display_name: String,
    pub installed: bool,
    pub taken_over: bool,
}

#[tauri::command]
pub async fn detect_agents(state: State<'_, SharedState>) -> Result<Vec<AgentInfoResponse>, String> {
    let s = state.lock().await;
    let agents = s.takeover_manager.detect_agents();
    Ok(agents
        .into_iter()
        .map(|a| AgentInfoResponse {
            agent_type: a.agent_type,
            display_name: a.display_name,
            installed: a.installed,
            taken_over: a.taken_over,
        })
        .collect())
}

#[tauri::command]
pub async fn takeover_agent(
    agent: String,
    state: State<'_, SharedState>,
) -> Result<(), String> {
    let mut s = state.lock().await;
    let agent_type = parse_agent_type_str(&agent)?;
    s.takeover_manager.takeover(&agent_type)?;
    Ok(())
}

#[tauri::command]
pub async fn restore_agent(
    agent: String,
    state: State<'_, SharedState>,
) -> Result<(), String> {
    let mut s = state.lock().await;
    let agent_type = parse_agent_type_str(&agent)?;
    s.takeover_manager.restore(&agent_type)?;
    Ok(())
}

#[tauri::command]
pub async fn get_takeover_status(
    state: State<'_, SharedState>,
) -> Result<Vec<crate::takeover::TakeoverState>, String> {
    let s = state.lock().await;
    Ok(s.takeover_manager.get_takeover_status())
}

/// Parse agent type string.
fn parse_agent_type_str(s: &str) -> Result<crate::takeover::AgentType, String> {
    match s {
        "GenericOpenAI" | "generic_openai" => Ok(crate::takeover::AgentType::GenericOpenAI),
        "ClaudeCode" | "claude_code" => Ok(crate::takeover::AgentType::ClaudeCode),
        _ => Err(format!("Unknown agent type: {}", s)),
    }
}

// ---------------------------------------------------------------------------
// Config Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_config(state: State<'_, SharedState>) -> Result<serde_json::Value, String> {
    let s = state.lock().await;
    let config_path = if s.config_path.is_empty() {
        let home = dirs_home()?;
        format!("{}/.qise/shield.yaml", home)
    } else {
        s.config_path.clone()
    };

    // Try to read shield.yaml
    match std::fs::read_to_string(&config_path) {
        Ok(content) => {
            match serde_yaml::from_str::<serde_json::Value>(&content) {
                Ok(val) => Ok(val),
                Err(e) => Err(format!("Failed to parse shield.yaml: {}", e)),
            }
        }
        Err(_) => {
            // File doesn't exist — return default config
            Ok(serde_json::json!({
                "version": "1.0",
                "integration": {
                    "mode": "proxy",
                    "proxy": {
                        "port": 8822,
                        "target_agents": ["claude_code"],
                        "auto_takeover": true,
                        "crash_recovery": true,
                    }
                },
                "models": {
                    "slm": {
                        "base_url": "http://localhost:11434/v1",
                        "model": "qwen3:4b",
                        "timeout_ms": 5000,
                    },
                    "llm": {
                        "base_url": "",
                        "model": "",
                        "timeout_ms": 5000,
                    },
                },
                "guards": {
                    "enabled": [
                        "prompt", "command", "credential", "reasoning",
                        "filesystem", "network", "exfil", "resource", "audit",
                        "tool_sanity", "context", "output", "tool_policy", "supply_chain",
                    ],
                    "config": {},
                },
            }))
        }
    }
}

#[tauri::command]
pub async fn save_config(
    config: serde_json::Value,
    state: State<'_, SharedState>,
) -> Result<(), String> {
    let s = state.lock().await;
    let config_path = if s.config_path.is_empty() {
        let home = dirs_home()?;
        let dir = format!("{}/.qise", home);
        let _ = std::fs::create_dir_all(&dir);
        format!("{}/shield.yaml", dir)
    } else {
        s.config_path.clone()
    };
    drop(s);

    // Convert JSON to YAML and write
    let yaml_str = serde_yaml::to_string(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    // Atomic write: write to temp file then rename
    let temp_path = format!("{}.tmp", config_path);
    std::fs::write(&temp_path, &yaml_str)
        .map_err(|e| format!("Failed to write config: {}", e))?;
    std::fs::rename(&temp_path, &config_path)
        .map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            format!("Failed to rename config file: {}", e)
        })?;

    tracing::info!("Config saved to {}", config_path);
    Ok(())
}

#[tauri::command]
pub async fn get_default_config() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "version": "1.0",
        "integration": {
            "mode": "proxy",
            "proxy": {
                "port": 8822,
                "target_agents": ["claude_code"],
                "auto_takeover": true,
                "crash_recovery": true,
            }
        },
        "models": {
            "slm": {
                "base_url": "http://localhost:11434/v1",
                "model": "qwen3:4b",
                "timeout_ms": 5000,
            },
            "llm": {
                "base_url": "",
                "model": "",
                "timeout_ms": 5000,
            },
        },
        "guards": {
            "enabled": [
                "prompt", "command", "credential", "reasoning",
                "filesystem", "network", "exfil", "resource", "audit",
                "tool_sanity", "context", "output", "tool_policy", "supply_chain",
            ],
            "config": {},
        },
    }))
}
