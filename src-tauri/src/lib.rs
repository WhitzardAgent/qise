//! Qise — AI Agent Security Framework (Tauri 2 Desktop App)
//!
//! Provides system tray, proxy toggle, and guard dashboard.

mod bridge;
mod commands;
mod decision;
mod guard_client;
mod parser;
mod proxy;
mod qise_cli;
mod streaming;
mod tray;

use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;

/// Shared application state.
pub struct AppState {
    /// Whether protection (proxy + bridge) is enabled.
    pub protection_enabled: bool,
    /// Proxy port (default 8822).
    pub proxy_port: u16,
    /// Bridge port (default 8823).
    pub bridge_port: u16,
    /// Number of blocked events since app start.
    pub blocked_count: u64,
    /// Number of warning events since app start.
    pub warning_count: u64,
    /// Handle to the running proxy server task (if started).
    pub proxy_handle: Option<proxy::ProxyHandle>,
    /// Handle to the running bridge subprocess (if started).
    pub bridge_handle: Option<bridge::BridgeHandle>,
    /// Upstream LLM API base URL.
    pub upstream_url: String,
    /// Upstream API key for Authorization header.
    pub upstream_api_key: String,
    /// Path to shield.yaml configuration file.
    pub config_path: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            protection_enabled: false,
            proxy_port: 8822,
            bridge_port: 8823,
            blocked_count: 0,
            warning_count: 0,
            proxy_handle: None,
            bridge_handle: None,
            upstream_url: String::new(),
            upstream_api_key: String::new(),
            config_path: String::new(),
        }
    }
}

pub type SharedState = Arc<Mutex<AppState>>;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Arc::new(Mutex::new(AppState::default())))
        .setup(|app| {
            // Set up system tray
            tray::setup_tray(app)?;

            // Register cleanup on window close
            let window = app.get_webview_window("main").expect("main window not found");
            let state: SharedState = app.state::<SharedState>().inner().clone();

            window.on_window_event(move |event| {
                if let tauri::WindowEvent::Destroyed = event {
                    tracing::info!("Window destroyed — cleaning up proxy + bridge");
                    let state = state.clone();
                    tokio::spawn(async move {
                        cleanup_services(&state).await;
                    });
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::toggle_protection,
            commands::get_status,
            commands::get_doctor,
            commands::get_slm_status,
            commands::get_events,
            commands::scan_skill,
            commands::scan_mcp,
            commands::scan_agent_config,
            commands::scan_agent_assets,
            commands::scan_all_agents,
            commands::slm_start,
            commands::slm_stop,
            commands::run_check,
            commands::get_context,
            commands::get_adapter_snippet,
            commands::stop_qise_services,
            commands::restore_all_agents,
            commands::get_guards,
            commands::set_guard_mode,
            commands::detect_agents,
            commands::takeover_agent,
            commands::protect_agent_with_options,
            commands::restore_agent,
            commands::get_takeover_status,
            commands::get_config_path,
            commands::get_config,
            commands::save_config,
            commands::get_default_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Stop proxy and bridge, restoring clean state.
pub(crate) async fn cleanup_services(state: &SharedState) {
    let (proxy_handle, bridge_handle) = {
        let mut s = state.lock().await;
        s.protection_enabled = false;
        (s.proxy_handle.take(), s.bridge_handle.take())
    };

    if let Some(handle) = proxy_handle {
        match proxy::stop_proxy(handle).await {
            Ok(()) => tracing::info!("Proxy stopped on cleanup"),
            Err(e) => tracing::error!("Failed to stop proxy on cleanup: {}", e),
        }
    }

    if let Some(handle) = bridge_handle {
        match bridge::stop_bridge(handle).await {
            Ok(()) => tracing::info!("Bridge stopped on cleanup"),
            Err(e) => tracing::error!("Failed to stop bridge on cleanup: {}", e),
        }
    }

    match qise_cli::run(qise_cli::args(&["stop"])).await {
        Ok(output) => {
            if !output.stdout.is_empty() {
                tracing::info!("Qise stop on cleanup: {}", output.stdout);
            }
            if !output.stderr.is_empty() {
                tracing::warn!("Qise stop stderr on cleanup: {}", output.stderr);
            }
        }
        Err(e) => tracing::error!("Failed to stop Qise managed services on cleanup: {}", e),
    }

    match qise_cli::run(qise_cli::args(&["restore", "all"])).await {
        Ok(output) => {
            if !output.stdout.is_empty() {
                tracing::info!("Qise restore on cleanup: {}", output.stdout);
            }
            if !output.stderr.is_empty() {
                tracing::warn!("Qise restore stderr on cleanup: {}", output.stderr);
            }
        }
        Err(e) => tracing::error!("Failed to restore Qise protection on cleanup: {}", e),
    }
}
