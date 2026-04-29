//! Qise — AI Agent Security Framework (Tauri 2 Desktop App)
//!
//! Provides system tray, proxy toggle, and guard dashboard.

mod bridge;
mod commands;
mod decision;
mod guard_client;
mod parser;
mod proxy;
mod streaming;
mod takeover;
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
    /// Takeover manager for agent config redirection.
    pub takeover_manager: takeover::TakeoverManager,
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
            takeover_manager: takeover::TakeoverManager::new(8822),
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

            // Recover any takeovers from previous crash
            {
                let mut s = state.blocking_lock();
                s.takeover_manager.recover_on_startup();
            }

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
            commands::get_events,
            commands::get_guards,
            commands::set_guard_mode,
            commands::detect_agents,
            commands::takeover_agent,
            commands::restore_agent,
            commands::get_takeover_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Stop proxy and bridge, restoring clean state.
async fn cleanup_services(state: &SharedState) {
    let mut s = state.lock().await;

    if let Some(handle) = s.proxy_handle.take() {
        match proxy::stop_proxy(handle).await {
            Ok(()) => tracing::info!("Proxy stopped on cleanup"),
            Err(e) => tracing::error!("Failed to stop proxy on cleanup: {}", e),
        }
    }

    if let Some(handle) = s.bridge_handle.take() {
        match bridge::stop_bridge(handle).await {
            Ok(()) => tracing::info!("Bridge stopped on cleanup"),
            Err(e) => tracing::error!("Failed to stop bridge on cleanup: {}", e),
        }
    }

    // Restore all active takeovers
    s.takeover_manager.restore_all();

    s.protection_enabled = false;
}
