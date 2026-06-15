//! Qise — AI Agent Security Framework (Tauri 2 Desktop App)
//!
//! Provides system tray, proxy toggle, and guard dashboard.

mod commands;
mod guard_client;
mod qise_cli;
mod tray;

use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;

/// Shared application state.
pub struct AppState {
    /// Bridge port (default 8823).
    pub bridge_port: u16,
    /// Path to shield.yaml configuration file.
    pub config_path: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            bridge_port: 8823,
            config_path: String::new(),
        }
    }
}

pub type SharedState = Arc<Mutex<AppState>>;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Arc::new(Mutex::new(AppState::default())))
        .setup(|app| {
            tray::setup_tray(app)?;

            let window = app
                .get_webview_window("main")
                .expect("main window not found");
            let window_to_hide = window.clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window_to_hide.hide();
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

/// Stop managed services and restore Agent configuration before quitting.
pub(crate) async fn cleanup_services() {
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
