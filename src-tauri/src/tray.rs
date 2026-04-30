//! System tray menu definition for Tauri 2.

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    App, Emitter, Manager,
};

pub fn setup_tray(app: &App) -> tauri::Result<()> {
    let toggle_item = MenuItem::with_id(app, "toggle_protection", "Enable Protection", true, None::<&str>)?;
    let show_item = MenuItem::with_id(app, "show_window", "Guard Dashboard", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit Qise", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;

    let menu = Menu::with_items(app, &[&toggle_item, &separator, &show_item, &separator, &quit_item])?;

    let _tray = TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .tooltip("Qise — AI Agent Security")
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "toggle_protection" => {
                // Get current state
                let state = app.state::<crate::SharedState>();
                let new_enabled = {
                    let s = state.blocking_lock();
                    !s.protection_enabled
                };

                // Emit event to frontend to handle the toggle via IPC
                // This avoids async issues in the sync tray callback
                let _ = app.emit("toggle-protection", new_enabled);
                tracing::info!("Tray: emitted toggle-protection event (enable={})", new_enabled);
            }
            "show_window" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}

/// Update the tray menu text based on current protection state.
pub fn update_tray_menu(app: &tauri::AppHandle, protection_enabled: bool) {
    if let Some(tray) = app.tray_by_id("main-tray") {
        let label = if protection_enabled { "Disable Protection" } else { "Enable Protection" };

        let toggle_item = match MenuItem::with_id(app, "toggle_protection", label, true, None::<&str>) {
            Ok(item) => item,
            Err(e) => {
                tracing::warn!("Failed to create toggle menu item: {}", e);
                return;
            }
        };
        let show_item = match MenuItem::with_id(app, "show_window", "Guard Dashboard", true, None::<&str>) {
            Ok(item) => item,
            Err(e) => {
                tracing::warn!("Failed to create show menu item: {}", e);
                return;
            }
        };
        let quit_item = match MenuItem::with_id(app, "quit", "Quit Qise", true, None::<&str>) {
            Ok(item) => item,
            Err(e) => {
                tracing::warn!("Failed to create quit menu item: {}", e);
                return;
            }
        };
        let separator = match PredefinedMenuItem::separator(app) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to create separator: {}", e);
                return;
            }
        };

        match Menu::with_items(app, &[&toggle_item, &separator, &show_item, &separator, &quit_item]) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(e) => {
                tracing::warn!("Failed to rebuild tray menu: {}", e);
            }
        }
    }
}
