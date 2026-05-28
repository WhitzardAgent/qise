//! System tray menu definition for Tauri 2.

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    App, Manager,
};

pub fn setup_tray(app: &App) -> tauri::Result<()> {
    let show_item = MenuItem::with_id(app, "show_window", "Guard Dashboard", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit Qise", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;

    let menu = Menu::with_items(app, &[&show_item, &separator, &quit_item])?;

    let _tray = TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .tooltip("Qise — AI Agent Security")
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "show_window" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                let state = app.state::<crate::SharedState>().inner().clone();
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    crate::cleanup_services(&state).await;
                    app_handle.exit(0);
                });
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}

/// Update the tray menu text based on current protection state.
pub fn update_tray_menu(app: &tauri::AppHandle, _protection_enabled: bool) {
    if let Some(tray) = app.tray_by_id("main-tray") {
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

        match Menu::with_items(app, &[&show_item, &separator, &quit_item]) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(e) => {
                tracing::warn!("Failed to rebuild tray menu: {}", e);
            }
        }
    }
}
