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
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    crate::cleanup_services().await;
                    app_handle.exit(0);
                });
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}
