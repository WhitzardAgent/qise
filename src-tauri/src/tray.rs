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
                tracing::info!("Toggle protection clicked");
                // TODO: Emit event to frontend for state toggle
                let _ = app.emit("toggle-protection", ());
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
