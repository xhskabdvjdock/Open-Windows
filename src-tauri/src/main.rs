// GUI application: never open a console window next to the app on Windows.
// Diagnostics still go to %APPDATA%\Open Windows\app.log and the in-app Logs page.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    open_windows::run()
}
