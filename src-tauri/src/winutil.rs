//! WinUtil: safe interface around Chris Titus Tech's Windows Utility.
//! Never silently downloads/executes remote code. Shows exact command,
//! source URL, requires explicit confirmation + admin, captures output.

pub const WINUTIL_CMD: &str = "irm https://christitus.com/win | iex";
pub const WINUTIL_URL: &str = "https://christitus.com/win";
pub const WINUTIL_SOURCE: &str = "https://github.com/ChrisTitusTech/winutil";

#[tauri::command]
pub fn cmd_winutil_info() -> serde_json::Value {
    serde_json::json!({
        "name": "Chris Titus Tech WinUtil",
        "description": "Official community utility for Windows installation helpers, tweaks, debloating, troubleshooting and updates. Requires Administrator because it performs system-wide changes.",
        "command": WINUTIL_CMD,
        "source_url": WINUTIL_URL,
        "review_url": WINUTIL_SOURCE,
        "requires_admin": true,
        "warning": "This downloads and runs remote PowerShell code from christitus.com. Review the source at the GitHub link first. Open Windows never runs it automatically — only after your explicit confirmation.",
        "categories": ["Install Programs", "Tweaks", "Debloat", "Troubleshooting", "Windows Updates", "Configuration"],
        "is_admin": crate::core::is_elevated(),
    })
}

#[tauri::command]
pub async fn cmd_winutil_launch(confirmed: bool) -> Result<String, String> {
    if !confirmed {
        return Err("Explicit confirmation is required before running WinUtil.".into());
    }
    if !crate::core::is_elevated() {
        return Err("WinUtil requires Administrator. Use “Restart as Administrator” first.".into());
    }
    crate::core::log_event("winutil.launch", WINUTIL_CMD, "started");
    // Run with Bypass for this invocation only; capture output.
    let mut cmd = tokio::process::Command::new("powershell.exe");
    crate::core::hide_console_async(&mut cmd);
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WINUTIL_CMD]);
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let out = cmd.output().await.map_err(|e| format!("Failed to launch WinUtil: {e}"))?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    let e = String::from_utf8_lossy(&out.stderr).to_string();
    if !e.trim().is_empty() {
        s.push_str("\n[stderr]\n");
        s.push_str(&e);
    }
    s.push_str(&format!("\n[exit: {}]", out.status));
    if s.len() > 60_000 {
        s.truncate(60_000);
    }
    crate::core::log_event("winutil.launch", WINUTIL_CMD, if out.status.success() { "ok" } else { "completed-with-errors" });
    Ok(s)
}
