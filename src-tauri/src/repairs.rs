//! System Repair: SFC / DISM with real captured output. Requires admin.

use std::process::Stdio;
use tokio::process::Command as AsyncCommand;

async fn run_elevated_capture(program: &str, args: &[&str]) -> Result<String, String> {
    if !crate::core::is_elevated() {
        return Err(format!(
            "{program} requires Administrator. Use “Restart as Administrator” first, then retry."
        ));
    }
    let mut cmd = AsyncCommand::new(program);
    crate::core::hide_console_async(&mut cmd);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = cmd.output().await.map_err(|e| format!("Failed to run {program}: {e}"))?;
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
    crate::core::log_event("repair.run", &format!("{program} {}", args.join(" ")), if out.status.success() { "ok" } else { "completed-with-errors" });
    Ok(s)
}

#[tauri::command]
pub async fn cmd_sfc_check() -> Result<String, String> {
    run_elevated_capture("sfc", &["/verifyonly"]).await
}

#[tauri::command]
pub async fn cmd_sfc_repair() -> Result<String, String> {
    let out = run_elevated_capture("sfc", &["/scannow"]).await?;
    Ok(out)
}

#[tauri::command]
pub async fn cmd_dism_check() -> Result<String, String> {
    run_elevated_capture("DISM", &["/Online", "/Cleanup-Image", "/CheckHealth"]).await
}

#[tauri::command]
pub async fn cmd_dism_repair() -> Result<String, String> {
    run_elevated_capture("DISM", &["/Online", "/Cleanup-Image", "/RestoreHealth"]).await
}
