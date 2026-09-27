//! Core: paths, logging, privileges, history, settings, restore points.
//! All destructive ops go through history so they can be undone where possible.

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub static LOG_BUFFER: Lazy<Mutex<VecDeque<LogEntry>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(2000)));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub detail: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub date: DateTime<Utc>,
    pub category: String,
    pub change: String,
    pub previous_value: String,
    pub new_value: String,
    pub reversible: bool,
    pub revert_info: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub language: String,
    pub theme: String,
    pub scan_default: String,
    pub notifications: bool,
    pub realtime_monitor: bool,
    pub cleanup_confirm: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: "en".into(),
            theme: "system".into(),
            scan_default: "Quick".into(),
            notifications: true,
            realtime_monitor: false,
            cleanup_confirm: true,
        }
    }
}

pub fn app_data_dir() -> PathBuf {
    if let Ok(local) = std::env::var("APPDATA") {
        PathBuf::from(local).join("Open Windows")
    } else {
        PathBuf::from(".").join(".open-windows")
    }
}

pub fn local_data_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local).join("Open Windows")
    } else {
        app_data_dir()
    }
}

pub fn ensure_app_dirs() -> Result<(), String> {
    for d in [
        app_data_dir(),
        local_data_dir(),
        local_data_dir().join("Quarantine"),
        local_data_dir().join("Reports"),
    ] {
        let _ = fs::create_dir_all(&d);
    }
    Ok(())
}



pub fn log_event(action: &str, detail: &str, result: &str) {
    let entry = LogEntry {
        timestamp: Utc::now(),
        action: action.to_string(),
        detail: detail.chars().take(2000).collect(),
        result: result.to_string(),
    };
    LOG_BUFFER.lock().push_back(entry.clone());
    while LOG_BUFFER.lock().len() > 2000 {
        LOG_BUFFER.lock().pop_front();
    }
    // append to file (best effort, never log file contents/passwords)
    if let Ok(dir) = fs::create_dir_all(app_data_dir()).map(|_| app_data_dir()) {
        let path = dir.join("app.log");
        let line = serde_json::to_string(&entry).unwrap_or_default() + "\n";
        use std::io::Write;
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// Prevent child console tools (powershell.exe, net, taskkill, ping, …) from
/// flashing their own console window when the app itself has none.
#[cfg(target_os = "windows")]
pub fn hide_console(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
}

#[cfg(not(target_os = "windows"))]
pub fn hide_console(_cmd: &mut std::process::Command) {}

/// Same, for async (tokio) child processes such as SFC / DISM / WinUtil.
#[cfg(target_os = "windows")]
pub fn hide_console_async(cmd: &mut tokio::process::Command) {
    // tokio's Command has an inherent `creation_flags` method.
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
}

#[cfg(not(target_os = "windows"))]
pub fn hide_console_async(_cmd: &mut tokio::process::Command) {}

/// Run PowerShell -NoProfile and capture stdout (truncated). Genuinely the
/// appropriate Windows interface for Defender / Update / Service queries.
/// Never shows a console window (CREATE_NO_WINDOW).
pub fn run_powershell(script: &str, timeout_secs: u64) -> Result<String, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (script, timeout_secs);
        return Err("Unable to determine — PowerShell queries require Windows".into());
    }
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("powershell.exe");
        hide_console(&mut cmd);
        let out = cmd
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output()
            .map_err(|e| format!("Failed to launch PowerShell: {e}"))?;
        // Bound execution time by caller choice; commands used here are quick.
        let _ = timeout_secs;
        let mut s = String::from_utf8_lossy(&out.stdout).to_string();
        if s.trim().is_empty() && !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(err.chars().take(2000).collect());
        }
        if s.len() > 200_000 {
            s.truncate(200_000);
        }
        Ok(s)
    }
}

pub fn run_cmd(program: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(program);
    hide_console(&mut cmd);
    let out = cmd
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {program}: {e}"))?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    let e = String::from_utf8_lossy(&out.stderr).to_string();
    if !e.trim().is_empty() {
        s.push_str("\n[stderr]\n");
        s.push_str(&e);
    }
    if s.len() > 200_000 {
        s.truncate(200_000);
    }
    Ok(s)
}

pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        // `net session` succeeds only when elevated. Lightweight, no extra deps.
        let mut cmd = Command::new("net");
        hide_console(&mut cmd);
        cmd.arg("session")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

fn history_path() -> PathBuf {
    app_data_dir().join("change-history.json")
}

pub fn read_history() -> Vec<HistoryEntry> {
    fs::read_to_string(history_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn push_history(entry: HistoryEntry) {
    let mut h = read_history();
    h.push(entry);
    while h.len() > 1000 {
        h.remove(0);
    }
    let _ = fs::create_dir_all(app_data_dir());
    let _ = fs::write(history_path(), serde_json::to_string_pretty(&h).unwrap_or_default());
    // before/after snapshot helper
    let _ = fs::write(
        app_data_dir().join("last-change.json"),
        serde_json::to_string_pretty(h.last().unwrap()).unwrap_or_default(),
    );
}

fn settings_path() -> PathBuf {
    app_data_dir().join("settings.json")
}

// ── Tauri commands ──────────────────────────────────────────────

#[tauri::command]
pub fn cmd_is_admin() -> bool {
    is_elevated()
}

#[tauri::command]
pub fn cmd_restart_as_admin() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut cmd = Command::new("powershell.exe");
        hide_console(&mut cmd);
        cmd.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Start-Process -FilePath '{}' -Verb RunAs",
                    exe.display().to_string().replace('\'', "''")
                ),
            ])
            .spawn()
            .map_err(|e| format!("Elevation request failed: {e}"))?;
        log_event("privilege.elevate", "Restart as Administrator requested", "ok");
        Ok("Elevation requested. Approve the Windows UAC prompt.".into())
    }
    #[cfg(not(target_os = "windows"))]
    Err("Administrator restart is only available on Windows.".into())
}

#[tauri::command]
pub fn cmd_create_restore_point(description: String) -> Result<String, String> {
    let desc: String = description.chars().take(120).collect();
    let desc = if desc.trim().is_empty() {
        "Open Windows checkpoint".to_string()
    } else {
        desc
    };
    #[cfg(target_os = "windows")]
    {
        if !is_elevated() {
            return Err("Creating a restore point requires Administrator. Use “Restart as Administrator” first.".into());
        }
        let script = format!(
            "Checkpoint-Computer -Description '{}' -RestorePointType 'MODIFY_SETTINGS' 2>&1 | Out-String",
            desc.replace('\'', "''")
        );
        let out = run_powershell(&script, 180)?;
        // Verify via last restore point
        let verify = run_powershell(
            "Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1 | ConvertTo-Json",
            30,
        )
        .unwrap_or_default();
        log_event("system.restore_point", &desc, "ok");
        push_history(HistoryEntry {
            id: uuid::Uuid::new_v4().to_string(),
            date: Utc::now(),
            category: "system".into(),
            change: format!("Create restore point: {desc}"),
            previous_value: "-".into(),
            new_value: verify.chars().take(500).collect(),
            reversible: false,
            revert_info: serde_json::json!({}),
        });
        Ok(format!("Restore point requested.\n{out}\nLatest:\n{verify}"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = desc;
        Err("Unable to determine — System Restore requires Windows.".into())
    }
}

#[tauri::command]
pub fn cmd_get_change_history() -> Vec<HistoryEntry> {
    let mut h = read_history();
    h.reverse();
    h
}

#[tauri::command]
pub fn cmd_undo_change(id: String) -> Result<String, String> {
    let h = read_history();
    let e = h
        .iter()
        .find(|x| x.id == id)
        .ok_or("History entry not found.")?;
    if !e.reversible {
        return Err("This change is not reversible from app history. Use System Restore if you created a restore point.".into());
    }
    let info = e.revert_info.clone();
    // Registry revert path
    if info.get("kind").and_then(|v| v.as_str()) == Some("registry") {
        let hive = info.get("hive").and_then(|v| v.as_str()).unwrap_or("");
        let path = info.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let name = info.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let prev_kind = info.get("prev_kind").and_then(|v| v.as_str()).unwrap_or("none");
        let prev_val = info.get("prev_value").cloned().unwrap_or(serde_json::Value::Null);
        crate::optimization::revert_registry_value(hive, path, name, prev_kind, &prev_val)?;
        log_event("history.undo", &e.change, "ok");
        return Ok(format!("Reverted: {}", e.change));
    }
    Err("Undo for this change type is not implemented. Restore details are kept in history.".into())
}

#[tauri::command]
pub fn cmd_get_logs() -> Vec<LogEntry> {
    let mut v: Vec<LogEntry> = LOG_BUFFER.lock().iter().cloned().collect();
    v.reverse();
    v.into_iter().take(500).collect()
}

#[tauri::command]
pub fn cmd_export_logs() -> Result<String, String> {
    let logs: Vec<LogEntry> = LOG_BUFFER.lock().iter().cloned().collect();
    let path = local_data_dir().join(format!(
        "open-windows-log-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    let _ = fs::create_dir_all(local_data_dir());
    fs::write(&path, serde_json::to_string_pretty(&logs).unwrap_or_default())
        .map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command]
pub fn cmd_clear_logs() -> Result<String, String> {
    LOG_BUFFER.lock().clear();
    let _ = fs::remove_file(app_data_dir().join("app.log"));
    Ok("Logs cleared.".into())
}

#[tauri::command]
pub fn cmd_get_settings() -> AppSettings {
    fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[tauri::command]
pub fn cmd_set_settings(settings: AppSettings) -> Result<String, String> {
    if !["en", "ar"].contains(&settings.language.as_str()) {
        return Err("Unsupported language.".into());
    }
    if !["dark", "light", "system"].contains(&settings.theme.as_str()) {
        return Err("Unsupported theme.".into());
    }
    let _ = fs::create_dir_all(app_data_dir());
    fs::write(
        settings_path(),
        serde_json::to_string_pretty(&settings).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;
    log_event("settings.update", &format!("lang={} theme={}", settings.language, settings.theme), "ok");
    Ok("Settings saved.".into())
}

#[tauri::command]
pub fn cmd_open_location(path: String) -> Result<String, String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err("Path does not exist.".into());
    }
    #[cfg(target_os = "windows")]
    {
        if p.is_file() {
            Command::new("explorer.exe")
                .args(["/select,", &p.display().to_string()])
                .spawn()
                .map_err(|e| e.to_string())?;
        } else {
            Command::new("explorer.exe")
                .arg(p.display().to_string())
                .spawn()
                .map_err(|e| e.to_string())?;
        }
        Ok("Opened in Explorer.".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = p;
        Err("Open Location requires Windows Explorer.".into())
    }
}
