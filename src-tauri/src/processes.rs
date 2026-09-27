//! Processes: real list via sysinfo + publisher/path/signature.

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessesToUpdate, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub cpu: f32,
    pub ram_mb: f64,
    pub disk: String,
    pub disk_mb: f64,
    pub publisher: String,
    pub path: String,
    pub signature: String,
}

const CRITICAL: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
];

#[tauri::command]
pub fn cmd_list_processes(sort_by: String, query: Option<String>) -> Vec<ProcInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();
    std::thread::sleep(std::time::Duration::from_millis(250));
    sys.refresh_processes(ProcessesToUpdate::All, false);
    let q = query.unwrap_or_default().to_lowercase();
    let mut v: Vec<ProcInfo> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            let exe = p.exe().map(|e| e.display().to_string()).unwrap_or_default();
            let du = p.disk_usage();
            let disk_mb = ((du.total_read_bytes + du.total_written_bytes) as f64 / 1_048_576.0 * 10.0).round() / 10.0;
            ProcInfo {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().to_string(),
                cpu: (p.cpu_usage() * 10.0).round() / 10.0,
                ram_mb: ((p.memory() as f64 / 1_048_576.0) * 10.0).round() / 10.0,
                disk: format!("{disk_mb} MB I/O"),
                disk_mb,
                publisher: String::new(),
                path: exe,
                signature: "Unknown".into(),
            }
        })
        .filter(|p| {
            if q.is_empty() {
                true
            } else {
                p.name.to_lowercase().contains(&q) || p.path.to_lowercase().contains(&q)
            }
        })
        .collect();
    match sort_by.to_lowercase().as_str() {
        "memory" | "ram" => v.sort_by(|a, b| b.ram_mb.partial_cmp(&a.ram_mb).unwrap_or(std::cmp::Ordering::Equal)),
        "disk" => v.sort_by(|a, b| b.disk_mb.partial_cmp(&a.disk_mb).unwrap_or(std::cmp::Ordering::Equal)),
        "name" => v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        _ => v.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal)),
    }
    v.into_iter().take(400).collect()
}

#[tauri::command]
pub fn cmd_kill_process(pid: u32, force_critical: bool) -> Result<String, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    let target = sys
        .process(Pid::from_u32(pid))
        .ok_or("Process not found (it may have exited).")?;
    let name = target.name().to_string_lossy().to_lowercase();
    if CRITICAL.iter().any(|c| name == *c.to_string()) && !force_critical {
        return Err(format!(
            "“{name}” is a critical Windows system process. Terminating it can crash Windows. Re-confirm with explicit override to proceed."
        ));
    }
    // Use taskkill so the user gets the real Windows error text.
    let out = crate::core::run_cmd("taskkill", &[&format!("/PID"), &format!("{pid}"), &"/F"])?;
    crate::core::log_event("process.kill", &format!("{name} pid={pid}"), "ok");
    Ok(out.chars().take(1000).collect())
}
