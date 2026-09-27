//! System overview, live monitor, health report, before/after.

use serde::{Deserialize, Serialize};
use sysinfo::{Disks, Networks, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemOverview {
    pub windows_version: String,
    pub build: String,
    pub edition: String,
    pub cpu: String,
    pub cpu_cores: usize,
    pub ram_total_gb: f64,
    pub ram_free_gb: f64,
    pub storage: Vec<DiskInfo>,
    pub uptime_secs: u64,
    pub uptime_human: String,
    pub is_admin: String,
    pub defender: String,
    pub firewall: String,
    pub update: String,
    pub hostname: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub mount: String,
    pub fs: String,
    pub total_gb: f64,
    pub free_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStats {
    pub cpu_pct: f32,
    pub ram_used_gb: f64,
    pub ram_total_gb: f64,
    pub ram_pct: f32,
    pub disks: Vec<DiskIo>,
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    pub gpu: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIo {
    pub mount: String,
    pub used_gb: f64,
    pub total_gb: f64,
    pub pct: f32,
}

fn windows_version_info() -> (String, String, String) {
    #[cfg(target_os = "windows")]
    {
        use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
        let base = LOCAL_MACHINE
            .open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            .ok();
        let product = base
            .as_ref()
            .and_then(|k| k.get_string("ProductName").ok())
            .unwrap_or_else(|| "Windows".into());
        let build = base
            .as_ref()
            .and_then(|k| k.get_string("CurrentBuildNumber").ok())
            .unwrap_or_default();
        let display = base
            .as_ref()
            .and_then(|k| {
                k.get_string("DisplayVersion")
                    .or_else(|_| k.get_string("ReleaseId"))
                    .ok()
            })
            .unwrap_or_default();
        let _ = CURRENT_USER;
        (product, build, display)
    }
    #[cfg(not(target_os = "windows"))]
    {
        ("Unable to determine (non-Windows dev host)".into(), "".into(), "".into())
    }
}

fn human_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

#[tauri::command]
pub fn cmd_get_system_overview() -> SystemOverview {
    let mut sys = System::new_all();
    sys.refresh_all();
    let (product, build, display) = windows_version_info();
    let cpu = sys
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .unwrap_or_else(|| "Unable to determine".into());
    let cores = sys.cpus().len();
    let ram_total = sys.total_memory() as f64 / 1_073_741_824.0;
    let ram_free = sys.available_memory() as f64 / 1_073_741_824.0;
    let disks = Disks::new_with_refreshed_list()
        .iter()
        .map(|d| {
            let total = d.total_space() as f64 / 1_073_741_824.0;
            let free = d.available_space() as f64 / 1_073_741_824.0;
            DiskInfo {
                mount: d.mount_point().to_string_lossy().to_string(),
                fs: d.file_system().to_string_lossy().to_string(),
                total_gb: (total * 10.0).round() / 10.0,
                free_gb: (free * 10.0).round() / 10.0,
            }
        })
        .take(8)
        .collect();
    let uptime = System::uptime();
    let admin = if crate::core::is_elevated() {
        "Administrator"
    } else {
        "Limited Mode"
    };
    // Defender / firewall / update — best-effort, "Unable to determine" on failure.
    let defender = crate::security::defender_summary().unwrap_or_else(|_| "Unable to determine".into());
    let firewall = crate::security::firewall_summary().unwrap_or_else(|_| "Unable to determine".into());
    let update = crate::updates::update_summary().unwrap_or_else(|_| "Unable to determine".into());
    SystemOverview {
        windows_version: format!("{product} {display}").trim().to_string(),
        build,
        edition: product,
        cpu: if cpu.is_empty() { "Unable to determine".into() } else { cpu },
        cpu_cores: cores,
        ram_total_gb: (ram_total * 10.0).round() / 10.0,
        ram_free_gb: (ram_free * 10.0).round() / 10.0,
        storage: disks,
        uptime_secs: uptime,
        uptime_human: human_uptime(uptime),
        is_admin: admin.into(),
        defender,
        firewall,
        update,
        hostname: System::host_name().unwrap_or_else(|| "Unable to determine".into()),
        username: std::env::var("USERNAME").unwrap_or_else(|_| "Unable to determine".into()),
    }
}

#[tauri::command]
pub fn cmd_get_live_stats() -> LiveStats {
    let mut sys = System::new_all();
    sys.refresh_cpu_all();
    std::thread::sleep(std::time::Duration::from_millis(400));
    sys.refresh_cpu_all();
    sys.refresh_memory();
    let cpu = sys.global_cpu_usage();
    let total = sys.total_memory() as f64;
    let used = sys.used_memory() as f64;
    let disks: Vec<DiskIo> = Disks::new_with_refreshed_list()
        .iter()
        .map(|d| {
            let t = d.total_space() as f64;
            let f = d.available_space() as f64;
            let pct = if t > 0.0 { ((t - f) / t * 100.0) as f32 } else { 0.0 };
            DiskIo {
                mount: d.mount_point().to_string_lossy().to_string(),
                used_gb: (((t - f) / 1_073_741_824.0) * 10.0).round() / 10.0,
                total_gb: ((t / 1_073_741_824.0) * 10.0).round() / 10.0,
                pct,
            }
        })
        .take(6)
        .collect();
    let nets = Networks::new_with_refreshed_list();
    let (mut rx, mut tx) = (0u64, 0u64);
    for (_, n) in nets.iter() {
        rx += n.received();
        tx += n.transmitted();
    }
    // GPU best-effort via PowerShell (may be "Unable to determine")
    let gpu_raw = crate::core::run_powershell(
        "Get-CimInstance Win32_VideoController | Select-Object -First 1 -ExpandProperty Name",
        10,
    )
    .map(|s| s.trim().to_string())
    .unwrap_or_default();
    let gpu = if gpu_raw.is_empty() {
        "Unable to determine".to_string()
    } else {
        gpu_raw
    };
    LiveStats {
        cpu_pct: (cpu * 10.0).round() / 10.0,
        ram_used_gb: ((used / 1_073_741_824.0) * 10.0).round() / 10.0,
        ram_total_gb: ((total / 1_073_741_824.0) * 10.0).round() / 10.0,
        ram_pct: if total > 0.0 { (used / total * 100.0) as f32 } else { 0.0 },
        disks,
        net_rx_bps: rx,
        net_tx_bps: tx,
        gpu,
    }
}

#[tauri::command]
pub fn cmd_generate_health_report(format: String) -> Result<String, String> {
    let overview = cmd_get_system_overview();
    let live = cmd_get_live_stats();
    let security: serde_json::Value = crate::security::audit_json();
    let startup = crate::startup::list_startup_impl().unwrap_or_default();
    let services = crate::services::list_services_impl().unwrap_or_default();
    let update = crate::updates::update_detail_impl().unwrap_or(serde_json::json!({"status":"Unable to determine"}));
    let history = crate::core::read_history();
    let report = serde_json::json!({
        "generated": chrono::Utc::now().to_rfc3339(),
        "tool": "Open Windows 1.0.0",
        "overview": overview,
        "live": live,
        "security": security,
        "startup_count": startup.len(),
        "startup": startup.iter().take(100).collect::<Vec<_>>(),
        "services_count": services.len(),
        "updates": update,
        "recent_changes": history.iter().rev().take(50).collect::<Vec<_>>(),
        "note": "All values were read from live Windows APIs at generation time. No estimated or fabricated metrics are included."
    });
    let dir = crate::core::local_data_dir().join("Reports");
    let _ = std::fs::create_dir_all(&dir);
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    match format.to_lowercase().as_str() {
        "json" => {
            let p = dir.join(format!("open-windows-report-{stamp}.json"));
            std::fs::write(&p, serde_json::to_string_pretty(&report).unwrap_or_default())
                .map_err(|e| e.to_string())?;
            Ok(p.display().to_string())
        }
        "html" => {
            let p = dir.join(format!("open-windows-report-{stamp}.html"));
            let html = format!(
                "<!doctype html><html><head><meta charset=utf-8><title>Open Windows System Report</title>\
                <style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:24px auto;color:#111}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px 8px;font-size:13px}}h1{{font-size:20px}}</style></head>\
                <body><h1>Open Windows System Report</h1><p>Generated {}</p><pre>{}</pre></body></html>",
                chrono::Utc::now().to_rfc3339(),
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            std::fs::write(&p, html).map_err(|e| e.to_string())?;
            Ok(p.display().to_string())
        }
        _ => {
            let p = dir.join(format!("open-windows-report-{stamp}.txt"));
            let mut t = format!("Open Windows System Report\nGenerated: {}\n\n", chrono::Utc::now().to_rfc3339());
            t.push_str(&serde_json::to_string_pretty(&report).unwrap_or_default());
            std::fs::write(&p, t).map_err(|e| e.to_string())?;
            Ok(p.display().to_string())
        }
    }
}

#[tauri::command]
pub fn cmd_get_before_after() -> serde_json::Value {
    // Real measured deltas from change history + current live readings.
    let history = crate::core::read_history();
    let live = cmd_get_live_stats();
    let disks_free: f64 = live.disks.iter().map(|d| d.total_gb - d.used_gb).sum();
    let tweaks = history.iter().filter(|h| h.category == "tweak").count();
    let services_changed = history.iter().filter(|h| h.category == "service").count();
    let startup_changed = history.iter().filter(|h| h.category == "startup").count();
    let cleaned = history.iter().filter(|h| h.category == "cleanup").count();
    serde_json::json!({
        "services_changed": services_changed,
        "tweaks_applied": tweaks,
        "startup_changes": startup_changed,
        "cleanup_operations": cleaned,
        "current_ram_used_gb": live.ram_used_gb,
        "current_cpu_pct": live.cpu_pct,
        "current_free_disk_gb": (disks_free*10.0).round()/10.0,
        "note": "Only counted changes are shown. No performance improvement is estimated or invented."
    })
}
