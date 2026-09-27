//! Services manager — real Win32 services. Warns before disabling.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display: String,
    pub status: String,
    pub startup: String,
    pub description: String,
}

pub fn list_services_impl() -> Result<Vec<ServiceInfo>, String> {
    let out = crate::core::run_powershell(
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,Description | ConvertTo-Json -Compress -Depth 2",
        40,
    )?;
    let v: serde_json::Value =
        serde_json::from_str(out.trim()).map_err(|e| format!("Service query failed: {e}"))?;
    let arr = if v.is_array() { v.as_array().cloned().unwrap_or_default() } else { vec![v] };
    Ok(arr
        .into_iter()
        .map(|i| ServiceInfo {
            name: i.get("Name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            display: i.get("DisplayName").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            status: i.get("State").and_then(|x| x.as_str()).unwrap_or("Unknown").to_string(),
            startup: i.get("StartMode").and_then(|x| x.as_str()).unwrap_or("Unknown").to_string(),
            description: i.get("Description").and_then(|x| x.as_str()).unwrap_or("").chars().take(400).collect(),
        })
        .collect())
}

#[tauri::command]
pub fn cmd_list_services(query: Option<String>) -> Result<Vec<ServiceInfo>, String> {
    let mut v = list_services_impl()?;
    if let Some(q) = query {
        let q = q.to_lowercase();
        if !q.is_empty() {
            v.retain(|s| s.name.to_lowercase().contains(&q) || s.display.to_lowercase().contains(&q));
        }
    }
    v.truncate(600);
    Ok(v)
}

fn guard_critical(name: &str) -> Option<String> {
    let n = name.to_lowercase();
    let critical = [
        "wscsvc", "windefend", "mpssvc", "wuauserv", "gpsvc", "lsass", "eventlog", "rpcss", "dcomlaunch",
    ];
    if critical.contains(&n.as_str()) {
        Some(format!(
            "“{name}” is a critical Windows security/service dependency. Stopping or disabling it can leave Windows unprotected or unbootable. This must be a deliberate, confirmed action."
        ))
    } else {
        None
    }
}

#[tauri::command]
pub fn cmd_service_action(name: String, action: String, confirmed_critical: bool) -> Result<String, String> {
    if name.trim().is_empty() || name.contains([';', '&', '|', '$', '`']) {
        return Err("Invalid service name.".into());
    }
    if let Some(warn) = guard_critical(&name) {
        if !confirmed_critical {
            return Err(format!("CRITICAL_GUARD: {warn}"));
        }
    }
    let verb = match action.to_lowercase().as_str() {
        "start" => "Start-Service",
        "stop" => "Stop-Service",
        "restart" => "Restart-Service",
        _ => return Err("Unknown action.".into()),
    };
    let script = format!("{verb} -Name '{svc}' -ErrorAction Stop 2>&1 | Out-String", svc = name.replace('\'', "''"));
    let out = crate::core::run_powershell(&script, 60)?;
    crate::core::push_history(crate::core::HistoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        date: chrono::Utc::now(),
        category: "service".into(),
        change: format!("{verb} {name}"),
        previous_value: "-".into(),
        new_value: out.chars().take(300).collect(),
        reversible: true,
        revert_info: serde_json::json!({"kind":"service-action","name":name,"action":action}),
    });
    crate::core::log_event("service.action", &format!("{verb} {name}"), "ok");
    Ok(out.chars().take(2000).collect())
}

#[tauri::command]
pub fn cmd_set_service_startup(name: String, startup: String, confirmed_critical: bool) -> Result<String, String> {
    if let Some(warn) = guard_critical(&name) {
        if !confirmed_critical {
            return Err(format!("CRITICAL_GUARD: {warn}"));
        }
    }
    let mode = match startup.to_lowercase().as_str() {
        "automatic" | "auto" => "Automatic",
        "manual" => "Manual",
        "disabled" => "Disabled",
        _ => return Err("Startup type must be Automatic, Manual or Disabled.".into()),
    };
    let script = format!(
        "Set-Service -Name '{svc}' -StartupType {mode} -ErrorAction Stop 2>&1 | Out-String; Get-Service -Name '{svc}' | Select-Object Name,StartType,Status | ConvertTo-Json -Compress",
        svc = name.replace('\'', "''")
    );
    let out = crate::core::run_powershell(&script, 60)?;
    crate::core::push_history(crate::core::HistoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        date: chrono::Utc::now(),
        category: "service".into(),
        change: format!("Set {name} startup to {mode}"),
        previous_value: "-".into(),
        new_value: mode.into(),
        reversible: true,
        revert_info: serde_json::json!({"kind":"service-startup","name":name,"mode":mode}),
    });
    crate::core::log_event("service.startup", &format!("{name} -> {mode}"), "ok");
    Ok(out.chars().take(2000).collect())
}
