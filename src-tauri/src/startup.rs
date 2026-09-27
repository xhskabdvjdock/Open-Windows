//! Startup: Run keys + Startup folders + Logon scheduled tasks.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupEntry {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub path: String,
    pub source: String,
    pub enabled: bool,
    pub impact: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedTask {
    pub name: String,
    pub state: String,
    pub action: String,
    pub author: String,
}

fn sig_of(path: &str) -> String {
    let p = std::path::Path::new(path);
    if !p.exists() || path.is_empty() {
        return "Unknown".into();
    }
    #[cfg(target_os = "windows")]
    {
        let esc = path.replace('\'', "''");
        if let Ok(out) = crate::core::run_powershell(
            &format!("(Get-AuthenticodeSignature -LiteralPath '{esc}').Status"),
            15,
        ) {
            let s = out.trim();
            if s.contains("Valid") {
                return "Signed".into();
            }
            if s.contains("NotSigned") {
                return "Unsigned".into();
            }
        }
        "Unknown".into()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = p;
        "Unknown".into()
    }
}

pub fn list_startup_impl() -> Result<Vec<StartupEntry>, String> {
    #[cfg(not(target_os = "windows"))]
    return Ok(vec![]);
    #[cfg(target_os = "windows")]
    {
        use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
        let mut out: Vec<StartupEntry> = vec![];
        let keys = [
            (true, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (true, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (false, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (false, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (false, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ];
        for (hkcu, sub) in keys {
            let key = if hkcu { CURRENT_USER.open(sub).ok() } else { LOCAL_MACHINE.open(sub).ok() };
            if let Some(k) = key {
                if let Ok(values) = k.values() {
                for (name, val) in values {
                    let data = format!("{:?}", val);
                    let cleaned = data.trim_matches('"').to_string();
                    let enabled = !name.starts_with("(disabled)") && !cleaned.is_empty();
                    // Extract executable path (first quoted token)
                    let exe = cleaned
                        .trim()
                        .trim_start_matches('"')
                        .split('"')
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_string();
                    out.push(StartupEntry {
                        id: format!("reg:{}:{}", if hkcu { "HKCU" } else { "HKLM" }, name),
                        name: name.clone(),
                        publisher: String::new(),
                        path: if exe.is_empty() { cleaned.clone() } else { exe.clone() },
                        source: format!("Registry {}", if hkcu { "HKCU" } else { "HKLM" }),
                        enabled,
                        impact: "Unknown".into(),
                        signature: sig_of(&exe),
                    });
                }
                }
            }
        }
        // Startup folders
        for folder in [
            std::env::var("APPDATA").map(|a| format!("{a}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")).unwrap_or_default(),
            std::env::var("PROGRAMDATA").map(|a| format!("{a}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")).unwrap_or_default(),
        ] {
            if folder.is_empty() {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&folder) {
                for e in rd.flatten() {
                    out.push(StartupEntry {
                        id: format!("folder:{}", e.path().display()),
                        name: e.file_name().to_string_lossy().to_string(),
                        publisher: String::new(),
                        path: e.path().display().to_string(),
                        source: "Startup folder".into(),
                        enabled: true,
                        impact: "Unknown".into(),
                        signature: sig_of(&e.path().display().to_string()),
                    });
                }
            }
        }
        Ok(out)
    }
}

pub fn list_scheduled_tasks_impl() -> Result<Vec<SchedTask>, String> {
    let out = crate::core::run_powershell(
        "Get-ScheduledTask | Where-Object {$_.Triggers} | Select-Object TaskName,State,Author -First 200 | ConvertTo-Json -Compress -Depth 3",
        30,
    )?;
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or(serde_json::json!([]));
    let arr = if v.is_array() { v.as_array().cloned().unwrap_or_default() } else { vec![v] };
    // Actions need a second query (bounded)
    let acts = crate::core::run_powershell(
        "Get-ScheduledTask | Select-Object TaskName,@{n='Action';e={($_.Actions | Select-Object -First 1 -ExpandProperty Execute) + ' ' + ($_.Actions | Select-Object -First 1 -ExpandProperty Arguments)}} -First 200 | ConvertTo-Json -Compress -Depth 3",
        30,
    )
    .unwrap_or_default();
    let amap: std::collections::HashMap<String, String> = serde_json::from_str::<serde_json::Value>(&acts)
        .ok()
        .map(|av| {
            let a = if av.is_array() { av.as_array().cloned().unwrap_or_default() } else { vec![av] };
            a.into_iter()
                .filter_map(|i| {
                    Some((
                        i.get("TaskName")?.as_str()?.to_string(),
                        i.get("Action").map(|x| x.to_string()).unwrap_or_default(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(arr
        .into_iter()
        .map(|i| {
            let name = i.get("TaskName").and_then(|x| x.as_str()).unwrap_or("").to_string();
            SchedTask {
                action: amap.get(&name).cloned().unwrap_or_default().trim_matches('"').to_string(),
                name,
                state: i.get("State").map(|x| x.to_string()).unwrap_or_default().trim_matches('"').to_string(),
                author: i.get("Author").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            }
        })
        .collect())
}

#[tauri::command]
pub fn cmd_list_startup() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "startup": list_startup_impl()?,
        "tasks": list_scheduled_tasks_impl().unwrap_or_default(),
    }))
}

#[tauri::command]
pub fn cmd_set_startup_enabled(id: String, enabled: bool) -> Result<String, String> {
    // Registry Run values: disabling = move to Run- backup? We rename by
    // toggling a backup value so it is reversible and logged.
    if let Some(rest) = id.strip_prefix("reg:") {
        #[cfg(target_os = "windows")]
        {
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err("Invalid startup id.".into());
            }
            let (hive, name) = (parts[0], parts[1]);
            let sub = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
            // Open with write
            let key = if hive == "HKCU" {
                CURRENT_USER.create(sub).map_err(|e| e.to_string())?
            } else {
                LOCAL_MACHINE.create(sub).map_err(|e| e.to_string())?
            };
            if enabled {
                // restore from backup "{name}.ow-disabled" if present
                let backup = format!("{name}.ow-disabled");
                if let Ok(v) = key.get_string(&backup) {
                    key.set_string(name, v.as_str()).map_err(|e| e.to_string())?;
                    let _ = key.remove_value(&backup);
                } else {
                    return Err("No disabled backup found for this entry.".into());
                }
            } else {
                let cur = key.get_string(name).map_err(|_| "Entry not found.".to_string())?;
                key.set_string(format!("{name}.ow-disabled"), cur.clone()).map_err(|e| e.to_string())?;
                key.remove_value(name).map_err(|e| e.to_string())?;
            }
            crate::core::push_history(crate::core::HistoryEntry {
                id: uuid::Uuid::new_v4().to_string(),
                date: chrono::Utc::now(),
                category: "startup".into(),
                change: format!("{} startup entry {name}", if enabled { "Enabled" } else { "Disabled" }),
                previous_value: (!enabled).to_string(),
                new_value: enabled.to_string(),
                reversible: true,
                revert_info: serde_json::json!({"kind":"startup-reg","hive":hive,"name":name,"enabled":enabled}),
            });
            crate::core::log_event("startup.toggle", &format!("{hive} {name} -> {enabled}"), "ok");
            return Ok(if enabled { "Startup entry enabled." } else { "Startup entry disabled (reversible in Change History)." }.into());
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (rest, enabled);
            return Err("Startup management requires Windows.".into());
        }
    }
    if id.starts_with("folder:") {
        return Err("Startup-folder shortcuts must be moved manually. Use “Open Location”, then move the shortcut out of the Startup folder to disable it.".into());
    }
    Err("Only Registry Run entries can be toggled from here. Scheduled tasks can be managed in Task Scheduler.".into())
}
