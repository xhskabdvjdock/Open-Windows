//! Privacy settings that can actually be controlled.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyItem {
    pub id: String,
    pub name: String,
    pub category: String,
    pub state: String,
    pub detail: String,
}

fn reg_u32(hive: &str, path: &str, name: &str) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
        let k = if hive == "HKCU" { CURRENT_USER.open(path).ok() } else { LOCAL_MACHINE.open(path).ok() }?;
        k.get_u32(name).ok()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (hive, path, name);
        None
    }
}

#[tauri::command]
pub fn cmd_list_privacy() -> Vec<PrivacyItem> {
    let mut v: Vec<PrivacyItem> = vec![];
    let get = |id: &str, name: &str, cat: &str, hive: &str, path: &str, val: &str, off_means: u32| {
        let cur = reg_u32(hive, path, val);
        let (state, detail) = match cur {
            Some(x) if x == off_means => ("Off", format!("{val} = {x}")),
            Some(x) => ("On", format!("{val} = {x}")),
            None => ("Unable to determine", "Value not present on this edition/version.".to_string()),
        };
        PrivacyItem { id: id.into(), name: name.into(), category: cat.into(), state: state.into(), detail: format!("{hive}\\{path} — {detail}") }
    };
    v.push(get("telemetry", "Telemetry / diagnostic data", "Telemetry", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0));
    v.push(get("adid", "Advertising ID", "Advertising ID", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0));
    v.push(get("location", "Location sensor", "Location", "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", 1));
    v.push(get("activity", "Activity History feed", "Activity History", "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0));
    v.push(get("bgapps", "Background apps (global)", "Background Apps", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1));
    v.push(get("searchbox", "Search highlights", "Windows Search", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsDynamicSearchBoxEnabled", 0));
    v.push(get("tailored", "Tailored experiences", "Diagnostics", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0));
    v
}

#[tauri::command]
pub fn cmd_set_privacy(id: String, off: bool) -> Result<String, String> {
    // Map to registry writes; HKLM needs admin.
    let (hive, path, val, off_v, on_v): (&str, &str, &str, u32, u32) = match id.as_str() {
        "telemetry" => ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0, 3),
        "adid" => ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, 1),
        "location" => ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", 1, 0),
        "activity" => ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0, 1),
        "bgapps" => ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1, 0),
        "searchbox" => ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsDynamicSearchBoxEnabled", 0, 1),
        "tailored" => ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0, 1),
        _ => return Err("Unknown privacy setting.".into()),
    };
    if hive == "HKLM" && !crate::core::is_elevated() {
        return Err("This setting requires Administrator.".into());
    }
    let target = if off { off_v } else { on_v };
    #[cfg(target_os = "windows")]
    {
        use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
        let prev = reg_u32(hive, path, val);
        let key = if hive == "HKCU" {
            CURRENT_USER.create(path).map_err(|e| e.to_string())?
        } else {
            LOCAL_MACHINE.create(path).map_err(|e| e.to_string())?
        };
        key.set_u32(val, target).map_err(|e| e.to_string())?;
        crate::core::push_history(crate::core::HistoryEntry {
            id: uuid::Uuid::new_v4().to_string(),
            date: chrono::Utc::now(),
            category: "privacy".into(),
            change: format!("Privacy {id} → {}", if off { "Off" } else { "On" }),
            previous_value: prev.map(|v| v.to_string()).unwrap_or("(not set)".into()),
            new_value: target.to_string(),
            reversible: true,
            revert_info: serde_json::json!({"kind":"registry","hive":hive,"path":path,"name":val,"prev_kind": if prev.is_some() {"u32"} else {"none"},"prev_value": prev.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null)}),
        });
        crate::core::log_event("privacy.set", &format!("{id} -> {target}"), "ok");
        Ok("Privacy setting updated. Some settings depend on Windows edition and take effect after sign-out.".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (path, val, target);
        Err("Privacy settings require Windows.".into())
    }
}
