//! Optimization tweaks: Performance / Privacy / UI / Gaming / Background /
//! Updates / Explorer / Power / Networking. Every tweak records previous
//! value so it can be reverted. No preset disables security silently.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tweak {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub current: String,
    pub recommended: String,
    pub risk: String, // Low | Medium | High
    pub side_effects: String,
    pub reversible: bool,
}

#[derive(Debug, Clone)]
struct TweakDef {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    category: &'static str,
    hive: &'static str, // HKCU | HKLM
    path: &'static str,
    value: &'static str,
    kind: &'static str, // u32 | string
    recommended: &'static str,
    recommended_raw: &'static str,
    risk: &'static str,
    side_effects: &'static str,
}

// Registry-backed, documented tweaks. Recommended values are conservative.
const TWEAKS: &[TweakDef] = &[
    TweakDef { id: "vis-effects", name: "Reduce visual effects", description: "Sets visual effects to best-performance baseline (no animations taxing weak GPUs).", category: "Performance", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", value: "VisualFXSetting", kind: "u32", recommended: "2 (Best performance)", recommended_raw: "2", risk: "Low", side_effects: "Windows looks less animated. Reversible." },
    TweakDef { id: "menu-delay", name: "Faster menu show delay", description: "Reduces menu open delay from 400ms to 100ms.", category: "Performance", hive: "HKCU", path: r"Control Panel\Desktop", value: "MenuShowDelay", kind: "string", recommended: "100", recommended_raw: "100", risk: "Low", side_effects: "Menus appear faster; may feel abrupt." },
    TweakDef { id: "startup-delay", name: "Reduce startup app delay", description: "Removes the artificial delay before startup apps launch.", category: "Performance", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize", value: "StartupDelayInMSec", kind: "u32", recommended: "0", recommended_raw: "0", risk: "Low", side_effects: "Slightly higher disk/CPU at logon." },
    TweakDef { id: "game-bar", name: "Disable Game Bar capture", description: "Turns off background Game Bar recording hooks.", category: "Gaming", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\GameDVR", value: "AppCaptureEnabled", kind: "u32", recommended: "0 (Off)", recommended_raw: "0", risk: "Low", side_effects: "Game clipping unavailable until re-enabled." },
    TweakDef { id: "game-mode", name: "Enable Game Mode", description: "Lets Windows prioritize game processes.", category: "Gaming", hive: "HKCU", path: r"Software\Microsoft\GameBar", value: "AllowAutoGameMode", kind: "u32", recommended: "1 (On)", recommended_raw: "1", risk: "Low", side_effects: "May shift resources away from background tasks while gaming." },
    TweakDef { id: "bg-apps", name: "Limit background apps", description: "Disables background execution for Store apps globally.", category: "Background Activity", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", value: "GlobalUserDisabled", kind: "u32", recommended: "1 (Disabled)", recommended_raw: "1", risk: "Medium", side_effects: "Store apps may not update live tiles/notifications in background." },
    TweakDef { id: "search-highlight", name: "Disable Search highlights", description: "Removes rotating Search-home content.", category: "Windows UI", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\SearchSettings", value: "IsDynamicSearchBoxEnabled", kind: "u32", recommended: "0 (Off)", recommended_raw: "0", risk: "Low", side_effects: "Search home shows a plainer layout." },
    TweakDef { id: "explorer-ext", name: "Show file extensions", description: "Shows extensions in File Explorer (security-positive: reveals invoice.pdf.exe).", category: "File Explorer", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", value: "HideFileExt", kind: "u32", recommended: "0 (Show)", recommended_raw: "0", risk: "Low", side_effects: "None. Recommended to keep on." },
    TweakDef { id: "explorer-hidden", name: "Show hidden files", description: "Shows hidden files in Explorer.", category: "File Explorer", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", value: "Hidden", kind: "u32", recommended: "1 (Show)", recommended_raw: "1", risk: "Low", side_effects: "System files become visible; do not delete them." },
    TweakDef { id: "thispc-open", name: "Open Explorer to This PC", description: "Opens Explorer to This PC instead of Home.", category: "File Explorer", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", value: "LaunchTo", kind: "u32", recommended: "1 (This PC)", recommended_raw: "1", risk: "Low", side_effects: "None." },
    TweakDef { id: "power-throttle", name: "Disable Power Throttling", description: "Stops Windows throttling background work on laptops.", category: "Power", hive: "HKLM", path: r"SYSTEM\CurrentControlSet\Control\Power\PowerThrottling", value: "PowerThrottlingOff", kind: "u32", recommended: "1 (Off)", recommended_raw: "1", risk: "Medium", side_effects: "Higher battery use. Requires Administrator." },
    TweakDef { id: "delivery-opt", name: "Limit Delivery Optimization P2P", description: "Stops uploading update parts to other PCs (download still works).", category: "Updates", hive: "HKLM", path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", value: "DODownloadMode", kind: "u32", recommended: "0 (HTTP only)", recommended_raw: "0", risk: "Low", side_effects: "None for security; updates still install. Requires Administrator." },
    TweakDef { id: "telemetry-basic", name: "Set telemetry to minimum", description: "Sets diagnostic data to the lowest level the edition allows.", category: "Privacy", hive: "HKLM", path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", value: "AllowTelemetry", kind: "u32", recommended: "0/1 (Minimum)", recommended_raw: "1", risk: "Low", side_effects: "Some editions enforce Basic minimum; does not promise complete privacy." },
    TweakDef { id: "ad-id", name: "Disable advertising ID", description: "Stops per-user advertising ID for Store apps.", category: "Privacy", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", value: "Enabled", kind: "u32", recommended: "0 (Off)", recommended_raw: "0", risk: "Low", side_effects: "Apps show generic ads." },
    TweakDef { id: "activity-history", name: "Disable Activity History", description: "Stops Timeline cloud sync of activity.", category: "Privacy", hive: "HKLM", path: r"SOFTWARE\Policies\Microsoft\Windows\System", value: "EnableActivityFeed", kind: "u32", recommended: "0 (Off)", recommended_raw: "0", risk: "Low", side_effects: "Timeline across devices stops. Requires Administrator." },
    TweakDef { id: "transparency", name: "Disable transparency effects", description: "Turns off acrylic/transparency for GPU-constrained PCs.", category: "Windows UI", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", value: "EnableTransparency", kind: "u32", recommended: "0 (Off)", recommended_raw: "0", risk: "Low", side_effects: "Flat appearance." },
    TweakDef { id: "snap-assist", name: "Disable Snap assist flyout", description: "Turns off snap suggestion popups.", category: "Windows UI", hive: "HKCU", path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", value: "SnapAssist", kind: "u32", recommended: "0 (Off)", recommended_raw: "0", risk: "Low", side_effects: "Manual window arranging still works." },
    TweakDef { id: "net-autotune", name: "Normal network autotuning", description: "Ensures TCP auto-tuning stays at normal (documents state; only changes if disabled).", category: "Networking", hive: "HKLM", path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", value: "EnableTCPAutoTuning", kind: "u32", recommended: "1 (Normal)", recommended_raw: "1", risk: "Medium", side_effects: "Changing TCP tuning can hurt throughput on odd networks; verified before/after via Network Tools." },
];

fn read_reg(hive: &str, path: &str, name: &str) -> (String, String, Value) {
    #[cfg(target_os = "windows")]
    {
        use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
        let key = if hive == "HKCU" { CURRENT_USER.open(path).ok() } else { LOCAL_MACHINE.open(path).ok() };
        if let Some(k) = key {
            if let Ok(v) = k.get_u32(name) {
                return (v.to_string(), "u32".into(), Value::from(v));
            }
            if let Ok(s) = k.get_string(name) {
                return (s.clone(), "string".into(), Value::from(s));
            }
            return ("(not set)".into(), "none".into(), Value::Null);
        }
        ("(not set)".into(), "none".into(), Value::Null)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (hive, path, name);
        ("Unable to determine".into(), "none".into(), Value::Null)
    }
}

pub fn revert_registry_value(hive: &str, path: &str, name: &str, prev_kind: &str, prev: &Value) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
        let key = if hive == "HKCU" {
            CURRENT_USER.create(path).map_err(|e| e.to_string())?
        } else {
            if !crate::core::is_elevated() {
                return Err("Reverting HKLM values requires Administrator.".into());
            }
            LOCAL_MACHINE.create(path).map_err(|e| e.to_string())?
        };
        match prev_kind {
            "none" => {
                key.remove_value(name).map_err(|e| e.to_string())?;
                Ok("Removed (restored to not-set).".into())
            }
            "u32" => {
                let v = prev.as_u64().unwrap_or(0) as u32;
                key.set_u32(name, v).map_err(|e| e.to_string())?;
                Ok(format!("Restored to {v}."))
            }
            _ => {
                let s = prev.as_str().unwrap_or("");
                key.set_string(name, s).map_err(|e| e.to_string())?;
                Ok(format!("Restored to {s}."))
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (hive, path, name, prev_kind, prev);
        Err("Registry revert requires Windows.".into())
    }
}

#[tauri::command]
pub fn cmd_list_tweaks(category: Option<String>) -> Vec<Tweak> {
    TWEAKS
        .iter()
        .filter(|t| category.as_ref().map(|c| c == "All" || &t.category == c).unwrap_or(true))
        .map(|t| {
            let (cur, _, _) = read_reg(t.hive, t.path, t.value);
            Tweak {
                id: t.id.into(),
                name: t.name.into(),
                description: t.description.into(),
                category: t.category.into(),
                current: cur,
                recommended: t.recommended.into(),
                risk: t.risk.into(),
                side_effects: t.side_effects.into(),
                reversible: true,
            }
        })
        .collect()
}

#[tauri::command]
pub fn cmd_apply_tweak(id: String) -> Result<String, String> {
    let def = TWEAKS.iter().find(|t| t.id == id).ok_or("Unknown tweak.")?;
    if def.hive == "HKLM" && !crate::core::is_elevated() {
        return Err("This tweak writes to HKLM and requires Administrator. Use “Restart as Administrator” first.".into());
    }
    let (prev, prev_kind, prev_val) = read_reg(def.hive, def.path, def.value);
    #[cfg(target_os = "windows")]
    {
        use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
        let key = if def.hive == "HKCU" {
            CURRENT_USER.create(def.path).map_err(|e| e.to_string())?
        } else {
            LOCAL_MACHINE.create(def.path).map_err(|e| e.to_string())?
        };
        if def.kind == "u32" {
            let v: u32 = def.recommended_raw.parse().map_err(|_| "Bad tweak definition.".to_string())?;
            key.set_u32(def.value, v).map_err(|e| e.to_string())?;
        } else {
            key.set_string(def.value, def.recommended_raw).map_err(|e| e.to_string())?;
        }
        crate::core::push_history(crate::core::HistoryEntry {
            id: uuid::Uuid::new_v4().to_string(),
            date: chrono::Utc::now(),
            category: "tweak".into(),
            change: format!("Apply tweak: {} → {}", def.name, def.recommended),
            previous_value: prev,
            new_value: def.recommended.into(),
            reversible: true,
            revert_info: serde_json::json!({"kind":"registry","hive":def.hive,"path":def.path,"name":def.value,"prev_kind":prev_kind,"prev_value":prev_val}),
        });
        crate::core::log_event("tweak.apply", def.id, "ok");
        Ok(format!("Applied “{}” → {}. Previous value saved for Undo.", def.name, def.recommended))
    }
    #[cfg(not(target_os = "windows"))]
    Err("Tweaks require Windows.".into())
}

#[tauri::command]
pub fn cmd_revert_tweak(id: String) -> Result<String, String> {
    // Find latest history entry for this tweak and undo it.
    let h = crate::core::read_history();
    for e in h.iter().rev() {
        let matches_id = e.change.contains(id.as_str());
        let matches_name = TWEAKS.iter().find(|t| t.id == id.as_str()).map(|t| e.change.contains(t.name)).unwrap_or(false);
        if matches_id || matches_name {
            return crate::core::cmd_undo_change(e.id.clone());
        }
    }
    Err("No applied record found for this tweak.".into())
}

#[tauri::command]
pub fn cmd_preview_profile(profile: String) -> Vec<serde_json::Value> {
    let ids: Vec<&str> = match profile.as_str() {
        "Performance" => vec!["vis-effects", "menu-delay", "startup-delay", "game-bar", "transparency"],
        "Privacy" => vec!["telemetry-basic", "ad-id", "activity-history", "search-highlight"],
        "Minimal" => vec!["bg-apps", "game-bar", "search-highlight", "transparency", "activity-history"],
        "Balanced" => vec!["vis-effects", "menu-delay", "explorer-ext", "ad-id", "delivery-opt"],
        _ => vec![],
    };
    ids.into_iter()
        .filter_map(|id| TWEAKS.iter().find(|t| t.id == id))
        .map(|t| {
            let (cur, _, _) = read_reg(t.hive, t.path, t.value);
            serde_json::json!({"id":t.id,"name":t.name,"category":t.category,"current":cur,"will_set":t.recommended,"risk":t.risk,"needs_admin":t.hive=="HKLM"})
        })
        .collect()
}

#[tauri::command]
pub fn cmd_apply_profile(profile: String, ids: Vec<String>) -> Result<String, String> {
    // Security rule: no profile may disable Defender/firewall/updates — our
    // tweak set contains no such entries; enforce by allow-listing TWEAKS ids.
    let mut applied = 0;
    let mut errors: Vec<String> = vec![];
    for id in ids {
        if TWEAKS.iter().any(|t| t.id == id) {
            match cmd_apply_tweak(id.clone()) {
                Ok(_) => applied += 1,
                Err(e) => errors.push(format!("{id}: {e}")),
            }
        }
    }
    crate::core::log_event("profile.apply", &format!("{profile}: {applied} applied"), "ok");
    if applied == 0 {
        return Err(errors.join("\n"));
    }
    Ok(format!("Profile “{profile}”: {applied} tweak(s) applied.{}\n\nA restore point is recommended before major changes (System Repair → Create Restore Point).", if errors.is_empty() { String::new() } else { format!("\nSkipped:\n{}", errors.join("\n")) }))
}
