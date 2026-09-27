//! Installed applications with honest classification.
//! Never calls ordinary software "malware".

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub install_path: String,
    pub uninstall: String,
    pub classification: String,
    pub reason: String,
    pub signature: String,
}

fn classify(name: &str, publisher: &str, path: &str) -> (String, String) {
    let n = name.to_lowercase();
    let p = publisher.to_lowercase();
    // Microsoft / major vendors → Installed Application
    if p.contains("microsoft") || p.contains("intel") || p.contains("nvidia") || p.contains("amd") || p.contains("realtek") {
        return ("Installed Application".into(), "From a known hardware/OS vendor.".into());
    }
    // Known PUP patterns (evidence-based, still "Potentially Unwanted", not malware)
    for pat in ["ask toolbar", "conduit", "mywebsearch", "babylon", "sweetpage", "delta homes", "genieo", "opencandy", "restoro", "reimage", "driver updater pro", "pc optimizer pro"] {
        if n.contains(pat) {
            return ("Potentially Unwanted".into(), format!("Matches known potentially-unwanted pattern “{pat}”. Verify before removing."));
        }
    }
    if publisher.trim().is_empty() && !path.is_empty() {
        return ("Unknown".into(), "No publisher recorded in the uninstall entry. Check install path and signature before acting.".into());
    }
    if publisher.trim().is_empty() {
        return ("Unknown".into(), "Publisher is not recorded.".into());
    }
    // Preinstalled / optional heuristics are conservative
    for pat in ["candy crush", "tiktok", "spotify music", "disney+", "clipchamp", "solitaire"] {
        if n.contains(pat) {
            return ("Optional".into(), "Preinstalled consumer app that can be removed safely if you do not use it.".into());
        }
    }
    ("Installed Application".into(), "No unwanted-software indicators found.".into())
}

#[tauri::command]
pub fn cmd_list_apps(query: Option<String>) -> Result<Vec<AppInfo>, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = query;
        return Ok(vec![]);
    }
    #[cfg(target_os = "windows")]
    {
        use windows_registry::LOCAL_MACHINE;
        use windows_registry::CURRENT_USER;
        let mut v: Vec<AppInfo> = vec![];
        let hives: Vec<(bool, &str)> = vec![
            (false, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (false, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (true, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ];
        for (hkcu, sub) in hives {
          let base = if hkcu { CURRENT_USER.open(sub).ok() } else { LOCAL_MACHINE.open(sub).ok() };
            if let Some(b) = base {
                if let Ok(keys) = b.keys() {
                for keyname in keys {
                    if let Ok(k) = b.open(&keyname) {
                        let name: String = k.get_string("DisplayName").unwrap_or_default();
                        if name.trim().is_empty() {
                            continue;
                        }
                        // Skip system components / updates unless they carry real names
                        let publisher: String = k.get_string("Publisher").unwrap_or_default();
                        let version: String = k.get_string("DisplayVersion").unwrap_or_default();
                        let inst: String = k.get_string("InstallLocation").unwrap_or_default();
                        let uninst: String = k.get_string("UninstallString").unwrap_or_default();
                        let (class, reason) = classify(&name, &publisher, &inst);
                        v.push(AppInfo {
                            name, publisher, version, install_path: inst, uninstall: uninst,
                            classification: class, reason,
                            signature: "Unknown".into(),
                        });
                    }
                }
                }
            }
        }
        if let Some(q) = query {
            let q = q.to_lowercase();
            if !q.is_empty() {
                v.retain(|a| a.name.to_lowercase().contains(&q) || a.publisher.to_lowercase().contains(&q));
            }
        }
        v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        v.truncate(800);
        Ok(v)
    }
}

#[tauri::command]
pub fn cmd_uninstall_hint(uninstall: String) -> Result<String, String> {
    if uninstall.trim().is_empty() {
        return Err("This entry has no recorded uninstall command.".into());
    }
    Ok(format!(
        "Run the vendor uninstaller to remove this safely:\n\n{uninstall}\n\nCopy this into an elevated Command Prompt, or use Settings → Apps → Installed apps."
    ))
}
