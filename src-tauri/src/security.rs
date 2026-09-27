//! Security: Defender, firewall, audit, vulnerability/configuration checks.
//! Never guesses: returns "Unable to determine" when detection is unreliable.
//! Never disables Defender/firewall as an "optimization".

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub defender: String,
    pub realtime: String,
    pub firewall: String,
    pub updates: String,
    pub definitions: String,
    pub last_scan: String,
    pub threat_count: String,
    pub raw: serde_json::Value,
}

fn mp_status() -> Result<serde_json::Value, String> {
    let out = crate::core::run_powershell(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntispywareEnabled,AntivirusSignatureLastUpdated,FullScanStartTime,QuickScanStartTime,TotalThreatsDetected | ConvertTo-Json -Compress",
        30,
    )?;
    serde_json::from_str(&out).map_err(|e| format!("Defender query failed: {e}"))
}

pub fn defender_summary() -> Result<String, String> {
    let v = mp_status()?;
    let av = v.get("AntivirusEnabled").and_then(|x| x.as_bool());
    Ok(match av {
        Some(true) => "On".into(),
        Some(false) => "Off".into(),
        None => "Unable to determine".into(),
    })
}

pub fn firewall_summary() -> Result<String, String> {
    let out = crate::core::run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress",
        20,
    )?;
    let v: serde_json::Value =
        serde_json::from_str(&out).map_err(|_| "Unable to determine".to_string())?;
    let profiles = if v.is_array() { v.as_array().cloned().unwrap_or_default() } else { vec![v] };
    if profiles.is_empty() {
        return Ok("Unable to determine".into());
    }
    let on = profiles
        .iter()
        .filter(|p| p.get("Enabled").and_then(|e| e.as_bool()) == Some(true))
        .count();
    Ok(format!("{on}/{} profiles on", profiles.len()))
}

#[tauri::command]
pub fn cmd_get_security_status() -> SecurityStatus {
    let unknown = "Unable to determine".to_string();
    match mp_status() {
        Ok(v) => {
            let b = |k: &str| match v.get(k).and_then(|x| x.as_bool()) {
                Some(true) => "On".to_string(),
                Some(false) => "Off".to_string(),
                None => unknown.clone(),
            };
            SecurityStatus {
                defender: b("AntivirusEnabled"),
                realtime: b("RealTimeProtectionEnabled"),
                firewall: firewall_summary().unwrap_or_else(|_| unknown.clone()),
                updates: crate::updates::update_summary().unwrap_or_else(|_| unknown.clone()),
                definitions: v
                    .get("AntivirusSignatureLastUpdated")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| unknown.clone()),
                last_scan: v
                    .get("FullScanStartTime")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        v.get("QuickScanStartTime")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| unknown.clone())
                    }),
                threat_count: v
                    .get("TotalThreatsDetected")
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| unknown.clone()),
                raw: v,
            }
        }
        Err(_) => SecurityStatus {
            defender: unknown.clone(),
            realtime: unknown.clone(),
            firewall: firewall_summary().unwrap_or_else(|_| unknown.clone()),
            updates: unknown.clone(),
            definitions: unknown.clone(),
            last_scan: unknown.clone(),
            threat_count: unknown.clone(),
            raw: serde_json::json!({}),
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditItem {
    pub id: String,
    pub name: String,
    pub state: String, // Healthy | Warning | Needs Attention | Unknown
    pub detail: String,
    pub kind: String, // vulnerability | configuration | recommendation
}

pub fn audit_json() -> serde_json::Value {
    serde_json::to_value(cmd_get_security_audit()).unwrap_or(serde_json::json!([]))
}

#[tauri::command]
pub fn cmd_get_security_audit() -> Vec<AuditItem> {
    let mut items: Vec<AuditItem> = vec![];
    let st = cmd_get_security_status();
    let map_state = |s: &str| {
        if s == "On" || s.contains("on") {
            "Healthy"
        } else if s == "Off" {
            "Needs Attention"
        } else if s == "Unable to determine" {
            "Unknown"
        } else {
            "Warning"
        }
    };
    items.push(AuditItem {
        id: "defender".into(),
        name: "Windows Defender antivirus".into(),
        state: map_state(&st.defender).into(),
        detail: format!("AntivirusEnabled: {}", st.defender),
        kind: "configuration".into(),
    });
    items.push(AuditItem {
        id: "realtime".into(),
        name: "Real-time protection".into(),
        state: map_state(&st.realtime).into(),
        detail: format!("RealTimeProtectionEnabled: {}", st.realtime),
        kind: "configuration".into(),
    });
    items.push(AuditItem {
        id: "firewall".into(),
        name: "Windows Firewall".into(),
        state: if st.firewall.contains("3/3") || st.firewall.starts_with("2/") {
            "Healthy"
        } else if st.firewall == "Unable to determine" {
            "Unknown"
        } else {
            "Needs Attention"
        }
        .into(),
        detail: st.firewall.clone(),
        kind: "configuration".into(),
    });
    // UAC
    #[cfg(target_os = "windows")]
    {
        use windows_registry::LOCAL_MACHINE;
        let uac = LOCAL_MACHINE
            .open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            .ok()
            .and_then(|k| k.get_u32("EnableLUA").ok());
        items.push(AuditItem {
            id: "uac".into(),
            name: "User Account Control (UAC)".into(),
            state: match uac {
                Some(1) => "Healthy",
                Some(_) => "Needs Attention",
                None => "Unknown",
            }
            .into(),
            detail: match uac {
                Some(v) => format!("EnableLUA = {v}"),
                None => "Unable to determine".into(),
            },
            kind: "configuration".into(),
        });
        // SmartScreen
        let ss = LOCAL_MACHINE
            .open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")
            .ok()
            .and_then(|k| k.get_string("SmartScreenEnabled").ok());
        items.push(AuditItem {
            id: "smartscreen".into(),
            name: "SmartScreen".into(),
            state: match ss.as_deref() {
                Some("RequireAdmin") | Some("Warn") | Some("Block") | Some("On") => "Healthy",
                Some("Off") => "Needs Attention",
                _ => "Unknown",
            }
            .into(),
            detail: ss.unwrap_or_else(|| "Unable to determine".into()),
            kind: "configuration".into(),
        });
        // Secure Boot
        let sb = crate::core::run_powershell("Confirm-SecureBootUEFI 2>&1", 15).unwrap_or_default();
        let sb_state = if sb.trim().eq_ignore_ascii_case("true") {
            "Healthy"
        } else if sb.trim().eq_ignore_ascii_case("false") {
            "Warning"
        } else {
            "Unknown"
        };
        items.push(AuditItem {
            id: "secureboot".into(),
            name: "Secure Boot".into(),
            state: sb_state.into(),
            detail: if sb.trim().is_empty() { "Unable to determine".into() } else { sb.trim().chars().take(300).collect() },
            kind: "configuration".into(),
        });
        // Reboot required / pending updates
        let reboot = LOCAL_MACHINE
            .open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
            .is_ok();
        items.push(AuditItem {
            id: "updates".into(),
            name: "Windows Update / restart".into(),
            state: if reboot { "Warning" } else { "Healthy" }.into(),
            detail: if reboot {
                "A restart is required to finish updates.".into()
            } else {
                st.updates.clone()
            },
            kind: if reboot { "vulnerability" } else { "recommendation" }.into(),
        });
    }
    #[cfg(not(target_os = "windows"))]
    {
        for (id, name) in [("uac", "User Account Control (UAC)"), ("smartscreen", "SmartScreen"), ("secureboot", "Secure Boot"), ("updates", "Windows Update / restart")] {
            items.push(AuditItem { id: id.into(), name: name.into(), state: "Unknown".into(), detail: "Unable to determine".into(), kind: "configuration".into() });
        }
    }
    items
}

#[tauri::command]
pub fn cmd_get_vuln_checks() -> Vec<AuditItem> {
    let mut items = cmd_get_security_audit();
    // Suspicious persistence surfaces (read-only evidence, not verdicts)
    let startup = crate::startup::list_startup_impl().unwrap_or_default();
    let unsigned_startup = startup
        .iter()
        .filter(|s| s.signature == "Unsigned" || s.signature == "Unknown")
        .count();
    items.push(AuditItem {
        id: "startup-persistence".into(),
        name: "Suspicious startup entries".into(),
        state: if unsigned_startup == 0 { "Healthy" } else { "Warning" }.into(),
        detail: format!("{unsigned_startup} unsigned/unknown startup entries. Review in Startup Manager — unsigned does not mean malicious."),
        kind: "recommendation".into(),
    });
    let tasks = crate::startup::list_scheduled_tasks_impl().unwrap_or_default();
    let temp_tasks = tasks
        .iter()
        .filter(|t| {
            let a = t.action.to_lowercase();
            a.contains("\\temp\\") || a.contains("\\tmp\\") || a.contains("appdata\\local\\temp")
        })
        .count();
    items.push(AuditItem {
        id: "sched-tasks".into(),
        name: "Suspicious scheduled tasks".into(),
        state: if temp_tasks == 0 { "Healthy" } else { "Warning" }.into(),
        detail: format!("{temp_tasks} scheduled tasks launch from a Temp directory. Review before acting."),
        kind: "recommendation".into(),
    });
    // Defender threat detections (trusted source)
    let threats = crate::threats::defender_threats_impl().unwrap_or_default();
    items.push(AuditItem {
        id: "defender-threats".into(),
        name: "Defender threat detections".into(),
        state: if threats.is_empty() { "Healthy" } else { "Needs Attention" }.into(),
        detail: if threats.is_empty() {
            "No threats currently reported by Windows Defender.".into()
        } else {
            format!("{} threat(s) reported by Defender. See Threats page.", threats.len())
        },
        kind: if threats.is_empty() { "recommendation" } else { "vulnerability" }.into(),
    });
    items
}

#[tauri::command]
pub fn cmd_export_security_report(format: String, scan_id: Option<String>) -> Result<String, String> {
    let status = cmd_get_security_status();
    let audit = cmd_get_security_audit();
    let vuln = cmd_get_vuln_checks();
    let scan = scan_id
        .as_ref()
        .and_then(|id| crate::scanner::get_scan_result(id))
        .unwrap_or(serde_json::json!(null));
    let report = serde_json::json!({
        "generated": chrono::Utc::now().to_rfc3339(),
        "tool": "Open Windows 1.0.0",
        "status": status,
        "audit": audit,
        "checks": vuln,
        "scan": scan,
        "methodology": "Defender + Firewall + UAC + SecureBoot + Update + persistence review. Unsigned/unfamiliar is NOT labelled malware without a trusted detection source."
    });
    let dir = crate::core::local_data_dir().join("Reports");
    let _ = std::fs::create_dir_all(&dir);
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    match format.to_lowercase().as_str() {
        "json" => {
            let p = dir.join(format!("open-windows-security-{stamp}.json"));
            std::fs::write(&p, serde_json::to_string_pretty(&report).unwrap_or_default())
                .map_err(|e| e.to_string())?;
            Ok(p.display().to_string())
        }
        "html" => {
            let p = dir.join(format!("open-windows-security-{stamp}.html"));
            let html = format!("<!doctype html><html><head><meta charset=utf-8><title>Security Report</title><style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:24px auto}}pre{{background:#f4f4f4;padding:12px;overflow:auto}}</style></head><body><h1>Open Windows — Security Report</h1><p>{}</p><pre>{}</pre></body></html>",
                chrono::Utc::now().to_rfc3339(),
                serde_json::to_string_pretty(&report).unwrap_or_default());
            std::fs::write(&p, html).map_err(|e| e.to_string())?;
            Ok(p.display().to_string())
        }
        _ => {
            let p = dir.join(format!("open-windows-security-{stamp}.txt"));
            std::fs::write(&p, serde_json::to_string_pretty(&report).unwrap_or_default())
                .map_err(|e| e.to_string())?;
            Ok(p.display().to_string())
        }
    }
}
