//! Windows Update status (read-only). Never disables updates.

pub fn update_summary() -> Result<String, String> {
    let reboot = {
        #[cfg(target_os = "windows")]
        {
            use windows_registry::LOCAL_MACHINE;
            LOCAL_MACHINE
                .open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
                .is_ok()
        }
        #[cfg(not(target_os = "windows"))]
        false
    };
    if reboot {
        return Ok("Restart required".into());
    }
    // Last hotfix as "last update" evidence
    let out = crate::core::run_powershell(
        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn,Description | ConvertTo-Json -Compress",
        30,
    )?;
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or(serde_json::json!({}));
    let id = v.get("HotFixID").and_then(|x| x.as_str()).unwrap_or("");
    let on = v.get("InstalledOn").and_then(|x| x.as_str()).unwrap_or("");
    if id.is_empty() {
        Ok("Unable to determine".into())
    } else {
        Ok(format!("Last: {id} ({on})"))
    }
}

pub fn update_detail_impl() -> Result<serde_json::Value, String> {
    let summary = update_summary().unwrap_or_else(|_| "Unable to determine".into());
    let hotfixes = crate::core::run_powershell(
        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn,Description | ConvertTo-Json -Compress -Depth 2",
        30,
    )
    .map(|s| serde_json::from_str::<serde_json::Value>(&s).unwrap_or(serde_json::json!([])))
    .unwrap_or(serde_json::json!("Unable to determine"));
    #[cfg(target_os = "windows")]
    let reboot_required = {
        use windows_registry::LOCAL_MACHINE;
        LOCAL_MACHINE
            .open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
            .is_ok()
    };
    #[cfg(not(target_os = "windows"))]
    let reboot_required = false;
    Ok(serde_json::json!({
        "status": summary,
        "restart_required": reboot_required,
        "recent": hotfixes,
        "policy": "Open Windows never disables Windows Update. Security updates should stay on."
    }))
}

#[tauri::command]
pub fn cmd_update_status() -> Result<serde_json::Value, String> {
    update_detail_impl()
}
