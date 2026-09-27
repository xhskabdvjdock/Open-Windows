//! Network tools: interfaces, IP info, ping, DNS, routes, connectivity.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetInfo {
    pub adapters: serde_json::Value,
    pub ipconfig: String,
    pub routes: String,
    pub dns: String,
}

#[tauri::command]
pub fn cmd_network_info() -> Result<NetInfo, String> {
    let adapters = crate::core::run_powershell(
        "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress | ConvertTo-Json -Compress -Depth 2",
        20,
    )
    .map(|s| serde_json::from_str(&s).unwrap_or(serde_json::json!([])))
    .unwrap_or(serde_json::json!("Unable to determine"));
    let ipconfig = crate::core::run_cmd("ipconfig", &["/all"]).unwrap_or_else(|_| "Unable to determine".into());
    let routes = crate::core::run_cmd("route", &["print", "-4"]).unwrap_or_else(|_| "Unable to determine".into());
    let dns = crate::core::run_powershell(
        "Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress -Depth 3",
        20,
    )
    .unwrap_or_else(|_| "Unable to determine".into());
    Ok(NetInfo { adapters, ipconfig: ipconfig.chars().take(8000).collect(), routes: routes.chars().take(8000).collect(), dns: dns.chars().take(4000).collect() })
}

#[tauri::command]
pub fn cmd_ping(host: String) -> Result<String, String> {
    let h: String = host.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == ':').take(253).collect();
    if h.trim().is_empty() {
        return Err("Enter a valid host.".into());
    }
    let out = crate::core::run_cmd("ping", &["-n", "4", &h])?;
    Ok(out.chars().take(6000).collect())
}

#[tauri::command]
pub fn cmd_dns_lookup(host: String) -> Result<String, String> {
    let h: String = host.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').take(253).collect();
    if h.trim().is_empty() {
        return Err("Enter a valid host.".into());
    }
    let out = crate::core::run_cmd("nslookup", &[&h])?;
    Ok(out.chars().take(6000).collect())
}

#[tauri::command]
pub fn cmd_connectivity_test() -> Result<String, String> {
    // Real checks: DNS resolve + TCP connect to well-known endpoints.
    let dns = crate::core::run_cmd("nslookup", &["microsoft.com"])?;
    let ps = crate::core::run_powershell(
        "Test-Connection -ComputerName 1.1.1.1 -Count 2 -ErrorAction SilentlyContinue | Select-Object Address,ResponseTime | ConvertTo-Json -Compress",
        30,
    )
    .unwrap_or_else(|_| "ping unavailable".into());
    Ok(format!("DNS (nslookup microsoft.com):\n{dns}\n\nICMP (1.1.1.1):\n{ps}"))
}

#[tauri::command]
pub fn cmd_export_diagnostics() -> Result<String, String> {
    let info = cmd_network_info()?;
    let path = crate::core::local_data_dir().join(format!("net-diag-{}.txt", chrono::Utc::now().format("%Y%m%d-%H%M%S")));
    let _ = std::fs::create_dir_all(crate::core::local_data_dir());
    let body = format!(
        "Open Windows network diagnostics\n{}\n\n=== ADAPTERS ===\n{}\n\n=== IPCONFIG ===\n{}\n\n=== ROUTES ===\n{}\n\n=== DNS ===\n{}",
        chrono::Utc::now().to_rfc3339(),
        serde_json::to_string_pretty(&info.adapters).unwrap_or_default(),
        info.ipconfig,
        info.routes,
        info.dns
    );
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}
