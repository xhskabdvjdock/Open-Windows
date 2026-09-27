//! Open Windows — Rust core library.
//!
//! Clean architecture (spec §66):
//!   core       — paths, logging, privileges, history, settings, restore points
//!   system     — OS / hardware overview, live monitor, health report
//!   security   — Defender, firewall, audit, vulnerabilities
//!   scanner    — Quick / Standard / Deep scans (real file walks + Defender signals)
//!   threats    — quarantine / remove / ignore workflows
//!   processes  — real process manager (sysinfo + Authenticode where available)
//!   startup    — Run keys, Startup folders, Scheduled Tasks (logon)
//!   services   — Win32 services via PowerShell/Win32 (no blind disables)
//!   apps       — installed software classification (not everything is malware)
//!   cleanup    — real size analysis + reviewed deletion
//!   optimization — registry tweaks with current/recommended/risk + revert
//!   privacy    — controllable Windows privacy settings
//!   repairs    — SFC / DISM with real captured output
//!   storage    — analyzer + duplicate finder (hashing)
//!   network    — interfaces, IP, ping, DNS, routes, connectivity
//!   updates    — Windows Update status (read-only; never disables WU)
//!   winutil    — safe interface around Chris Titus Tech WinUtil

pub mod apps;
pub mod cleanup;
pub mod core;
pub mod network;
pub mod optimization;
pub mod privacy;
pub mod processes;
pub mod repairs;
pub mod scanner;
pub mod security;
pub mod services;
pub mod startup;
pub mod storage;
pub mod system;
pub mod threats;
pub mod updates;
pub mod winutil;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|_app| {
            let _ = core::ensure_app_dirs();
            core::log_event("app.start", "Open Windows started", "ok");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // core
            core::cmd_is_admin,
            core::cmd_restart_as_admin,
            core::cmd_create_restore_point,
            core::cmd_get_change_history,
            core::cmd_undo_change,
            core::cmd_get_logs,
            core::cmd_export_logs,
            core::cmd_clear_logs,
            core::cmd_get_settings,
            core::cmd_set_settings,
            core::cmd_open_location,
            // system
            system::cmd_get_system_overview,
            system::cmd_get_live_stats,
            system::cmd_generate_health_report,
            system::cmd_get_before_after,
            // security
            security::cmd_get_security_status,
            security::cmd_get_security_audit,
            security::cmd_get_vuln_checks,
            security::cmd_export_security_report,
            // scanner
            scanner::cmd_start_scan,
            scanner::cmd_cancel_scan,
            scanner::cmd_pause_scan,
            scanner::cmd_resume_scan,
            scanner::cmd_get_scan_history,
            // threats
            threats::cmd_list_threats,
            threats::cmd_quarantine_file,
            threats::cmd_remove_file,
            threats::cmd_ignore_detection,
            // processes
            processes::cmd_list_processes,
            processes::cmd_kill_process,
            // startup
            startup::cmd_list_startup,
            startup::cmd_set_startup_enabled,
            // services
            services::cmd_list_services,
            services::cmd_service_action,
            services::cmd_set_service_startup,
            // apps
            apps::cmd_list_apps,
            apps::cmd_uninstall_hint,
            // cleanup
            cleanup::cmd_analyze_cleanup,
            cleanup::cmd_clean_cleanup,
            // optimization
            optimization::cmd_list_tweaks,
            optimization::cmd_apply_tweak,
            optimization::cmd_revert_tweak,
            optimization::cmd_preview_profile,
            optimization::cmd_apply_profile,
            // privacy
            privacy::cmd_list_privacy,
            privacy::cmd_set_privacy,
            // repairs
            repairs::cmd_sfc_check,
            repairs::cmd_dism_check,
            repairs::cmd_sfc_repair,
            repairs::cmd_dism_repair,
            // storage
            storage::cmd_analyze_storage,
            storage::cmd_find_duplicates,
            storage::cmd_delete_files,
            // network
            network::cmd_network_info,
            network::cmd_ping,
            network::cmd_dns_lookup,
            network::cmd_connectivity_test,
            network::cmd_export_diagnostics,
            // updates
            updates::cmd_update_status,
            // winutil
            winutil::cmd_winutil_info,
            winutil::cmd_winutil_launch,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Open Windows");
}
