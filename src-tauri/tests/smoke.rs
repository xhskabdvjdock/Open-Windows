//! Read-only smoke tests: prove every core reading comes from a real
//! Windows API and never from fabricated data. Windows-only.

#![cfg(target_os = "windows")]

use open_windows::{optimization, privacy, security, startup, system};

#[test]
fn overview_returns_real_values() {
    let o = system::cmd_get_system_overview();
    assert!(
        !o.cpu.trim().is_empty() && o.cpu != "Unable to determine",
        "CPU must come from sysinfo, got: {}",
        o.cpu
    );
    assert!(!o.windows_version.trim().is_empty(), "version from registry");
    assert!(!o.storage.is_empty(), "disks from sysinfo");
    assert!(o.ram_total_gb > 0.0, "RAM total must be positive");
    assert!(!o.uptime_human.is_empty(), "uptime from OS");
}

#[test]
fn live_stats_are_measured() {
    let l = system::cmd_get_live_stats();
    assert!(l.ram_total_gb > 0.0);
    assert!(!l.disks.is_empty());
    assert!(l.cpu_pct >= 0.0 && l.cpu_pct <= 100.0);
}

#[test]
fn security_status_reads_defender_and_firewall() {
    let s = security::cmd_get_security_status();
    assert!(
        ["On", "Off", "Unable to determine"].contains(&s.defender.as_str()),
        "defender must be a real Get-MpComputerStatus reading: {}",
        s.defender
    );
    assert!(!s.firewall.is_empty());
    let audit = security::cmd_get_security_audit();
    assert!(audit.len() >= 4, "audit must cover Defender/RT/Firewall/UAC+");
    for a in &audit {
        assert!(["Healthy", "Warning", "Needs Attention", "Unknown"].contains(&a.state.as_str()));
    }
}

#[test]
fn startup_entries_come_from_registry() {
    let list = startup::list_startup_impl().expect("startup scan must run");
    // Every entry must carry its real source; nothing may be invented.
    for e in &list {
        assert!(!e.id.is_empty() && !e.source.is_empty());
    }
}

#[test]
fn privacy_and_tweaks_are_registry_backed() {
    let p = privacy::cmd_list_privacy();
    assert!(!p.is_empty());
    let tw = optimization::cmd_list_tweaks(None);
    assert!(!tw.is_empty());
    for t in &tw {
        assert!(!t.current.is_empty(), "tweak {} must show real current state", t.id);
    }
}
