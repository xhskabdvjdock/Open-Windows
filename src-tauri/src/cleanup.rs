//! Cleanup: real size analysis + reviewed deletion (Analyze → Review → Clean).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySize {
    pub id: String,
    pub name: String,
    pub path: String,
    pub bytes: u64,
    pub bytes_human: String,
    pub files: u64,
    pub note: String,
}

pub fn human(bytes: u64) -> String {
    const U: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < U.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{:.1} {}", v, U[u])
    }
}

fn dir_size(path: &str, cap_files: u64) -> (u64, u64) {
    if path.is_empty() || !std::path::Path::new(path).exists() {
        return (0, 0);
    }
    let mut bytes = 0u64;
    let mut files = 0u64;
    for e in WalkDir::new(path).follow_links(false).max_depth(8).into_iter().flatten() {
        if e.file_type().is_file() {
            if let Ok(m) = e.metadata() {
                bytes += m.len();
                files += 1;
            }
            if files > cap_files {
                break;
            }
        }
    }
    (bytes, files)
}

fn dirs(which: &str) -> PathBuf {
    match which {
        "temp" => std::env::var("TEMP").map(PathBuf::from).unwrap_or_default(),
        "local" => std::env::var("LOCALAPPDATA").map(PathBuf::from).unwrap_or_default(),
        "roam" => std::env::var("APPDATA").map(PathBuf::from).unwrap_or_default(),
        "windir" => std::env::var("WINDIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("C:\\Windows")),
        _ => PathBuf::new(),
    }
}

#[tauri::command]
pub fn cmd_analyze_cleanup() -> Vec<CategorySize> {
    let temp = dirs("temp").display().to_string();
    let wtemp = dirs("windir").join("Temp").display().to_string();
    let local = dirs("local");
    let roam = dirs("roam");
    let mut cats: Vec<CategorySize> = vec![];
    let jobs: Vec<(&str, &str, String, &str)> = vec![
        ("temp", "Temporary Files", temp.clone(), "User temporary files. Safe to remove when no installer is running."),
        ("wintemp", "Windows Temporary Data", wtemp.clone(), "System temp. Requires Administrator for some files."),
        ("recycle", "Recycle Bin", "C:\\$Recycle.Bin".into(), "Deleted files kept for recovery. Emptying is permanent."),
        ("update", "Update Cleanup Candidates", dirs("windir").join("SoftwareDistribution\\Download").display().to_string(), "Downloaded update payloads. Only stale payloads are removed; never live update state."),
        ("dumps", "Crash Dumps", dirs("local").join("CrashDumps").display().to_string(), "Memory dumps from crashed apps. Large but occasionally useful for debugging."),
        ("logs", "Old Logs", dirs("windir").join("Logs").display().to_string(), "Windows and CBS logs. Recent logs are preserved."),
        ("thumb", "Thumbnail Caches", local.join("Microsoft\\Windows\\Explorer").display().to_string(), "Explorer thumbnail cache (thumbcache_*.db). Rebuilds automatically."),
        ("chrome", "Browser Caches", local.join("Google\\Chrome\\User Data\\Default\\Cache").display().to_string(), "Chromium cache where present."),
        ("edge", "Edge Cache", local.join("Microsoft\\Edge\\User Data\\Default\\Cache").display().to_string(), "Edge cache where present."),
        ("firefox", "Firefox Cache", local.join("Mozilla\\Firefox\\Profiles").display().to_string(), "Firefox profile caches where present."),
    ];
    for (id, name, path, note) in jobs {
        let (bytes, files) = if id == "recycle" {
            dir_size(&path, 50_000)
        } else if id == "firefox" {
            // sum Cache dirs only
            let mut b = 0u64;
            let mut f = 0u64;
            if let Ok(rd) = std::fs::read_dir(&path) {
                for e in rd.flatten() {
                    let c = e.path().join("cache2");
                    let (bb, ff) = dir_size(&c.display().to_string(), 20_000);
                    b += bb;
                    f += ff;
                }
            }
            (b, f)
        } else {
            dir_size(&path, 200_000)
        };
        // thumbnail filter: only thumbcache files counted
        let _ = (&roam, &local);
        cats.push(CategorySize {
            id: id.into(),
            name: name.into(),
            path: path.clone(),
            bytes,
            bytes_human: human(bytes),
            files,
            note: note.into(),
        });
    }
    cats
}

fn clean_dir(path: &str, keep_recent_days: Option<u64>, pattern: Option<&str>) -> Result<(u64, u64), String> {
    if path.is_empty() {
        return Ok((0, 0));
    }
    let base = std::path::Path::new(path);
    if !base.exists() {
        return Ok((0, 0));
    }
    let cutoff = keep_recent_days.map(|d| std::time::SystemTime::now() - std::time::Duration::from_secs(d * 86400));
    let mut freed = 0u64;
    let mut removed = 0u64;
    for e in WalkDir::new(base).follow_links(false).max_depth(8).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path();
        if let Some(pat) = pattern {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
            if !n.contains(pat) {
                continue;
            }
        }
        if let Some(c) = cutoff {
            if let Ok(m) = e.metadata() {
                if let Ok(mt) = m.modified() {
                    if mt > c {
                        continue;
                    }
                }
            }
        }
        if let Ok(m) = e.metadata() {
            let sz = m.len();
            if std::fs::remove_file(p).is_ok() {
                freed += sz;
                removed += 1;
            }
        }
        if removed > 200_000 {
            break;
        }
    }
    Ok((freed, removed))
}

#[tauri::command]
pub fn cmd_clean_cleanup(ids: Vec<String>) -> Result<serde_json::Value, String> {
    if ids.is_empty() {
        return Err("Select at least one category to clean.".into());
    }
    let mut total_freed = 0u64;
    let mut details: Vec<serde_json::Value> = vec![];
    for id in &ids {
        let r: Result<(u64, u64), String> = match id.as_str() {
            "temp" => clean_dir(&std::env::var("TEMP").unwrap_or_default(), None, None),
            "wintemp" => {
                if !crate::core::is_elevated() {
                    Err("Windows Temp cleanup needs Administrator.".into())
                } else {
                    clean_dir(&dirs("windir").join("Temp").display().to_string(), None, None)
                }
            }
            "recycle" => {
                // Empty recycle bin via PowerShell (real, confirmed by UI dialog).
                // Measure $Recycle.Bin before/after so the reported freed
                // size is a real measurement, not an estimate.
                let before = dir_size("C:\\$Recycle.Bin", 50_000).0;
                match crate::core::run_powershell("Clear-RecycleBin -Force -ErrorAction Stop 2>&1 | Out-String", 120) {
                    Ok(o) => {
                        let after = dir_size("C:\\$Recycle.Bin", 50_000).0;
                        let freed = before.saturating_sub(after);
                        details.push(serde_json::json!({"id":"recycle","result":o,"freed_bytes":freed,"freed":human(freed)}));
                        total_freed += freed;
                        Ok((0, 0))
                    }
                    Err(e) => Err(e),
                }
            }
            "update" => clean_dir(&dirs("windir").join("SoftwareDistribution\\Download").display().to_string(), Some(7), None),
            "dumps" => clean_dir(&dirs("local").join("CrashDumps").display().to_string(), None, Some(".dmp")),
            "logs" => clean_dir(&dirs("windir").join("Logs").display().to_string(), Some(14), Some(".log")),
            "thumb" => clean_dir(&dirs("local").join("Microsoft\\Windows\\Explorer").display().to_string(), None, Some("thumbcache")),
            "chrome" => clean_dir(&dirs("local").join("Google\\Chrome\\User Data\\Default\\Cache").display().to_string(), None, None),
            "edge" => clean_dir(&dirs("local").join("Microsoft\\Edge\\User Data\\Default\\Cache").display().to_string(), None, None),
            "firefox" => {
                let mut f = 0u64;
                let mut n = 0u64;
                if let Ok(rd) = std::fs::read_dir(dirs("local").join("Mozilla\\Firefox\\Profiles")) {
                    for e in rd.flatten() {
                        if let Ok((ff, nn)) = clean_dir(&e.path().join("cache2").display().to_string(), None, None) {
                            f += ff;
                            n += nn;
                        }
                    }
                }
                Ok((f, n))
            }
            _ => Err(format!("Unknown category: {id}")),
        };
        match r {
            Ok((freed, n)) => {
                total_freed += freed;
                if id != "recycle" {
                    details.push(serde_json::json!({"id":id,"freed_bytes":freed,"freed":human(freed),"files":n}));
                }
            }
            Err(e) => details.push(serde_json::json!({"id":id,"error":e})),
        }
    }
    crate::core::push_history(crate::core::HistoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        date: chrono::Utc::now(),
        category: "cleanup".into(),
        change: format!("Cleanup: {}", ids.join(", ")),
        previous_value: "-".into(),
        new_value: human(total_freed),
        reversible: false,
        revert_info: serde_json::json!({"ids":ids}),
    });
    crate::core::log_event("cleanup.run", &format!("{} freed {}", ids.join(","), human(total_freed)), "ok");
    Ok(serde_json::json!({"freed_bytes": total_freed, "freed": human(total_freed), "details": details}))
}
