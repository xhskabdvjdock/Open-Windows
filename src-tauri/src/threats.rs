//! Threats store: Defender detections + scan detections, with safe
//! quarantine / remove / ignore. Never auto-deletes.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderThreat {
    pub path: String,
    pub detail: String,
}

static STORE: Lazy<Mutex<Vec<crate::scanner::Detection>>> =
    Lazy::new(|| Mutex::new(vec![]));

pub fn defender_threats_impl() -> Result<Vec<DefenderThreat>, String> {
    let out = crate::core::run_powershell(
        "Get-MpThreatDetection 2>$null | Select-Object Resources,ThreatID,SeverityID,CategoryID,DetectionID | ConvertTo-Json -Compress -Depth 3",
        30,
    )?;
    let t = out.trim();
    if t.is_empty() || t == "null" {
        return Ok(vec![]);
    }
    let v: serde_json::Value =
        serde_json::from_str(t).map_err(|e| format!("Defender detection parse failed: {e}"))?;
    let arr = if v.is_array() {
        v.as_array().cloned().unwrap_or_default()
    } else {
        vec![v]
    };
    let mut out_v = vec![];
    for item in arr {
        let res = item.get("Resources").map(|r| r.to_string()).unwrap_or_default();
        // Resources may be "C:\\path" or ["C:\\a","C:\\b"]
        let paths: Vec<String> = if let Some(a) = item.get("Resources").and_then(|r| r.as_array()) {
            a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()
        } else if let Some(s) = item.get("Resources").and_then(|r| r.as_str()) {
            vec![s.to_string()]
        } else if !res.is_empty() && res != "null" {
            vec![res.trim_matches('"').to_string()]
        } else {
            vec![]
        };
        for p in paths {
            if p.is_empty() {
                continue;
            }
            out_v.push(DefenderThreat {
                path: p,
                detail: format!(
                    "Reported by Windows Defender (ThreatID={} Severity={} Category={})",
                    item.get("ThreatID").map(|x| x.to_string()).unwrap_or_default(),
                    item.get("SeverityID").map(|x| x.to_string()).unwrap_or_default(),
                    item.get("CategoryID").map(|x| x.to_string()).unwrap_or_default(),
                ),
            });
        }
    }
    Ok(out_v)
}

pub fn merge_scan_detections(dets: Vec<crate::scanner::Detection>) {
    let mut s = STORE.lock();
    for d in dets {
        if !s.iter().any(|x| x.path == d.path && x.risk == d.risk) {
            s.push(d);
        }
    }
    while s.len() > 1000 {
        s.remove(0);
    }
}

#[tauri::command]
pub fn cmd_list_threats() -> Vec<crate::scanner::Detection> {
    let mut v = STORE.lock().clone();
    v.reverse();
    v.into_iter().filter(|d| !d.ignored).take(500).collect()
}

#[tauri::command]
pub fn cmd_quarantine_file(id: String) -> Result<String, String> {
    let det = STORE
        .lock()
        .iter()
        .find(|d| d.id == id)
        .cloned()
        .ok_or("Detection not found.")?;
    let src = std::path::PathBuf::from(&det.path);
    if !src.exists() {
        return Err("File no longer exists.".into());
    }
    let qdir = crate::core::local_data_dir().join("Quarantine");
    let _ = std::fs::create_dir_all(&qdir);
    let dest = qdir.join(format!(
        "{}_{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        src.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    std::fs::rename(&src, &dest).or_else(|_| {
        std::fs::copy(&src, &dest).and_then(|_| std::fs::remove_file(&src).map(|_| 0))?;
        Ok::<_, std::io::Error>(())
    })
    .map_err(|e| format!("Quarantine failed (need Administrator for system paths?): {e}"))?;
    // record
    let meta = qdir.join(format!("{}.json", dest.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    let _ = std::fs::write(&meta, serde_json::to_string_pretty(&det).unwrap_or_default());
    crate::core::push_history(crate::core::HistoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        date: chrono::Utc::now(),
        category: "threat".into(),
        change: format!("Quarantined {}", det.path),
        previous_value: det.path.clone(),
        new_value: dest.display().to_string(),
        reversible: true,
        revert_info: serde_json::json!({"quarantined_from": det.path, "quarantined_to": dest.display().to_string()}),
    });
    crate::core::log_event("threat.quarantine", &det.path, "ok");
    // mark ignored so it disappears from active list
    for d in STORE.lock().iter_mut() {
        if d.id == id {
            d.ignored = true;
        }
    }
    Ok(format!("Quarantined to {}", dest.display()))
}

#[tauri::command]
pub fn cmd_remove_file(id: String) -> Result<String, String> {
    let det = STORE
        .lock()
        .iter()
        .find(|d| d.id == id)
        .cloned()
        .ok_or("Detection not found.")?;
    let src = std::path::PathBuf::from(&det.path);
    if src.exists() {
        // Prefer quarantine first; deletion requires explicit confirm in UI.
        std::fs::remove_file(&src).map_err(|e| format!("Delete failed: {e}"))?;
    }
    crate::core::push_history(crate::core::HistoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        date: chrono::Utc::now(),
        category: "threat".into(),
        change: format!("Deleted {}", det.path),
        previous_value: det.path.clone(),
        new_value: "(deleted)".into(),
        reversible: false,
        revert_info: serde_json::json!({}),
    });
    crate::core::log_event("threat.remove", &det.path, "ok");
    for d in STORE.lock().iter_mut() {
        if d.id == id {
            d.ignored = true;
        }
    }
    Ok("File deleted.".into())
}

#[tauri::command]
pub fn cmd_ignore_detection(id: String) -> Result<String, String> {
    for d in STORE.lock().iter_mut() {
        if d.id == id {
            d.ignored = true;
            crate::core::log_event("threat.ignore", &d.path, "ok");
            return Ok("Detection ignored.".into());
        }
    }
    Err("Detection not found.".into())
}
