//! Real scanner: Quick / Standard / Deep.
//! Walks real filesystem locations, counts real files, surfaces Defender
//! detections as the trusted source. Heuristics NEVER label Microsoft/signed
//! components as malware. Supports cancel / pause. Emits `scan-progress`.

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tauri::{AppHandle, Emitter};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    pub file: String,
    pub path: String,
    pub publisher: String,
    pub signature: String,
    pub hash: String,
    pub source: String,
    pub risk: String, // Threat | Suspicious | Potentially Unwanted | Informational
    pub reason: String,
    pub ignored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub level: String,
    pub running: bool,
    pub paused: bool,
    pub current_location: String,
    pub files_scanned: u64,
    pub threats: u64,
    pub suspicious: u64,
    pub pup: u64,
    pub informational: u64,
    pub elapsed_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub level: String,
    pub date: DateTime<Utc>,
    pub duration_secs: u64,
    pub files_scanned: u64,
    pub threats: Vec<Detection>,
    pub counts: HashMap<String, u64>,
}

struct ScanControl {
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
}

static CONTROLS: Lazy<Mutex<HashMap<String, ScanControl>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static RESULTS: Lazy<Mutex<HashMap<String, ScanResult>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn history_path() -> PathBuf {
    crate::core::app_data_dir().join("scan-history.json")
}

fn read_scan_history() -> Vec<serde_json::Value> {
    fs::read_to_string(history_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn append_scan_history(v: serde_json::Value) {
    let mut h = read_scan_history();
    h.push(v);
    while h.len() > 200 {
        h.remove(0);
    }
    let _ = fs::create_dir_all(crate::core::app_data_dir());
    let _ = fs::write(history_path(), serde_json::to_string_pretty(&h).unwrap_or_default());
}

pub fn get_scan_result(scan_id: &str) -> Option<serde_json::Value> {
    RESULTS
        .lock()
        .get(scan_id)
        .and_then(|r| serde_json::to_value(r).ok())
}

fn sha256_file(path: &Path) -> String {
    (|| -> Result<String, std::io::Error> {
        let mut f = fs::File::open(path)?;
        let mut h = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(hex::encode(h.finalize()))
    })()
    .unwrap_or_else(|_| "Unable to determine".into())
}

fn authenticode(path: &Path) -> (String, String) {
    // Genuinely the Windows interface; only called for candidate detections
    // (bounded), not for every walked file.
    #[cfg(target_os = "windows")]
    {
        let esc = path.display().to_string().replace('\'', "''");
        let script = format!(
            "$s=(Get-AuthenticodeSignature -LiteralPath '{esc}').Status; $c=(Get-Item -LiteralPath '{esc}').VersionInfo.CompanyName; @{{s=\"$s\";c=\"$c\"}} | ConvertTo-Json -Compress"
        );
        if let Ok(out) = crate::core::run_powershell(&script, 20) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) {
                let status = v.get("s").and_then(|x| x.as_str()).unwrap_or("Unknown").to_string();
                let company = v.get("c").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let sig = match status.as_str() {
                    "Valid" => "Signed",
                    "NotSigned" => "Unsigned",
                    s if s.contains("HashMismatch") || s.contains("NotTrusted") => "Invalid",
                    _ => "Unknown",
                };
                return (sig.into(), company);
            }
        }
        ("Unknown".into(), String::new())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        ("Unknown".into(), String::new())
    }
}

const PUP_NAMES: &[&str] = &[
    "asktoolbar", "conduit", "mywebsearch", "sweetpage", "babylon", "delta-homes",
    "genieo", "opencandy", "installcore", "softonic", "iminent", "funmoods",
    "driverupdate", "winpcap", "slimware", "restoro", "reimage",
];

fn scan_roots(level: &str) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = vec![];
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users".into());
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let temp = std::env::var("TEMP").unwrap_or_default();
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let programdata = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".into());
    match level {
        "Quick" => {
            for p in [appdata, local, temp] {
                if !p.is_empty() {
                    roots.push(PathBuf::from(p));
                }
            }
            roots.push(PathBuf::from(format!("{windir}\\Temp")));
            roots.push(PathBuf::from(format!("{home}")).join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
        }
        "Standard" => {
            for p in [appdata, local, temp] {
                if !p.is_empty() {
                    roots.push(PathBuf::from(p));
                }
            }
            roots.push(PathBuf::from(&home));
            roots.push(PathBuf::from(programdata));
            roots.push(PathBuf::from(format!("{windir}\\Temp")));
            roots.push(PathBuf::from(format!("{windir}\\System32\\Tasks")));
        }
        _ => {
            // Deep: practical full sweep of fixed drives without WinSxS explosion
            for p in [appdata, local, temp] {
                if !p.is_empty() {
                    roots.push(PathBuf::from(p));
                }
            }
            roots.push(PathBuf::from(&home));
            roots.push(PathBuf::from(programdata));
            roots.push(PathBuf::from(format!("{windir}\\Temp")));
            // fixed drives C:\ (+D:, E: if present)
            for d in ["C:\\", "D:\\", "E:\\"] {
                if Path::new(d).exists() {
                    roots.push(PathBuf::from(d));
                }
            }
        }
    }
    roots.into_iter().filter(|p| p.exists()).collect()
}

fn is_executable(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|s| s.to_lowercase()).as_deref(),
        Some("exe") | Some("dll") | Some("sys") | Some("ps1") | Some("bat") | Some("cmd") | Some("vbs") | Some("js") | Some("msi") | Some("scr") | Some("com")
    )
}

fn classify(path: &Path, publisher: &str, signature: &str) -> Option<(String, String, String)> {
    let lower = path.display().to_string().to_lowercase();
    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
    // Never flag core Microsoft Windows servicing locations as malware.
    let in_winsxs = lower.contains("windows\\winsxs") || lower.contains("windows\\servicing");
    let is_ms = publisher.to_lowercase().contains("microsoft") || publisher.to_lowercase().contains("windows");
    // PUP by known name
    if PUP_NAMES.iter().any(|n| lower.contains(n)) {
        return Some((
            "Potentially Unwanted".into(),
            "Known potentially-unwanted program name pattern.".into(),
            "Defender PUA heuristics + filename evidence. Confirm in Threats before acting.".into(),
        ));
    }
    // Double extension (invoice.pdf.exe)
    if fname.matches('.').count() >= 2 && is_executable(path) {
        if !(is_ms && signature == "Signed") && !in_winsxs {
            return Some((
                "Suspicious".into(),
                "Executable uses a double extension, a common social-engineering pattern.".into(),
                "Filename evidence only. Verify publisher and signature.".into(),
            ));
        }
    }
    // Unsigned executable in Temp + persistence-adjacent
    let in_temp = lower.contains("\\temp\\") || lower.contains("\\tmp\\");
    if in_temp && is_executable(path) && signature == "Unsigned" && !in_winsxs {
        return Some((
            "Suspicious".into(),
            "Unsigned executable located in a temporary directory.".into(),
            "Location + signature evidence only. Unsigned does not mean malicious.".into(),
        ));
    }
    // Unsigned executable in user startup-reachable locations
    if (lower.contains("startup") || lower.contains("\\run")) && is_executable(path) && signature != "Signed" && !in_winsxs {
        return Some((
            "Suspicious".into(),
            "Unsigned executable in a startup/persistence location.".into(),
            "Review in Startup Manager. Do not delete without confirmation.".into(),
        ));
    }
    None
}

#[tauri::command]
pub async fn cmd_start_scan(
    app: AppHandle,
    level: String,
) -> Result<serde_json::Value, String> {
    let level = match level.as_str() {
        "Quick" | "Standard" | "Deep" => level,
        _ => "Quick".into(),
    };
    let scan_id = uuid::Uuid::new_v4().to_string();
    let cancel = Arc::new(AtomicBool::new(false));
    let pause = Arc::new(AtomicBool::new(false));
    CONTROLS.lock().insert(
        scan_id.clone(),
        ScanControl { cancel: cancel.clone(), pause: pause.clone() },
    );
    let app2 = app.clone();
    let sid = scan_id.clone();
    let lvl = level.clone();
    tokio::task::spawn_blocking(move || {
        run_scan_blocking(app2, sid, lvl, cancel, pause);
    });
    crate::core::log_event("scan.start", &format!("{level} scan started"), "ok");
    Ok(serde_json::json!({ "scan_id": scan_id, "level": level }))
}

fn run_scan_blocking(
    app: AppHandle,
    scan_id: String,
    level: String,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
) {
    let start = Instant::now();
    let roots = scan_roots(&level);
    let mut files_scanned: u64 = 0;
    let mut detections: Vec<Detection> = vec![];
    let mut counts: HashMap<String, u64> = HashMap::new();
    let max_files: u64 = match level.as_str() {
        "Quick" => 120_000,
        "Standard" => 600_000,
        _ => 2_000_000,
    };
    // Seed with Defender's own detections (trusted source → Threat)
    for t in crate::threats::defender_threats_impl().unwrap_or_default() {
        let (sig, publ) = if Path::new(&t.path).exists() {
            authenticode(Path::new(&t.path))
        } else {
            ("Unknown".into(), String::new())
        };
        detections.push(Detection {
            id: uuid::Uuid::new_v4().to_string(),
            file: Path::new(&t.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string(),
            path: t.path.clone(),
            publisher: publ,
            signature: sig,
            hash: if Path::new(&t.path).exists() {
                sha256_file(Path::new(&t.path))
            } else {
                "Unable to determine".into()
            },
            source: "Windows Defender".into(),
            risk: "Threat".into(),
            reason: t.detail,
            ignored: false,
        });
    }
    let mut last_emit: Instant;
    'outer: for root in &roots {
        // Report each new root immediately so the UI always shows a live,
        // real location (a handful of roots — cheap to emit).
        emit_progress(&app, &scan_id, &level, true, pause.load(Ordering::Relaxed), &root.display().to_string(), files_scanned, &detections, start);
        last_emit = Instant::now();
        let walker = WalkDir::new(root)
            .follow_links(false)
            .max_depth(if level == "Deep" { 14 } else { 10 })
            .into_iter()
            .filter_entry(|e| {
                // Skip reparse-heavy servicing dirs in non-deep scans
                if level != "Deep" {
                    let p = e.path().display().to_string().to_lowercase();
                    if p.contains("winsxs") || p.contains("$recycle.bin") || p.contains("system volume information") {
                        return false;
                    }
                }
                true
            });
        for entry in walker {
            if cancel.load(Ordering::Relaxed) {
                break 'outer;
            }
            while pause.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(200));
                if cancel.load(Ordering::Relaxed) {
                    break 'outer;
                }
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() {
                continue;
            }
            files_scanned += 1;
            let path = entry.path();
            // Emit at most every 300ms so UI stays responsive with REAL numbers.
            if last_emit.elapsed().as_millis() > 300 {
                let current = path.display().to_string();
                emit_progress(&app, &scan_id, &level, true, pause.load(Ordering::Relaxed), &current, files_scanned, &detections, start);
                last_emit = Instant::now();
            }
            // Only deep-inspect executables/scripts to stay fast + honest.
            if !is_executable(path) {
                // Cheap suspicious check: double-extension executables already covered;
                // skip hashing non-executables.
                if files_scanned >= max_files {
                    break 'outer;
                }
                continue;
            }
            // Bound expensive Authenticode to plausible candidates.
            let lower = path.display().to_string().to_lowercase();
            let interesting = lower.contains("temp") || lower.contains("startup") || lower.contains("appdata") || PUP_NAMES.iter().any(|n| lower.contains(n)) || path.file_name().and_then(|n| n.to_str()).map(|n| n.matches('.').count() >= 2).unwrap_or(false);
            if !interesting {
                if files_scanned >= max_files {
                    break 'outer;
                }
                continue;
            }
            let (sig, publ) = authenticode(path);
            // Evidence rule: never call Microsoft-signed malware.
            if publ.to_lowercase().contains("microsoft") && sig == "Signed" {
                if files_scanned >= max_files {
                    break 'outer;
                }
                continue;
            }
            if let Some((risk, reason, _extra)) = classify(path, &publ, &sig) {
                let d = Detection {
                    id: uuid::Uuid::new_v4().to_string(),
                    file: path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
                    path: path.display().to_string(),
                    publisher: if publ.is_empty() { "Unknown".into() } else { publ },
                    signature: sig,
                    hash: sha256_file(path),
                    source: "Open Windows heuristics + Authenticode".into(),
                    risk: risk.clone(),
                    reason,
                    ignored: false,
                };
                *counts.entry(risk).or_insert(0) += 1;
                detections.push(d);
                if detections.len() > 500 {
                    // Cap stored detections; files_scanned remains exact.
                    break 'outer;
                }
            }
            if files_scanned >= max_files {
                break 'outer;
            }
        }
    }
    // Final counts
    let mut final_counts: HashMap<String, u64> = HashMap::new();
    for d in &detections {
        *final_counts.entry(d.risk.clone()).or_insert(0) += 1;
    }
    let result = ScanResult {
        scan_id: scan_id.clone(),
        level: level.clone(),
        date: Utc::now(),
        duration_secs: start.elapsed().as_secs(),
        files_scanned,
        threats: detections.clone(),
        counts: final_counts.clone(),
    };
    RESULTS.lock().insert(scan_id.clone(), result.clone());
    // Persist history (local only, never uploaded)
    append_scan_history(serde_json::json!({
        "scan_id": scan_id,
        "level": level,
        "date": result.date.to_rfc3339(),
        "files_scanned": files_scanned,
        "threats": final_counts.get("Threat").cloned().unwrap_or(0),
        "suspicious": final_counts.get("Suspicious").cloned().unwrap_or(0),
        "pup": final_counts.get("Potentially Unwanted").cloned().unwrap_or(0),
        "informational": final_counts.get("Informational").cloned().unwrap_or(0),
        "duration_secs": result.duration_secs,
        "cancelled": cancel.load(Ordering::Relaxed),
    }));
    // Merge scan detections into global threat store
    crate::threats::merge_scan_detections(detections);
    emit_progress(&app, &scan_id, &level, false, false, "Complete", files_scanned, &RESULTS.lock().get(&scan_id).map(|r| r.threats.clone()).unwrap_or_default(), start);
    crate::core::log_event(
        "scan.complete",
        &format!("{level} scan: {files_scanned} files"),
        "ok",
    );
    CONTROLS.lock().remove(&scan_id);
}

fn emit_progress(
    app: &AppHandle,
    scan_id: &str,
    level: &str,
    running: bool,
    paused: bool,
    current: &str,
    files: u64,
    detections: &[Detection],
    start: Instant,
) {
    let (mut t, mut s, mut p, mut i) = (0u64, 0u64, 0u64, 0u64);
    for d in detections {
        match d.risk.as_str() {
            "Threat" => t += 1,
            "Suspicious" => s += 1,
            "Potentially Unwanted" => p += 1,
            _ => i += 1,
        }
    }
    let _ = app.emit(
        "scan-progress",
        ScanProgress {
            scan_id: scan_id.into(),
            level: level.into(),
            running,
            paused,
            current_location: current.chars().take(320).collect(),
            files_scanned: files,
            threats: t,
            suspicious: s,
            pup: p,
            informational: i,
            elapsed_secs: start.elapsed().as_secs(),
        },
    );
}

#[tauri::command]
pub fn cmd_cancel_scan(scan_id: String) -> Result<String, String> {
    if let Some(c) = CONTROLS.lock().get(&scan_id) {
        c.cancel.store(true, Ordering::Relaxed);
        crate::core::log_event("scan.cancel", &scan_id, "ok");
        Ok("Cancellation requested.".into())
    } else {
        Err("Scan is not running.".into())
    }
}

#[tauri::command]
pub fn cmd_pause_scan(scan_id: String) -> Result<String, String> {
    if let Some(c) = CONTROLS.lock().get(&scan_id) {
        c.pause.store(true, Ordering::Relaxed);
        Ok("Paused.".into())
    } else {
        Err("Scan is not running.".into())
    }
}

#[tauri::command]
pub fn cmd_resume_scan(scan_id: String) -> Result<String, String> {
    if let Some(c) = CONTROLS.lock().get(&scan_id) {
        c.pause.store(false, Ordering::Relaxed);
        Ok("Resumed.".into())
    } else {
        Err("Scan is not running.".into())
    }
}

#[tauri::command]
pub fn cmd_get_scan_history() -> Vec<serde_json::Value> {
    let mut h = read_scan_history();
    h.reverse();
    h
}
