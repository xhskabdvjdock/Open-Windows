//! Storage analyzer + duplicate finder (SHA-256 hashing).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderEntry {
    pub path: String,
    pub bytes: u64,
    pub human: String,
    pub files: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DupGroup {
    pub hash: String,
    pub size: u64,
    pub human: String,
    pub files: Vec<String>,
}

fn human(b: u64) -> String {
    crate::cleanup::human(b)
}

fn dir_size_shallow(path: &Path, depth: u32) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut files = 0u64;
    for e in WalkDir::new(path).follow_links(false).max_depth(depth as usize).into_iter().flatten() {
        if e.file_type().is_file() {
            if let Ok(m) = e.metadata() {
                bytes += m.len();
                files += 1;
            }
            if files > 300_000 {
                break;
            }
        }
    }
    (bytes, files)
}

#[tauri::command]
pub fn cmd_analyze_storage(path: String) -> Result<serde_json::Value, String> {
    let base = if path.trim().is_empty() { "C:\\".to_string() } else { path };
    let bp = Path::new(&base);
    if !bp.exists() {
        return Err("Path does not exist.".into());
    }
    // Top-level breakdown
    let mut entries: Vec<FolderEntry> = vec![];
    if let Ok(rd) = fs::read_dir(bp) {
        for e in rd.flatten().take(60) {
            let p = e.path();
            let (b, f) = if p.is_dir() { dir_size_shallow(&p, 6) } else { e.metadata().map(|m| (m.len(), 1)).unwrap_or((0, 0)) };
            entries.push(FolderEntry {
                path: p.display().to_string(),
                bytes: b,
                human: human(b),
                files: f,
            });
        }
    }
    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    // Category rollup for C:\
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let progfiles = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
    let users = "C:\\Users";
    let temp = std::env::var("TEMP").unwrap_or_default();
    let cat = |p: &str| dir_size_shallow(Path::new(p), 5).0;
    let categories = serde_json::json!({
        "Windows": human(cat(&windir)),
        "Applications": human(cat(&progfiles)),
        "Users": human(if Path::new(users).exists() { cat(users) } else { 0 }),
        "Temporary": human(if temp.is_empty() { 0 } else { cat(&temp) }),
    });
    Ok(serde_json::json!({"base": base, "categories": categories, "entries": entries.into_iter().take(40).collect::<Vec<_>>()}))
}

fn hash_file(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    // Skip huge files > 2GB for practicality
    if f.metadata().ok()?.len() > 2_147_483_648 {
        return None;
    }
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

#[tauri::command]
pub fn cmd_find_duplicates(path: String, min_kb: u64) -> Result<Vec<DupGroup>, String> {
    let base = if path.trim().is_empty() { "C:\\Users".to_string() } else { path };
    if !Path::new(&base).exists() {
        return Err("Path does not exist.".into());
    }
    let min_bytes = min_kb.max(1) * 1024;
    // Phase 1: group by size
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    for e in WalkDir::new(&base).follow_links(false).max_depth(10).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        if let Ok(m) = e.metadata() {
            let sz = m.len();
            if sz >= min_bytes && sz < 2_147_483_648 {
                by_size.entry(sz).or_default().push(e.path().to_path_buf());
            }
        }
        if by_size.len() > 50_000 {
            break;
        }
    }
    // Phase 2: hash candidates with >1 same-size file
    let mut groups: Vec<DupGroup> = vec![];
    for (size, files) in by_size.into_iter().filter(|(_, f)| f.len() > 1).take(2000) {
        let mut by_hash: HashMap<String, Vec<String>> = HashMap::new();
        for f in files.into_iter().take(20) {
            if let Some(h) = hash_file(&f) {
                by_hash.entry(h).or_default().push(f.display().to_string());
            }
        }
        for (h, fs) in by_hash.into_iter().filter(|(_, f)| f.len() > 1) {
            groups.push(DupGroup { hash: h, size, human: human(size), files: fs });
            if groups.len() >= 200 {
                break;
            }
        }
        if groups.len() >= 200 {
            break;
        }
    }
    groups.sort_by(|a, b| b.size.cmp(&a.size));
    crate::core::log_event("storage.duplicates", &format!("{base}: {} groups", groups.len()), "ok");
    Ok(groups)
}

#[tauri::command]
pub fn cmd_delete_files(paths: Vec<String>) -> Result<String, String> {
    if paths.is_empty() {
        return Err("No files selected.".into());
    }
    if paths.len() > 100 {
        return Err("Select at most 100 files per operation.".into());
    }
    let mut ok = 0;
    let mut errs: Vec<String> = vec![];
    for p in &paths {
        // Safety: refuse Windows / Program Files / System32 deletes
        let l = p.to_lowercase();
        if l.starts_with("c:\\windows") || l.starts_with("c:\\program files") || l.contains("system32") {
            errs.push(format!("Refused (system location): {p}"));
            continue;
        }
        match fs::remove_file(p) {
            Ok(_) => ok += 1,
            Err(e) => errs.push(format!("{p}: {e}")),
        }
    }
    crate::core::push_history(crate::core::HistoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        date: chrono::Utc::now(),
        category: "storage".into(),
        change: format!("Deleted {ok} file(s) via Storage/Duplicates"),
        previous_value: paths.join("; ").chars().take(800).collect(),
        new_value: format!("{ok} deleted"),
        reversible: false,
        revert_info: serde_json::json!({}),
    });
    Ok(format!("{ok} file(s) deleted.{}", if errs.is_empty() { String::new() } else { format!("\nSkipped:\n{}", errs.join("\n")) }))
}
