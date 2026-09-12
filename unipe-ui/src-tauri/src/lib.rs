use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ALERTS: &str = "/tmp/unipe/alerts.jsonl";
const DEFAULT_STATUS: &str = "/tmp/unipe/status.json";
const DEFAULT_SOCKET: &str = "/tmp/unipe.sock";
const DEFAULT_ENTITIES: &str = "/tmp/unipe/entities.json";
const MAX_ALERT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ENTITY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct PipelineSnapshot {
    pub alerts: Vec<Value>,
    pub alert_count: usize,
    pub alerts_path: String,
    /// file identity so the UI can skip re-parsing when nothing changed
    pub alerts_stamp: String,
    pub alerts_unchanged: bool,
    pub status: Option<Value>,
    pub status_path: String,
    pub entities: Option<Value>,
    pub entities_path: String,
    pub entities_stamp: String,
    pub entities_unchanged: bool,
    pub socket_path: String,
    pub exporter_up: bool,
    pub engine_up: bool,
    pub flows_per_sec: f64,
    pub tap_one_directional: bool,
    pub tap_message: String,
    pub live: bool,
    pub polled_at: f64,
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn file_stamp(path: &Path) -> String {
    match fs::metadata(path) {
        Ok(meta) => {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("{}:{}", mtime, meta.len())
        }
        Err(_) => "missing".to_string(),
    }
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    if !meta.is_file() {
        return Vec::new();
    }
    // avoid loading a runaway log into the webview
    if meta.len() > MAX_ALERT_BYTES {
        return read_jsonl_tail(path, MAX_ALERT_BYTES);
    }
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_jsonl(&text)
}

fn read_jsonl_tail(path: &Path, max_bytes: u64) -> Vec<Value> {
    let Ok(file) = fs::File::open(path) else {
        return Vec::new();
    };
    use std::io::{Read, Seek, SeekFrom};
    let mut file = file;
    let Ok(len) = file.seek(SeekFrom::End(0)) else {
        return Vec::new();
    };
    let start = len.saturating_sub(max_bytes);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = String::new();
    if file.read_to_string(&mut buf).is_err() {
        return Vec::new();
    };
    // drop a possible partial first line
    if start > 0 {
        if let Some(idx) = buf.find('\n') {
            buf = buf[idx + 1..].to_string();
        }
    }
    parse_jsonl(&buf)
}

fn parse_jsonl(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            if value.get("threat_class").is_some() && value.get("message").is_some() {
                out.push(value);
            }
        }
    }
    out
}

fn read_status(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn read_entities(path: &Path) -> Option<Value> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_ENTITY_BYTES {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn engine_fresh(status: &Option<Value>) -> bool {
    let Some(status) = status else {
        return false;
    };
    let updated = status
        .get("updated_at")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let running = status
        .get("running")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    running && now_secs() - updated < 15.0
}

/// Read pipeline snapshot. When `load_entities` is false (default), skip
/// reading/parsing entities.json — dossier opens on demand.
#[tauri::command]
fn read_pipeline(
    alerts_path: Option<String>,
    status_path: Option<String>,
    socket_path: Option<String>,
    entities_path: Option<String>,
    previous_stamp: Option<String>,
    previous_entities_stamp: Option<String>,
    load_entities: Option<bool>,
) -> PipelineSnapshot {
    let alerts_path = alerts_path.unwrap_or_else(|| DEFAULT_ALERTS.to_string());
    let status_path = status_path.unwrap_or_else(|| DEFAULT_STATUS.to_string());
    let socket_path = socket_path.unwrap_or_else(|| DEFAULT_SOCKET.to_string());
    let entities_path =
        entities_path.unwrap_or_else(|| DEFAULT_ENTITIES.to_string());
    let load_entities = load_entities.unwrap_or(false);

    let alerts_stamp = file_stamp(Path::new(&alerts_path));
    let alerts_unchanged = previous_stamp
        .as_deref()
        .is_some_and(|prev| prev == alerts_stamp);
    let alerts = if alerts_unchanged {
        Vec::new()
    } else {
        read_jsonl(Path::new(&alerts_path))
    };

    let entities_stamp = file_stamp(Path::new(&entities_path));
    let entities_unchanged = previous_entities_stamp
        .as_deref()
        .is_some_and(|prev| prev == entities_stamp);
    let entities = if !load_entities || entities_unchanged {
        None
    } else {
        read_entities(Path::new(&entities_path))
    };

    let status = read_status(Path::new(&status_path));
    let exporter_up = PathBuf::from(&socket_path).exists();
    let engine_up = engine_fresh(&status);

    let flows_per_sec = status
        .as_ref()
        .and_then(|s| s.get("flows_per_sec"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let tap = status.as_ref().and_then(|s| s.get("tap"));
    let tap_one_directional = tap
        .and_then(|t| t.get("one_directional"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let tap_message = tap
        .and_then(|t| t.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let alert_count = if alerts_unchanged {
        status
            .as_ref()
            .and_then(|s| s.get("alerts"))
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(0)
    } else {
        status
            .as_ref()
            .and_then(|s| s.get("alerts"))
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(alerts.len())
    };

    PipelineSnapshot {
        alert_count,
        alerts,
        alerts_path,
        alerts_stamp,
        alerts_unchanged,
        status,
        status_path,
        entities,
        entities_path,
        entities_stamp,
        entities_unchanged,
        socket_path,
        exporter_up,
        engine_up,
        flows_per_sec,
        tap_one_directional,
        tap_message,
        live: exporter_up || engine_up,
        polled_at: now_secs(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![read_pipeline])
        .run(tauri::generate_context!())
        .expect("failed to run tauri application");
}
