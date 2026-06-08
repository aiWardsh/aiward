use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::ValueEnum;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::fs_util;

const GENESIS_HASH: &str = "GENESIS";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const LOG_KEY_ALGORITHM: &str = "AES-256-GCM";

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogKind {
    Requests,
    Approvals,
    Executions,
    Alerts,
    Sessions,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent<T> {
    pub id: uuid::Uuid,
    pub timestamp: String,
    pub payload: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedLogEntry {
    pub version: u32,
    pub kind: LogKind,
    pub sequence: u64,
    pub timestamp: String,
    pub previous_hash: String,
    pub nonce: String,
    pub ciphertext: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogVerification {
    pub kind: LogKind,
    pub path: PathBuf,
    pub entries: usize,
    pub valid: bool,
}

pub fn ward_home() -> PathBuf {
    match std::env::var("WARD_HOME")
        .ok()
        .filter(|path| !path.trim().is_empty())
    {
        Some(path) => PathBuf::from(path),
        None => default_ward_home(),
    }
}

fn default_ward_home() -> PathBuf {
    dirs::home_dir().unwrap_or(PathBuf::from(".")).join(".ward")
}

pub fn logs_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new("logs"), "logs directory")
        .expect("logs directory should stay inside Ward home")
}

pub fn recovery_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new("recovery"), "recovery directory")
        .expect("recovery directory should stay inside Ward home")
}

pub fn project_modes_dir(project: &str) -> PathBuf {
    let relative = PathBuf::from("projects").join(slugify(project));
    fs_util::resolve_ward_home_path(&relative, "project modes directory")
        .expect("project modes directory should stay inside Ward home")
}

fn slugify(project: &str) -> String {
    project
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn cache_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new("cache"), "cache directory")
        .expect("cache directory should stay inside Ward home")
}

fn log_key_path() -> PathBuf {
    cache_dir().join("log-key.json")
}

pub fn log_path(kind: LogKind) -> PathBuf {
    logs_dir().join(kind.file_name())
}

pub fn entry_count(kind: LogKind) -> Result<usize> {
    Ok(read_entries(&log_path(kind))?.len())
}

pub fn append_event<T: Serialize>(kind: LogKind, payload: T) -> Result<()> {
    let event = AuditEvent {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        payload,
    };
    let payload = serde_json::to_vec(&event)?;
    append_encrypted_payload(kind, &payload)?;
    Ok(())
}

fn append_encrypted_payload(kind: LogKind, payload: &[u8]) -> Result<()> {
    fs_util::ensure_private_dir(&ward_home())?;
    let dir = logs_dir();
    fs_util::ensure_private_dir(&dir)?;

    let key = log_key()?;
    let path = log_path(kind);
    let last = last_entry(&path)?;
    let (sequence, previous_hash) = match last.as_ref() {
        Some(entry) => (entry.sequence + 1, entry.entry_hash.clone()),
        None => (1, GENESIS_HASH.to_string()),
    };
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = aad(kind, sequence, &timestamp, &previous_hash);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("log key has valid AES-256 length");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: aad.as_bytes(),
            },
        )
        .expect("AES-GCM encryption should not fail for a valid nonce");

    let mut entry = EncryptedLogEntry {
        version: 1,
        kind,
        sequence,
        timestamp,
        previous_hash,
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
        entry_hash: String::new(),
    };
    entry.entry_hash = entry_hash(&entry);

    let mut file = fs_util::open_private_append(&path)?;
    let line = serde_json::to_string(&entry).expect("encrypted log entry should serialize");
    writeln!(file, "{line}").context(format!("failed to write {}", path.display()))
}

pub fn decrypt_events(kind: LogKind) -> Result<Vec<Value>> {
    let key = log_key()?;
    let entries = read_entries(&log_path(kind))?;
    entries
        .iter()
        .map(|entry| decrypt_entry(entry, &key))
        .collect()
}

pub fn verify_logs(kind: Option<LogKind>) -> Result<Vec<LogVerification>> {
    verify_logs_with_mode(kind, false)
}

pub fn verify_logs_full(kind: Option<LogKind>) -> Result<Vec<LogVerification>> {
    verify_logs_with_mode(kind, true)
}

fn verify_logs_with_mode(
    kind: Option<LogKind>,
    decrypt_payloads: bool,
) -> Result<Vec<LogVerification>> {
    let kinds = match kind {
        Some(kind) => vec![kind],
        None => LogKind::all().to_vec(),
    };
    kinds
        .into_iter()
        .map(|kind| verify_log(kind, decrypt_payloads))
        .collect::<Result<Vec<_>>>()
}

fn verify_log(kind: LogKind, decrypt_payloads: bool) -> Result<LogVerification> {
    let path = log_path(kind);
    let entries = read_entries(&path)?;
    let mut previous_hash = GENESIS_HASH.to_string();
    let mut expected_sequence = 1_u64;
    let key = if decrypt_payloads {
        Some(log_key()?)
    } else {
        None
    };

    for entry in &entries {
        if entry.kind != kind {
            anyhow::bail!(
                "{} contains an entry for a different log kind",
                path.display()
            );
        }
        if entry.sequence != expected_sequence {
            anyhow::bail!(
                "{} has a sequence gap at {}",
                path.display(),
                entry.sequence
            );
        }
        if entry.previous_hash != previous_hash {
            anyhow::bail!("{} has a broken hash chain", path.display());
        }
        if entry.entry_hash != entry_hash(entry) {
            anyhow::bail!("{} has a modified entry hash", path.display());
        }
        if let Some(key) = key.as_ref() {
            decrypt_entry(entry, key)?;
        }
        previous_hash = entry.entry_hash.clone();
        expected_sequence += 1;
    }

    Ok(LogVerification {
        kind,
        path,
        entries: entries.len(),
        valid: true,
    })
}

fn decrypt_entry(entry: &EncryptedLogEntry, key: &[u8; KEY_LEN]) -> Result<Value> {
    if entry.version != 1 {
        anyhow::bail!("unsupported encrypted log version {}", entry.version);
    }
    let nonce = STANDARD.decode(&entry.nonce)?;
    if nonce.len() != NONCE_LEN {
        anyhow::bail!("encrypted log nonce has invalid length");
    }
    let ciphertext = STANDARD.decode(&entry.ciphertext)?;
    let aad = aad(
        entry.kind,
        entry.sequence,
        &entry.timestamp,
        &entry.previous_hash,
    );
    let cipher = Aes256Gcm::new_from_slice(key).expect("log key has valid AES-256 length");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("failed to decrypt encrypted log entry"))?;
    serde_json::from_slice(&plaintext).context("encrypted log payload is not valid JSON")
}

fn last_entry(path: &Path) -> Result<Option<EncryptedLogEntry>> {
    let entries = read_entries(path)?;
    Ok(entries.into_iter().last())
}

fn read_entries(path: &Path) -> Result<Vec<EncryptedLogEntry>> {
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        anyhow::bail!("Invalid input: {}", path.display());
    }
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents =
        fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
    contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<EncryptedLogEntry>(line).with_context(|| {
                format!(
                    "failed to parse encrypted log entry on line {} of {}",
                    index + 1,
                    path.display()
                )
            })
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogKeyFile {
    version: u32,
    algorithm: String,
    key: String,
}

fn log_key() -> Result<[u8; KEY_LEN]> {
    let path = log_key_path();
    if path.exists() {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let stored: LogKeyFile = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        if stored.version != 1 {
            anyhow::bail!("stored log key has unsupported version {}", stored.version);
        }
        if stored.algorithm != LOG_KEY_ALGORITHM {
            anyhow::bail!(
                "stored log key has unsupported algorithm {}",
                stored.algorithm
            );
        }
        let bytes = STANDARD
            .decode(stored.key)
            .context("stored log key is not valid base64")?;
        return bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored log key has invalid length"));
    }

    let mut key = [0_u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    write_log_key(&path, &key)?;
    Ok(key)
}

fn write_log_key(path: &Path, key: &[u8; KEY_LEN]) -> Result<()> {
    fs_util::ensure_private_dir(&ward_home())?;
    fs_util::ensure_private_dir(&cache_dir())?;
    let stored = LogKeyFile {
        version: 1,
        algorithm: LOG_KEY_ALGORITHM.to_string(),
        key: STANDARD.encode(key),
    };
    let contents =
        serde_json::to_string_pretty(&stored).expect("log key serialization is infallible");
    fs_util::write_private_file(path, format!("{contents}\n").as_bytes())
}

fn aad(kind: LogKind, sequence: u64, timestamp: &str, previous_hash: &str) -> String {
    format!(
        "{}:{}:{}:{}",
        kind.as_str(),
        sequence,
        timestamp,
        previous_hash
    )
}

fn entry_hash(entry: &EncryptedLogEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.version.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(entry.kind.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(entry.sequence.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(entry.timestamp.as_bytes());
    hasher.update(b"\0");
    hasher.update(entry.previous_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(entry.nonce.as_bytes());
    hasher.update(b"\0");
    hasher.update(entry.ciphertext.as_bytes());
    hex::encode(hasher.finalize())
}

impl LogKind {
    pub fn file_name(self) -> &'static str {
        match self {
            LogKind::Requests => "requests.jsonl",
            LogKind::Approvals => "approvals.jsonl",
            LogKind::Executions => "executions.jsonl",
            LogKind::Alerts => "alerts.jsonl",
            LogKind::Sessions => "sessions.jsonl",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LogKind::Requests => "requests",
            LogKind::Approvals => "approvals",
            LogKind::Executions => "executions",
            LogKind::Alerts => "alerts",
            LogKind::Sessions => "sessions",
        }
    }

    pub fn all() -> &'static [LogKind] {
        &[
            LogKind::Requests,
            LogKind::Approvals,
            LogKind::Executions,
            LogKind::Alerts,
            LogKind::Sessions,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn log_kind_file_names_are_stable() {
        assert_eq!(LogKind::Requests.file_name(), "requests.jsonl");
        assert_eq!(LogKind::Approvals.file_name(), "approvals.jsonl");
        assert_eq!(LogKind::Executions.file_name(), "executions.jsonl");
        assert_eq!(LogKind::Alerts.file_name(), "alerts.jsonl");
        assert_eq!(LogKind::Sessions.file_name(), "sessions.jsonl");
    }

    #[test]
    #[serial_test::serial]
    fn ward_home_uses_override_and_falls_back_to_home() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();

        std::env::set_var("WARD_HOME", tempdir.path());
        assert_eq!(ward_home(), tempdir.path());

        std::env::set_var("WARD_HOME", "");
        assert!(ward_home().ends_with(".ward"));

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn append_decrypt_and_verify_encrypted_events() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");

        append_event(
            LogKind::Requests,
            json!({ "kind": "request", "secret": "hidden" }),
        )
        .unwrap();
        append_event(LogKind::Alerts, json!({ "kind": "alert" })).unwrap();

        let raw = std::fs::read_to_string(log_path(LogKind::Requests)).unwrap();
        assert!(!raw.contains("hidden"));
        let events = decrypt_events(LogKind::Requests).unwrap();
        assert_eq!(events[0]["payload"]["kind"], "request");
        assert!(verify_logs(Some(LogKind::Requests)).unwrap()[0].valid);

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn log_key_is_stored_in_private_local_cache_file() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());

        let first = log_key().unwrap();
        let second = log_key().unwrap();
        assert_eq!(first, second);

        let path = log_key_path();
        assert!(path.ends_with("cache/log-key.json"));
        assert!(path.exists());
        assert!(!tempdir.path().join("cache").join("keystore.json").exists());

        let stored: LogKeyFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.algorithm, LOG_KEY_ALGORITHM);
        assert_eq!(STANDARD.decode(stored.key).unwrap().len(), KEY_LEN);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let home_mode = std::fs::metadata(tempdir.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let cache_mode = std::fs::metadata(tempdir.path().join("cache"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(home_mode, 0o700);
            assert_eq!(cache_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn verification_detects_tampered_entries() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");

        append_event(LogKind::Sessions, json!({ "kind": "session" })).unwrap();
        let path = log_path(LogKind::Sessions);
        let mut entry: EncryptedLogEntry =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        entry.sequence = 99;
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();

        assert!(verify_logs(Some(LogKind::Sessions)).is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn verifies_all_logs_and_detects_chain_kind_hash_and_parse_errors() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");

        for kind in LogKind::all() {
            append_event(*kind, json!({ "kind": kind.as_str() })).unwrap();
            append_event(*kind, json!({ "kind": kind.as_str(), "second": true })).unwrap();
        }
        assert_eq!(verify_logs(None).unwrap().len(), LogKind::all().len());
        assert!(!decrypt_events(LogKind::Approvals).unwrap().is_empty());
        assert!(!decrypt_events(LogKind::Executions).unwrap().is_empty());

        let path = log_path(LogKind::Alerts);
        let mut entries = read_entries(&path).unwrap();
        entries[0].kind = LogKind::Requests;
        entries[0].entry_hash = entry_hash(&entries[0]);
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entries[0]).unwrap()),
        )
        .unwrap();
        assert!(verify_logs(Some(LogKind::Alerts)).is_err());

        let path = log_path(LogKind::Sessions);
        let mut entries = read_entries(&path).unwrap();
        entries[1].previous_hash = "broken".to_string();
        entries[1].entry_hash = entry_hash(&entries[1]);
        std::fs::write(
            &path,
            entries
                .iter()
                .map(|entry| serde_json::to_string(entry).unwrap())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        assert!(verify_logs(Some(LogKind::Sessions)).is_err());

        let path = log_path(LogKind::Requests);
        let mut entries = read_entries(&path).unwrap();
        entries[0].ciphertext.push('a');
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entries[0]).unwrap()),
        )
        .unwrap();
        assert!(verify_logs_full(Some(LogKind::Requests)).is_err());

        std::fs::write(log_path(LogKind::Approvals), "{bad-json}\n").unwrap();
        assert!(verify_logs(Some(LogKind::Approvals)).is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn decrypt_rejects_invalid_entry_metadata_and_key_material() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");

        append_event(LogKind::Requests, json!({ "kind": "request" })).unwrap();
        let mut entry = read_entries(&log_path(LogKind::Requests)).unwrap()[0].clone();
        let key = log_key().unwrap();

        std::fs::write(
            log_key_path(),
            r#"{"version":1,"algorithm":"AES-256-GCM","key":"not-base64"}"#,
        )
        .unwrap();
        assert!(verify_logs_full(Some(LogKind::Requests)).is_err());
        write_log_key(&log_key_path(), &key).unwrap();

        entry.version = 99;
        assert!(decrypt_entry(&entry, &key).is_err());
        entry.version = 1;
        entry.nonce = STANDARD.encode([0_u8; 2]);
        assert!(decrypt_entry(&entry, &key).is_err());
        entry.nonce = STANDARD.encode([0_u8; NONCE_LEN]);
        assert!(decrypt_entry(&entry, &key).is_err());

        std::fs::write(
            log_key_path(),
            r#"{"version":1,"algorithm":"AES-256-GCM","key":"not-base64"}"#,
        )
        .unwrap();
        assert!(log_key().is_err());
        std::fs::write(
            log_key_path(),
            format!(
                r#"{{"version":1,"algorithm":"AES-256-GCM","key":"{}"}}"#,
                STANDARD.encode([1_u8; 2])
            ),
        )
        .unwrap();
        assert!(log_key().is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn append_event_reports_log_directory_creation_failures() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let blocked = tempdir.path().join("blocked");
        std::fs::write(&blocked, "").unwrap();
        std::env::set_var("WARD_HOME", &blocked);
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");

        append_event(LogKind::Requests, json!({ "kind": "request" }))
            .expect_err("read-only log directory should reject append");

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn append_event_reports_log_file_open_failures() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::fs::create_dir_all(log_path(LogKind::Requests)).unwrap();

        assert!(append_event(LogKind::Requests, json!({ "kind": "request" })).is_err());

        std::fs::remove_dir_all(log_path(LogKind::Requests)).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn log_helpers_report_serialization_read_decrypt_and_key_creation_failures() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");

        append_event(LogKind::Requests, json!({ "kind": "request" })).unwrap();
        let path = log_path(LogKind::Requests);
        let key = log_key().unwrap();
        let mut entry = read_entries(&path).unwrap()[0].clone();

        entry.ciphertext.push('a');
        entry.entry_hash = entry_hash(&entry);
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        assert!(verify_logs_full(Some(LogKind::Requests)).is_err());

        let mut invalid = entry.clone();
        invalid.nonce = "***".to_string();
        assert!(decrypt_entry(&invalid, &key).is_err());
        invalid.nonce = STANDARD.encode([0_u8; NONCE_LEN]);
        invalid.ciphertext = "***".to_string();
        assert!(decrypt_entry(&invalid, &key).is_err());

        let directory_path = log_path(LogKind::Approvals);
        std::fs::create_dir_all(&directory_path).unwrap();
        assert!(read_entries(&directory_path).is_err());
        assert!(decrypt_events(LogKind::Approvals).is_err());
        assert!(append_event(LogKind::Approvals, json!({ "kind": "approval" })).is_err());

        std::fs::write(
            log_key_path(),
            r#"{"version":1,"algorithm":"AES-256-GCM","key":"not-base64"}"#,
        )
        .unwrap();
        assert!(append_event(LogKind::Alerts, json!({ "kind": "alert" })).is_err());
        assert!(decrypt_events(LogKind::Requests).is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");

        let corrupt_home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", corrupt_home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let cache = corrupt_home.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("log-key.json"), "{bad-json}").unwrap();
        assert!(log_key().is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");

        let blocked_home = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("WARD_HOME", blocked_home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        assert!(log_key().is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }
}
