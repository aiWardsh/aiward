use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{approval_receipts, fs_util, key_store, logs};

const RUN_UNLOCK_PREFIX: &str = "unlock/run";
const LOG_UNLOCK_PREFIX: &str = "unlock/logs";
const MODE_UNLOCK_PREFIX: &str = "unlock/mode";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockSession {
    pub id: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub project: String,
    pub vault: PathBuf,
    pub key_name: String,
    pub purpose: UnlockPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_ciphertext: Option<approval_receipts::SigningKeyCiphertext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockPurpose {
    Run,
    Logs,
    Mode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunUnlockLookup {
    Available(String),
    Missing,
    MaterialUnavailable { reason: String },
}

impl RunUnlockLookup {
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Missing => Some("missing_unlock_session"),
            Self::MaterialUnavailable { reason } => Some(reason.as_str()),
            Self::Available(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum RunSigningLookup {
    Available(approval_receipts::SessionSigningKey),
    Missing,
    MaterialUnavailable { reason: String },
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockState {
    sessions: Vec<UnlockSession>,
}

pub fn unlocks_path() -> PathBuf {
    let relative = PathBuf::from("sessions").join("unlocks.json");
    fs_util::resolve_ward_home_path(&relative, "unlock metadata path")
        .expect("unlock metadata path should stay inside Ward home")
}

pub fn parse_ttl(value: &str) -> Result<Duration> {
    let value = value.trim();
    if value.len() < 2 {
        anyhow::bail!("ttl must use a suffix: m, h, or d");
    }
    let (number, suffix) = value.split_at(value.len() - 1);
    let amount = number
        .parse::<i64>()
        .with_context(|| format!("invalid ttl amount: {number}"))?;
    if amount <= 0 {
        anyhow::bail!("ttl must be greater than zero");
    }

    match suffix {
        "m" => Ok(Duration::minutes(amount)),
        "h" => Ok(Duration::hours(amount)),
        "d" => Ok(Duration::days(amount)),
        other => anyhow::bail!("unsupported ttl suffix: {other}"),
    }
}

pub fn create_run_unlock(
    project: &str,
    vault: &Path,
    passphrase: &str,
    ttl: Duration,
) -> Result<UnlockSession> {
    create_unlock(project, vault, passphrase, ttl, UnlockPurpose::Run)
}

pub fn create_logs_unlock(project: &str, vault: &Path, ttl: Duration) -> Result<UnlockSession> {
    create_unlock(project, vault, "", ttl, UnlockPurpose::Logs)
}

pub fn create_mode_unlock(
    project: &str,
    vault: &Path,
    passphrase: &str,
    ttl: Duration,
    mode_name: &str,
) -> Result<UnlockSession> {
    create_unlock(
        project,
        vault,
        passphrase,
        ttl,
        UnlockPurpose::Mode(mode_name.to_string()),
    )
}

pub fn active_run_passphrase(project: &str, vault: &Path) -> Result<Option<String>> {
    let Some(session) = active_session(project, vault, UnlockPurpose::Run)? else {
        return Ok(None);
    };
    #[cfg(not(test))]
    {
        let _ = session;
        return Ok(None);
    }
    #[cfg(test)]
    key_store::get_secret(&session.key_name)
}

pub fn active_run_lookup(project: &str, vault: &Path) -> Result<RunUnlockLookup> {
    let Some(session) = active_session(project, vault, UnlockPurpose::Run)? else {
        return Ok(RunUnlockLookup::Missing);
    };
    #[cfg(not(test))]
    {
        let _ = session;
        return Ok(RunUnlockLookup::MaterialUnavailable {
            reason: "broker_unlock_only".to_string(),
        });
    }
    #[cfg(test)]
    match key_store::get_secret(&session.key_name) {
        Ok(Some(passphrase)) => Ok(RunUnlockLookup::Available(passphrase)),
        Ok(None) => Ok(RunUnlockLookup::MaterialUnavailable {
            reason: "unlock_material_unavailable".to_string(),
        }),
        Err(error) => Ok(RunUnlockLookup::MaterialUnavailable {
            reason: format!("unlock_material_unreadable: {error}"),
        }),
    }
}

pub fn active_run_session_metadata(project: &str, vault: &Path) -> Result<Option<UnlockSession>> {
    active_session(project, vault, UnlockPurpose::Run)
}

pub fn active_run_signing_key(project: &str, vault: &Path) -> Result<RunSigningLookup> {
    let Some(session) = active_session(project, vault, UnlockPurpose::Run)? else {
        return Ok(RunSigningLookup::Missing);
    };
    #[cfg(not(test))]
    {
        let _ = session;
        return Ok(RunSigningLookup::MaterialUnavailable {
            reason: "signing_key_unavailable".to_string(),
        });
    }
    #[cfg(test)]
    {
        let Some(ciphertext) = session.signing_key_ciphertext.as_ref() else {
            return Ok(RunSigningLookup::MaterialUnavailable {
                reason: "signing_key_unavailable".to_string(),
            });
        };
        let session_secret = match key_store::get_secret(&session.key_name) {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                return Ok(RunSigningLookup::MaterialUnavailable {
                    reason: "unlock_material_unavailable".to_string(),
                })
            }
            Err(error) => {
                return Ok(RunSigningLookup::MaterialUnavailable {
                    reason: format!("unlock_material_unreadable: {error}"),
                })
            }
        };
        match approval_receipts::decrypt_session_signing_key(ciphertext, &session_secret) {
            Ok(signing_key) => Ok(RunSigningLookup::Available(signing_key)),
            Err(error) => Ok(RunSigningLookup::MaterialUnavailable {
                reason: format!("signing_key_unavailable: {error}"),
            }),
        }
    }
}

pub fn logs_unlocked(project: &str, vault: &Path) -> Result<bool> {
    Ok(active_session(project, vault, UnlockPurpose::Logs)?.is_some())
}

pub fn clear_all_unlocks() -> Result<usize> {
    let path = unlocks_path();
    let state = load_state(&path)?;
    for session in &state.sessions {
        if session.purpose == UnlockPurpose::Logs {
            key_store::delete_secret(&session.key_name)?;
        }
    }
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(state.sessions.len())
}

pub fn clear_run_unlocks() -> Result<usize> {
    clear_unlocks_matching(|session| session.purpose == UnlockPurpose::Run)
}

pub fn clear_project_unlocks(project: &str) -> Result<usize> {
    clear_unlocks_matching(|session| session.project == project)
}

fn clear_unlocks_matching(mut should_remove: impl FnMut(&UnlockSession) -> bool) -> Result<usize> {
    let path = unlocks_path();
    let mut state = load_state(&path)?;
    let before = state.sessions.len();
    let mut removed_keys = Vec::new();
    state.sessions.retain(|session| {
        let remove = should_remove(session);
        if remove {
            if session.purpose == UnlockPurpose::Logs {
                removed_keys.push(session.key_name.clone());
            }
        }
        !remove
    });
    for key_name in removed_keys {
        key_store::delete_secret(&key_name)?;
    }
    let removed = before - state.sessions.len();
    if removed > 0 {
        write_state(&path, &state)?;
    }
    Ok(removed)
}

fn create_unlock(
    project: &str,
    vault: &Path,
    _secret: &str,
    ttl: Duration,
    purpose: UnlockPurpose,
) -> Result<UnlockSession> {
    let mut state = load_state(&unlocks_path())?;
    let now = Utc::now();
    remove_expired_and_matching(&mut state, project, vault, &purpose, now)?;

    let key_name = key_name(project, vault, &purpose);
    #[cfg(test)]
    if purpose == UnlockPurpose::Run {
        key_store::set_secret(&key_name, _secret)?;
    }
    if purpose == UnlockPurpose::Logs {
        key_store::set_secret(&key_name, &random_marker())?;
    }

    #[cfg(test)]
    let signing_key_ciphertext = if purpose == UnlockPurpose::Run {
        let ciphertext =
            approval_receipts::session_signing_key_ciphertext(project, _secret, _secret)?;
        Some(ciphertext)
    } else {
        None
    };
    #[cfg(not(test))]
    let signing_key_ciphertext = None;

    let session = UnlockSession {
        id: uuid::Uuid::new_v4(),
        created_at: now,
        expires_at: now + ttl,
        project: project.to_string(),
        vault: vault.to_path_buf(),
        key_name,
        purpose,
        signing_key_ciphertext,
    };
    state.sessions.push(session.clone());
    write_state(&unlocks_path(), &state)?;
    Ok(session)
}

fn active_session(
    project: &str,
    vault: &Path,
    purpose: UnlockPurpose,
) -> Result<Option<UnlockSession>> {
    let mut state = load_state(&unlocks_path())?;
    let before = state.sessions.len();
    remove_expired(&mut state, Utc::now())?;
    if before != state.sessions.len() {
        write_state(&unlocks_path(), &state)?;
    }

    Ok(state.sessions.into_iter().rev().find(|session| {
        session.project == project
            && session.vault == vault
            && session.purpose == purpose
            && session.expires_at > Utc::now()
    }))
}

fn remove_expired_and_matching(
    state: &mut UnlockState,
    project: &str,
    vault: &Path,
    purpose: &UnlockPurpose,
    now: DateTime<Utc>,
) -> Result<()> {
    let mut removed = Vec::new();
    state.sessions.retain(|session| {
        let should_remove = session.expires_at <= now
            || (session.project == project
                && session.vault == vault
                && session.purpose == *purpose);
        if should_remove {
            if session.purpose == UnlockPurpose::Logs {
                removed.push(session.key_name.clone());
            }
        }
        !should_remove
    });
    for key_name in removed {
        key_store::delete_secret(&key_name)?;
    }
    Ok(())
}

fn remove_expired(state: &mut UnlockState, now: DateTime<Utc>) -> Result<()> {
    let mut removed = Vec::new();
    state.sessions.retain(|session| {
        let expired = session.expires_at <= now;
        if expired {
            if session.purpose == UnlockPurpose::Logs {
                removed.push(session.key_name.clone());
            }
        }
        !expired
    });
    for key_name in removed {
        key_store::delete_secret(&key_name)?;
    }
    Ok(())
}

fn load_state(path: &Path) -> Result<UnlockState> {
    if !path.exists() {
        return Ok(UnlockState::default());
    }
    let contents = fs_util::read_file_to_string(path, "unlock metadata")?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_state(path: &Path, state: &UnlockState) -> Result<()> {
    let contents =
        serde_json::to_string_pretty(state).expect("unlock state serialization is infallible");
    fs_util::ensure_private_dir(&logs::ward_home())?;
    fs_util::write_private_file(path, format!("{contents}\n").as_bytes())
}

fn key_name(project: &str, vault: &Path, purpose: &UnlockPurpose) -> String {
    let prefix = match purpose {
        UnlockPurpose::Run => RUN_UNLOCK_PREFIX,
        UnlockPurpose::Logs => LOG_UNLOCK_PREFIX,
        UnlockPurpose::Mode(_) => MODE_UNLOCK_PREFIX,
    };
    let mut hasher = Sha256::new();
    hasher.update(project.as_bytes());
    hasher.update(b"\0");
    hasher.update(vault.to_string_lossy().as_bytes());
    format!("{prefix}/{}", hex::encode(hasher.finalize()))
}

fn random_marker() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn parse_ttl_supports_minutes_hours_days_and_rejects_bad_values() {
        assert_eq!(parse_ttl("15m").unwrap(), Duration::minutes(15));
        assert_eq!(parse_ttl("8h").unwrap(), Duration::hours(8));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::days(1));
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("8x").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("xh").is_err());
    }

    #[test]
    #[serial_test::serial]
    fn run_and_logs_unlocks_are_scoped_and_clearable() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");

        create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        create_logs_unlock("demo", &vault, Duration::minutes(15)).unwrap();

        assert_eq!(
            active_run_passphrase("demo", &vault).unwrap().as_deref(),
            Some("passphrase")
        );
        assert!(logs_unlocked("demo", &vault).unwrap());
        assert_eq!(clear_all_unlocks().unwrap(), 2);
        assert!(active_run_passphrase("demo", &vault).unwrap().is_none());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn run_unlock_lookup_distinguishes_missing_available_and_unavailable_material() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");

        assert_eq!(
            active_run_lookup("demo", &vault).unwrap().reason(),
            Some("missing_unlock_session")
        );
        create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        let available = active_run_lookup("demo", &vault).unwrap();
        assert_eq!(available.reason(), None);
        assert!(matches!(
            available,
            RunUnlockLookup::Available(secret) if secret == "passphrase"
        ));
        assert!(create_run_unlock("demo", &vault, "wrong-passphrase", Duration::hours(1)).is_err());

        let key_store_path = crate::logs::ward_home().join("cache").join("keystore.json");
        std::fs::remove_file(&key_store_path).unwrap();
        let unavailable = active_run_lookup("demo", &vault).unwrap();
        assert_eq!(unavailable.reason(), Some("unlock_material_unavailable"));
        assert!(matches!(
            unavailable,
            RunUnlockLookup::MaterialUnavailable { reason } if reason == "unlock_material_unavailable"
        ));

        std::fs::write(&key_store_path, "{bad-json}").unwrap();
        assert!(matches!(
            active_run_lookup("demo", &vault).unwrap(),
            RunUnlockLookup::MaterialUnavailable { reason } if reason.starts_with("unlock_material_unreadable:")
        ));
        assert!(active_run_passphrase("demo", &vault).is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn signing_key_lookup_reports_missing_unreadable_and_bad_ciphertext() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");

        create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        let available = active_run_signing_key("demo", &vault).unwrap();
        assert!(matches!(available, RunSigningLookup::Available(_)));

        let mut state = load_state(&unlocks_path()).unwrap();
        state.sessions[0].signing_key_ciphertext = None;
        write_state(&unlocks_path(), &state).unwrap();
        assert!(matches!(
            active_run_signing_key("demo", &vault).unwrap(),
            RunSigningLookup::MaterialUnavailable { reason } if reason == "signing_key_unavailable"
        ));

        create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        let key_store_path = crate::logs::ward_home().join("cache").join("keystore.json");
        std::fs::remove_file(&key_store_path).unwrap();
        assert!(matches!(
            active_run_signing_key("demo", &vault).unwrap(),
            RunSigningLookup::MaterialUnavailable { reason } if reason == "unlock_material_unavailable"
        ));

        std::fs::write(&key_store_path, "{bad-json}").unwrap();
        assert!(matches!(
            active_run_signing_key("demo", &vault).unwrap(),
            RunSigningLookup::MaterialUnavailable { reason } if reason.starts_with("unlock_material_unreadable:")
        ));

        std::fs::remove_file(&key_store_path).unwrap();
        create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        let mut state = load_state(&unlocks_path()).unwrap();
        state.sessions[0].signing_key_ciphertext = Some(
            crate::approval_receipts::session_signing_key_ciphertext(
                "demo",
                "passphrase",
                "other-session",
            )
            .unwrap(),
        );
        write_state(&unlocks_path(), &state).unwrap();
        assert!(matches!(
            active_run_signing_key("demo", &vault).unwrap(),
            RunSigningLookup::MaterialUnavailable { reason } if reason.starts_with("signing_key_unavailable:")
        ));

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn clears_only_one_projects_unlock_sessions() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let demo_vault = tempdir.path().join("demo.env.vault");
        let other_vault = tempdir.path().join("other.env.vault");

        create_run_unlock("demo", &demo_vault, "demo-passphrase", Duration::hours(1)).unwrap();
        create_logs_unlock("demo", &demo_vault, Duration::minutes(15)).unwrap();
        create_run_unlock(
            "other",
            &other_vault,
            "other-passphrase",
            Duration::hours(1),
        )
        .unwrap();

        assert_eq!(clear_project_unlocks("missing").unwrap(), 0);
        assert_eq!(clear_project_unlocks("demo").unwrap(), 2);
        assert!(active_run_passphrase("demo", &demo_vault)
            .unwrap()
            .is_none());
        assert_eq!(
            active_run_passphrase("other", &other_vault)
                .unwrap()
                .as_deref(),
            Some("other-passphrase")
        );

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn expired_unlock_is_removed() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");

        create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        let mut state = load_state(&unlocks_path()).unwrap();
        state.sessions[0].expires_at = Utc::now() - Duration::minutes(1);
        write_state(&unlocks_path(), &state).unwrap();

        assert!(active_run_passphrase("demo", &vault).unwrap().is_none());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn replacing_unlock_removes_previous_secret_and_load_errors_surface() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");

        let first = create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        let second = create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(
            active_run_passphrase("demo", &vault).unwrap().as_deref(),
            Some("passphrase")
        );
        assert_eq!(clear_all_unlocks().unwrap(), 1);
        assert_eq!(clear_all_unlocks().unwrap(), 0);

        std::fs::create_dir_all(unlocks_path().parent().unwrap()).unwrap();
        std::fs::write(unlocks_path(), "{bad-json}").unwrap();
        assert!(active_run_passphrase("demo", &vault).is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn unlock_storage_and_key_store_failures_are_reported() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");

        std::fs::create_dir_all(unlocks_path().parent().unwrap()).unwrap();
        std::fs::write(unlocks_path(), "{bad-json}").unwrap();
        assert!(clear_all_unlocks().is_err());
        assert!(create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).is_err());
        assert!(logs_unlocked("demo", &vault).is_err());

        std::fs::remove_file(unlocks_path()).unwrap();
        std::fs::create_dir(unlocks_path()).unwrap();
        assert!(load_state(&unlocks_path()).is_err());
        assert!(write_state(&unlocks_path(), &UnlockState::default()).is_err());
        std::fs::remove_dir(unlocks_path()).unwrap();

        let key_store_path = crate::logs::ward_home().join("cache").join("keystore.json");
        std::fs::create_dir_all(key_store_path.parent().unwrap()).unwrap();
        std::fs::write(&key_store_path, "{bad-json}").unwrap();
        assert!(create_logs_unlock("demo", &vault, Duration::minutes(15)).is_err());

        std::fs::remove_file(&key_store_path).unwrap();

        #[cfg(unix)]
        {
            write_state(&unlocks_path(), &UnlockState::default()).unwrap();
            let sessions_dir = unlocks_path().parent().unwrap().to_path_buf();
            let original_permissions = std::fs::metadata(&sessions_dir).unwrap().permissions();
            std::fs::set_permissions(&sessions_dir, std::fs::Permissions::from_mode(0o500))
                .unwrap();
            let result = clear_all_unlocks();
            std::fs::set_permissions(&sessions_dir, original_permissions).unwrap();
            assert!(result.is_err());
            std::fs::remove_file(unlocks_path()).unwrap();
        }

        let sessions_dir = unlocks_path().parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&sessions_dir).unwrap();
        std::fs::write(&sessions_dir, "").unwrap();
        assert!(create_run_unlock("demo", &vault, "passphrase", Duration::hours(1)).is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }
}
