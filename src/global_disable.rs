use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{fs_util, logs};

const DISABLED_STATE_VERSION: u32 = 1;
const DISABLED_FILE: &str = "disabled.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisabledState {
    pub version: u32,
    pub disabled_at: DateTime<Utc>,
    pub reason: String,
}

pub fn disabled_path() -> PathBuf {
    logs::ward_home().join(DISABLED_FILE)
}

pub fn disable(reason: &str) -> Result<DisabledState> {
    let state = DisabledState {
        version: DISABLED_STATE_VERSION,
        disabled_at: Utc::now(),
        reason: reason.to_string(),
    };
    let contents =
        serde_json::to_string_pretty(&state).expect("disabled state serialization is infallible");
    fs_util::write_private_file(&disabled_path(), format!("{contents}\n").as_bytes())?;
    Ok(state)
}

pub fn enable() -> Result<bool> {
    let path = disabled_path();
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(true)
}

pub fn read() -> Result<Option<DisabledState>> {
    let path = disabled_path();
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let state: DisabledState = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    anyhow::ensure!(
        state.version == DISABLED_STATE_VERSION,
        "unsupported disabled state version {}",
        state.version
    );
    Ok(Some(state))
}

pub fn is_disabled() -> bool {
    disabled_path().exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> crate::test_support::TestEnvironment {
        crate::test_support::TestEnvironment::lock()
    }

    #[test]
    #[serial_test::serial]
    fn disabled_state_round_trips_and_removes() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        assert!(!is_disabled());
        assert!(read().unwrap().is_none());

        let state = disable("ward off").unwrap();
        assert_eq!(state.version, DISABLED_STATE_VERSION);
        assert!(is_disabled());
        assert_eq!(read().unwrap().unwrap().reason, "ward off");
        assert!(enable().unwrap());
        assert!(!enable().unwrap());
        assert!(!is_disabled());

        std::env::remove_var("WARD_HOME");
    }
}
