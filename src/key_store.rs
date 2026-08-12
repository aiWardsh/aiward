use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{fs_util, logs};

#[cfg(not(coverage))]
const SERVICE: &str = "ward";

#[cfg(coverage)]
pub fn set_secret(name: &str, secret: &str) -> Result<()> {
    set_file_secret(name, secret)
}

#[cfg(not(coverage))]
pub fn set_secret(name: &str, secret: &str) -> Result<()> {
    if use_keychain_store() {
        let entry = keyring::Entry::new(SERVICE, name)
            .with_context(|| format!("failed to open keychain entry {name}"))?;
        return entry
            .set_password(secret)
            .with_context(|| format!("failed to store keychain entry {name}"));
    }

    set_file_secret(name, secret)
}

#[cfg(coverage)]
#[allow(dead_code)]
pub fn get_secret(name: &str) -> Result<Option<String>> {
    get_file_secret(name)
}

#[cfg(not(coverage))]
#[allow(dead_code)]
pub fn get_secret(name: &str) -> Result<Option<String>> {
    if use_keychain_store() {
        let entry = keyring::Entry::new(SERVICE, name)
            .with_context(|| format!("failed to open keychain entry {name}"))?;
        return match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("failed to read keychain entry {name}"))
            }
        };
    }

    get_file_secret(name)
}

#[cfg(coverage)]
pub fn delete_secret(name: &str) -> Result<()> {
    delete_file_secret(name)
}

#[cfg(not(coverage))]
pub fn delete_secret(name: &str) -> Result<()> {
    if use_keychain_store() {
        let entry = keyring::Entry::new(SERVICE, name)
            .with_context(|| format!("failed to open keychain entry {name}"))?;
        return match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("failed to delete keychain entry {name}"))
            }
        };
    }

    delete_file_secret(name)
}

#[cfg(not(coverage))]
fn use_keychain_store() -> bool {
    std::env::var("WARD_KEYCHAIN")
        .ok()
        .is_some_and(|value| value == "1")
}

fn file_store_path() -> PathBuf {
    let relative = PathBuf::from("cache").join("keystore.json");
    fs_util::resolve_ward_home_path(&relative, "file keystore path")
        .expect("file keystore path should stay inside Ward home")
}

fn legacy_file_store_path() -> PathBuf {
    let relative = PathBuf::from("cache").join("test-keyring.json");
    fs_util::resolve_ward_home_path(&relative, "legacy file keystore path")
        .expect("legacy file keystore path should stay inside Ward home")
}

fn set_file_secret(name: &str, secret: &str) -> Result<()> {
    let path = file_store_path();
    let mut store = load_file_store(&path)?;
    store.entries.insert(name.to_string(), secret.to_string());
    write_file_store(&path, &store)
}

#[allow(dead_code)]
fn get_file_secret(name: &str) -> Result<Option<String>> {
    let path = file_store_path();
    let store = load_file_store(&path)?;
    Ok(store.entries.get(name).cloned())
}

fn delete_file_secret(name: &str) -> Result<()> {
    let path = file_store_path();
    let mut store = load_file_store(&path)?;
    store.entries.remove(name);
    write_file_store(&path, &store)
}

fn load_file_store(path: &Path) -> Result<FileStore> {
    migrate_legacy_file_store(path)?;
    if !path.exists() {
        return Ok(FileStore::default());
    }

    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn migrate_legacy_file_store(path: &Path) -> Result<()> {
    let legacy = legacy_file_store_path();
    if path.exists() || !legacy.exists() || path == legacy {
        return Ok(());
    }
    fs_util::ensure_private_parent_dir(path)?;
    fs::rename(&legacy, path).or_else(|_| {
        fs::copy(&legacy, path)?;
        fs::remove_file(&legacy)
    })?;
    fs_util::set_private_file_permissions(path)
}

fn write_file_store(path: &Path, store: &FileStore) -> Result<()> {
    let contents =
        serde_json::to_string_pretty(store).expect("file store serialization is infallible");
    ensure_ward_home_for(path)?;
    fs_util::write_private_file(path, format!("{contents}\n").as_bytes())
}

fn ensure_ward_home_for(path: &Path) -> Result<()> {
    let home = logs::ward_home();
    if path.starts_with(&home) {
        fs_util::ensure_private_dir(&home)?;
    }
    Ok(())
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileStore {
    entries: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> crate::test_support::TestEnvironment {
        crate::test_support::TestEnvironment::lock()
    }

    #[test]
    #[serial_test::serial]
    fn file_store_sets_gets_and_deletes_secrets() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");

        set_secret("demo", "secret").unwrap();
        assert!(file_store_path().ends_with("cache/keystore.json"));
        assert_eq!(get_secret("demo").unwrap().as_deref(), Some("secret"));
        delete_secret("demo").unwrap();
        assert!(get_secret("demo").unwrap().is_none());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    #[serial_test::serial]
    fn migrates_legacy_test_keyring_file_to_keystore() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        let legacy = legacy_file_store_path();
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, r#"{"entries":{"demo":"secret"}}"#).unwrap();

        assert_eq!(get_secret("demo").unwrap().as_deref(), Some("secret"));
        assert!(file_store_path().exists());
        assert!(!legacy.exists());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    #[cfg(not(coverage))]
    fn keychain_is_explicit_opt_in_only() {
        let _guard = env_lock();
        std::env::remove_var("WARD_KEYCHAIN");
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        assert!(!use_keychain_store());
        std::env::set_var("WARD_KEYCHAIN", "1");
        assert!(use_keychain_store());
        std::env::remove_var("WARD_KEYCHAIN");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    fn load_file_store_reports_invalid_json() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("store.json");
        std::fs::write(&path, "{bad-json}").unwrap();

        assert!(load_file_store(&path).is_err());

        let directory_path = tempdir.path().join("store-dir.json");
        std::fs::create_dir(&directory_path).unwrap();
        assert!(load_file_store(&directory_path).is_err());
        assert!(write_file_store(&directory_path, &FileStore::default()).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn file_store_operations_report_corrupt_store() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let path = file_store_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{bad-json}").unwrap();

        assert!(set_secret("demo", "secret").is_err());
        assert!(get_secret("demo").is_err());
        assert!(delete_secret("demo").is_err());

        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }
}
