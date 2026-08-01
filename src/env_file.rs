use std::{
    collections::BTreeMap,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::{fs_util, vault};

const LOCKED_MARKER: &str = "# Ward managed locked .env";
const VAULT_HASH_PREFIX: &str = "# ward-vault-sha256:";
const UNLOCKED_HEADER: &str = "\
# Ward unlocked plaintext .env.
# This file contains secrets for manual local development.
# Run `ward env lock` when you are done to re-encrypt and restore the locked file.

";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvFileState {
    Missing,
    Locked,
    StaleLocked,
    Plaintext,
}

pub fn lock_env_file(env_path: &Path, vault_path: &Path) -> Result<()> {
    fs_util::write_private_file(env_path, locked_contents(vault_path)?.as_bytes())
}

pub fn unlock_env_file(
    env_path: &Path,
    vault_path: &Path,
    passphrase: &str,
    force: bool,
) -> Result<()> {
    if env_path.exists() && !force && !is_locked_env_file(env_path)? {
        anyhow::bail!(
            "{} already exists and is not an Ward locked file; pass --force to overwrite",
            env_path.display()
        );
    }
    let plaintext = vault::decrypt_vault_file(vault_path, passphrase)?;
    ensure_not_locked_marker(&plaintext, vault_path)?;
    write_plaintext_env(env_path, &plaintext, true)
}

pub fn unlock_env_file_preserving_plaintext(
    env_path: &Path,
    vault_path: &Path,
    passphrase: &str,
    timestamp: &str,
) -> Result<PathBuf> {
    let plaintext = vault::decrypt_vault_file(vault_path, passphrase)?;
    ensure_not_locked_marker(&plaintext, vault_path)?;
    let output = if env_path.exists() && !is_locked_env_file(env_path)? {
        sibling_with_file_name(env_path, &format!(".env.ward-off.{timestamp}"))
    } else {
        env_path.to_path_buf()
    };
    write_plaintext_env(&output, &plaintext, true)?;
    Ok(output)
}

pub fn export_env_file(
    output: &Path,
    vault_path: &Path,
    passphrase: &str,
    force: bool,
) -> Result<()> {
    export_env_file_with_key(output, vault_path, passphrase, force)
}

pub fn export_env_file_with_key(
    output: &Path,
    vault_path: &Path,
    decrypt_key: &str,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            output.display()
        );
    }
    let plaintext = vault::decrypt_vault_file(vault_path, decrypt_key)?;
    ensure_not_locked_marker(&plaintext, vault_path)?;
    write_plaintext_env(output, &plaintext, false)
}

pub fn lock_plaintext_source(source: &Path, vault_path: &Path, passphrase: &str) -> Result<()> {
    let plaintext = fs_util::read_file_to_string(source, "dotenv source")?;
    let plaintext = strip_ward_unlocked_header(&plaintext);
    if is_locked_env_contents(&plaintext) {
        anyhow::bail!(
            "{} is already an Ward locked marker; unlock it before editing or provide a plaintext dotenv file",
            source.display()
        );
    }
    vault::validate_dotenv(&plaintext)?;
    let envelope = match vault::read_vault(vault_path) {
        Ok(existing) => vault::encrypt_env_like(&existing, &plaintext, passphrase)?,
        Err(_) => vault::encrypt_env(&plaintext, passphrase)?,
    };
    vault::write_vault(vault_path, &envelope)?;
    vault::decrypt_vault_file(vault_path, passphrase)?;
    lock_env_file(source, vault_path)
}

pub fn list_env_names(vault_path: &Path, passphrase: &str) -> Result<Vec<String>> {
    let plaintext = vault::decrypt_vault_file(vault_path, passphrase)?;
    ensure_not_locked_marker(&plaintext, vault_path)?;
    Ok(parse_env_map(&plaintext)?.into_keys().collect())
}

pub fn set_env_value(vault_path: &Path, passphrase: &str, assignment: &str) -> Result<String> {
    let (key, value) = assignment
        .split_once('=')
        .context("assignment must use KEY=value syntax")?;
    validate_key(key)?;
    let plaintext = vault::decrypt_vault_file(vault_path, passphrase)?;
    ensure_not_locked_marker(&plaintext, vault_path)?;
    let mut env = parse_env_map(&plaintext)?;
    env.insert(key.to_string(), value.to_string());
    let updated = serialize_env_map(&env);
    write_updated_vault(vault_path, passphrase, &updated)?;
    Ok(key.to_string())
}

pub fn unset_env_value(vault_path: &Path, passphrase: &str, key: &str) -> Result<bool> {
    validate_key(key)?;
    let plaintext = vault::decrypt_vault_file(vault_path, passphrase)?;
    ensure_not_locked_marker(&plaintext, vault_path)?;
    let mut env = parse_env_map(&plaintext)?;
    let removed = env.remove(key).is_some();
    let updated = serialize_env_map(&env);
    write_updated_vault(vault_path, passphrase, &updated)?;
    Ok(removed)
}

pub fn refresh_locked_env(project_path: &Path, vault_path: &Path) -> Result<()> {
    let env_path = project_path.join(".env");
    if !env_path.exists() || !is_locked_env_file(&env_path)? {
        return Ok(());
    }
    lock_env_file(&env_path, vault_path)
}

pub fn inspect_env_file(env_path: &Path, vault_path: &Path) -> Result<EnvFileState> {
    if !env_path.exists() {
        return Ok(EnvFileState::Missing);
    }
    let contents = fs_util::read_file_to_string(env_path, "dotenv file")?;
    if !contents.starts_with(LOCKED_MARKER) {
        return Ok(EnvFileState::Plaintext);
    }
    let Some(recorded) = recorded_vault_hash(&contents) else {
        return Ok(EnvFileState::StaleLocked);
    };
    let actual = vault_hash(vault_path)?;
    if recorded == actual {
        Ok(EnvFileState::Locked)
    } else {
        Ok(EnvFileState::StaleLocked)
    }
}

pub fn is_locked_env_file(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let contents = fs_util::read_file_to_string(path, "locked env file")?;
    Ok(is_locked_env_contents(&contents))
}

pub fn is_locked_env_contents(contents: &str) -> bool {
    contents.starts_with(LOCKED_MARKER)
}

pub fn locked_contents(vault_path: &Path) -> Result<String> {
    let hash = vault_hash(vault_path)?;
    Ok(format!(
        "\
{LOCKED_MARKER}
# Secrets are encrypted in {vault}.
# Use `ward run ...` for AI-safe secret injection.
# Use `ward env unlock` to write plaintext `.env` for manual local development.
# Use `ward env lock` to re-encrypt manual edits and restore this locked file.
{VAULT_HASH_PREFIX} {hash}
WARD_LOCKED=1
WARD_VAULT={vault}
",
        vault = display_path(vault_path),
    ))
}

pub fn vault_hash(path: &Path) -> Result<String> {
    let bytes = fs_util::read_file(path, "vault hash source")?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub fn parse_env_map(contents: &str) -> Result<BTreeMap<String, String>> {
    let iter = dotenvy::from_read_iter(Cursor::new(contents.as_bytes()));
    let mut env = BTreeMap::new();
    for item in iter {
        let (key, value) = item?;
        env.insert(key, value);
    }
    Ok(env)
}

pub fn serialize_env_map(env: &BTreeMap<String, String>) -> String {
    let mut contents = String::new();
    for (key, value) in env {
        contents.push_str(key);
        contents.push('=');
        contents.push_str(&quote_value(value));
        contents.push('\n');
    }
    contents
}

fn write_updated_vault(vault_path: &Path, passphrase: &str, plaintext: &str) -> Result<()> {
    ensure_not_locked_marker(plaintext, vault_path)?;
    vault::validate_dotenv(plaintext)?;
    let envelope = match vault::read_vault(vault_path) {
        Ok(existing) => vault::encrypt_env_like(&existing, plaintext, passphrase)?,
        Err(_) => vault::encrypt_env(plaintext, passphrase)?,
    };
    vault::write_vault(vault_path, &envelope)?;
    vault::decrypt_vault_file(vault_path, passphrase)?;
    Ok(())
}

fn ensure_not_locked_marker(plaintext: &str, vault_path: &Path) -> Result<()> {
    if is_locked_env_contents(plaintext) {
        anyhow::bail!(
            "{} contains an Ward locked marker instead of plaintext secrets; restore or re-import a plaintext dotenv file",
            vault_path.display()
        );
    }
    Ok(())
}

fn write_plaintext_env(path: &Path, plaintext: &str, include_unlock_header: bool) -> Result<()> {
    vault::validate_dotenv(plaintext)?;
    let contents = if include_unlock_header {
        format!("{UNLOCKED_HEADER}{plaintext}")
    } else {
        plaintext.to_string()
    };
    fs_util::write_private_file(path, contents.as_bytes())
}

fn recorded_vault_hash(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        line.strip_prefix(VAULT_HASH_PREFIX)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn strip_ward_unlocked_header(contents: &str) -> String {
    contents
        .lines()
        .filter(|line| !line.starts_with("# Ward unlocked plaintext .env."))
        .filter(|line| {
            !line.starts_with("# This file contains secrets for manual local development.")
        })
        .filter(|line| !line.starts_with("# Run `ward env lock`"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn quote_value(value: &str) -> String {
    if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '/' | ':')
    }) {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn validate_key(key: &str) -> Result<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        anyhow::bail!("env key cannot be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        anyhow::bail!("env key must start with a letter or underscore");
    }
    if !chars.all(|character| character == '_' || character.is_ascii_alphanumeric()) {
        anyhow::bail!("env key contains invalid characters");
    }
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.file_name()
        .map(|value| PathBuf::from(value).display().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn sibling_with_file_name(path: &Path, file_name: &str) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join(file_name))
        .unwrap_or_else(|| PathBuf::from(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_env_round_trip_and_state_detection() {
        let tempdir = tempfile::tempdir().unwrap();
        let vault_path = tempdir.path().join(".env.vault");
        let env_path = tempdir.path().join(".env");
        let envelope = vault::encrypt_env("DATABASE_URL=postgres://local\n", "passphrase").unwrap();
        vault::write_vault(&vault_path, &envelope).unwrap();

        lock_env_file(&env_path, &vault_path).unwrap();
        let contents = std::fs::read_to_string(&env_path).unwrap();
        assert!(contents.contains("WARD_LOCKED=1"));
        assert!(!contents.contains("postgres://local"));
        assert_eq!(
            inspect_env_file(&env_path, &vault_path).unwrap(),
            EnvFileState::Locked
        );

        std::fs::write(&vault_path, "changed").unwrap();
        assert_eq!(
            inspect_env_file(&env_path, &vault_path).unwrap(),
            EnvFileState::StaleLocked
        );

        std::fs::write(&vault_path, "changed-again").unwrap();
        refresh_locked_env(tempdir.path(), &vault_path).unwrap();
        assert_eq!(
            inspect_env_file(&env_path, &vault_path).unwrap(),
            EnvFileState::Locked
        );
    }

    #[test]
    fn plaintext_missing_and_invalid_locked_states_are_reported() {
        let tempdir = tempfile::tempdir().unwrap();
        let env_path = tempdir.path().join(".env");
        let vault_path = tempdir.path().join(".env.vault");

        assert_eq!(
            inspect_env_file(&env_path, &vault_path).unwrap(),
            EnvFileState::Missing
        );
        refresh_locked_env(tempdir.path(), &vault_path).unwrap();
        assert!(!is_locked_env_file(&env_path).unwrap());
        std::fs::write(&env_path, "DATABASE_URL=postgres://local\n").unwrap();
        assert_eq!(
            inspect_env_file(&env_path, &vault_path).unwrap(),
            EnvFileState::Plaintext
        );
        std::fs::write(&env_path, LOCKED_MARKER).unwrap();
        assert_eq!(
            inspect_env_file(&env_path, &vault_path).unwrap(),
            EnvFileState::StaleLocked
        );
    }

    #[test]
    fn unlock_export_lock_set_unset_and_list_env_values() {
        let tempdir = tempfile::tempdir().unwrap();
        let vault_path = tempdir.path().join(".env.vault");
        let env_path = tempdir.path().join(".env");
        let export_path = tempdir.path().join(".env.export");
        let envelope = vault::encrypt_env(
            "DATABASE_URL=postgres://local\nPAYLOAD_SECRET=secret-value\n",
            "passphrase",
        )
        .unwrap();
        vault::write_vault(&vault_path, &envelope).unwrap();
        lock_env_file(&env_path, &vault_path).unwrap();

        unlock_env_file(&env_path, &vault_path, "passphrase", false).unwrap();
        let unlocked = std::fs::read_to_string(&env_path).unwrap();
        assert!(unlocked.contains("postgres://local"));
        assert!(unlocked.contains("Ward unlocked plaintext"));

        lock_plaintext_source(&env_path, &vault_path, "passphrase").unwrap();
        assert!(is_locked_env_file(&env_path).unwrap());
        assert!(lock_plaintext_source(&env_path, &vault_path, "passphrase").is_err());
        assert!(vault::decrypt_vault_file(&vault_path, "passphrase")
            .unwrap()
            .contains("postgres://local"));

        assert_eq!(
            list_env_names(&vault_path, "passphrase").unwrap(),
            vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()]
        );
        assert_eq!(
            set_env_value(&vault_path, "passphrase", "OPENAI_API_KEY=sk test").unwrap(),
            "OPENAI_API_KEY"
        );
        assert!(vault::decrypt_vault_file(&vault_path, "passphrase")
            .unwrap()
            .contains("OPENAI_API_KEY=\"sk test\""));
        assert!(unset_env_value(&vault_path, "passphrase", "OPENAI_API_KEY").unwrap());
        assert!(!unset_env_value(&vault_path, "passphrase", "MISSING").unwrap());

        export_env_file(&export_path, &vault_path, "passphrase", false).unwrap();
        assert!(std::fs::read_to_string(&export_path)
            .unwrap()
            .contains("DATABASE_URL=postgres://local"));
        assert!(export_env_file(&export_path, &vault_path, "passphrase", false).is_err());
        export_env_file(&export_path, &vault_path, "passphrase", true).unwrap();

        let unsafe_existing = tempdir.path().join(".env.unsafe");
        std::fs::write(&unsafe_existing, "DATABASE_URL=postgres://plaintext\n").unwrap();
        assert!(unlock_env_file(&unsafe_existing, &vault_path, "passphrase", false).is_err());
    }

    #[test]
    fn unlock_preserving_plaintext_uses_env_or_sidecar() {
        let tempdir = tempfile::tempdir().unwrap();
        let vault_path = tempdir.path().join(".env.vault");
        let env_path = tempdir.path().join(".env");
        let envelope = vault::encrypt_env("DATABASE_URL=postgres://local\n", "passphrase").unwrap();
        vault::write_vault(&vault_path, &envelope).unwrap();

        let missing_output =
            unlock_env_file_preserving_plaintext(&env_path, &vault_path, "passphrase", "20260731")
                .unwrap();
        assert_eq!(missing_output, env_path);
        assert!(std::fs::read_to_string(&env_path)
            .unwrap()
            .contains("postgres://local"));

        std::fs::write(&env_path, "DATABASE_URL=postgres://existing\n").unwrap();
        let sidecar =
            unlock_env_file_preserving_plaintext(&env_path, &vault_path, "passphrase", "20260731")
                .unwrap();
        assert_eq!(sidecar, tempdir.path().join(".env.ward-off.20260731"));
        assert!(std::fs::read_to_string(&env_path)
            .unwrap()
            .contains("postgres://existing"));
        assert!(std::fs::read_to_string(&sidecar)
            .unwrap()
            .contains("postgres://local"));

        lock_env_file(&env_path, &vault_path).unwrap();
        let locked_output =
            unlock_env_file_preserving_plaintext(&env_path, &vault_path, "passphrase", "ignored")
                .unwrap();
        assert_eq!(locked_output, env_path);
        assert!(std::fs::read_to_string(&env_path)
            .unwrap()
            .contains("postgres://local"));
    }

    #[test]
    fn refuses_to_treat_locked_marker_as_plaintext_secrets() {
        let tempdir = tempfile::tempdir().unwrap();
        let vault_path = tempdir.path().join(".env.vault");
        let env_path = tempdir.path().join(".env");
        let initial = vault::encrypt_env("DATABASE_URL=postgres://local\n", "passphrase").unwrap();
        vault::write_vault(&vault_path, &initial).unwrap();
        let locked_marker = locked_contents(&vault_path).unwrap();
        let corrupted = vault::encrypt_env(&locked_marker, "passphrase").unwrap();
        vault::write_vault(&vault_path, &corrupted).unwrap();

        assert!(unlock_env_file(&env_path, &vault_path, "passphrase", true).is_err());
        assert!(export_env_file(
            &tempdir.path().join(".env.export"),
            &vault_path,
            "passphrase",
            true
        )
        .is_err());
        assert!(list_env_names(&vault_path, "passphrase").is_err());
        assert!(set_env_value(&vault_path, "passphrase", "PAYLOAD_SECRET=secret").is_err());
        assert!(unset_env_value(&vault_path, "passphrase", "WARD_LOCKED").is_err());
    }

    #[test]
    fn env_map_and_key_validation_edges() {
        assert!(parse_env_map("DATABASE_URL='unterminated\n").is_err());
        assert!(set_env_value(Path::new("missing"), "passphrase", "NO_EQUALS").is_err());
        assert!(set_env_value(Path::new("missing"), "passphrase", "=value").is_err());
        assert!(set_env_value(Path::new("missing"), "passphrase", "1BAD=value").is_err());
        assert!(set_env_value(Path::new("missing"), "passphrase", "BAD-NAME=value").is_err());
        assert_eq!(display_path(Path::new("/")), "/");

        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "plain-value".to_string());
        env.insert("B".to_string(), "needs space".to_string());
        assert_eq!(
            serialize_env_map(&env),
            "A=plain-value\nB=\"needs space\"\n"
        );
    }
}
