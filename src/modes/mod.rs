use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{fs_util, logs, vault};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModeLevel {
    Read,
    Write,
    Admin,
    Supervised,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeConfig {
    pub name: String,
    pub level: ModeLevel,
    pub allowed_env: Vec<String>,
    pub allowed_commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ActiveMode {
    pub config: ModeConfig,
    pub expires_at: DateTime<Utc>,
}

pub fn local_modes_path(project_root: &Path) -> PathBuf {
    fs_util::resolve_project_path(
        project_root,
        Path::new(".ward.modes.json"),
        "local modes path",
    )
    .expect("local modes path should stay inside the project")
}

pub fn broker_modes_vault_path(project: &str) -> PathBuf {
    logs::project_modes_dir(project).join("modes.vault")
}

pub fn broker_modes_checksum_path(project: &str) -> PathBuf {
    logs::project_modes_dir(project).join("modes.checksum")
}

pub fn load_local_modes(project_root: &Path) -> Result<Vec<ModeConfig>> {
    let path = local_modes_path(project_root);
    if !path.exists() {
        return Ok(vec![]);
    }
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if path.components().any(|c| c == Component::ParentDir) {
        anyhow::bail!("Invalid input: {}", path.display());
    }
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let modes: Vec<ModeConfig> =
        serde_json::from_str(&content).context("failed to parse .ward.modes.json")?;
    Ok(modes)
}

pub fn push_modes(
    modes: &[ModeConfig],
    project: &str,
    passphrase: &str,
    local_path: &Path,
) -> Result<()> {
    let dir = logs::project_modes_dir(project);
    fs_util::ensure_private_dir(&dir)?;

    let plaintext = serde_json::to_string(modes).context("failed to serialize modes")?;
    let envelope = vault::encrypt_env(&plaintext, passphrase).context("failed to encrypt modes")?;
    let vault_path = broker_modes_vault_path(project);
    let vault_json =
        serde_json::to_string_pretty(&envelope).context("failed to serialize modes vault")?;
    fs::write(&vault_path, vault_json)
        .with_context(|| format!("failed to write {}", vault_path.display()))?;

    // Store checksum of the local file for drift detection
    if local_path.exists() {
        // Prevent path traversal attacks by rejecting paths containing '..'.
        if local_path.components().any(|c| c == Component::ParentDir) {
            anyhow::bail!("Invalid input: {}", local_path.display());
        }
        let content = fs::read(local_path)?;
        let checksum = hex::encode(Sha256::digest(&content));
        fs::write(broker_modes_checksum_path(project), checksum)?;
    }

    Ok(())
}

pub fn load_broker_modes(project: &str, passphrase: &str) -> Result<Vec<ModeConfig>> {
    let vault_path = broker_modes_vault_path(project);
    if !vault_path.exists() {
        return Ok(vec![]);
    }
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if vault_path.components().any(|c| c == Component::ParentDir) {
        anyhow::bail!("Invalid input: {}", vault_path.display());
    }
    let vault_json = fs::read_to_string(&vault_path)
        .with_context(|| format!("failed to read {}", vault_path.display()))?;
    let envelope: vault::VaultEnvelope =
        serde_json::from_str(&vault_json).context("failed to parse modes vault")?;
    let plaintext = vault::decrypt_env(&envelope, passphrase)
        .context("failed to decrypt modes vault — wrong passphrase?")?;
    let modes: Vec<ModeConfig> =
        serde_json::from_str(&plaintext).context("failed to parse decrypted modes")?;
    Ok(modes)
}

pub fn find_mode<'a>(modes: &'a [ModeConfig], name: &str) -> Option<&'a ModeConfig> {
    modes.iter().find(|m| m.name == name)
}

pub fn mode_allows_env(mode: &ActiveMode, env_name: &str) -> bool {
    mode.config
        .allowed_env
        .iter()
        .any(|pattern| glob_match(pattern, env_name))
}

pub fn mode_allows_command(mode: &ActiveMode, command: &str) -> bool {
    if mode.config.allowed_commands.is_empty() {
        return true;
    }
    mode.config
        .allowed_commands
        .iter()
        .any(|pattern| glob_match(pattern, command))
}

/// Returns true if the local .ward.modes.json has changed since the last push.
pub fn check_local_drift(project: &str, local_path: &Path) -> bool {
    let checksum_path = broker_modes_checksum_path(project);
    if !checksum_path.exists() || !local_path.exists() {
        return false;
    }
    let Ok(stored) = fs::read_to_string(&checksum_path) else {
        return false;
    };
    let Ok(content) = fs::read(local_path) else {
        return false;
    };
    let current = hex::encode(Sha256::digest(&content));
    current.trim() != stored.trim()
}

/// Simple glob matching supporting `*` (matches any sequence except `/`) and `**` (matches any sequence including `/`).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // Exact match fast path
    if !pattern.contains('*') {
        return pattern == text;
    }
    glob_match_recursive(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_recursive(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (None, _) => false,
        (Some(b'*'), _) => {
            // Check for **
            if pattern.get(1) == Some(&b'*') {
                let rest = &pattern[2..];
                // Skip optional separator after **
                let rest = rest.strip_prefix(b"/".as_ref()).unwrap_or(rest);
                // Try matching ** against 0 or more characters
                for i in 0..=text.len() {
                    if glob_match_recursive(rest, &text[i..]) {
                        return true;
                    }
                }
                false
            } else {
                // Single * — match any sequence except '/'
                let rest = &pattern[1..];
                for i in 0..=text.len() {
                    if text[..i].contains(&b'/') {
                        break;
                    }
                    if glob_match_recursive(rest, &text[i..]) {
                        return true;
                    }
                }
                false
            }
        }
        (Some(&p), Some(&t)) => {
            if p == t {
                glob_match_recursive(&pattern[1..], &text[1..])
            } else {
                false
            }
        }
        (Some(_), None) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact() {
        assert!(glob_match("pnpm dev", "pnpm dev"));
        assert!(!glob_match("pnpm dev", "pnpm build"));
    }

    #[test]
    fn glob_star() {
        assert!(glob_match("node scripts/*.mjs", "node scripts/seed.mjs"));
        assert!(glob_match("node scripts/*.mjs", "node scripts/cleanup.mjs"));
        assert!(!glob_match(
            "node scripts/*.mjs",
            "node scripts/sub/seed.mjs"
        ));
    }

    #[test]
    fn glob_double_star() {
        assert!(glob_match("node **/*.mjs", "node scripts/sub/seed.mjs"));
    }
}
