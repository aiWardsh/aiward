use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::{AgentPolicyConfig, ProfileConfig, ProjectConfig},
    env_file, fs_util, vault,
};

const STORE_RECORD_VERSION: u32 = 1;
const PROJECT_STORE_DIR: &str = "store/projects";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStoreRecord {
    pub version: u32,
    pub project_id: String,
    pub project_name: String,
    pub source: ProjectStoreSource,
    pub created_at: String,
    pub updated_at: String,
    pub env_names: Vec<String>,
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default)]
    pub agent_policies: BTreeMap<String, AgentPolicyConfig>,
    pub encrypted_secrets: EncryptedProjectSecrets,
    #[serde(default)]
    pub recipient_key_wraps: Vec<ProjectStoreRecipient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStoreSource {
    pub project: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub snapshot_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedProjectSecrets {
    pub algorithm: String,
    pub key_wrap: vault::VaultEnvelope,
    pub payload: vault::VaultEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStoreRecipient {
    pub recipient_id: String,
    pub wrapped_key: vault::VaultEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStoreSummary {
    pub project_id: String,
    pub project_name: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub env_names: Vec<String>,
    pub profile_names: Vec<String>,
    pub agent_names: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStoreDiagnostics {
    pub path: PathBuf,
    pub exists: bool,
    pub stale: bool,
    pub env_count: usize,
    pub profile_count: usize,
    pub agent_policy_count: usize,
}

pub fn projects_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new(PROJECT_STORE_DIR), "project store directory")
        .expect("project store directory should stay inside Ward home")
}

pub fn record_path(project: &str) -> PathBuf {
    let relative = PathBuf::from(PROJECT_STORE_DIR).join(format!("{}.json", slugify(project)));
    fs_util::resolve_ward_home_path(&relative, "project store record")
        .expect("project store record should stay inside Ward home")
}

pub fn list_summaries() -> Result<Vec<ProjectStoreSummary>> {
    let dir = projects_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut summaries = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let record = read_record_path(&path)?;
        summaries.push(summary_for_record(&record));
    }
    summaries.sort_by(|left, right| left.project_name.cmp(&right.project_name));
    Ok(summaries)
}

pub fn show_summary(project: &str) -> Result<ProjectStoreSummary> {
    let record = read_record(project)?;
    Ok(summary_for_record(&record))
}

pub fn remove_record(project: &str) -> Result<bool> {
    let path = record_path(project);
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(true)
}

pub fn diagnostics(project: &str) -> Result<ProjectStoreDiagnostics> {
    let path = record_path(project);
    if !path.exists() {
        return Ok(ProjectStoreDiagnostics {
            path,
            exists: false,
            stale: true,
            env_count: 0,
            profile_count: 0,
            agent_policy_count: 0,
        });
    }
    let record = read_record(project)?;
    Ok(ProjectStoreDiagnostics {
        path,
        exists: true,
        stale: record_is_stale(&record),
        env_count: record.env_names.len(),
        profile_count: record.profiles.len(),
        agent_policy_count: record.agent_policies.len(),
    })
}

pub fn refresh_from_plaintext(
    project: &str,
    project_path: &Path,
    vault_path: &Path,
    config: &ProjectConfig,
    plaintext: &str,
    passphrase: &str,
) -> Result<ProjectStoreSummary> {
    let record = record_from_plaintext(
        project,
        project_path,
        vault_path,
        config,
        plaintext,
        passphrase,
    )?;
    write_record(&record)?;
    Ok(summary_for_record(&record))
}

pub fn refresh_from_vault(
    project: &str,
    project_path: &Path,
    vault_path: &Path,
    config: &ProjectConfig,
    passphrase: &str,
) -> Result<ProjectStoreSummary> {
    let plaintext = vault::decrypt_vault_file(vault_path, passphrase)?;
    refresh_from_plaintext(
        project,
        project_path,
        vault_path,
        config,
        &plaintext,
        passphrase,
    )
}

pub fn record_from_plaintext(
    project: &str,
    project_path: &Path,
    vault_path: &Path,
    config: &ProjectConfig,
    plaintext: &str,
    passphrase: &str,
) -> Result<ProjectStoreRecord> {
    vault::validate_dotenv(plaintext)?;
    let env_names = env_file::parse_env_map(plaintext)?
        .into_keys()
        .collect::<Vec<_>>();
    let existing = read_record(project).ok();
    let created_at = existing
        .as_ref()
        .map(|record| record.created_at.clone())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let project_id = existing
        .as_ref()
        .map(|record| record.project_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let updated_at = chrono::Utc::now().to_rfc3339();
    let data_key = random_data_key();
    let payload = vault::encrypt_env(plaintext, &data_key)?;
    let key_wrap = vault::encrypt_env(&data_key, passphrase)?;

    Ok(ProjectStoreRecord {
        version: STORE_RECORD_VERSION,
        project_id,
        project_name: project.to_string(),
        source: ProjectStoreSource {
            project: project.to_string(),
            path: project_path.to_path_buf(),
            vault: vault_path.to_path_buf(),
            snapshot_hash: snapshot_hash(plaintext),
        },
        created_at,
        updated_at,
        env_names: normalize_strings(env_names),
        profiles: config.profiles.clone(),
        agent_policies: config.agent_policies.clone(),
        encrypted_secrets: EncryptedProjectSecrets {
            algorithm: "AES-256-GCM data key wrapped by local passphrase".to_string(),
            key_wrap,
            payload,
        },
        recipient_key_wraps: Vec::new(),
    })
}

pub fn write_record(record: &ProjectStoreRecord) -> Result<PathBuf> {
    fs_util::ensure_private_dir(&projects_dir())?;
    let path = record_path(&record.project_name);
    let contents = serde_json::to_string_pretty(record)?;
    fs_util::write_private_file(&path, format!("{contents}\n").as_bytes())?;
    Ok(path)
}

pub fn read_record(project: &str) -> Result<ProjectStoreRecord> {
    read_record_path(&record_path(project))
}

fn read_record_path(path: &Path) -> Result<ProjectStoreRecord> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn summary_for_record(record: &ProjectStoreRecord) -> ProjectStoreSummary {
    ProjectStoreSummary {
        project_id: record.project_id.clone(),
        project_name: record.project_name.clone(),
        path: record.source.path.clone(),
        vault: record.source.vault.clone(),
        env_names: record.env_names.clone(),
        profile_names: record.profiles.keys().cloned().collect(),
        agent_names: record.agent_policies.keys().cloned().collect(),
        created_at: record.created_at.clone(),
        updated_at: record.updated_at.clone(),
        stale: record_is_stale(record),
    }
}

fn record_is_stale(record: &ProjectStoreRecord) -> bool {
    !record.source.vault.exists()
}

fn normalize_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn snapshot_hash(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex::encode(hasher.finalize())
}

fn random_data_key() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn slugify(project: &str) -> String {
    project
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct WardHomeGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl WardHomeGuard {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var_os("WARD_HOME");
            std::env::set_var("WARD_HOME", path);
            Self { previous }
        }
    }

    impl Drop for WardHomeGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("WARD_HOME", value),
                None => std::env::remove_var("WARD_HOME"),
            }
        }
    }

    #[test]
    #[serial]
    fn store_record_contains_names_but_not_plaintext_values() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.profiles.get_mut("dev").unwrap().env = vec!["API_KEY".to_string()];
        config.agent_policies.insert(
            "codex".to_string(),
            AgentPolicyConfig {
                profiles: vec!["dev".to_string()],
                env: vec!["API_KEY".to_string()],
            },
        );
        let record = record_from_plaintext(
            "demo",
            tempdir.path(),
            &tempdir.path().join(".env.vault"),
            &config,
            "API_KEY=super-secret-value\n",
            "1234",
        )
        .unwrap();
        let serialized = serde_json::to_string(&record).unwrap();
        assert!(serialized.contains("API_KEY"));
        assert!(serialized.contains("codex"));
        assert!(!serialized.contains("super-secret-value"));
    }
}
