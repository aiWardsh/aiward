use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{approvals::ApprovalScope, fs_util, policy::ApprovalMode, vault};

pub const PROJECT_CONFIG_FILE: &str = ".ward.json";
pub const WARD_JSON_GITIGNORE_ENTRY: &str = ".ward.json";
pub const DEFAULT_VAULT_FILE: &str = ".env.vault";
pub const AGENT_INSTRUCTIONS_FILE: &str = "AGENTS.md";
pub const CLAUDE_INSTRUCTIONS_FILE: &str = "CLAUDE.md";
pub const CONFIG_BACKUP_DIR: &str = "config-backups";
const CONFIG_BACKUP_VERSION: u32 = 1;

const ENV_EXAMPLE_HEADER: &str = "# Ward managed environment.\n# Plaintext .env files should not be committed or shared with AI agents.\n# Agents should request scoped access with ward request, then run approved commands with ward run.\n\n";
pub const AGENT_INSTRUCTIONS_MARKER: &str = "<!-- ward-agent-instructions -->";

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum StorageMode {
    #[default]
    VaultFile,
    Keychain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfig {
    pub version: u32,
    pub project: String,
    pub vault: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<PresetConfig>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agent_policies: BTreeMap<String, AgentPolicyConfig>,
    #[serde(default = "default_anomaly_detection")]
    pub anomaly_detection: AnomalyDetectionConfig,
    #[serde(default)]
    pub storage_mode: StorageMode,
    /// Random hex nonce used to derive the vault filename. Regenerated on each rotation.
    #[serde(default)]
    pub vault_nonce: String,
    /// Whether the user has exported a recovery backup.
    #[serde(default)]
    pub backup_exported: bool,
    /// Whether a recovery key has been created for this project.
    #[serde(default)]
    pub recovery_created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetConfig {
    pub name: String,
    #[serde(rename = "match")]
    pub match_commands: Vec<String>,
    pub allowed_env: Vec<String>,
    pub approval: ApprovalMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConfig {
    pub command: String,
    pub env: Vec<String>,
    pub default_scope: ApprovalScope,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentPolicyConfig {
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyDetectionConfig {
    pub enabled: bool,
    pub working_hours_start: u8,
    pub working_hours_end: u8,
    pub max_runs_per_hour_per_grant: usize,
    pub max_branches_per_grant: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfigBackup {
    pub version: u32,
    pub project: String,
    pub project_path: PathBuf,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub updated_at: String,
    pub config: ProjectConfig,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfigRestore {
    pub project: String,
    pub project_path: PathBuf,
    pub config_path: PathBuf,
    pub backup_path: PathBuf,
    pub updated_at: String,
}

impl ProjectConfig {
    pub fn default_for_dir(cwd: &Path, project: Option<String>) -> Result<Self> {
        let project = match project {
            Some(project) => project,
            None => cwd
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
                .context("could not infer project name from current directory")?,
        };

        let profiles = default_profiles(&default_env_keys(), cwd);

        Ok(Self {
            version: 1,
            project,
            vault: PathBuf::from(DEFAULT_VAULT_FILE),
            presets: Vec::new(),
            profiles,
            agent_policies: BTreeMap::new(),
            anomaly_detection: default_anomaly_detection(),
            storage_mode: StorageMode::VaultFile,
            vault_nonce: vault::generate_vault_nonce(),
            backup_exported: false,
            recovery_created: false,
        })
    }
}

include!("parts/persistence.rs");
include!("parts/defaults.rs");
include!("parts/resolution.rs");
include!("parts/tests.rs");
