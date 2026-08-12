use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::Serialize;

use crate::{config, registry, vault};

const MAX_PIN_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStrategy {
    Shared,
    PerProject,
}

#[derive(Debug, Clone)]
pub struct ProjectTarget {
    pub project: String,
    pub registry_key: String,
    pub display_name: String,
    pub path: PathBuf,
    pub config: Option<config::ProjectConfig>,
    pub registered_vault: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OffOutcome {
    Restored,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OnOutcome {
    Locked,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UnlockFailure {
    IncorrectPassphrase,
    MarkerWrite,
    PassphrasePrompt,
    PlaintextInspection,
    ProjectMissing,
    Reencrypt,
    VaultMissing,
    VaultResolution,
    VaultWrite,
}

impl UnlockFailure {
    fn retryable(self, uses_derived_vault: bool) -> bool {
        self == Self::IncorrectPassphrase || self == Self::VaultMissing && uses_derived_vault
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OffProjectStatus {
    pub project: String,
    pub registry_key: String,
    pub display_name: String,
    pub path: PathBuf,
    pub vault: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub status: OffOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<UnlockFailure>,
    pub message: String,
    pub pin_attempts: usize,
}

impl OffProjectStatus {
    fn prompt_failure(target: &ProjectTarget, message: String, pin_attempts: usize) -> Self {
        Self {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: None,
            output: None,
            status: OffOutcome::Failed,
            failure: Some(UnlockFailure::PassphrasePrompt),
            message,
            pin_attempts,
        }
    }

    fn retryable(&self, target: &ProjectTarget) -> bool {
        self.failure
            .is_some_and(|failure| failure.retryable(target.uses_derived_vault()))
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnProjectStatus {
    pub project: String,
    pub registry_key: String,
    pub display_name: String,
    pub path: PathBuf,
    pub vault: Option<PathBuf>,
    pub locked_files: Vec<PathBuf>,
    pub status: OnOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<UnlockFailure>,
    pub message: String,
    pub pin_attempts: usize,
}

impl OnProjectStatus {
    fn prompt_failure(target: &ProjectTarget, message: String, pin_attempts: usize) -> Self {
        Self {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: None,
            locked_files: Vec::new(),
            status: OnOutcome::Failed,
            failure: Some(UnlockFailure::PassphrasePrompt),
            message,
            pin_attempts,
        }
    }

    fn retryable(&self, target: &ProjectTarget) -> bool {
        self.failure
            .is_some_and(|failure| failure.retryable(target.uses_derived_vault()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionCounts {
    pub succeeded: usize,
    pub skipped: usize,
    pub failed: usize,
}

pub struct GlobalTransitionService {
    targets: Vec<ProjectTarget>,
}

impl GlobalTransitionService {
    pub fn discover() -> Result<Self> {
        let mut targets = BTreeMap::new();
        collect_registry_targets(&mut targets);
        enrich_from_config_backups(&mut targets);
        Ok(Self {
            targets: targets.into_values().collect(),
        })
    }

    pub fn targets(&self) -> &[ProjectTarget] {
        &self.targets
    }

    pub fn run_off<F>(
        &self,
        strategy: PinStrategy,
        timestamp: &str,
        transition: F,
    ) -> Result<Vec<OffProjectStatus>>
    where
        F: Fn(&ProjectTarget, &str, &str, usize) -> OffProjectStatus,
    {
        match strategy {
            PinStrategy::Shared => {
                let passphrase = self.shared_passphrase()?;
                Ok(self
                    .targets
                    .iter()
                    .map(|target| {
                        transition(
                            target,
                            passphrase.as_deref().unwrap_or(""),
                            timestamp,
                            usize::from(passphrase.is_some()),
                        )
                    })
                    .collect())
            }
            PinStrategy::PerProject => Ok(self
                .targets
                .iter()
                .enumerate()
                .map(|(index, target)| {
                    retry_off_target(
                        target,
                        timestamp,
                        index + 1,
                        self.targets.len(),
                        &transition,
                    )
                })
                .collect()),
        }
    }

    pub fn run_on<F>(&self, strategy: PinStrategy, transition: F) -> Result<Vec<OnProjectStatus>>
    where
        F: Fn(&ProjectTarget, &str, usize) -> OnProjectStatus,
    {
        match strategy {
            PinStrategy::Shared => {
                let passphrase = self.shared_passphrase()?;
                Ok(self
                    .targets
                    .iter()
                    .map(|target| {
                        transition(
                            target,
                            passphrase.as_deref().unwrap_or(""),
                            usize::from(passphrase.is_some()),
                        )
                    })
                    .collect())
            }
            PinStrategy::PerProject => Ok(self
                .targets
                .iter()
                .enumerate()
                .map(|(index, target)| {
                    retry_on_target(target, index + 1, self.targets.len(), &transition)
                })
                .collect()),
        }
    }

    fn shared_passphrase(&self) -> Result<Option<String>> {
        if self.targets.iter().any(|target| target.path.is_dir()) {
            vault::read_existing_passphrase().map(Some)
        } else {
            Ok(None)
        }
    }
}

pub fn off_counts(projects: &[OffProjectStatus]) -> TransitionCounts {
    TransitionCounts {
        succeeded: projects
            .iter()
            .filter(|project| project.status == OffOutcome::Restored)
            .count(),
        skipped: projects
            .iter()
            .filter(|project| project.status == OffOutcome::Skipped)
            .count(),
        failed: projects
            .iter()
            .filter(|project| project.status == OffOutcome::Failed)
            .count(),
    }
}

pub fn on_counts(projects: &[OnProjectStatus]) -> TransitionCounts {
    TransitionCounts {
        succeeded: projects
            .iter()
            .filter(|project| project.status == OnOutcome::Locked)
            .count(),
        skipped: projects
            .iter()
            .filter(|project| project.status == OnOutcome::Skipped)
            .count(),
        failed: projects
            .iter()
            .filter(|project| project.status == OnOutcome::Failed)
            .count(),
    }
}

fn retry_off_target<F>(
    target: &ProjectTarget,
    timestamp: &str,
    index: usize,
    total: usize,
    transition: &F,
) -> OffProjectStatus
where
    F: Fn(&ProjectTarget, &str, &str, usize) -> OffProjectStatus,
{
    if !target.path.is_dir() {
        return transition(target, "", timestamp, 0);
    }
    let mut last_status = None;
    for attempt in 1..=MAX_PIN_ATTEMPTS {
        print_project_prompt(target, index, total);
        let passphrase = match vault::read_existing_passphrase_for_project(&target.display_name) {
            Ok(passphrase) => passphrase,
            Err(error) => {
                return OffProjectStatus::prompt_failure(
                    target,
                    error.to_string(),
                    attempt.saturating_sub(1),
                )
            }
        };
        let status = transition(target, &passphrase, timestamp, attempt);
        if status.status == OffOutcome::Restored || !status.retryable(target) {
            return status;
        }
        if attempt == MAX_PIN_ATTEMPTS {
            return status;
        }
        print_retry(target, attempt);
        last_status = Some(status);
    }
    last_status.unwrap_or_else(|| transition(target, "", timestamp, 0))
}

fn retry_on_target<F>(
    target: &ProjectTarget,
    index: usize,
    total: usize,
    transition: &F,
) -> OnProjectStatus
where
    F: Fn(&ProjectTarget, &str, usize) -> OnProjectStatus,
{
    if !target.path.is_dir() {
        return transition(target, "", 0);
    }
    let mut last_status = None;
    for attempt in 1..=MAX_PIN_ATTEMPTS {
        print_project_prompt(target, index, total);
        let passphrase = match vault::read_existing_passphrase_for_project(&target.display_name) {
            Ok(passphrase) => passphrase,
            Err(error) => {
                return OnProjectStatus::prompt_failure(
                    target,
                    error.to_string(),
                    attempt.saturating_sub(1),
                )
            }
        };
        let status = transition(target, &passphrase, attempt);
        if matches!(status.status, OnOutcome::Locked | OnOutcome::Skipped)
            || !status.retryable(target)
        {
            return status;
        }
        if attempt == MAX_PIN_ATTEMPTS {
            return status;
        }
        print_retry(target, attempt);
        last_status = Some(status);
    }
    last_status.unwrap_or_else(|| transition(target, "", 0))
}

fn print_project_prompt(target: &ProjectTarget, index: usize, total: usize) {
    eprintln!(
        "Project {index}/{total}: {} ({})",
        target.display_name,
        target.path.display()
    );
}

fn print_retry(target: &ProjectTarget, attempt: usize) {
    eprintln!(
        "  PIN/passphrase did not unlock {}; retrying ({}/{MAX_PIN_ATTEMPTS})",
        target.display_name, attempt
    );
}

fn collect_registry_targets(targets: &mut BTreeMap<(String, PathBuf), ProjectTarget>) {
    let Ok(registry) = registry::list_projects() else {
        return;
    };
    for (project, registered) in registry.projects {
        add_target(
            targets,
            ProjectTarget {
                display_name: registered
                    .display_name
                    .clone()
                    .unwrap_or_else(|| project.clone()),
                registry_key: project.clone(),
                project,
                path: registered.path.clone(),
                config: config::read_project_config(&registered.path).ok(),
                registered_vault: Some(registered.vault),
            },
        );
    }
}

fn enrich_from_config_backups(targets: &mut BTreeMap<(String, PathBuf), ProjectTarget>) {
    let dir = config::config_backups_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(backup) = serde_json::from_str::<config::ProjectConfigBackup>(&contents) else {
            continue;
        };
        let key = target_key(&backup.project, &backup.project_path);
        if let Some(existing) = targets.get_mut(&key) {
            if existing.config.is_none() {
                existing.config = Some(backup.config);
            }
        }
    }
}

fn add_target(targets: &mut BTreeMap<(String, PathBuf), ProjectTarget>, target: ProjectTarget) {
    let key = target_key(&target.project, &target.path);
    targets
        .entry(key)
        .and_modify(|existing| {
            if existing.config.is_none() {
                existing.config = target.config.clone();
            }
            if existing.registered_vault.is_none() {
                existing.registered_vault = target.registered_vault.clone();
            }
        })
        .or_insert(target);
}

fn target_key(project: &str, path: &Path) -> (String, PathBuf) {
    (
        project.to_string(),
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf()),
    )
}

impl ProjectTarget {
    fn uses_derived_vault(&self) -> bool {
        self.config
            .as_ref()
            .is_some_and(|config| !config.vault_nonce.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryability_is_structural() {
        assert!(UnlockFailure::IncorrectPassphrase.retryable(false));
        assert!(UnlockFailure::VaultMissing.retryable(true));
        assert!(!UnlockFailure::VaultMissing.retryable(false));
        assert!(!UnlockFailure::VaultWrite.retryable(true));
    }
}
