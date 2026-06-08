use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    config, env_file, fs_util, grants, logs, pending_requests, project_store, registry, unlock,
    vault, worktrees,
};

#[derive(Debug, Clone)]
pub struct ProjectTeardownRequest {
    pub project: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub export_path: PathBuf,
    pub restore_env: bool,
    pub decrypt_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectTeardownOutcome {
    pub project: String,
    pub export_path: PathBuf,
    pub removed_files: Vec<String>,
    pub removed_grants: usize,
    pub removed_pending_requests: usize,
    pub removed_worktree_records: usize,
    pub cleared_unlock_sessions: usize,
    pub removed_store_records: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeardownEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    export_path: &'a Path,
    removed_files: &'a [String],
    removed_grants: usize,
    removed_pending_requests: usize,
    removed_worktree_records: usize,
    cleared_unlock_sessions: usize,
    removed_store_records: usize,
}

pub fn teardown_project(request: ProjectTeardownRequest) -> Result<ProjectTeardownOutcome> {
    let export_path = if request.restore_env && request.export_path == PathBuf::from(".env.export")
    {
        PathBuf::from(".env")
    } else {
        request.export_path
    };
    let output = project_relative_path(&request.path, export_path)?;
    if output == request.path.join(".env") && !request.restore_env {
        anyhow::bail!("restoring plaintext .env requires --restore-env");
    }

    env_file::export_env_file_with_key(&output, &request.vault, &request.decrypt_key, true)?;
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if output
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        anyhow::bail!("Invalid input: {}", output.display());
    }
    vault::validate_dotenv(&fs::read_to_string(&output)?)?;

    let mut removed_files = Vec::new();
    for path in [
        request.path.join(config::PROJECT_CONFIG_FILE),
        request.vault.clone(),
    ] {
        remove_project_file_if_exists(&path, &mut removed_files)?;
    }

    let env_path = request.path.join(".env");
    remove_locked_env_if_needed(&env_path, &output, &mut removed_files)?;

    for path in [
        request.path.join(config::AGENT_INSTRUCTIONS_FILE),
        request.path.join(config::CLAUDE_INSTRUCTIONS_FILE),
    ] {
        if remove_agent_instruction_section(&path)? {
            removed_files.push(format!("updated {}", path.display()));
        }
    }

    registry::remove_project(&request.project)?;
    let removed_grants = grants::remove_project_grants(&request.project)?;
    let removed_pending_requests = pending_requests::remove_project_requests(&request.project)?;
    let removed_worktree_records = worktrees::remove_project(&request.project)?;
    let cleared_unlock_sessions = unlock::clear_project_unlocks(&request.project)?;
    let mut removed_store_records = 0;
    if project_store::remove_record(&request.project)? {
        removed_store_records += 1;
    }

    let outcome = ProjectTeardownOutcome {
        project: request.project,
        export_path: output,
        removed_files,
        removed_grants,
        removed_pending_requests,
        removed_worktree_records,
        cleared_unlock_sessions,
        removed_store_records,
    };
    let event = TeardownEvent {
        event_type: "teardown.completed",
        project: &outcome.project,
        export_path: &outcome.export_path,
        removed_files: &outcome.removed_files,
        removed_grants: outcome.removed_grants,
        removed_pending_requests: outcome.removed_pending_requests,
        removed_worktree_records: outcome.removed_worktree_records,
        cleared_unlock_sessions: outcome.cleared_unlock_sessions,
        removed_store_records: outcome.removed_store_records,
    };
    logs::append_event(logs::LogKind::Sessions, event)?;
    Ok(outcome)
}

fn project_relative_path(project_path: &Path, path: PathBuf) -> Result<PathBuf> {
    fs_util::resolve_project_path(project_path, &path, "teardown export path")
}

pub(crate) fn remove_locked_env_if_needed(
    env_path: &Path,
    output: &Path,
    removed_files: &mut Vec<String>,
) -> Result<()> {
    let should_keep_env = env_path == output || !env_file::is_locked_env_file(env_path)?;
    if should_keep_env {
        return Ok(());
    }
    remove_project_file_if_exists(env_path, removed_files)
}

pub(crate) fn remove_project_file_if_exists(
    path: &Path,
    removed_files: &mut Vec<String>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(path).context(format!("failed to remove {}", path.display()))?;
    removed_files.push(path.display().to_string());
    Ok(())
}

pub(crate) fn remove_agent_instruction_section(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        anyhow::bail!("Invalid input: {}", path.display());
    }
    let contents =
        fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
    let Some(index) = contents.find(config::AGENT_INSTRUCTIONS_MARKER) else {
        return Ok(false);
    };
    let retained = contents[..index].trim_end();
    if retained.is_empty() {
        fs::remove_file(path).context(format!("failed to remove {}", path.display()))?;
    } else {
        fs::write(path, format!("{retained}\n"))
            .context(format!("failed to write {}", path.display()))?;
    }
    Ok(true)
}
