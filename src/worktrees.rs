use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{context, fs_util, logs, registry};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorktreeState {
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectWorktrees>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProjectWorktrees {
    #[serde(default)]
    pub allowed_roots: Vec<PathBuf>,
    #[serde(default)]
    pub known_worktrees: Vec<KnownWorktree>,
    #[serde(default)]
    pub pending: Vec<PendingWorktree>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KnownWorktree {
    pub path: PathBuf,
    pub git_remote: String,
    pub git_common_dir: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub match_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PendingWorktree {
    pub id: uuid::Uuid,
    pub project: String,
    pub path: PathBuf,
    pub git_remote: String,
    pub branch: String,
    pub commit: String,
    pub created_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorktreeDecision {
    Trusted { match_kind: String },
    AutoBound { match_kind: String },
    ApprovalRequired { request: PendingWorktree },
    Denied { reason: String },
}

pub fn worktrees_path() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new("worktrees.json"), "worktrees path")
        .expect("worktrees path should stay inside Ward home")
}

pub fn load_state() -> Result<WorktreeState> {
    let path = worktrees_path();
    if !path.exists() {
        return Ok(WorktreeState::default());
    }
    let contents =
        std::fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).context(format!("failed to parse {}", path.display()))
}

pub fn save_state(state: &WorktreeState) -> Result<()> {
    fs_util::ensure_private_dir(&logs::ward_home())?;
    let contents = serde_json::to_string_pretty(state).expect("worktree state should serialize");
    fs_util::write_private_file(&worktrees_path(), format!("{contents}\n").as_bytes())
}

pub fn allow_root(project: &str, root: &Path) -> Result<PathBuf> {
    let mut state = load_state()?;
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let project_state = state.projects.entry(project.to_string()).or_default();
    if !project_state.allowed_roots.contains(&root) {
        project_state.allowed_roots.push(root.clone());
    }
    save_state(&state)?;
    Ok(root)
}

pub fn remove_root(project: &str, root: &Path) -> Result<bool> {
    let mut state = load_state()?;
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let Some(project_state) = state.projects.get_mut(project) else {
        return Ok(false);
    };
    let before = project_state.allowed_roots.len();
    project_state
        .allowed_roots
        .retain(|candidate| candidate != &root);
    let removed = before != project_state.allowed_roots.len();
    if removed {
        save_state(&state)?;
    }
    Ok(removed)
}

pub fn list_project(project: &str) -> Result<ProjectWorktrees> {
    let mut state = load_state()?;
    Ok(state.projects.remove(project).unwrap_or_default())
}

pub fn list_pending_worktrees() -> Result<Vec<PendingWorktree>> {
    let state = load_state()?;
    let mut pending = state
        .projects
        .values()
        .flat_map(|project| project.pending.iter().cloned())
        .collect::<Vec<_>>();
    pending.sort_by_key(|request| std::cmp::Reverse(request.created_at));
    Ok(pending)
}

pub fn load_pending_worktree(id: uuid::Uuid) -> Result<Option<PendingWorktree>> {
    Ok(list_pending_worktrees()?
        .into_iter()
        .find(|pending| pending.id == id))
}

pub fn is_known_worktree(project: &str, path: &Path) -> Result<bool> {
    let state = load_state()?;
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    Ok(state
        .projects
        .get(project)
        .map(|project_state| {
            project_state.known_worktrees.iter().any(|known| {
                known
                    .path
                    .canonicalize()
                    .unwrap_or_else(|_| known.path.clone())
                    == path
            })
        })
        .unwrap_or(false))
}

pub fn trust_worktree(
    project: &str,
    path: &Path,
    git_remote: &str,
    git_common_dir: Option<String>,
    match_kind: &str,
) -> Result<KnownWorktree> {
    let mut state = load_state()?;
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let project_state = state.projects.entry(project.to_string()).or_default();
    project_state.pending.retain(|pending| pending.path != path);

    let known = KnownWorktree {
        path,
        git_remote: context::normalize_remote(git_remote),
        git_common_dir,
        detected_at: Utc::now(),
        match_kind: match_kind.to_string(),
    };

    if let Some(existing) = project_state
        .known_worktrees
        .iter_mut()
        .find(|candidate| candidate.path == known.path)
    {
        *existing = known.clone();
    } else {
        project_state.known_worktrees.push(known.clone());
    }

    save_state(&state)?;
    Ok(known)
}

pub fn approve_pending(id: uuid::Uuid) -> Result<Option<KnownWorktree>> {
    let mut state = load_state()?;
    for project_state in state.projects.values_mut() {
        if let Some(index) = project_state
            .pending
            .iter()
            .position(|candidate| candidate.id == id)
        {
            let pending = project_state.pending.remove(index);
            let known = KnownWorktree {
                path: pending.path,
                git_remote: pending.git_remote,
                git_common_dir: None,
                detected_at: Utc::now(),
                match_kind: "manual-approval".to_string(),
            };
            project_state.known_worktrees.push(known.clone());
            save_state(&state)?;
            return Ok(Some(known));
        }
    }
    Ok(None)
}

pub fn deny_pending(id: uuid::Uuid) -> Result<bool> {
    let mut state = load_state()?;
    for project_state in state.projects.values_mut() {
        let before = project_state.pending.len();
        project_state.pending.retain(|candidate| candidate.id != id);
        if before != project_state.pending.len() {
            save_state(&state)?;
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn remove_project(project: &str) -> Result<usize> {
    let mut state = load_state()?;
    let removed = state
        .projects
        .remove(project)
        .map(|project_state| {
            project_state.allowed_roots.len()
                + project_state.known_worktrees.len()
                + project_state.pending.len()
        })
        .unwrap_or(0);
    if removed > 0 {
        save_state(&state)?;
    }
    Ok(removed)
}

pub fn evaluate_worktree(
    registered: &registry::RegisteredProject,
    project: &str,
    verified: &context::VerifiedContext,
) -> Result<WorktreeDecision> {
    let mut state = load_state()?;
    let project_state = state.projects.entry(project.to_string()).or_default();
    let worktree = verified
        .worktree
        .canonicalize()
        .unwrap_or_else(|_| verified.worktree.clone());
    let repo_root = registered
        .path
        .canonicalize()
        .unwrap_or_else(|_| registered.path.clone());
    if worktree == repo_root || worktree.starts_with(&repo_root) {
        return Ok(WorktreeDecision::Trusted {
            match_kind: "registered-repo-root".to_string(),
        });
    }
    if project_state
        .known_worktrees
        .iter()
        .any(|known| known.path == worktree)
    {
        return Ok(WorktreeDecision::Trusted {
            match_kind: "known-worktree".to_string(),
        });
    }

    let registered_remote = registered
        .git_remote
        .as_deref()
        .map(context::normalize_remote)
        .unwrap_or_default();
    let remote_matches = registered_remote.is_empty() || registered_remote == verified.git_remote;
    if !remote_matches {
        return Ok(WorktreeDecision::Denied {
            reason: "git_remote_mismatch".to_string(),
        });
    }

    let under_allowed_root = project_state.allowed_roots.iter().any(|root| {
        let root = root.canonicalize().unwrap_or_else(|_| root.clone());
        worktree.starts_with(root)
    });
    if under_allowed_root {
        let known = KnownWorktree {
            path: worktree,
            git_remote: verified.git_remote.clone(),
            git_common_dir: verified.git_common_dir.clone(),
            detected_at: Utc::now(),
            match_kind: "allowed-root-and-git-remote".to_string(),
        };
        project_state.known_worktrees.push(known);
        save_state(&state)?;
        return Ok(WorktreeDecision::AutoBound {
            match_kind: "allowed-root-and-git-remote".to_string(),
        });
    }

    if let Some(existing) = project_state
        .pending
        .iter()
        .find(|pending| pending.path == worktree)
        .cloned()
    {
        return Ok(WorktreeDecision::ApprovalRequired { request: existing });
    }
    let pending = PendingWorktree {
        id: uuid::Uuid::new_v4(),
        project: project.to_string(),
        path: worktree,
        git_remote: verified.git_remote.clone(),
        branch: verified.branch.clone(),
        commit: verified.commit.clone(),
        created_at: Utc::now(),
        reason: "new_worktree_outside_allowed_roots".to_string(),
    };
    project_state.pending.push(pending.clone());
    save_state(&state)?;
    Ok(WorktreeDecision::ApprovalRequired { request: pending })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn env_lock() -> crate::test_support::TestEnvironment {
        crate::test_support::TestEnvironment::lock()
    }

    fn verified(path: PathBuf) -> context::VerifiedContext {
        context::VerifiedContext {
            project: "demo".to_string(),
            agent: "codex".to_string(),
            agent_key_id: "agent:key".to_string(),
            worktree: path,
            branch: "main".to_string(),
            git_remote: "https://example.test/repo".to_string(),
            commit: "abc".to_string(),
            git_common_dir: None,
        }
    }

    fn registered(repo: &std::path::Path) -> registry::RegisteredProject {
        registry::RegisteredProject {
            path: repo.to_path_buf(),
            vault: repo.join(".env.vault"),
            git_remote: Some("https://example.test/repo.git".to_string()),
            created_at: "now".to_string(),
            last_used: None,
            display_name: None,
            source: None,
            last_seen_at: None,
            allowed_worktree_roots: Vec::new(),
            known_worktrees: Vec::new(),
            auto_bind_worktrees: true,
            canonical_repo_path: None,
            git_common_dir: None,
            workspace_root: None,
            workspace_name: None,
            app_slug: None,
            parent_workspace: None,
        }
    }

    #[test]
    #[serial]
    fn allowed_roots_auto_bind_and_pending_can_be_approved_or_denied() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let worktree = root.path().join("wt");
        std::fs::create_dir(&worktree).unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let registered = registered(repo.path());

        allow_root("demo", root.path()).unwrap();
        assert_eq!(list_project("demo").unwrap().allowed_roots.len(), 1);
        assert!(matches!(
            evaluate_worktree(&registered, "demo", &verified(worktree.clone())).unwrap(),
            WorktreeDecision::AutoBound { .. }
        ));
        assert!(matches!(
            evaluate_worktree(&registered, "demo", &verified(worktree)).unwrap(),
            WorktreeDecision::Trusted { .. }
        ));

        let outside = tempfile::tempdir().unwrap();
        let decision =
            evaluate_worktree(&registered, "demo", &verified(outside.path().into())).unwrap();
        assert!(matches!(
            decision,
            WorktreeDecision::ApprovalRequired { .. }
        ));
        let pending = list_project("demo").unwrap().pending[0].clone();
        assert!(matches!(
            evaluate_worktree(&registered, "demo", &verified(outside.path().into())).unwrap(),
            WorktreeDecision::ApprovalRequired { .. }
        ));
        assert!(approve_pending(pending.id).unwrap().is_some());
        assert!(approve_pending(uuid::Uuid::new_v4()).unwrap().is_none());

        let second = tempfile::tempdir().unwrap();
        let decision =
            evaluate_worktree(&registered, "demo", &verified(second.path().into())).unwrap();
        assert!(matches!(
            decision,
            WorktreeDecision::ApprovalRequired { .. }
        ));
        let pending = list_project("demo").unwrap().pending[0].clone();
        assert!(deny_pending(pending.id).unwrap());
        assert!(!deny_pending(uuid::Uuid::new_v4()).unwrap());
        assert!(!remove_root("missing", root.path()).unwrap());
        assert!(remove_root("demo", root.path()).unwrap());
        assert!(!remove_root("demo", root.path()).unwrap());

        let remote_mismatch = tempfile::tempdir().unwrap();
        let mut mismatch = verified(remote_mismatch.path().into());
        mismatch.git_remote = "https://example.test/other".to_string();
        assert!(matches!(
            evaluate_worktree(&registered, "demo", &mismatch).unwrap(),
            WorktreeDecision::Denied { .. }
        ));

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn worktree_paths_fall_back_when_canonicalization_is_unavailable() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let missing_root = base.path().join("missing-root");
        let missing_worktree = missing_root.join("agent-wt");
        let missing_repo = base.path().join("missing-repo");
        let registered = registered(&missing_repo);

        let stored = allow_root("demo", &missing_root).unwrap();
        assert_eq!(stored, missing_root);
        assert!(matches!(
            evaluate_worktree(&registered, "demo", &verified(missing_worktree)).unwrap(),
            WorktreeDecision::AutoBound { .. }
        ));
        assert!(remove_root("demo", &missing_root).unwrap());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn trust_worktree_upserts_known_worktree_and_clears_pending() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let worktree = root.path().join("repo");
        std::fs::create_dir(&worktree).unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let registered = registered(repo.path());
        assert!(matches!(
            evaluate_worktree(&registered, "demo", &verified(worktree.clone())).unwrap(),
            WorktreeDecision::ApprovalRequired { .. }
        ));

        let known = trust_worktree(
            "demo",
            &worktree,
            "https://example.test/repo.git",
            Some(".git".to_string()),
            "workspace-root-setup",
        )
        .unwrap();
        assert_eq!(known.path, worktree.canonicalize().unwrap());
        assert_eq!(known.git_remote, "https://example.test/repo");
        assert_eq!(known.git_common_dir.as_deref(), Some(".git"));
        assert_eq!(known.match_kind, "workspace-root-setup");

        let state = list_project("demo").unwrap();
        assert_eq!(state.pending.len(), 0);
        assert_eq!(state.known_worktrees.len(), 1);

        let known_again =
            trust_worktree("demo", &worktree, "", None, "workspace-root-setup").unwrap();
        assert_eq!(known_again.path, known.path);
        let state = list_project("demo").unwrap();
        assert_eq!(state.known_worktrees.len(), 1);

        std::env::remove_var("WARD_HOME");
    }
}
