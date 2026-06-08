use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    config::{read_project_config, resolve_vault_path, resolve_vault_path_with_passphrase},
    fs_util,
    git_context::collect_git_context,
    logs,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    #[serde(default)]
    pub active_project: Option<String>,
    #[serde(default)]
    pub projects: BTreeMap<String, RegisteredProject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredProject {
    pub path: PathBuf,
    pub vault: PathBuf,
    pub git_remote: Option<String>,
    pub created_at: String,
    pub last_used: Option<String>,
    #[serde(default)]
    pub allowed_worktree_roots: Vec<PathBuf>,
    #[serde(default)]
    pub known_worktrees: Vec<PathBuf>,
    #[serde(default = "default_auto_bind_worktrees")]
    pub auto_bind_worktrees: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_repo_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_common_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_workspace: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedProject {
    pub name: String,
    pub path: PathBuf,
    pub vault: PathBuf,
}

pub fn registry_path() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new("registry.json"), "registry path")
        .expect("registry path should stay inside Ward home")
}

pub fn load_registry() -> Result<Registry> {
    let path = registry_path();
    if !path.exists() {
        return Ok(Registry::default());
    }

    let contents =
        fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    let registry: Registry =
        serde_json::from_str(&contents).context(format!("failed to parse {}", path.display()))?;
    Ok(sanitize_registry(registry))
}

pub fn save_registry(registry: &Registry) -> Result<()> {
    let path = registry_path();

    let contents = serde_json::to_string_pretty(registry).expect("registry should serialize");
    fs_util::ensure_private_dir(&logs::ward_home())?;
    fs_util::write_private_file(&path, format!("{contents}\n").as_bytes())
}

pub fn register_project(
    project: String,
    path: PathBuf,
    vault: PathBuf,
) -> Result<RegisteredProject> {
    let mut registry = load_registry()?;
    let vault = validate_vault_path(&path, &vault)?;
    let git = collect_git_context(&path);
    let canonical_repo_path = path.canonicalize().ok();
    let registered = RegisteredProject {
        path,
        vault,
        git_remote: git.remote,
        created_at: chrono::Utc::now().to_rfc3339(),
        last_used: Some(chrono::Utc::now().to_rfc3339()),
        allowed_worktree_roots: Vec::new(),
        known_worktrees: Vec::new(),
        auto_bind_worktrees: true,
        canonical_repo_path,
        git_common_dir: git.common_dir,
        workspace_root: None,
        workspace_name: None,
        app_slug: None,
        parent_workspace: None,
    };

    registry
        .projects
        .insert(project.clone(), registered.clone());
    registry.active_project = Some(project);
    save_registry(&registry)?;

    Ok(registered)
}

pub fn update_project_vault(project: &str, path: PathBuf, vault: PathBuf) -> Result<()> {
    let mut registry = load_registry()?;
    let vault = validate_vault_path(&path, &vault)?;
    let git = collect_git_context(&path);
    let canonical_repo_path = path.canonicalize().ok();
    match registry.projects.get_mut(project) {
        Some(registered) => {
            registered.path = path;
            registered.vault = vault;
            registered.git_remote = git.remote;
            registered.last_used = Some(chrono::Utc::now().to_rfc3339());
            registered.canonical_repo_path = canonical_repo_path;
            registered.git_common_dir = git.common_dir;
        }
        None => {
            let registered = RegisteredProject {
                path,
                vault,
                git_remote: git.remote,
                created_at: chrono::Utc::now().to_rfc3339(),
                last_used: Some(chrono::Utc::now().to_rfc3339()),
                allowed_worktree_roots: Vec::new(),
                known_worktrees: Vec::new(),
                auto_bind_worktrees: true,
                canonical_repo_path,
                git_common_dir: git.common_dir,
                workspace_root: None,
                workspace_name: None,
                app_slug: None,
                parent_workspace: None,
            };
            registry.projects.insert(project.to_string(), registered);
        }
    }
    registry.active_project = Some(project.to_string());
    save_registry(&registry)
}

pub fn update_project_workspace_metadata(
    project: &str,
    workspace_root: Option<PathBuf>,
    workspace_name: Option<String>,
    app_slug: Option<String>,
    parent_workspace: Option<String>,
) -> Result<()> {
    let mut registry = load_registry()?;
    let Some(registered) = registry.projects.get_mut(project) else {
        anyhow::bail!("project {project} is not registered");
    };
    registered.workspace_root = workspace_root;
    registered.workspace_name = workspace_name;
    registered.app_slug = app_slug;
    registered.parent_workspace = parent_workspace;
    save_registry(&registry)
}

fn default_auto_bind_worktrees() -> bool {
    true
}

pub fn list_projects() -> Result<Registry> {
    load_registry()
}

pub fn set_active_project(project: &str) -> Result<()> {
    let mut registry = load_registry()?;
    if !registry.projects.contains_key(project) {
        anyhow::bail!("project {project} is not registered");
    }

    registry.active_project = Some(project.to_string());
    save_registry(&registry)
}

pub fn remove_project(project: &str) -> Result<bool> {
    let mut registry = load_registry()?;
    let removed = registry.projects.remove(project).is_some();
    if registry.active_project.as_deref() == Some(project) {
        registry.active_project = None;
    }
    if removed {
        save_registry(&registry)?;
    }
    Ok(removed)
}

pub fn resolve_project(explicit_project: Option<&str>, cwd: &Path) -> Result<ResolvedProject> {
    let registry = load_registry()?;

    if let Some(project) = explicit_project {
        return registered_project(&registry, project)
            .context(format!("project {project} is not registered"));
    }

    let local_config_root =
        crate::config::find_project_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    if let Ok(config) = read_project_config(&local_config_root) {
        if registry.projects.contains_key(&config.project) {
            return registered_project(&registry, &config.project)
                .context(format!("project {} is not registered", config.project));
        }

        return Ok(ResolvedProject {
            name: config.project.clone(),
            path: local_config_root.clone(),
            vault: resolve_vault_path(&local_config_root, &config),
        });
    }

    let git = collect_git_context(cwd);
    if let Some(remote) = git.remote.as_deref() {
        if let Some((name, registered)) = registry
            .projects
            .iter()
            .find(|(_, registered)| registered.git_remote.as_deref() == Some(remote))
        {
            return Ok(ResolvedProject {
                name: name.clone(),
                path: registered.path.clone(),
                vault: validate_vault_path(&registered.path, &registered.vault)?,
            });
        }
    }

    if let Some((name, registered)) = registry
        .projects
        .iter()
        .filter(|(_, registered)| cwd.starts_with(&registered.path))
        .max_by(|(left_name, left), (right_name, right)| {
            left.path
                .components()
                .count()
                .cmp(&right.path.components().count())
                .then_with(|| left.git_remote.is_none().cmp(&right.git_remote.is_none()))
                .then_with(|| left_name.cmp(right_name))
        })
    {
        return Ok(ResolvedProject {
            name: name.clone(),
            path: registered.path.clone(),
            vault: validate_vault_path(&registered.path, &registered.vault)?,
        });
    }

    if let Some(active) = registry.active_project.as_deref() {
        return registered_project(&registry, active)
            .context(format!("active project {active} is not registered"));
    }

    anyhow::bail!("could not resolve Ward project; run ward init or ward use <project>")
}

pub fn resolve_project_with_passphrase(
    explicit_project: Option<&str>,
    cwd: &Path,
    passphrase: &str,
) -> Result<ResolvedProject> {
    let mut resolved = resolve_project(explicit_project, cwd)?;
    if let Ok(config) = read_project_config(&resolved.path) {
        if config.project == resolved.name {
            resolved.vault =
                resolve_vault_path_with_passphrase(&resolved.path, &config, passphrase);
        }
    }
    Ok(resolved)
}

fn registered_project(registry: &Registry, project: &str) -> Option<ResolvedProject> {
    let registered = registry.projects.get(project)?;
    let vault = validate_vault_path(&registered.path, &registered.vault).ok()?;
    Some(ResolvedProject {
        name: project.to_string(),
        path: registered.path.clone(),
        vault,
    })
}

fn sanitize_registry(mut registry: Registry) -> Registry {
    registry
        .projects
        .retain(|_, registered| validate_registered_project(registered).is_ok());
    if registry
        .active_project
        .as_ref()
        .is_some_and(|project| !registry.projects.contains_key(project))
    {
        registry.active_project = None;
    }
    registry
}

fn validate_registered_project(registered: &RegisteredProject) -> Result<()> {
    validate_vault_path(&registered.path, &registered.vault)?;
    Ok(())
}

fn validate_vault_path(project_path: &Path, vault: &Path) -> Result<PathBuf> {
    fs_util::resolve_project_path(project_path, vault, "registry vault path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Command,
        sync::{Mutex, OnceLock},
    };

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn set_home(path: &Path) {
        std::env::set_var("WARD_HOME", path);
    }

    fn registered(path: &Path, vault: &Path) -> RegisteredProject {
        RegisteredProject {
            path: path.to_path_buf(),
            vault: vault.to_path_buf(),
            git_remote: None,
            allowed_worktree_roots: Vec::new(),
            known_worktrees: Vec::new(),
            auto_bind_worktrees: true,
            canonical_repo_path: None,
            git_common_dir: None,
            workspace_root: None,
            workspace_name: None,
            app_slug: None,
            parent_workspace: None,
            created_at: "2026-05-26T00:00:00Z".to_string(),
            last_used: None,
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_registry_handles_missing_and_invalid_registry() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        set_home(home.path());

        assert!(load_registry().unwrap().projects.is_empty());
        std::fs::create_dir_all(home.path()).unwrap();
        std::fs::write(registry_path(), "{bad-json}").unwrap();
        assert!(load_registry().is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn load_and_save_registry_report_io_failures() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        set_home(home.path());

        std::fs::create_dir(registry_path()).unwrap();
        assert!(load_registry().is_err());

        std::fs::remove_dir(registry_path()).unwrap();
        std::fs::write(home.path().join("registry.json"), "{}").unwrap();
        std::fs::write(home.path().join("registry.json.tmp"), "").unwrap();

        let blocked_home = tempfile::NamedTempFile::new().unwrap();
        set_home(blocked_home.path());
        assert!(save_registry(&Registry::default()).is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn registry_callers_propagate_load_and_save_failures() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        set_home(home.path());

        std::fs::create_dir(registry_path()).unwrap();
        assert!(register_project(
            "demo".to_string(),
            project.path().to_path_buf(),
            project.path().join(".env.vault"),
        )
        .is_err());
        assert!(set_active_project("demo").is_err());
        assert!(resolve_project(None, project.path()).is_err());

        std::fs::remove_dir(registry_path()).unwrap();
        let blocked_home = tempfile::NamedTempFile::new().unwrap();
        set_home(blocked_home.path());
        assert!(register_project(
            "demo".to_string(),
            project.path().to_path_buf(),
            project.path().join(".env.vault"),
        )
        .is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn register_set_active_and_resolve_explicit_project() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let vault = project.path().join(".env.vault");
        set_home(home.path());

        register_project(
            "demo".to_string(),
            project.path().to_path_buf(),
            vault.clone(),
        )
        .unwrap();
        set_active_project("demo").unwrap();
        let resolved = resolve_project(Some("demo"), project.path()).unwrap();

        assert_eq!(resolved.name, "demo");
        assert_eq!(resolved.vault, vault);
        assert!(set_active_project("missing").is_err());
        assert!(resolve_project(Some("missing"), project.path()).is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn register_and_update_reject_vault_outside_project() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        set_home(home.path());

        let outside_vault = outside.path().join("outside.vault");
        let register_error = register_project(
            "demo".to_string(),
            project.path().to_path_buf(),
            outside_vault.clone(),
        )
        .unwrap_err()
        .to_string();
        assert!(register_error.contains("must stay inside"));

        let update_error =
            update_project_vault("demo", project.path().to_path_buf(), outside_vault)
                .unwrap_err()
                .to_string();
        assert!(update_error.contains("must stay inside"));

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn load_registry_filters_invalid_vault_paths() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let valid_project = tempfile::tempdir().unwrap();
        let invalid_project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        set_home(home.path());
        std::fs::create_dir_all(home.path()).unwrap();

        let mut registry = Registry {
            active_project: Some("invalid".to_string()),
            projects: BTreeMap::new(),
        };
        registry.projects.insert(
            "valid".to_string(),
            registered(
                valid_project.path(),
                &valid_project.path().join(".env.vault"),
            ),
        );
        registry.projects.insert(
            "invalid".to_string(),
            registered(
                invalid_project.path(),
                &outside.path().join("outside.vault"),
            ),
        );
        std::fs::write(
            registry_path(),
            serde_json::to_string_pretty(&registry).unwrap(),
        )
        .unwrap();

        let loaded = load_registry().unwrap();
        assert!(loaded.projects.contains_key("valid"));
        assert!(!loaded.projects.contains_key("invalid"));
        assert!(loaded.active_project.is_none());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn resolve_project_uses_local_config_when_registered_or_unregistered() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        set_home(home.path());

        std::fs::write(
            project.path().join(".ward.json"),
            r#"{"version":1,"project":"demo","vault":".env.vault","presets":[]}"#,
        )
        .unwrap();

        let unregistered = resolve_project(None, project.path()).unwrap();
        assert_eq!(unregistered.name, "demo");
        assert_eq!(unregistered.path, project.path());

        let mut registry = Registry::default();
        registry.projects.insert(
            "demo".to_string(),
            registered(project.path(), &project.path().join("registered.vault")),
        );
        save_registry(&registry).unwrap();
        let registered = resolve_project(None, project.path()).unwrap();
        assert_eq!(registered.vault, project.path().join("registered.vault"));

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn resolve_project_uses_git_remote_path_ancestry_and_active_project() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let canonical = tempfile::tempdir().unwrap();
        let active_root = tempfile::tempdir().unwrap();
        let child = canonical.path().join("child");
        let git_repo = tempfile::tempdir().unwrap();
        set_home(home.path());
        std::fs::create_dir(&child).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(git_repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["remote", "add", "origin", "https://example.test/demo.git"])
            .current_dir(git_repo.path())
            .output()
            .unwrap();

        let mut registry = Registry::default();
        registry.active_project = Some("active".to_string());
        registry.projects.insert(
            "remote".to_string(),
            RegisteredProject {
                git_remote: Some("https://example.test/demo.git".to_string()),
                ..registered(canonical.path(), &canonical.path().join("remote.vault"))
            },
        );
        registry.projects.insert(
            "path".to_string(),
            registered(canonical.path(), &canonical.path().join("path.vault")),
        );
        registry.projects.insert(
            "active".to_string(),
            registered(active_root.path(), &active_root.path().join("active.vault")),
        );
        save_registry(&registry).unwrap();

        assert_eq!(
            resolve_project(None, git_repo.path()).unwrap().name,
            "remote"
        );
        let unmatched_git_repo = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(unmatched_git_repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["remote", "add", "origin", "https://example.test/other.git"])
            .current_dir(unmatched_git_repo.path())
            .output()
            .unwrap();
        assert_eq!(
            resolve_project(None, unmatched_git_repo.path())
                .unwrap()
                .name,
            "active"
        );
        assert_eq!(resolve_project(None, &child).unwrap().name, "path");

        let outside = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_project(None, outside.path()).unwrap().name,
            "active"
        );

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    fn registered_project_returns_none_for_missing_project() {
        assert!(registered_project(&Registry::default(), "missing").is_none());
    }

    #[test]
    #[serial_test::serial]
    fn resolve_project_reports_stale_active_project() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        set_home(home.path());

        let registry = Registry {
            active_project: Some("missing".to_string()),
            projects: BTreeMap::new(),
        };
        save_registry(&registry).unwrap();

        assert!(resolve_project(None, outside.path()).is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn resolve_project_reports_unresolved_project_without_active_project() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        set_home(home.path());

        save_registry(&Registry::default()).unwrap();

        assert!(resolve_project(None, outside.path()).is_err());

        std::env::remove_var("WARD_HOME");
    }
}
