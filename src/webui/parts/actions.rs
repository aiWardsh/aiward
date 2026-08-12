#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DashboardApprovalRequest {
    #[serde(default)]
    scope: Option<approvals::ApprovalScope>,
    #[serde(default)]
    confirm_critical: bool,
}

fn approval_action(
    req: &mut tiny_http::Request,
    request_id: uuid::Uuid,
    action: &str,
) -> Result<Value> {
    match action {
        "approve" => {
            let body = read_optional_body(req)?;
            let request = if body.trim().is_empty() {
                DashboardApprovalRequest {
                    scope: Some(approvals::ApprovalScope::Session),
                    confirm_critical: false,
                }
            } else {
                serde_json::from_str::<DashboardApprovalRequest>(&body)
                    .context("failed to parse approval JSON request")?
            };
            crate::cli::approve_request_from_dashboard(
                request_id,
                request.scope.unwrap_or(approvals::ApprovalScope::Session),
                request.confirm_critical,
            )
        }
        "deny" => crate::cli::deny_request_from_dashboard(request_id),
        _ => anyhow::bail!("unknown approval action: {action}"),
    }
}

fn worktree_action(request_id: uuid::Uuid, action: &str) -> Result<Value> {
    match action {
        "approve" => {
            let Some(known) = worktrees::approve_pending(request_id)? else {
                anyhow::bail!("pending worktree request not found: {request_id}");
            };
            Ok(json!({
                "status": "approved",
                "requestId": request_id,
                "worktree": known.path,
                "matchKind": known.match_kind,
            }))
        }
        "deny" => {
            if !worktrees::deny_pending(request_id)? {
                anyhow::bail!("pending worktree request not found: {request_id}");
            }
            Ok(json!({
                "status": "denied",
                "requestId": request_id,
            }))
        }
        _ => anyhow::bail!("unknown worktree action: {action}"),
    }
}

fn notification_action(notification_id: uuid::Uuid, action: &str) -> Result<Value> {
    match action {
        "dismiss" => Ok(serde_json::to_value(notifications::dismiss_notification(
            notification_id,
        )?)?),
        _ => anyhow::bail!("unknown notification action: {action}"),
    }
}

fn lock_project_session(project: &str) -> Result<broker::BrokerProjectLockStatus> {
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    broker::lock_project(project, &registered.vault)
}

fn lock_all_sessions() -> Result<Value> {
    let revoked_session_grants = crate::grants::revoke_session_grants()?;
    let cleared_unlock_sessions = crate::unlock::clear_all_unlocks()?;
    broker::stop()?;
    Ok(json!({
        "status": "locked",
        "revokedSessionGrants": revoked_session_grants,
        "clearedUnlockSessions": cleared_unlock_sessions,
    }))
}

fn remove_project_from_dashboard(
    project: &str,
    req: &mut tiny_http::Request,
) -> Result<project_teardown::ProjectTeardownOutcome> {
    let requested: RemoveProjectRequest = read_json_body(req)?;
    if requested.confirm != project {
        anyhow::bail!("project removal requires confirm to equal the project name");
    }
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    broker::remove_project_from_active_session(
        project,
        &registered.vault,
        requested.export_path,
        requested.restore_env,
    )
}

fn update_profile_env(
    project: &str,
    profile: &str,
    req: &mut tiny_http::Request,
) -> Result<ProjectView> {
    let mut body = String::new();
    std::io::Read::read_to_string(req.as_reader(), &mut body)
        .context("failed to read request body")?;
    let requested: UpdateProfileEnvRequest =
        serde_json::from_str(&body).context("failed to parse profile env update")?;
    let env = normalize_env_names(requested.env)?;
    update_profile_env_for_project(project, profile, env)
}

fn update_profile_env_for_project(
    project: &str,
    profile: &str,
    env: Vec<String>,
) -> Result<ProjectView> {
    let env = normalize_env_names(env)?;
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    let profile_cfg = cfg
        .profiles
        .get_mut(profile)
        .with_context(|| format!("profile {profile} not found in project {project}"))?;
    profile_cfg.env = env;
    config::write_project_config(&registered.path, &cfg, true)?;

    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn create_profile_policy(project: &str, req: &mut tiny_http::Request) -> Result<ProjectView> {
    let requested: ProfilePolicyRequest = read_json_body(req)?;
    create_profile_policy_for_project(project, requested)
}

fn create_profile_policy_for_project(
    project: &str,
    requested: ProfilePolicyRequest,
) -> Result<ProjectView> {
    let name = requested
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .context("profile name is required")?
        .to_string();
    validate_profile_name(&name)?;
    let profile = profile_from_request(None, requested)?;

    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    if cfg.profiles.contains_key(&name) {
        anyhow::bail!("profile {name} already exists in project {project}");
    }
    cfg.profiles.insert(name, profile);
    config::write_project_config(&registered.path, &cfg, true)?;
    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn update_profile_policy(
    project: &str,
    profile: &str,
    req: &mut tiny_http::Request,
) -> Result<ProjectView> {
    let requested: ProfilePolicyRequest = read_json_body(req)?;
    update_profile_policy_for_project(project, profile, requested)
}

fn update_profile_policy_for_project(
    project: &str,
    profile: &str,
    requested: ProfilePolicyRequest,
) -> Result<ProjectView> {
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    let existing = cfg
        .profiles
        .remove(profile)
        .with_context(|| format!("profile {profile} not found in project {project}"))?;
    let new_name = requested
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(profile)
        .to_string();
    validate_profile_name(&new_name)?;
    if new_name != profile && cfg.profiles.contains_key(&new_name) {
        anyhow::bail!("profile {new_name} already exists in project {project}");
    }
    let profile_config = profile_from_request(Some(existing), requested)?;
    cfg.profiles.insert(new_name, profile_config);
    config::write_project_config(&registered.path, &cfg, true)?;
    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn delete_profile_policy(project: &str, profile: &str) -> Result<ProjectView> {
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    if cfg.profiles.remove(profile).is_none() {
        anyhow::bail!("profile {profile} not found in project {project}");
    }
    config::write_project_config(&registered.path, &cfg, true)?;
    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn profile_from_request(
    existing: Option<ProfileConfig>,
    requested: ProfilePolicyRequest,
) -> Result<ProfileConfig> {
    let command = string_field(
        "command",
        requested.command,
        existing.as_ref().map(|p| &p.command),
    )?;
    let action = string_field(
        "action",
        requested.action,
        existing.as_ref().map(|p| &p.action),
    )?;
    let default_scope = requested
        .default_scope
        .or_else(|| existing.as_ref().map(|p| p.default_scope))
        .unwrap_or(crate::approvals::ApprovalScope::Session);
    let env = match requested.env {
        Some(env) => normalize_env_names(env)?,
        None => existing.map(|profile| profile.env).unwrap_or_default(),
    };
    Ok(ProfileConfig {
        command,
        env,
        default_scope,
        action,
    })
}

fn string_field(
    name: &str,
    requested: Option<String>,
    existing: Option<&String>,
) -> Result<String> {
    let value = requested
        .as_deref()
        .or(existing.map(String::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is required"))?;
    Ok(value.to_string())
}

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|ch| ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
    {
        anyhow::bail!("invalid profile name: {name}");
    }
    Ok(())
}

fn pick_project_folder(req: &mut tiny_http::Request) -> Result<PickFolderResponse> {
    let body = read_optional_body(req)?;
    if !body.trim().is_empty() {
        let requested: PickFolderRequest =
            serde_json::from_str(&body).context("failed to parse folder picker request")?;
        if requested.path.is_some() {
            return pick_folder_from_request(requested);
        }
    }
    pick_folder_with_native_dialog()
}

fn pick_folder_from_request(requested: PickFolderRequest) -> Result<PickFolderResponse> {
    requested
        .path
        .map(|path| PickFolderResponse { path })
        .context("path is required")
}

fn pick_folder_with_native_dialog() -> Result<PickFolderResponse> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("osascript")
            .args([
                "-e",
                r#"POSIX path of (choose folder with prompt "Select a project folder for Ward")"#,
            ])
            .output()
            .context("failed to open Finder folder picker")?;
        if !output.status.success() {
            anyhow::bail!("folder selection was cancelled");
        }
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            anyhow::bail!("folder selection returned no path");
        }
        Ok(PickFolderResponse {
            path: PathBuf::from(path),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("native folder picker is only available on macOS")
    }
}

fn setup_project_from_dashboard(
    req: &mut tiny_http::Request,
) -> Result<broker::BrokerProjectSetupStatus> {
    let requested: ProjectSetupRequest = read_json_body(req)?;
    let target_path = validate_dashboard_setup_target(&requested.path)?;
    let cwd = std::env::current_dir()?;
    let current = registry::resolve_project(requested.source_project.as_deref(), &cwd)?;
    broker::setup_project_with_active_passphrase(
        &current.name,
        &current.vault,
        &target_path,
        requested.project,
    )
}

fn snapshot_project_from_dashboard(project: &str) -> Result<broker::BrokerProjectSnapshotStatus> {
    let cwd = std::env::current_dir()?;
    let resolved = registry::resolve_project(Some(project), &cwd)?;
    broker::snapshot_project_from_active_session(&resolved.name, &resolved.vault)
}

fn provision_project_from_dashboard(
    req: &mut tiny_http::Request,
) -> Result<broker::BrokerProjectProvisionStatus> {
    let requested: ProjectProvisionRequest = read_json_body(req)?;
    let target_path = requested.path;
    let cwd = std::env::current_dir()?;
    let source = registry::resolve_project(requested.source_project.as_deref(), &cwd)?;
    let status = broker::provision_project_from_active_session(broker::ProjectProvisionRequest {
        source_project: source.name,
        source_vault: source.vault,
        target_path,
        project: requested.project,
        profiles: requested.profiles,
        env_names: requested.env,
        agents: requested.agents,
    })?;
    Ok(status)
}

fn validate_dashboard_setup_target(path: &Path) -> Result<PathBuf> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !path.is_dir() {
        anyhow::bail!("selected path is not a directory: {}", path.display());
    }
    if !path.join(".ward.json").exists() && !path.join(".env").exists() {
        anyhow::bail!(
            "selected folder has no .env or .ward.json; choose a project folder that already has secrets or run ward setup manually"
        );
    }
    Ok(path)
}

fn read_json_body<T: for<'de> Deserialize<'de>>(req: &mut tiny_http::Request) -> Result<T> {
    let body = read_optional_body(req)?;
    serde_json::from_str(&body).context("failed to parse JSON request")
}

fn read_optional_body(req: &mut tiny_http::Request) -> Result<String> {
    let mut body = String::new();
    std::io::Read::read_to_string(req.as_reader(), &mut body)
        .context("failed to read request body")?;
    Ok(body)
}

fn normalize_env_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let trimmed = name.trim();
        if !is_valid_env_name(trimmed) {
            anyhow::bail!("invalid env name: {trimmed}");
        }
        normalized.insert(trimmed.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
}
