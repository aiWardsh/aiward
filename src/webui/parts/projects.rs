fn dashboard_status() -> Result<DashboardStatus> {
    Ok(DashboardStatus {
        instances: running_instances()?,
        broker: broker::status()?,
        human: human_runtime_view(),
    })
}

fn dashboard_projects() -> Result<Vec<ProjectView>> {
    let registry = registry::list_projects()?;
    let broker_status = broker::status().ok();
    let mut projects = Vec::new();
    for (name, project) in &registry.projects {
        if should_hide_invalid_workspace_root(project) {
            continue;
        }
        projects.push(project_view(
            name,
            project,
            registry.active_project.as_deref(),
            broker_status.as_ref(),
        )?);
    }
    append_discovered_workspace_apps(&mut projects, &registry, broker_status.as_ref())?;
    projects.sort_by(|left, right| {
        left.workspace_root
            .cmp(&right.workspace_root)
            .then_with(|| left.parent_project.cmp(&right.parent_project))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(projects)
}

fn should_hide_invalid_workspace_root(project: &RegisteredProject) -> bool {
    !config::config_path(&project.path).is_file()
        && workspace::discover(&project.path)
            .ok()
            .flatten()
            .is_some_and(|discovery| discovery.app_candidates().next().is_some())
}

fn project_view(
    name: &str,
    project: &RegisteredProject,
    active_project: Option<&str>,
    broker_status: Option<&broker::BrokerStatus>,
) -> Result<ProjectView> {
    let config_result = config::read_project_config(&project.path);
    let mut env_names = BTreeSet::new();
    let mut profiles = Vec::new();
    let mut agent_policies = Vec::new();
    let config_status = match config_result {
        Ok(cfg) => {
            for (profile_name, profile) in cfg.profiles {
                collect_profile_env(&profile, &mut env_names);
                profiles.push(ProfileView {
                    name: profile_name,
                    command: profile.command,
                    env: profile.env,
                    default_scope: profile.default_scope,
                    action: profile.action,
                });
            }
            for (agent, policy) in cfg.agent_policies {
                env_names.extend(policy.env.iter().cloned());
                agent_policies.push(AgentPolicyView {
                    agent,
                    profiles: policy.profiles,
                    env: policy.env,
                });
            }
            "ok".to_string()
        }
        Err(error) => format!("unavailable: {error}"),
    };

    let status_expires_at = broker_status.and_then(|status| {
        status
            .sessions
            .iter()
            .filter(|session| session.project == name && same_path(&session.vault, &project.vault))
            .map(|session| session.expires_at)
            .max()
    });

    let mut vault_keys_verified = false;
    let broker_session_expires_at = if status_expires_at.is_some() {
        match broker::list_vault_keys_from_active_session(name, &project.vault) {
            Ok(vault_keys) => {
                vault_keys_verified = true;
                env_names.extend(vault_keys);
                status_expires_at
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let broker_session_active = broker_session_expires_at.is_some();

    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    agent_policies.sort_by(|left, right| left.agent.cmp(&right.agent));
    Ok(ProjectView {
        name: name.to_string(),
        path: project.path.clone(),
        vault: project.vault.clone(),
        active: active_project == Some(name),
        config_status,
        setup_status: "configured".to_string(),
        setup_available: false,
        workspace_root: project.workspace_root.clone(),
        parent_project: project.parent_workspace.clone(),
        package_name: None,
        package_kind: None,
        profiles,
        agent_policies,
        env_names: env_names.into_iter().collect(),
        vault_keys_verified,
        broker_session_active,
        broker_session_expires_at,
        store_snapshot: project_store::show_summary(name).ok(),
    })
}

fn append_discovered_workspace_apps(
    projects: &mut Vec<ProjectView>,
    registry: &registry::Registry,
    broker_status: Option<&broker::BrokerStatus>,
) -> Result<()> {
    let mut known_paths = projects
        .iter()
        .map(|project| canonical_or_self(&project.path))
        .collect::<BTreeSet<_>>();
    let known_names = projects
        .iter()
        .map(|project| project.name.clone())
        .collect::<BTreeSet<_>>();

    for (root_project_name, registered) in &registry.projects {
        let Some(discovery) = workspace::discover(&registered.path)? else {
            continue;
        };
        for package in discovery.app_candidates() {
            let canonical_path = canonical_or_self(&package.path);
            if known_paths.contains(&canonical_path) || known_names.contains(&package.project_name)
            {
                continue;
            }
            known_paths.insert(canonical_path);
            projects.push(discovered_project_view(
                root_project_name,
                package,
                registry.active_project.as_deref(),
                broker_status,
            )?);
        }
    }
    Ok(())
}

fn discovered_project_view(
    parent_project: &str,
    package: &workspace::WorkspacePackage,
    active_project: Option<&str>,
    broker_status: Option<&broker::BrokerStatus>,
) -> Result<ProjectView> {
    let mut env_names = BTreeSet::new();
    env_names.extend(package.env_example_keys.iter().cloned());
    let config_status = match package.setup_status {
        workspace::WorkspaceSetupStatus::Configured => "ok".to_string(),
        workspace::WorkspaceSetupStatus::NeedsEnv => "needs env".to_string(),
        workspace::WorkspaceSetupStatus::NotConfigured => "not configured".to_string(),
    };
    let package_vault = package.path.join(config::DEFAULT_VAULT_FILE);
    let status_expires_at = broker_status.and_then(|status| {
        status
            .sessions
            .iter()
            .filter(|session| {
                session.project == package.project_name && same_path(&session.vault, &package_vault)
            })
            .map(|session| session.expires_at)
            .max()
    });
    let broker_session_expires_at = if status_expires_at.is_some() {
        match broker::list_vault_keys_from_active_session(&package.project_name, &package_vault) {
            Ok(_) => status_expires_at,
            Err(_) => None,
        }
    } else {
        None
    };
    let broker_session_active = broker_session_expires_at.is_some();

    Ok(ProjectView {
        name: package.project_name.clone(),
        path: package.path.clone(),
        vault: package_vault,
        active: active_project == Some(package.project_name.as_str()),
        config_status,
        setup_status: workspace_setup_status_label(&package.setup_status).to_string(),
        setup_available: package.can_setup(),
        workspace_root: Some(
            package
                .path
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
                .unwrap_or_else(|| package.path.clone()),
        ),
        parent_project: Some(parent_project.to_string()),
        package_name: package.name.clone(),
        package_kind: Some(workspace_package_kind_label(&package.package_kind).to_string()),
        profiles: Vec::new(),
        agent_policies: Vec::new(),
        env_names: env_names.into_iter().collect(),
        vault_keys_verified: false,
        broker_session_active,
        broker_session_expires_at,
        store_snapshot: None,
    })
}

fn workspace_setup_status_label(status: &workspace::WorkspaceSetupStatus) -> &'static str {
    match status {
        workspace::WorkspaceSetupStatus::Configured => "configured",
        workspace::WorkspaceSetupStatus::NeedsEnv => "needsEnv",
        workspace::WorkspaceSetupStatus::NotConfigured => "notConfigured",
    }
}

fn workspace_package_kind_label(kind: &workspace::WorkspacePackageKind) -> &'static str {
    match kind {
        workspace::WorkspacePackageKind::App => "app",
        workspace::WorkspacePackageKind::Package => "package",
    }
}

fn canonical_or_self(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn collect_profile_env(profile: &ProfileConfig, names: &mut BTreeSet<String>) {
    names.extend(profile.env.iter().cloned());
}

fn load_all_events(project_filter: Option<&str>) -> Vec<Value> {
    let registry = registry::list_projects().unwrap_or_default();
    let mut all = Vec::new();
    for &kind in LogKind::all() {
        if let Ok(events) = logs::decrypt_events(kind) {
            for mut event in events {
                scrub_sensitive_fields(&mut event);
                let project = infer_event_project(&event, &registry.projects);
                if let Some(filter) = project_filter {
                    if project.as_deref() != Some(filter) {
                        continue;
                    }
                }
                if let Some(obj) = event.as_object_mut() {
                    obj.insert(
                        "_kind".to_string(),
                        Value::String(event_kind_str(kind).to_string()),
                    );
                    if let Some(project) = project {
                        obj.insert("_project".to_string(), Value::String(project));
                    }
                }
                all.push(event);
            }
        }
    }
    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(Value::as_str).unwrap_or("");
        let tb = b.get("timestamp").and_then(Value::as_str).unwrap_or("");
        tb.cmp(ta)
    });
    all
}

fn event_kind_str(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Executions => "execution",
        LogKind::Requests => "request",
        LogKind::Approvals => "approval",
        LogKind::Alerts => "alert",
        LogKind::Sessions => "session",
    }
}

fn infer_event_project(
    event: &Value,
    projects: &BTreeMap<String, RegisteredProject>,
) -> Option<String> {
    let payload = event.get("payload").unwrap_or(event);
    for path in [
        vec!["project"],
        vec!["access", "project"],
        vec!["verifiedContext", "project"],
        vec!["payload", "project"],
    ] {
        if let Some(project) = nested_str(payload, &path) {
            return Some(project.to_string());
        }
    }

    for path in [
        vec!["cwd"],
        vec!["worktree"],
        vec!["git", "worktreePath"],
        vec!["access", "worktree"],
    ] {
        if let Some(candidate) = nested_str(payload, &path) {
            if let Some(project) = project_for_path(candidate, projects) {
                return Some(project);
            }
        }
    }
    None
}

fn nested_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_str)
}

fn project_for_path(path: &str, projects: &BTreeMap<String, RegisteredProject>) -> Option<String> {
    let candidate = Path::new(path);
    projects
        .iter()
        .filter(|(_, project)| candidate.starts_with(&project.path))
        .max_by_key(|(_, project)| project.path.components().count())
        .map(|(name, _)| name.clone())
}

fn scrub_sensitive_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                if should_redact_key(key) {
                    *nested = Value::String("[redacted]".to_string());
                } else {
                    scrub_sensitive_fields(nested);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_sensitive_fields(item);
            }
        }
        _ => {}
    }
}

fn should_redact_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("passphrase")
        || lower.contains("sessiontoken")
        || lower == "token"
        || lower.contains("plaintext")
        || lower == "secret"
}
