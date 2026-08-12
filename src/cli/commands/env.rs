fn env_command(command: EnvCommand) -> Result<()> {
    match command {
        EnvCommand::List {
            project,
            app,
            all,
            json,
            no_prompt,
        } => {
            if no_prompt {
                if !json {
                    anyhow::bail!("ward env list --no-prompt requires --json");
                }
                let targets = resolve_env_targets(project, app, all)?;
                let mut projects = Vec::new();
                for target in targets {
                    let names =
                        broker::list_vault_keys_from_active_session(&target.name, &target.vault)
                            .with_context(|| {
                                format!(
                                    "env list requires an active broker session for {}",
                                    target.name
                                )
                            })?;
                    projects.push(serde_json::json!({
                        "project": target.name,
                        "envNames": names,
                    }));
                }
                if all {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "projects": projects,
                        }))?
                    );
                } else {
                    let project = projects
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| serde_json::json!({ "project": "", "envNames": [] }));
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "project": project.get("project").cloned().unwrap_or_default(),
                            "envNames": project.get("envNames").cloned().unwrap_or_default(),
                        }))?
                    );
                }
                return Ok(());
            }
            let passphrase = vault::read_existing_passphrase()?;
            let targets = resolve_env_targets_with_passphrase(project, app, all, &passphrase)?;
            let mut json_projects = Vec::new();
            for target in targets {
                let resolved = target.resolved_project();
                let names = with_passphrase_vault_access(&resolved, &passphrase, || {
                    env_file::list_env_names(&resolved.vault, &passphrase)
                })?;
                if json {
                    json_projects.push(serde_json::json!({
                        "project": resolved.name,
                        "envNames": names,
                    }));
                } else {
                    for name in names {
                        if all {
                            println!("{}\t{name}", resolved.name);
                        } else {
                            println!("{name}");
                        }
                    }
                }
            }
            if json {
                if all {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "projects": json_projects,
                        }))?
                    );
                } else {
                    let project = json_projects
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| serde_json::json!({ "project": "", "envNames": [] }));
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "project": project.get("project").cloned().unwrap_or_default(),
                            "envNames": project.get("envNames").cloned().unwrap_or_default(),
                        }))?
                    );
                }
            }
        }
        EnvCommand::RequestSet {
            project,
            app,
            key,
            wait_for_approval,
            approval_timeout,
            json,
            no_prompt,
        } => {
            if no_prompt && !json {
                anyhow::bail!("ward env request-set --no-prompt requires --json");
            }
            let key = key.trim().to_string();
            validate_env_key(&key)?;
            let target = resolve_env_project(project, app)?;
            let fix_command = format!(
                "ward env set --project {} {}=<value> && ward env lock --project {}",
                shell_quote(&target.name),
                key,
                shell_quote(&target.name)
            );
            let notification = notifications::create_block_notification(
                notifications::BlockNotificationRequest {
                    kind: notifications::NotificationKind::VaultKeyMissing,
                    project: &target.name,
                    agent: None,
                    command: Some("ward env request-set"),
                    env: std::slice::from_ref(&key),
                    findings: &[],
                    risk: "warning".to_string(),
                    message: format!(
                        "Env key {key} is missing from the vault. A human must add its value."
                    ),
                    fix_command: Some(&fix_command),
                },
            )?;
            if wait_for_approval {
                wait_for_env_key(&target, &key, &approval_timeout)?;
                notifications::remove_block_notification(notification.id)?;
                print_env_request_set_response(
                    json,
                    "env_available",
                    &target.name,
                    &key,
                    notification.id,
                    Some(&fix_command),
                )?;
            } else {
                print_env_request_set_response(
                    json,
                    "notification_created",
                    &target.name,
                    &key,
                    notification.id,
                    Some(&fix_command),
                )?;
            }
        }
        EnvCommand::Set {
            project,
            app,
            assignment,
        } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            let key = with_passphrase_vault_access(&resolved, &passphrase, || {
                let key = env_file::set_env_value(&resolved.vault, &passphrase, &assignment)?;
                warn_store_refresh_failure(refresh_project_store_with_passphrase(
                    &resolved,
                    &passphrase,
                ));
                Ok(key)
            })?;
            env_file::refresh_locked_env(&resolved.path, &resolved.vault)?;
            log_env_file_event("env.set", &resolved, None, Some(&key))?;
            term::emit_header(&term::Header {
                command: Some("env set"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            term::ok_detail("encrypted env set", &key);
        }
        EnvCommand::Unset { project, app, key } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            let removed = with_passphrase_vault_access(&resolved, &passphrase, || {
                let removed = env_file::unset_env_value(&resolved.vault, &passphrase, &key)?;
                warn_store_refresh_failure(refresh_project_store_with_passphrase(
                    &resolved,
                    &passphrase,
                ));
                Ok(removed)
            })?;
            env_file::refresh_locked_env(&resolved.path, &resolved.vault)?;
            log_env_file_event("env.unset", &resolved, None, Some(&key))?;
            if removed {
                term::emit_header(&term::Header {
                    command: Some("env unset"),
                    project: &resolved.name,
                    path: Some(&resolved.path),
                    mode: None,
                });
                term::ok_detail("encrypted env removed", &key);
            } else {
                term::warn_detail("encrypted env not found", &key);
            }
        }
        EnvCommand::Unlock {
            project,
            app,
            all,
            output,
            force,
        } => {
            if all && !force {
                anyhow::bail!("ward env unlock --all requires --force");
            }
            let passphrase = vault::read_existing_passphrase()?;
            let targets = resolve_env_targets_with_passphrase(project, app, all, &passphrase)?;
            for target in targets {
                let resolved = target.resolved_project();
                let output =
                    project_relative_path(&resolved.path, output.clone(), "env unlock output")?;
                with_passphrase_vault_access(&resolved, &passphrase, || {
                    env_file::unlock_env_file(&output, &resolved.vault, &passphrase, force)
                })?;
                log_env_file_event("env.unlock", &resolved, Some(&output), None)?;
                term::emit_header(&term::Header {
                    command: Some("env unlock"),
                    project: &resolved.name,
                    path: Some(&resolved.path),
                    mode: None,
                });
                term::warn_detail("plaintext env written", &term::short_path(&output));
            }
            term::next("run: ward env lock");
        }
        EnvCommand::Lock {
            project,
            app,
            source,
        } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            let source = project_relative_path(&resolved.path, source, "env lock source")?;
            with_passphrase_vault_access(&resolved, &passphrase, || {
                env_file::lock_plaintext_source(&source, &resolved.vault, &passphrase)?;
                warn_store_refresh_failure(refresh_project_store_with_passphrase(
                    &resolved,
                    &passphrase,
                ));
                Ok(())
            })?;
            log_env_file_event("env.lock", &resolved, Some(&source), None)?;
            term::emit_header(&term::Header {
                command: Some("env lock"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            term::ok_detail("vault re-encrypted", &term::short_path(&resolved.vault));
            term::ok_detail("locked marker", &term::short_path(&source));
        }
        EnvCommand::Export {
            project,
            app,
            output,
            force,
            unsafe_stdout,
        } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            if unsafe_stdout {
                let plaintext = with_passphrase_vault_access(&resolved, &passphrase, || {
                    let plaintext = vault::decrypt_vault_file(&resolved.vault, &passphrase)?;
                    vault::validate_dotenv(&plaintext)?;
                    Ok(plaintext)
                })?;
                print!("{plaintext}");
                log_env_file_event("env.export.stdout", &resolved, None, None)?;
            } else {
                let output_path = match output {
                    Some(path) => path,
                    None => ".env.export".into(),
                };
                let output =
                    project_relative_path(&resolved.path, output_path, "env export output")?;
                with_passphrase_vault_access(&resolved, &passphrase, || {
                    env_file::export_env_file(&output, &resolved.vault, &passphrase, force)
                })?;
                log_env_file_event("env.export", &resolved, Some(&output), None)?;
                term::emit_header(&term::Header {
                    command: Some("env export"),
                    project: &resolved.name,
                    path: Some(&resolved.path),
                    mode: None,
                });
                term::warn_detail("plaintext env exported", &term::short_path(&output));
            }
        }
    }
    Ok(())
}

fn resolve_env_project_with_passphrase(
    project: Option<String>,
    app: Option<String>,
    passphrase: &str,
) -> Result<registry::ResolvedProject> {
    let cwd = env::current_dir()?;
    let target = workspace_target::resolve_one_with_passphrase(
        &workspace_target::TargetSelector::one(project, app),
        &cwd,
        passphrase,
    )?;
    let resolved = target.resolved_project();
    if resolved.vault.exists() {
        registry::update_project_vault(
            &resolved.name,
            resolved.path.clone(),
            resolved.vault.clone(),
        )?;
    }
    Ok(resolved)
}

fn resolve_env_project(
    project: Option<String>,
    app: Option<String>,
) -> Result<registry::ResolvedProject> {
    let cwd = env::current_dir()?;
    let target =
        workspace_target::resolve_one(&workspace_target::TargetSelector::one(project, app), &cwd)?;
    Ok(target.resolved_project())
}

fn resolve_env_targets(
    project: Option<String>,
    app: Option<String>,
    all: bool,
) -> Result<Vec<workspace_target::WorkspaceTarget>> {
    let cwd = env::current_dir()?;
    workspace_target::resolve_many(
        &workspace_target::TargetSelector { project, app, all },
        &cwd,
    )
}

fn resolve_env_targets_with_passphrase(
    project: Option<String>,
    app: Option<String>,
    all: bool,
    passphrase: &str,
) -> Result<Vec<workspace_target::WorkspaceTarget>> {
    let cwd = env::current_dir()?;
    let selector = workspace_target::TargetSelector { project, app, all };
    let targets = workspace_target::resolve_many_with_passphrase(&selector, &cwd, passphrase)?;
    for target in &targets {
        if target.vault.exists() {
            registry::update_project_vault(
                &target.name,
                target.path.clone(),
                target.vault.clone(),
            )?;
        }
    }
    Ok(targets)
}

fn validate_env_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !key
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        anyhow::bail!("invalid env name: {key}");
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.' | '/'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn wait_for_env_key(target: &registry::ResolvedProject, key: &str, timeout: &str) -> Result<()> {
    let timeout = unlock::parse_ttl(timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    loop {
        if let Ok(names) = broker::list_vault_keys_from_active_session(&target.name, &target.vault)
        {
            if names.iter().any(|name| name == key) {
                return Ok(());
            }
        }
        if chrono::Utc::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for env key {key} to be added to {}",
                target.name
            );
        }
        thread::sleep(StdDuration::from_millis(500));
    }
}

fn print_env_request_set_response(
    json_output: bool,
    status: &str,
    project: &str,
    key: &str,
    notification_id: uuid::Uuid,
    fix_command: Option<&str>,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "project": project,
                "envName": key,
                "notificationId": notification_id,
                "fixCommand": fix_command,
            }))?
        );
    } else {
        term::emit_header(&term::Header {
            command: Some("env request-set"),
            project,
            path: None,
            mode: None,
        });
        term::ok_detail(status, key);
        if let Some(command) = fix_command {
            term::next(command);
        }
    }
    Ok(())
}

fn project_relative_path(project_path: &Path, path: PathBuf, label: &str) -> Result<PathBuf> {
    fs_util::resolve_project_path(project_path, &path, label)
}

fn log_env_file_event(
    event_type: &'static str,
    resolved: &registry::ResolvedProject,
    env_file: Option<&Path>,
    key: Option<&str>,
) -> Result<()> {
    let event = EnvFileEvent {
        event_type,
        project: &resolved.name,
        vault: &resolved.vault,
        env_file,
        key,
    };
    audit_logs::append_event(LogKind::Sessions, event)
}

fn with_passphrase_vault_access<T>(
    resolved: &registry::ResolvedProject,
    passphrase: &str,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let active_expires_at = broker::active_session_expiry(&resolved.name, &resolved.vault)?;
    let active_ttl = active_expires_at
        .and_then(|expires_at| remaining_session_ttl(expires_at, chrono::Utc::now()));
    if active_ttl.is_some() {
        if let Some(session_fingerprint) =
            broker::active_session_fingerprint(&resolved.name, &resolved.vault)?
        {
            let file_fingerprint = vault_file_fingerprint(&resolved.vault)?;
            if session_fingerprint != file_fingerprint {
                anyhow::bail!(
                    "active broker session is stale for {}; run ward unlock again before modifying the vault",
                    resolved.name
                );
            }
        }
    }

    let result = operation();
    if let Some(ttl) = active_ttl {
        let refresh_result =
            broker::unlock_project(&resolved.name, &resolved.vault, passphrase, ttl);
        match (&result, refresh_result) {
            (Ok(_), Err(error)) => {
                return Err(error).context(
                    "vault operation succeeded, but Ward could not refresh the active broker session",
                );
            }
            (Err(_), Err(error)) => {
                term::warn_detail("broker session refresh failed", &error.to_string());
            }
            _ => {}
        }
    }
    result
}

fn vault_file_fingerprint(vault: &Path) -> Result<String> {
    let vault = fs_util::resolve_existing_external_file(vault, "vault fingerprint")?;
    let bytes = fs::read(&vault).with_context(|| format!("failed to read {}", vault.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn refresh_project_store_with_passphrase(
    resolved: &registry::ResolvedProject,
    passphrase: &str,
) -> Result<project_store::ProjectStoreSummary> {
    let config = config::read_project_config(&resolved.path)?;
    project_store::refresh_from_vault(
        &resolved.name,
        &resolved.path,
        &resolved.vault,
        &config,
        passphrase,
    )
}

fn warn_store_refresh_failure(result: Result<project_store::ProjectStoreSummary>) {
    if let Err(error) = result {
        term::warn_detail("project-store refresh failed", &error.to_string());
    }
}

fn remaining_session_ttl(
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::Duration> {
    let ttl = expires_at.signed_duration_since(now);
    (ttl.num_seconds() > 0).then_some(ttl)
}

fn verified_no_prompt_context(
    cwd: &Path,
    resolved: &registry::ResolvedProject,
    context_options: &AgentContextOptions,
) -> Result<Option<context::VerifiedContext>> {
    let Some(agent_name) = context_options
        .agent
        .as_deref()
        .filter(|agent| agent_identity_is_present(Some(*agent)))
    else {
        let problem = context::ContextProblem::ContextRequired {
            missing: vec!["agent"],
        };
        println!("{}", context::context_problem_json(&problem)?);
        return Ok(None);
    };
    let agent = agents::ensure_agent(&resolved.name, agent_name)?;
    if let Some(claimed_key) = context_options.agent_key_id.as_deref() {
        if claimed_key != agent.agent_key_id {
            let problem = context::ContextProblem::ContextMismatch {
                field: "agentKeyId",
                claimed: claimed_key.to_string(),
                actual: agent.agent_key_id,
            };
            println!("{}", context::context_problem_json(&problem)?);
            return Ok(None);
        }
    }
    let claimed = context::ClaimedContext {
        agent: context_options.agent.clone(),
        agent_key_id: Some(agent.agent_key_id.clone()),
        worktree: context_options.worktree.clone(),
        branch: context_options.branch.clone(),
        git_remote: context_options.git_remote.clone(),
        commit: context_options.commit.clone(),
    };
    match context::verify_no_prompt_context(&claimed, cwd, resolved, agent.agent_key_id) {
        Ok(verified) => Ok(Some(verified)),
        Err(problem) => {
            println!("{}", context::context_problem_json(&problem)?);
            Ok(None)
        }
    }
}

fn agent_identity_is_present(agent: Option<&str>) -> bool {
    agent.is_some_and(|value| !value.trim().is_empty())
}

fn require_agent_identity_for_non_human(agent: Option<&str>) -> Result<()> {
    if agent_identity_is_present(agent) {
        return Ok(());
    }
    anyhow::bail!("--agent is required outside human mode; pass --agent <name> or run ward human")
}

fn enforce_worktree_for_no_prompt(
    resolved: &registry::ResolvedProject,
    verified: &context::VerifiedContext,
    wait_for_approval: bool,
    approval_timeout: &str,
) -> Result<bool> {
    let registry = registry::load_registry()?;
    let Some(registered) = registry.projects.get(&resolved.name) else {
        return Ok(true);
    };
    match worktrees::evaluate_worktree(registered, &resolved.name, verified)? {
        worktrees::WorktreeDecision::Trusted { .. } => Ok(true),
        worktrees::WorktreeDecision::AutoBound { match_kind } => {
            let response = WorktreeBoundResponse {
                status: "worktree_bound",
                project: &resolved.name,
                worktree: &verified.worktree,
                match_kind: &match_kind,
                continued: true,
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(true)
        }
        worktrees::WorktreeDecision::ApprovalRequired { request } => {
            if wait_for_approval {
                return wait_for_worktree_approval(resolved, verified, request, approval_timeout);
            }
            let approve_command = format!("ward worktrees approve {}", request.id);
            let deny_command = format!("ward worktrees deny {}", request.id);
            let response = WorktreeRequiredResponse {
                status: "worktree_approval_required",
                approval_required: true,
                approval_type: "worktreeBinding",
                project: &resolved.name,
                worktree: &request.path,
                git_remote: &request.git_remote,
                branch: &request.branch,
                commit: &request.commit,
                reason: &request.reason,
                approval_options: vec![
                    WorktreeApprovalOption {
                        action: "approve",
                        label: "Approve this worktree",
                        command: approve_command.clone(),
                    },
                    WorktreeApprovalOption {
                        action: "deny",
                        label: "Deny this worktree",
                        command: deny_command.clone(),
                    },
                ],
                approve_command,
                deny_command,
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(false)
        }
        worktrees::WorktreeDecision::Denied { reason } => {
            let response = serde_json::json!({
                "status": "worktree_denied",
                "project": resolved.name,
                "worktree": verified.worktree,
                "reason": reason,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(false)
        }
    }
}

fn wait_for_worktree_approval(
    resolved: &registry::ResolvedProject,
    verified: &context::VerifiedContext,
    request: worktrees::PendingWorktree,
    approval_timeout: &str,
) -> Result<bool> {
    let timeout = unlock::parse_ttl(approval_timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    term::emit_block(&term::MessageBlock {
        level: term::StatusLevel::Info,
        title: "waiting for worktree approval",
        body: Some("open the dashboard notification center or approve from a human terminal"),
        command: Some(&format!("ward worktrees approve {}", request.id)),
    });
    loop {
        if worktrees::is_known_worktree(&resolved.name, &request.path)? {
            return Ok(true);
        }
        if worktrees::load_pending_worktree(request.id)?.is_none() {
            let response = serde_json::json!({
                "status": "worktree_denied",
                "project": resolved.name,
                "worktree": verified.worktree,
                "requestId": request.id,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(false);
        }
        if chrono::Utc::now() >= deadline {
            let response = serde_json::json!({
                "status": "approval_timeout",
                "approvalType": "worktreeBinding",
                "project": resolved.name,
                "worktree": verified.worktree,
                "requestId": request.id,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(false);
        }
        thread::sleep(StdDuration::from_millis(500));
    }
}
