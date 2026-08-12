fn modes_command(command: ModesCommand) -> Result<()> {
    match command {
        ModesCommand::List { project, app } => {
            let cwd = env::current_dir()?;
            let target = workspace_target::resolve_one(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
            )?;
            let resolved = target.resolved_project();
            let modes = modes::load_local_modes(&resolved.path)?;
            term::emit_header(&term::Header {
                command: Some("modes list"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            if modes.is_empty() {
                term::info("no modes defined in .ward.modes.json");
            } else {
                for mode in &modes {
                    let level = serde_json::to_string(&mode.level)
                        .unwrap_or_default()
                        .trim_matches('"')
                        .to_string();
                    term::ok_detail(&mode.name, &level);
                }
            }
            Ok(())
        }
        ModesCommand::Push {
            project,
            app,
            global: _,
        } => {
            let cwd = env::current_dir()?;
            let selector = workspace_target::TargetSelector::one(project, app);
            let initial = workspace_target::resolve_one(&selector, &cwd)?.resolved_project();
            let modes_path = modes::local_modes_path(&initial.path);
            let local_modes = modes::load_local_modes(&initial.path)?;
            if local_modes.is_empty() {
                anyhow::bail!("no modes found in {}", modes_path.display());
            }
            let passphrase = vault::read_existing_passphrase()?;
            let resolved =
                workspace_target::resolve_one_with_passphrase(&selector, &cwd, &passphrase)?
                    .resolved_project();
            // Validate passphrase by decrypting the vault
            with_passphrase_vault_access(&resolved, &passphrase, || {
                vault::decrypt_vault_file(&resolved.vault, &passphrase)
                    .context("invalid passphrase — cannot push modes")
            })?;
            modes::push_modes(&local_modes, &resolved.name, &passphrase, &modes_path)?;
            term::emit_header(&term::Header {
                command: Some("modes push"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            term::ok_detail("modes pushed", &format!("{} mode(s)", local_modes.len()));
            Ok(())
        }
        ModesCommand::Status { project, app } => {
            let cwd = env::current_dir()?;
            let target = workspace_target::resolve_one(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
            )?;
            let resolved = target.resolved_project();
            term::emit_header(&term::Header {
                command: Some("modes status"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            match broker::status() {
                Ok(status) => {
                    let session = status.sessions.iter().find(|s| s.project == resolved.name);
                    match session.and_then(|s| s.active_mode.as_deref()) {
                        Some(mode_name) => term::ok_detail("active mode", mode_name),
                        None => term::info("no active mode"),
                    }
                }
                Err(_) => term::warn("broker not running; no active mode"),
            }
            Ok(())
        }
    }
}

fn teardown(
    project: Option<String>,
    app: Option<String>,
    export_path: PathBuf,
    yes: bool,
    restore_env: bool,
) -> Result<()> {
    if !yes {
        anyhow::bail!("teardown requires --yes");
    }
    let cwd = env::current_dir()?;
    let selector = workspace_target::TargetSelector::one(project, app);
    if env::var_os("WARD_UNSAFE_TEST_PASSPHRASE").is_none() && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "teardown requires the vault PIN/passphrase; --yes only skips destructive confirmation and does not bypass secret export approval"
        );
    }
    let passphrase = vault::read_existing_passphrase().context(
        "teardown requires the vault PIN/passphrase even with --yes; run from an interactive terminal or set the unsafe test passphrase only in tests",
    )?;
    let resolved = workspace_target::resolve_one_with_passphrase(&selector, &cwd, &passphrase)?
        .resolved_project();
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::decrypt_vault_file(&resolved.vault, &passphrase)
    })?;
    let outcome = crate::project_teardown::teardown_project(
        crate::project_teardown::ProjectTeardownRequest {
            project: resolved.name.clone(),
            path: resolved.path.clone(),
            vault: resolved.vault.clone(),
            export_path,
            restore_env,
            decrypt_key: passphrase,
        },
    )?;
    term::emit_header(&term::Header {
        command: Some("teardown"),
        project: &outcome.project,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("plaintext export", &term::short_path(&outcome.export_path));
    term::ok("Ward project removed");
    term::ok("encrypted audit logs preserved");
    Ok(())
}

fn unlock_logs(ttl: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let passphrase = vault::read_existing_passphrase()?;
    let resolved = registry::resolve_project_with_passphrase(None, &cwd, &passphrase)?;
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::decrypt_vault_file(&resolved.vault, &passphrase)
    })?;
    let event = LogsUnlockEvent {
        event_type: "logs.unlock",
        project: &resolved.name,
        vault: &resolved.vault,
        expires_at: "deprecated-validate-only".to_string(),
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    term::emit_header(&term::Header {
        command: Some("logs unlock"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::warn("logs unlock is deprecated");
    term::info("logs view/export validates the passphrase every time");
    term::info_detail("requested TTL ignored", ttl);
    Ok(())
}

fn ensure_logs_passphrase() -> Result<()> {
    let cwd = env::current_dir()?;
    let passphrase = vault::read_existing_passphrase()?;
    let resolved = registry::resolve_project_with_passphrase(None, &cwd, &passphrase)?;
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::decrypt_vault_file(&resolved.vault, &passphrase)
    })?;
    Ok(())
}

fn warn_log_view_access() {
    term::emit_block(&term::MessageBlock {
        level: term::StatusLevel::Warn,
        title: "decrypted logs are for review only",
        body: Some(
            "edits are tamper-evident through the hash chain; deleted logs should be treated as high severity",
        ),
        command: None,
    });
}

fn resolve_profile(
    config: &config::ProjectConfig,
    profile: Option<&str>,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
) -> Result<ResolvedProfile> {
    if let Some(profile_name) = profile {
        if command.is_some() || !env_names.is_empty() {
            anyhow::bail!("--profile cannot be combined with --command or --env");
        }
        let Some(profile) = config.profiles.get(profile_name) else {
            anyhow::bail!("profile {profile_name} is not defined in .ward.json");
        };
        return Ok(ResolvedProfile {
            command: profile.command.clone(),
            command_args: split_profile_command(&profile.command),
            env_names: profile.env.clone(),
            action: action.or_else(|| Some(profile.action.clone())),
            default_scope: profile.default_scope,
        });
    }

    let command = command.context("--command is required unless --profile is used")?;
    if env_names.is_empty() {
        anyhow::bail!("at least one --env is required unless --profile is used");
    }
    Ok(ResolvedProfile {
        command: command.clone(),
        command_args: split_profile_command(&command),
        env_names,
        action,
        default_scope: ApprovalScope::Once,
    })
}

fn resolve_run_profile(
    config: &config::ProjectConfig,
    profile: Option<&str>,
    action: Option<String>,
    env_names: Vec<String>,
    command: Vec<String>,
    allow_empty_env: bool,
) -> Result<ResolvedProfile> {
    if let Some(profile_name) = profile {
        if !env_names.is_empty() {
            anyhow::bail!("--profile cannot be combined with --env");
        }
        let Some(profile) = config.profiles.get(profile_name) else {
            anyhow::bail!("profile {profile_name} is not defined in .ward.json");
        };
        let mut command_args = split_profile_command(&profile.command);
        command_args.extend(command);
        let command_text = if command_args.is_empty() {
            profile.command.clone()
        } else {
            command_args.join(" ")
        };
        return Ok(ResolvedProfile {
            command: command_text,
            command_args,
            env_names: profile.env.clone(),
            action: action.or_else(|| Some(profile.action.clone())),
            default_scope: profile.default_scope,
        });
    }

    if command.is_empty() {
        anyhow::bail!("command args are required unless --profile is used");
    }
    if env_names.is_empty() && !allow_empty_env {
        anyhow::bail!("at least one --env is required unless --profile is used");
    }
    Ok(ResolvedProfile {
        command: command.join(" "),
        command_args: command,
        env_names,
        action,
        default_scope: ApprovalScope::Once,
    })
}

fn split_profile_command(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn plan_resolved_profile(
    plan: &workspace_target::WorkspaceExecutionPlan,
    mut profile: ResolvedProfile,
    from_profile: bool,
) -> Result<PlannedProfile> {
    let policy_command = profile.command.clone();
    let mounted = if from_profile {
        workspace_target::mount_profile_command(plan, &profile.command_args)?
    } else {
        workspace_target::mount_command(plan, &profile.command_args)?
    };
    profile.command = mounted.display;
    profile.command_args = mounted.argv;
    Ok(PlannedProfile {
        profile,
        policy_command,
        mounted: mounted.mounted,
    })
}

fn effective_grant_id(
    decision: &ApprovalDecision,
    persisted_grant: Option<&grants::ApprovalGrant>,
) -> Option<uuid::Uuid> {
    decision
        .grant_id
        .or_else(|| persisted_grant.map(|grant| grant.id))
}

fn grant_receipt_hash(
    decision: &ApprovalDecision,
    persisted_grant: Option<&grants::ApprovalGrant>,
) -> Result<Option<String>> {
    if let Some(grant) = persisted_grant {
        return Ok(grant
            .receipt
            .as_ref()
            .map(|receipt| receipt.payload_hash.clone()));
    }
    let Some(grant_id) = decision.grant_id else {
        return Ok(None);
    };
    Ok(grants::load_grants()?
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .and_then(|grant| grant.receipt.map(|receipt| receipt.payload_hash)))
}

fn log_anomaly_alerts(config: &config::ProjectConfig, grant_id: Option<uuid::Uuid>) -> Result<()> {
    let Some(grant_id) = grant_id else {
        return Ok(());
    };
    let events = audit_logs::decrypt_events(LogKind::Executions)?;
    for alert in anomaly::detect_grant_anomalies(
        &config.anomaly_detection,
        &events,
        grant_id,
        chrono::Utc::now(),
    ) {
        audit_logs::append_event(LogKind::Alerts, alert)?;
    }
    Ok(())
}

#[allow(dead_code)]
fn evaluate_access(
    config: &config::ProjectConfig,
    access: &AccessRequest,
) -> policy::PolicyEvaluation {
    evaluate_access_with_policy_command(config, access, &access.command)
}

fn evaluate_access_with_policy_command(
    config: &config::ProjectConfig,
    access: &AccessRequest,
    policy_command: &str,
) -> policy::PolicyEvaluation {
    let findings =
        detection::preflight_findings(&access.command, &access.env, access.action.as_deref());
    if policy_command == access.command {
        return policy::evaluate_request(config, access, None, findings);
    }
    let mut policy_access = access.clone();
    policy_access.command = policy_command.to_string();
    policy::evaluate_request(config, &policy_access, None, findings)
}

fn request_audit_snapshot<'a>(
    access: &'a AccessRequest,
    evaluation: &'a policy::PolicyEvaluation,
    git: &'a git_context::GitContext,
    verified_context: Option<&'a context::VerifiedContext>,
) -> RequestAuditSnapshot<'a> {
    RequestAuditSnapshot {
        project: &access.project,
        agent: &access.agent,
        branch: &access.branch,
        action: &access.action,
        command: &access.command,
        env: &access.env,
        requested_env: &evaluation.requested_env,
        matched_profile: &evaluation.matched_profile,
        matched_preset: &evaluation.matched_preset,
        matched_mode: &evaluation.matched_mode,
        policy_findings: &evaluation.findings,
        git,
        verified_context,
    }
}

fn approval_channel_for_source(source: approvals::ApprovalSource) -> ApprovalChannel {
    match source {
        approvals::ApprovalSource::LocalTty => ApprovalChannel::LocalPrompt,
        approvals::ApprovalSource::ManualAllow => ApprovalChannel::ManualAllow,
        approvals::ApprovalSource::AgentMediated => ApprovalChannel::AgentMediatedCli,
        approvals::ApprovalSource::BrokerApproval => ApprovalChannel::Dashboard,
        approvals::ApprovalSource::Grant => ApprovalChannel::GrantReuse,
        approvals::ApprovalSource::PolicyAuto => ApprovalChannel::PolicyAuto,
        approvals::ApprovalSource::PolicyDeny => ApprovalChannel::PolicyDeny,
    }
}

fn grant_origin_request_id(decision: &ApprovalDecision) -> Option<uuid::Uuid> {
    if decision.source != approvals::ApprovalSource::Grant {
        return None;
    }
    let grant_id = decision.grant_id?;
    grants::load_grants()
        .ok()?
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .and_then(|grant| grant.request_id)
}

fn should_log_approval_event(decision: &ApprovalDecision) -> bool {
    decision.source != approvals::ApprovalSource::Grant
}

fn approval_human_proof(source: approvals::ApprovalSource) -> Option<&'static str> {
    match source {
        approvals::ApprovalSource::AgentMediated => Some("external-agent-ui"),
        approvals::ApprovalSource::BrokerApproval => Some("broker-approval"),
        approvals::ApprovalSource::LocalTty => Some("local-tty"),
        approvals::ApprovalSource::ManualAllow => Some("local-cli"),
        _ => None,
    }
}

fn critical_confirmation_for_decision(
    decision: &ApprovalDecision,
    evaluation: &policy::PolicyEvaluation,
) -> bool {
    decision.approved
        && decision.scope == ApprovalScope::Once
        && detection::has_critical_findings(&evaluation.findings)
}

fn handle_post_run_logging_result(exit_code: i32, result: Result<()>) -> Result<()> {
    if let Err(error) = result {
        term::warn_detail("post-run audit logging failed", &error.to_string());
        if exit_code == 0 {
            anyhow::bail!("Ward post-run audit logging failed");
        }
    }
    Ok(())
}

fn warn_anomaly_failure(result: Result<()>) {
    if let Err(error) = result {
        term::warn_detail("anomaly detection failed", &error.to_string());
    }
}
