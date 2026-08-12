#[cfg(any(test, coverage))]
fn request(
    profile: Option<String>,
    context_options: AgentContextOptions,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
    json: bool,
    no_prompt: bool,
) -> Result<()> {
    request_for_target(RequestTargetOptions {
        project: None,
        app: None,
        profile,
        context: context_options,
        action,
        command,
        env_names,
        json,
        no_prompt,
    })
}

struct RequestTargetOptions {
    project: Option<String>,
    app: Option<String>,
    profile: Option<String>,
    context: AgentContextOptions,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
    json: bool,
    no_prompt: bool,
}

fn request_for_target(options: RequestTargetOptions) -> Result<()> {
    let RequestTargetOptions {
        project,
        app,
        profile,
        context: mut context_options,
        action,
        command,
        env_names,
        json,
        no_prompt,
    } = options;
    let cwd = env::current_dir()?;
    let profile_command = profile.is_some() && command.is_none();
    let plan = workspace_target::resolve_execution_plan(
        &workspace_target::TargetSelector::one(project, app),
        &cwd,
        workspace_target::ExecutionPlanOptions { profile_command },
    )?;
    let resolved = plan.resolved_project();
    let config = config::read_project_config(&resolved.path)?;
    let git = git_context::collect_git_context(&plan.execution_cwd);
    let human_terminal = crate::human::is_human_terminal();
    if human_terminal && !agent_identity_is_present(context_options.agent.as_deref()) {
        context_options.agent = Some("human".to_string());
    }
    let branch = context_options.branch.clone().or(git.branch.clone());
    let resolved_profile =
        resolve_profile(&config, profile.as_deref(), action, command, env_names)?;
    let planned_profile = plan_resolved_profile(&plan, resolved_profile, profile.is_some())?;
    let resolved_profile = planned_profile.profile;
    if !human_terminal && !no_prompt {
        require_agent_identity_for_non_human(context_options.agent.as_deref())?;
    }
    let access = AccessRequest {
        project: resolved.name.clone(),
        agent: context_options.agent.clone(),
        branch,
        action: resolved_profile.action,
        command: resolved_profile.command,
        env: resolved_profile.env_names,
    };
    let evaluation =
        evaluate_access_with_policy_command(&config, &access, &planned_profile.policy_command);

    if no_prompt {
        if !json {
            anyhow::bail!("--no-prompt requires --json");
        }
        let Some(verified_context) =
            verified_no_prompt_context(&plan.execution_cwd, &resolved, &context_options)?
        else {
            return Ok(());
        };
        if !enforce_worktree_for_no_prompt(&resolved, &verified_context, false, "30m")? {
            return Ok(());
        }
        let pending =
            create_run_pending_request(&access, &evaluation, &git, Some(verified_context))?;
        let request_event = RequestEvent {
            correlation_id: pending.id,
            request_id: Some(pending.id),
            expires_at: Some(&pending.expires_at),
            access: &pending.access,
            policy: &pending.policy,
            git: &pending.git,
            verified_context: pending.verified_context.as_ref(),
        };
        audit_logs::append_event(LogKind::Requests, request_event)?;
        let response = serde_json::to_string_pretty(&pending_requests::response_for(&pending))?;
        println!("{response}");
        return Ok(());
    }

    let correlation_id = uuid::Uuid::new_v4();
    let decision = decide_access(&access, &evaluation, true)?;
    let critical_confirmation = critical_confirmation_for_decision(&decision, &evaluation);
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(
        critical_confirmation,
    ));
    let persisted_grant =
        grants::persist_grant(&access, &decision, &resolved.vault, receipt_context)?;
    let receipt = persisted_grant
        .as_ref()
        .and_then(|grant| grant.receipt.as_ref());

    let request_event = RequestEvent {
        correlation_id,
        request_id: None,
        expires_at: None,
        access: &access,
        policy: &evaluation,
        git: &git,
        verified_context: None,
    };
    let request_snapshot = request_audit_snapshot(&access, &evaluation, &git, None);
    let approval_event = ApprovalEvent {
        correlation_id,
        request_id: None,
        project: &access.project,
        approval_channel: approval_channel_for_source(decision.source),
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: persisted_grant.as_ref().map(|grant| grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Requests, request_event)?;
    if should_log_approval_event(&decision) {
        audit_logs::append_event(LogKind::Approvals, &approval_event)?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&approval_event)?);
    } else if decision.approved {
        term::emit_header(&term::Header {
            command: Some("request"),
            project: &access.project,
            path: Some(&resolved.path),
            mode: None,
        });
        term::ok_detail("approved env", &decision.approved_env.join(", "));
        term::ok_detail("scope", &format!("{:?}", decision.scope));
    } else {
        term::emit_header(&term::Header {
            command: Some("request"),
            project: &access.project,
            path: Some(&resolved.path),
            mode: None,
        });
        term::warn("request denied");
    }

    Ok(())
}

#[cfg(test)]
fn allow(
    profile: Option<String>,
    scope: Option<ApprovalScope>,
    agent: Option<String>,
    branch: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
) -> Result<()> {
    allow_for_target(AllowTargetOptions {
        project: None,
        app: None,
        profile,
        scope,
        agent,
        branch,
        command,
        env_names,
    })
}

struct AllowTargetOptions {
    project: Option<String>,
    app: Option<String>,
    profile: Option<String>,
    scope: Option<ApprovalScope>,
    agent: Option<String>,
    branch: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
}

fn allow_for_target(options: AllowTargetOptions) -> Result<()> {
    let AllowTargetOptions {
        project,
        app,
        profile,
        scope,
        agent,
        branch,
        command,
        env_names,
    } = options;
    let cwd = env::current_dir()?;
    let profile_selected = profile.is_some();
    let profile_command = profile_selected && command.is_none();
    let plan = workspace_target::resolve_execution_plan(
        &workspace_target::TargetSelector::one(project, app),
        &cwd,
        workspace_target::ExecutionPlanOptions { profile_command },
    )?;
    let resolved = plan.resolved_project();
    let config = config::read_project_config(&resolved.path)?;
    let resolved_profile = resolve_profile(
        &config,
        profile.as_deref(),
        Some("Manual allow grant".to_string()),
        command,
        env_names,
    )?;
    let planned_profile = plan_resolved_profile(&plan, resolved_profile, profile_selected)?;
    let resolved_profile = planned_profile.profile;
    let scope = match scope {
        Some(scope) => scope,
        None if profile_selected => resolved_profile.default_scope,
        None => anyhow::bail!("--scope is required unless --profile is used"),
    };
    if matches!(scope, ApprovalScope::Once | ApprovalScope::Deny) {
        anyhow::bail!("ward allow supports session, branch, and always scopes");
    }
    require_manual_allow_confirmation(scope)?;
    require_agent_identity_for_non_human(agent.as_deref())?;

    let git = git_context::collect_git_context(&plan.execution_cwd);
    let branch = branch.or(git.branch.clone());
    let correlation_id = uuid::Uuid::new_v4();
    let access = AccessRequest {
        project: resolved.name,
        agent,
        branch,
        action: resolved_profile.action,
        command: resolved_profile.command,
        env: resolved_profile.env_names,
    };
    let evaluation =
        evaluate_access_with_policy_command(&config, &access, &planned_profile.policy_command);
    if detection::has_critical_findings(&evaluation.findings) {
        anyhow::bail!(
            "critical exploit findings cannot be stored as durable allow grants; use ward request and approve once with --confirm-critical"
        );
    }
    approvals::validate_scope_for_findings(scope, &evaluation.findings)?;
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(false));
    let source = approvals::ApprovalSource::ManualAllow;
    let grant =
        grants::persist_manual_grant(&access, scope, source, &resolved.vault, receipt_context)?;
    let receipt = grant.receipt.as_ref();
    let mut decision = grants::approval_from_grant(&access, &grant);
    decision.source = approvals::ApprovalSource::ManualAllow;
    let request_snapshot = request_audit_snapshot(&access, &evaluation, &git, None);
    let approval_event = ApprovalEvent {
        correlation_id,
        request_id: None,
        project: &access.project,
        approval_channel: ApprovalChannel::ManualAllow,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: Some(grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation: false,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    term::emit_header(&term::Header {
        command: Some("allow"),
        project: &access.project,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("grant created", &grant.id.to_string());
    term::ok_detail("scope", &scope.to_string());
    Ok(())
}

fn require_manual_allow_confirmation(scope: ApprovalScope) -> Result<()> {
    #[cfg(debug_assertions)]
    if env::var_os("WARD_UNSAFE_TEST_KEYRING").is_some() {
        return Ok(());
    }

    #[cfg(any(test, coverage))]
    {
        let _ = scope;
        Ok(())
    }

    #[cfg(not(any(test, coverage)))]
    {
        use std::io::IsTerminal as _;

        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            anyhow::bail!(
                "ward allow requires an interactive local terminal; agents must use ward run --wait-for-approval"
            );
        }
        term::emit_block(&term::MessageBlock {
            level: term::StatusLevel::Warn,
            title: "durable grant confirmation required",
            body: Some("ward allow creates a reusable approval grant"),
            command: Some(&format!("type: ALLOW {}", approval_scope_cli_value(scope))),
        });
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("failed to read allow confirmation")?;
        if input.trim() != format!("ALLOW {}", approval_scope_cli_value(scope)) {
            anyhow::bail!("confirmation did not match; no grant was created");
        }
        Ok(())
    }
}

#[cfg(not(any(test, coverage)))]
fn approval_scope_cli_value(scope: ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "once",
        ApprovalScope::Session => "session",
        ApprovalScope::Branch => "branch",
        ApprovalScope::Always => "always",
        ApprovalScope::Deny => "deny",
    }
}

fn grants_command(command: GrantsCommand) -> Result<()> {
    match command {
        GrantsCommand::List => {
            term::emit_header(&term::Header {
                command: Some("grants list"),
                project: "local",
                path: None,
                mode: None,
            });
            let grants = grants::load_grants()?;
            if grants.is_empty() {
                term::info("no stored approval grants");
                return Ok(());
            }
            term::section("grants");
            for grant in grants {
                let expires = match grant.expires_at {
                    Some(value) => value.to_rfc3339(),
                    None => "-".to_string(),
                };
                let status =
                    grant_status_label(grants::grant_integrity_status(&grant, chrono::Utc::now()));
                let receipt_hash = grant
                    .receipt
                    .as_ref()
                    .map(|receipt| receipt.payload_hash.as_str())
                    .unwrap_or("-");
                term::ok_detail(
                    &grant.id.to_string(),
                    &format!(
                        "scope={:?} status={} project={} command=\"{}\" env={} agent={} branch={} expires={} receipt={}",
                        grant.scope,
                        status,
                        grant.project,
                        grant.command,
                        grant.approved_env.join(","),
                        grant.agent.as_deref().unwrap_or("-"),
                        grant.branch.as_deref().unwrap_or("-"),
                        expires,
                        receipt_hash,
                    ),
                );
            }
        }
        GrantsCommand::Revoke { grant_id } => {
            if grants::revoke_grant(grant_id)? {
                term::emit_header(&term::Header {
                    command: Some("grants revoke"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::ok_detail("grant revoked", &grant_id.to_string());
            } else {
                term::warn_detail("grant not found", &grant_id.to_string());
            }
        }
        GrantsCommand::Prune => {
            let pruned = grants::prune_expired_grants()?;
            term::emit_header(&term::Header {
                command: Some("grants prune"),
                project: "local",
                path: None,
                mode: None,
            });
            term::ok_detail("expired grants pruned", &pruned.to_string());
        }
    }
    Ok(())
}

fn approvals_command(command: ApprovalsCommand) -> Result<()> {
    match command {
        ApprovalsCommand::List { json } => {
            let notifications = notifications::list_notifications()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&notifications)?);
            } else if notifications.is_empty() {
                term::emit_header(&term::Header {
                    command: Some("approvals list"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::info("no pending approval notifications");
            } else {
                term::emit_header(&term::Header {
                    command: Some("approvals list"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::section("pending");
                for notification in notifications {
                    term::warn_detail(
                        &notification.id.to_string(),
                        &format!(
                            "{:?} project={} risk={} {}",
                            notification.kind,
                            notification.project,
                            notification.risk,
                            notification.command.as_deref().unwrap_or("")
                        ),
                    );
                }
            }
            Ok(())
        }
        ApprovalsCommand::Wait {
            request_id,
            json,
            timeout,
        } => wait_for_approval_command(request_id, json, &timeout),
    }
}

fn wait_for_approval_command(request_id: uuid::Uuid, json: bool, timeout: &str) -> Result<()> {
    let timeout = unlock::parse_ttl(timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    loop {
        if let Some(resolution) = pending_requests::load_resolution(request_id)? {
            if json {
                println!("{}", serde_json::to_string_pretty(&resolution)?);
            } else {
                term::emit_header(&term::Header {
                    command: Some("approvals wait"),
                    project: &resolution.project,
                    path: None,
                    mode: None,
                });
                term::ok_detail(&resolution.status, &resolution.request_id.to_string());
            }
            return Ok(());
        }
        if chrono::Utc::now() >= deadline {
            let response = serde_json::json!({
                "status": "approval_timeout",
                "requestId": request_id,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                term::warn_detail("approval wait timed out", &request_id.to_string());
            }
            return Ok(());
        }
        thread::sleep(StdDuration::from_millis(500));
    }
}

fn require_human_terminal_confirmation(action: &str, request_id: uuid::Uuid) -> Result<()> {
    #[cfg(debug_assertions)]
    if env::var_os("WARD_UNSAFE_TEST_KEYRING").is_some() {
        return Ok(());
    }

    #[cfg(any(test, coverage))]
    {
        let _ = (action, request_id);
        Ok(())
    }

    #[cfg(not(any(test, coverage)))]
    {
        use std::io::IsTerminal as _;

        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            anyhow::bail!(
                "Ward {action} requires an interactive local terminal; use the dashboard approval flow or ask a human to run this command"
        );
        }
        term::emit_block(&term::MessageBlock {
            level: term::StatusLevel::Warn,
            title: "human confirmation required",
            body: Some("approval state can only be changed from an interactive local terminal"),
            command: Some(&format!("type: {action} {request_id}")),
        });
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("failed to read approval confirmation")?;
        if input.trim() != format!("{action} {request_id}") {
            anyhow::bail!("confirmation did not match; no approval state was changed");
        }
        Ok(())
    }
}

fn approve(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    agent_mediated: bool,
    json: bool,
) -> Result<()> {
    if agent_mediated {
        anyhow::bail!(
            "--agent-mediated can no longer create approvals; agents must use `ward run --wait-for-approval` or `ward approvals wait <request-id> --json`"
        );
    }
    require_human_terminal_confirmation("APPROVE", request_id)?;
    match approve_inner(
        request_id,
        scope,
        confirm_critical,
        ApprovalChannel::TerminalApprove,
    ) {
        Ok(response) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                term::emit_header(&term::Header {
                    command: Some("approve"),
                    project: &response.project,
                    path: None,
                    mode: None,
                });
                term::ok_detail("request approved", &request_id.to_string());
                term::ok_detail("grant", &response.grant_id.to_string());
            }
            Ok(())
        }
        Err(error) if json && is_unlock_or_signing_error(&error) => {
            print_unlock_required_json(error.to_string())?;
            Ok(())
        }
        Err(error) if json => {
            if print_pending_request_error_json(request_id, &error)? {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApproveJsonResponse {
    status: &'static str,
    request_id: uuid::Uuid,
    project: String,
    grant_id: uuid::Uuid,
    approval_receipt_hash: Option<String>,
    signer_key_id: Option<String>,
    signature_algorithm: Option<String>,
    approval_source: approvals::ApprovalSource,
    approval_channel: ApprovalChannel,
}

fn approve_inner(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    approval_channel: ApprovalChannel,
) -> Result<ApproveJsonResponse> {
    if scope == ApprovalScope::Deny {
        anyhow::bail!("use ward deny for denied requests");
    }
    let pending = pending_requests::load_pending_request(request_id)?;
    let critical = detection::has_critical_findings(&pending.policy.findings);
    validate_pending_approval(&pending, scope, confirm_critical)?;
    let status =
        broker::approve_pending_request(request_id, scope, confirm_critical, approval_channel)?;
    let source = approvals::ApprovalSource::BrokerApproval;
    let decision = ApprovalDecision {
        approved: true,
        scope,
        approved_env: status.access.env.clone(),
        denied_env: Vec::new(),
        source,
        grant_id: Some(status.grant_id),
    };
    let request_snapshot = request_audit_snapshot(
        &pending.access,
        &pending.policy,
        &pending.git,
        pending.verified_context.as_ref(),
    );
    let approval_event = ApprovalEvent {
        correlation_id: request_id,
        request_id: Some(request_id),
        project: &pending.access.project,
        approval_channel,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: Some(status.grant_id),
        approval_receipt_hash: status.approval_receipt_hash.as_deref(),
        signer_key_id: status.signer_key_id.as_deref(),
        signature_algorithm: status.signature_algorithm.as_deref(),
        critical_confirmation: critical && confirm_critical,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    Ok(ApproveJsonResponse {
        status: "approved",
        request_id,
        project: pending.access.project,
        grant_id: status.grant_id,
        approval_receipt_hash: status.approval_receipt_hash,
        signer_key_id: status.signer_key_id,
        signature_algorithm: status.signature_algorithm,
        approval_source: source,
        approval_channel,
    })
}

pub(crate) fn approve_request_from_dashboard(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
) -> Result<Value> {
    let response = approve_inner(
        request_id,
        scope,
        confirm_critical,
        ApprovalChannel::Dashboard,
    )?;
    serde_json::to_value(response).context("failed to serialize approval response")
}

fn validate_pending_approval(
    pending: &pending_requests::PendingRequest,
    scope: ApprovalScope,
    confirm_critical: bool,
) -> Result<()> {
    let critical = detection::has_critical_findings(&pending.policy.findings);
    if critical && !confirm_critical {
        anyhow::bail!("critical request requires --confirm-critical");
    }
    approvals::validate_scope_for_findings(scope, &pending.policy.findings)
}

fn deny(request_id: uuid::Uuid, agent_mediated: bool, json: bool) -> Result<()> {
    if agent_mediated {
        anyhow::bail!(
            "--agent-mediated can no longer deny requests; agents must use `ward run --wait-for-approval` or `ward approvals wait <request-id> --json`"
        );
    }
    require_human_terminal_confirmation("DENY", request_id)?;
    let pending = match pending_requests::load_pending_request(request_id) {
        Ok(pending) => pending,
        Err(error) if json => {
            if print_pending_request_error_json(request_id, &error)? {
                return Ok(());
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let status = broker::deny_pending_request(request_id, ApprovalChannel::TerminalApprove)?;
    let source = approvals::ApprovalSource::BrokerApproval;
    let decision = ApprovalDecision {
        approved: false,
        scope: ApprovalScope::Deny,
        approved_env: Vec::new(),
        denied_env: pending.access.env.clone(),
        source,
        grant_id: None,
    };
    let approval_channel = ApprovalChannel::TerminalApprove;
    let request_snapshot = request_audit_snapshot(
        &pending.access,
        &pending.policy,
        &pending.git,
        pending.verified_context.as_ref(),
    );
    let approval_event = ApprovalEvent {
        correlation_id: request_id,
        request_id: Some(request_id),
        project: &pending.access.project,
        approval_channel,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: None,
        approval_receipt_hash: None,
        signer_key_id: None,
        signature_algorithm: None,
        critical_confirmation: false,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "denied",
                "requestId": request_id,
                "project": status.project,
                "approvalSource": source,
                "approvalChannel": approval_channel,
            }))?
        );
    } else {
        term::emit_header(&term::Header {
            command: Some("deny"),
            project: &status.project,
            path: None,
            mode: None,
        });
        term::ok_detail("request denied", &request_id.to_string());
    }
    Ok(())
}

pub(crate) fn deny_request_from_dashboard(request_id: uuid::Uuid) -> Result<Value> {
    let pending = pending_requests::load_pending_request(request_id)?;
    let status = broker::deny_pending_request(request_id, ApprovalChannel::Dashboard)?;
    let source = approvals::ApprovalSource::BrokerApproval;
    let decision = ApprovalDecision {
        approved: false,
        scope: ApprovalScope::Deny,
        approved_env: Vec::new(),
        denied_env: pending.access.env.clone(),
        source,
        grant_id: None,
    };
    let request_snapshot = request_audit_snapshot(
        &pending.access,
        &pending.policy,
        &pending.git,
        pending.verified_context.as_ref(),
    );
    let approval_event = ApprovalEvent {
        correlation_id: request_id,
        request_id: Some(request_id),
        project: &pending.access.project,
        approval_channel: ApprovalChannel::Dashboard,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: None,
        approval_receipt_hash: None,
        signer_key_id: None,
        signature_algorithm: None,
        critical_confirmation: false,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    Ok(serde_json::json!({
        "status": "denied",
        "requestId": request_id,
        "project": status.project,
        "approvalSource": source,
        "approvalChannel": ApprovalChannel::Dashboard,
    }))
}

fn is_unlock_or_signing_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<broker::BrokerError>()
            .is_some_and(|error| error.kind() == broker::BrokerFailureKind::Unavailable)
    })
}

fn print_unlock_required_json(reason: String) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "unlock_required",
            "reason": reason,
            "unlockCommand": "ward unlock --ttl 8h",
        }))?
    );
    Ok(())
}

fn print_pending_request_error_json(request_id: uuid::Uuid, error: &anyhow::Error) -> Result<bool> {
    let path = pending_requests::pending_request_path(request_id);
    let (status, reason) = if !path.exists() {
        ("not_found", "pending_request_not_found")
    } else {
        let message = error.to_string();
        if message.contains("failed to parse") {
            ("invalid_request", "pending_request_malformed")
        } else if message.contains("pending request") && message.contains("expired") {
            ("invalid_request", "pending_request_expired")
        } else if message.contains("failed to read") {
            ("invalid_request", "pending_request_unreadable")
        } else {
            return Ok(false);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": status,
            "requestId": request_id,
            "reason": reason,
        }))?
    );
    Ok(true)
}
