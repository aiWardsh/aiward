fn consume_once_grant_if_reused(decision: &ApprovalDecision) -> Result<()> {
    let should_consume = decision.source == approvals::ApprovalSource::Grant
        && decision.scope == ApprovalScope::Once;
    if !should_consume {
        return Ok(());
    }

    let Some(grant_id) = decision.grant_id else {
        return Ok(());
    };

    grants::consume_once_grant(grant_id).map(|_| ())
}

fn decide_access(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    allow_grants: bool,
) -> Result<ApprovalDecision> {
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        });
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    if allow_grants {
        let grant = if critical {
            grants::find_matching_once_grant(access, true)?
        } else if suspicious_action {
            grants::find_matching_non_always_grant(access)?
        } else {
            grants::find_matching_grant(access)?
        };
        if let Some(grant) = grant {
            return Ok(grants::approval_from_grant(access, &grant));
        }
    }

    if evaluation.requires_prompt {
        approvals::prompt_for_approval(access, evaluation)
    } else {
        Ok(approvals::auto_approval(evaluation))
    }
}

fn non_interactive_decision(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
) -> Result<Option<ApprovalDecision>> {
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(Some(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        }));
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    let grant = if critical {
        grants::find_matching_once_grant(access, true)?
    } else if suspicious_action {
        grants::find_matching_non_always_grant(access)?
    } else {
        grants::find_matching_grant(access)?
    };
    if let Some(grant) = grant {
        return Ok(Some(grants::approval_from_grant(access, &grant)));
    }
    if evaluation.requires_prompt {
        return Ok(None);
    }
    Ok(Some(approvals::auto_approval(evaluation)))
}

fn non_interactive_decision_with_context(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    verified_context: Option<&context::VerifiedContext>,
) -> Result<Option<ApprovalDecision>> {
    let Some(verified_context) = verified_context else {
        return non_interactive_decision(access, evaluation);
    };
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(Some(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        }));
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    let grant = if critical {
        grants::find_matching_once_grant_with_context(access, true, verified_context)?
    } else if suspicious_action {
        grants::find_matching_non_always_grant_with_context(access, verified_context)?
    } else {
        grants::find_matching_grant_with_context(access, verified_context)?
    };
    if let Some(grant) = grant {
        return Ok(Some(grants::approval_from_grant(access, &grant)));
    }
    if evaluation.requires_prompt {
        return Ok(None);
    }
    Ok(Some(approvals::auto_approval(evaluation)))
}

fn create_run_pending_request(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    git: &git_context::GitContext,
    verified_context: Option<context::VerifiedContext>,
) -> Result<pending_requests::PendingRequest> {
    pending_requests::create_pending_request_with_context(
        access.clone(),
        evaluation.clone(),
        git.clone(),
        verified_context,
    )
}

fn print_run_approval_required(pending: &pending_requests::PendingRequest) -> Result<()> {
    let response = RunApprovalRequiredResponse {
        status: "approval_required",
        unlock_required: false,
        request: pending_requests::response_for(pending),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_unlock_required(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    unlock_reason: Option<&str>,
) -> Result<()> {
    let response = RunUnlockRequiredResponse {
        status: "unlock_required",
        approval_required: false,
        unlock_required: true,
        unlock_reason,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
        unlock_command: "ward unlock --ttl 8h",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_vault_key_missing(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    missing_env: Vec<String>,
) -> Result<()> {
    let response = RunVaultKeyMissingResponse {
        status: "vault_key_missing",
        approval_required: false,
        unlock_required: false,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        missing_env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
        message: "One or more approved env vars are not present in the vault.",
        remediation: "Add/update a profile that covers this command and env name, or run ward env request-set --key <ENV_NAME> --wait-for-approval --json --no-prompt so a human can add the missing vault key.",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_denied(access: &AccessRequest, evaluation: &policy::PolicyEvaluation) -> Result<()> {
    let response = RunDeniedResponse {
        status: "denied",
        approval_required: false,
        unlock_required: false,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn wait_for_run_approval(
    pending: &pending_requests::PendingRequest,
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    verified_context: Option<&context::VerifiedContext>,
    approval_timeout: &str,
) -> Result<Option<ApprovalDecision>> {
    let timeout = unlock::parse_ttl(approval_timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    term::emit_block(&term::MessageBlock {
        level: term::StatusLevel::Info,
        title: "waiting for approval",
        body: Some("open the dashboard notification center or approve from a human terminal"),
        command: Some(&format!("ward approve {} --scope session", pending.id)),
    });

    loop {
        if let Some(resolution) = pending_requests::load_resolution(pending.id)? {
            if resolution.status == "denied" {
                print_run_wait_denied(pending.id, access)?;
                return Ok(None);
            }
            if resolution.status == "approved" {
                if let Some(decision) =
                    non_interactive_decision_with_context(access, evaluation, verified_context)?
                {
                    return Ok(Some(decision));
                }
            }
        }

        if !pending_requests::pending_request_path(pending.id).exists() {
            if let Some(decision) =
                non_interactive_decision_with_context(access, evaluation, verified_context)?
            {
                return Ok(Some(decision));
            }
        }

        if chrono::Utc::now() >= deadline {
            print_run_wait_timeout(Some(pending.id), access, "run")?;
            return Ok(None);
        }

        thread::sleep(StdDuration::from_millis(500));
    }
}

struct NoPromptExecution<'a> {
    resolved: &'a registry::ResolvedProject,
    cwd: &'a Path,
    decision: &'a ApprovalDecision,
    command_args: &'a [String],
    execute_payload: broker::ExecuteAuthorizationPayload,
    context: &'a context::VerifiedContext,
    access: &'a AccessRequest,
    evaluation: &'a policy::PolicyEvaluation,
    wait_for_approval: bool,
    approval_timeout: &'a str,
}

fn execute_no_prompt_with_optional_wait(
    execution: NoPromptExecution<'_>,
) -> Result<Option<runner::RunCommandOutcome>> {
    let NoPromptExecution {
        resolved,
        cwd,
        decision,
        command_args,
        mut execute_payload,
        context,
        access,
        evaluation,
        wait_for_approval,
        approval_timeout,
    } = execution;
    let timeout = unlock::parse_ttl(approval_timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    let mut unlock_notification = None;

    loop {
        execute_payload.expires_at = chrono::Utc::now() + chrono::Duration::seconds(60);
        execute_payload.nonce = uuid::Uuid::new_v4().to_string();
        let proof_payload =
            serde_json::to_string(&execute_payload).expect("execution payload should serialize");
        let proof = agents::sign_payload(&resolved.name, &context.agent, &proof_payload)?;

        match broker::execute(
            &resolved.name,
            &resolved.vault,
            cwd,
            decision.approved_env.clone(),
            command_args.to_vec(),
            broker::ExecuteAuthorization::Agent { proof },
        ) {
            Ok(outcome) => {
                if let Some(notification_id) = unlock_notification.take() {
                    notifications::remove_block_notification(notification_id)?;
                }
                return Ok(Some(outcome));
            }
            Err(error) => {
                if let Some(missing_env) = broker_vault_key_missing_envs(&error) {
                    create_run_block_notification(
                        notifications::NotificationKind::VaultKeyMissing,
                        access,
                        evaluation,
                        "The approved request references env names that are not present in the vault.",
                        Some(
                            "ward env request-set --key <ENV_NAME> --wait-for-approval --json --no-prompt",
                        ),
                    )?;
                    print_run_vault_key_missing(access, evaluation, missing_env)?;
                    return Ok(None);
                }
                let retryable_unavailable = error
                    .downcast_ref::<broker::BrokerError>()
                    .is_some_and(|error| error.kind() == broker::BrokerFailureKind::Unavailable);
                if !retryable_unavailable {
                    return Err(error).context("broker rejected no-prompt execution");
                }
                if !wait_for_approval {
                    let reason = error.to_string();
                    print_run_unlock_required(access, evaluation, Some(&reason))?;
                    return Ok(None);
                }

                if unlock_notification.is_none() {
                    let notification = create_run_block_notification(
                        notifications::NotificationKind::UnlockRequired,
                        access,
                        evaluation,
                        "This request is waiting for the vault to be unlocked before it can run.",
                        Some("ward unlock --ttl 8h"),
                    )?;
                    unlock_notification = Some(notification.id);
                    term::emit_block(&term::MessageBlock {
                        level: term::StatusLevel::Warn,
                        title: "waiting for unlock",
                        body: Some("the command will resume after the broker session is active"),
                        command: Some("ward unlock --ttl 8h"),
                    });
                }

                if chrono::Utc::now() >= deadline {
                    if let Some(notification_id) = unlock_notification.take() {
                        notifications::remove_block_notification(notification_id)?;
                    }
                    print_run_wait_timeout(None, access, "unlock")?;
                    return Ok(None);
                }

                if broker::active_session_expiry(&resolved.name, &resolved.vault)?.is_some() {
                    if let Some(notification_id) = unlock_notification.take() {
                        notifications::remove_block_notification(notification_id)?;
                    }
                    continue;
                }

                thread::sleep(StdDuration::from_millis(500));
            }
        }
    }
}

fn create_run_block_notification(
    kind: notifications::NotificationKind,
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    message: &str,
    fix_command: Option<&str>,
) -> Result<notifications::BlockNotification> {
    notifications::create_block_notification(notifications::BlockNotificationRequest {
        kind,
        project: &access.project,
        agent: access.agent.as_deref(),
        command: Some(&access.command),
        env: &access.env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
        message: message.to_string(),
        fix_command,
    })
}

fn print_run_wait_denied(request_id: uuid::Uuid, access: &AccessRequest) -> Result<()> {
    let response = serde_json::json!({
        "status": "denied",
        "approvalRequired": false,
        "unlockRequired": false,
        "requestId": request_id,
        "project": access.project,
        "command": access.command,
    });
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_wait_timeout(
    request_id: Option<uuid::Uuid>,
    access: &AccessRequest,
    approval_type: &str,
) -> Result<()> {
    let mut response = serde_json::json!({
        "status": "approval_timeout",
        "approvalType": approval_type,
        "project": access.project,
        "command": access.command,
    });
    if let Some(request_id) = request_id {
        response["requestId"] = serde_json::json!(request_id);
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn broker_vault_key_missing_envs(error: &anyhow::Error) -> Option<Vec<String>> {
    let broker_error = error.downcast_ref::<broker::BrokerError>()?;
    if broker_error.reason() != &broker::BrokerReason::VaultKeyMissing {
        return None;
    }
    Some(
        broker_error
            .message()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn run_risk_summary(evaluation: &policy::PolicyEvaluation) -> String {
    if detection::has_critical_findings(&evaluation.findings) {
        "critical".to_string()
    } else if !evaluation.findings.is_empty() || !evaluation.denied_env.is_empty() {
        "warning".to_string()
    } else {
        "low".to_string()
    }
}

#[cfg(any(test, coverage))]
fn marker(ok: bool) -> &'static str {
    if ok {
        "[ok]"
    } else {
        "!"
    }
}

#[cfg(any(test, coverage))]
fn grant_integrity_messages(unsigned: usize, invalid: usize) -> Vec<String> {
    let mut messages = Vec::new();
    if unsigned == 0 && invalid == 0 {
        messages.push("[ok] Approval grants are signed and valid.".to_string());
    }
    if unsigned > 0 {
        messages.push(format!(
            "! Legacy unsigned approval grants: {unsigned}. Re-approve them."
        ));
    }
    if invalid > 0 {
        messages.push(format!(
            "! Invalid signed approval grants: {invalid}. Revoke and re-approve them."
        ));
    }
    messages
}

fn grant_status_label(status: grants::GrantIntegrityStatus) -> &'static str {
    match status {
        grants::GrantIntegrityStatus::Valid => "valid-signed",
        grants::GrantIntegrityStatus::Expired => "expired",
        grants::GrantIntegrityStatus::LegacyUnsigned => "legacy-unsigned",
        grants::GrantIntegrityStatus::Invalid => "invalid-signature",
    }
}

fn verified_agent_key_id(context: Option<&context::VerifiedContext>) -> Option<&str> {
    match context {
        Some(context) => Some(context.agent_key_id.as_str()),
        None => None,
    }
}
