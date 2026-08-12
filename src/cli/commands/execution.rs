#[cfg(any(test, coverage))]
fn run(options: RunOptions) -> Result<()> {
    run_with_context(options, AgentContextOptions::default(), None)
}

fn run_with_context(
    options: RunOptions,
    context_options: AgentContextOptions,
    app: Option<String>,
) -> Result<()> {
    ExecutionCoordinator {
        options,
        context_options,
        app,
    }
    .execute()
}

struct ExecutionCoordinator {
    options: RunOptions,
    context_options: AgentContextOptions,
    app: Option<String>,
}

impl ExecutionCoordinator {
    fn execute(self) -> Result<()> {
        let Self {
            mut options,
            context_options,
            app,
        } = self;
        if reject_misplaced_run_flags(&options.command)? {
            return Ok(());
        }
        let invocation_cwd = env::current_dir()?;
        let selector = workspace_target::TargetSelector::one(options.project.clone(), app);
        let profile_command = options.profile.is_some() && options.command.is_empty();
        let plan = workspace_target::resolve_execution_plan(
            &selector,
            &invocation_cwd,
            workspace_target::ExecutionPlanOptions { profile_command },
        )?;
        let cwd = plan.execution_cwd.clone();
        let resolved = plan.resolved_project();
        let config = config::read_project_config(&resolved.path)?;
        let git = git_context::collect_git_context(&cwd);
        let branch = options.branch.or(git.branch.clone());
        let mut context_options = context_options;
        let human_terminal = crate::human::is_human_terminal();
        if context_options.agent.is_none() {
            context_options.agent = options.agent.clone();
        }
        if context_options.branch.is_none() {
            context_options.branch = branch.clone();
        }
        // In a human terminal, infer remaining context from the current git repo.
        if human_terminal {
            if !agent_identity_is_present(context_options.agent.as_deref()) {
                context_options.agent = Some("human".to_string());
            }
            if !agent_identity_is_present(options.agent.as_deref()) {
                options.agent = Some("human".to_string());
            }
            if context_options.worktree.is_none() {
                context_options.worktree = git.worktree_path.as_deref().map(PathBuf::from);
            }
            if context_options.commit.is_none() {
                context_options.commit = git.commit.clone();
            }
            if context_options.git_remote.is_none() {
                context_options.git_remote = git.remote.clone();
            }
            // Inject all vault keys automatically when no --env was specified.
            if options.env_names.is_empty() && options.profile.is_none() {
                options.env_names = broker::list_vault_keys_for_human(
                &resolved.name,
                &resolved.vault,
                crate::human::current_shell_pid(),
            )
            .context(
                    "human mode requires an active broker session; run `ward human` or `ward unlock --ttl 8h`",
                )?;
            }
        }
        let resolved_profile = resolve_run_profile(
            &config,
            options.profile.as_deref(),
            options.action,
            options.env_names,
            options.command,
            human_terminal,
        )?;
        let planned_profile =
            plan_resolved_profile(&plan, resolved_profile, options.profile.is_some())?;
        let resolved_profile = planned_profile.profile;
        if !human_terminal && !options.no_prompt {
            require_agent_identity_for_non_human(options.agent.as_deref())?;
        }
        let command_text = resolved_profile.command.clone();
        let mounted_command = planned_profile
            .mounted
            .then(|| resolved_profile.command.clone());

        let access = AccessRequest {
            project: resolved.name.clone(),
            agent: options.agent,
            branch,
            action: resolved_profile.action,
            command: command_text.clone(),
            env: resolved_profile.env_names.clone(),
        };
        let evaluation =
            evaluate_access_with_policy_command(&config, &access, &planned_profile.policy_command);
        let mut verified_context = None;
        let mut correlation_id = uuid::Uuid::new_v4();
        let mut linked_request_id = None;
        let decision = if human_terminal && !options.no_prompt {
            ApprovalDecision {
                approved: true,
                scope: ApprovalScope::Once,
                approved_env: resolved_profile.env_names.clone(),
                denied_env: Vec::new(),
                source: approvals::ApprovalSource::LocalTty,
                grant_id: None,
            }
        } else if options.no_prompt {
            if !options.json {
                anyhow::bail!("--no-prompt requires --json");
            }
            let Some(context) = verified_no_prompt_context(&cwd, &resolved, &context_options)?
            else {
                return Ok(());
            };
            if !enforce_worktree_for_no_prompt(
                &resolved,
                &context,
                options.wait_for_approval,
                &options.approval_timeout,
            )? {
                return Ok(());
            }
            verified_context = Some(context);
            let decision = match non_interactive_decision_with_context(
                &access,
                &evaluation,
                verified_context.as_ref(),
            )? {
                Some(decision) => decision,
                None => {
                    let pending = create_run_pending_request(
                        &access,
                        &evaluation,
                        &git,
                        verified_context.clone(),
                    )?;
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
                    if options.wait_for_approval {
                        correlation_id = pending.id;
                        linked_request_id = Some(pending.id);
                        let Some(decision) = wait_for_run_approval(
                            &pending,
                            &access,
                            &evaluation,
                            verified_context.as_ref(),
                            &options.approval_timeout,
                        )?
                        else {
                            return Ok(());
                        };
                        decision
                    } else {
                        print_run_approval_required(&pending)?;
                        return Ok(());
                    }
                }
            };
            if !decision.approved {
                let request_event = RequestEvent {
                    correlation_id,
                    request_id: linked_request_id,
                    expires_at: None,
                    access: &access,
                    policy: &evaluation,
                    git: &git,
                    verified_context: verified_context.as_ref(),
                };
                let request_snapshot =
                    request_audit_snapshot(&access, &evaluation, &git, verified_context.as_ref());
                let approval_event = ApprovalEvent {
                    correlation_id,
                    request_id: linked_request_id,
                    project: &access.project,
                    approval_channel: approval_channel_for_source(decision.source),
                    request_snapshot: Some(request_snapshot),
                    decision: &decision,
                    persisted_grant: None,
                    approval_receipt_hash: None,
                    signer_key_id: None,
                    signature_algorithm: None,
                    critical_confirmation: false,
                    human_proof: approval_human_proof(decision.source),
                };
                audit_logs::append_event(LogKind::Requests, request_event)?;
                audit_logs::append_event(LogKind::Approvals, approval_event)?;
                create_run_block_notification(
                    notifications::NotificationKind::PolicyDenied,
                    &access,
                    &evaluation,
                    "Ward policy denied this request.",
                    None,
                )?;
                print_run_denied(&access, &evaluation)?;
                return Ok(());
            }
            decision
        } else {
            decide_access(&access, &evaluation, true)?
        };
        let critical_confirmation = critical_confirmation_for_decision(&decision, &evaluation);
        let receipt_context = Some(grants::GrantReceiptContext {
            request_id: uuid::Uuid::new_v4(),
            pending_request: false,
            critical_confirmation,
            verified_context: verified_context.clone(),
        });
        let persisted_grant =
            grants::persist_grant(&access, &decision, &resolved.vault, receipt_context)?;
        let receipt = persisted_grant
            .as_ref()
            .and_then(|grant| grant.receipt.as_ref());

        let request_event = RequestEvent {
            correlation_id,
            request_id: linked_request_id,
            expires_at: None,
            access: &access,
            policy: &evaluation,
            git: &git,
            verified_context: verified_context.as_ref(),
        };
        let request_snapshot =
            request_audit_snapshot(&access, &evaluation, &git, verified_context.as_ref());
        let approval_channel = approval_channel_for_source(decision.source);
        let approval_event = ApprovalEvent {
            correlation_id,
            request_id: linked_request_id,
            project: &access.project,
            approval_channel,
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
            audit_logs::append_event(LogKind::Approvals, approval_event)?;
        }

        if !decision.approved {
            anyhow::bail!("Ward access denied");
        }

        let grant_id = effective_grant_id(&decision, persisted_grant.as_ref());
        let grant_origin_request_id = grant_origin_request_id(&decision);
        let approval_receipt_hash = grant_receipt_hash(&decision, persisted_grant.as_ref())?;
        let started_event = ExecutionStartedEvent {
            event_type: "execution.started",
            correlation_id,
            request_id: linked_request_id,
            project: &resolved.name,
            agent: &access.agent,
            branch: &access.branch,
            declared_action: &access.action,
            requested_command: &command_text,
            cwd: &cwd,
            execution_cwd: &cwd,
            workspace_root: plan.workspace_root.as_deref(),
            app_relative_path: plan.app_relative_path.as_deref(),
            mounted_command: mounted_command.as_deref(),
            git: &git,
            requested_env: &evaluation.requested_env,
            injected_env: &decision.approved_env,
            policy_findings: &evaluation.findings,
            approval_scope: decision.scope,
            approval_source: decision.source,
            approval_channel,
            grant_id,
            grant_origin_request_id,
            approval_receipt_hash: approval_receipt_hash.as_deref(),
            agent_key_id: verified_agent_key_id(verified_context.as_ref()),
            verified_context: verified_context.as_ref(),
        };
        audit_logs::append_event(LogKind::Executions, started_event)?;

        consume_once_grant_if_reused(&decision)?;

        let command_args = resolved_profile.command_args.clone();
        let mut execute_payload = broker::ExecuteAuthorizationPayload::new(
            resolved.name.clone(),
            resolved.vault.clone(),
            cwd.clone(),
            decision.approved_env.clone(),
            command_args.clone(),
            decision.scope,
            decision.source,
        );
        execute_payload.agent = access.agent.clone();
        execute_payload.branch = access.branch.clone();
        execute_payload.action = access.action.clone();
        execute_payload.grant_id = grant_id;
        execute_payload.approval_receipt_hash = approval_receipt_hash.clone();
        if let Some(context) = verified_context.as_ref() {
            execute_payload.worktree = Some(context.worktree.clone());
            execute_payload.git_remote = Some(context.git_remote.clone());
            execute_payload.commit = Some(context.commit.clone());
        }

        let outcome = if options.no_prompt {
            let context = verified_context
                .as_ref()
                .expect("verified in no-prompt mode");
            let Some(outcome) = execute_no_prompt_with_optional_wait(NoPromptExecution {
                resolved: &resolved,
                cwd: &cwd,
                decision: &decision,
                command_args: &command_args,
                execute_payload,
                context,
                access: &access,
                evaluation: &evaluation,
                wait_for_approval: options.wait_for_approval,
                approval_timeout: &options.approval_timeout,
            })?
            else {
                return Ok(());
            };
            outcome
        } else {
            broker::execute(
                &resolved.name,
                &resolved.vault,
                &cwd,
                decision.approved_env.clone(),
                command_args.clone(),
                if human_terminal {
                    broker::ExecuteAuthorization::Human {
                        shell_pid: crate::human::current_shell_pid(),
                    }
                } else {
                    broker::ExecuteAuthorization::Internal {
                        payload: Box::new(execute_payload),
                    }
                },
            )
            .context("broker execution failed closed; run `ward unlock --ttl 8h` and retry")?
        };

        let execution_event = ExecutionEvent {
            event_type: "execution.finished",
            correlation_id,
            request_id: linked_request_id,
            project: &resolved.name,
            agent: &access.agent,
            branch: &access.branch,
            declared_action: &access.action,
            requested_command: &command_text,
            cwd: &cwd,
            execution_cwd: &cwd,
            workspace_root: plan.workspace_root.as_deref(),
            app_relative_path: plan.app_relative_path.as_deref(),
            mounted_command: mounted_command.as_deref(),
            git: &git,
            requested_env: &evaluation.requested_env,
            injected_env: &decision.approved_env,
            policy_findings: &evaluation.findings,
            approval_scope: decision.scope,
            approval_source: decision.source,
            approval_channel,
            grant_id,
            grant_origin_request_id,
            approval_receipt_hash: approval_receipt_hash.as_deref(),
            agent_key_id: verified_agent_key_id(verified_context.as_ref()),
            verified_context: verified_context.as_ref(),
            outcome: &outcome,
        };
        let finish_result = audit_logs::append_event(LogKind::Executions, execution_event);
        let anomaly_result = log_anomaly_alerts(&config, grant_id);

        let alert_result = if outcome.redaction_alerts > 0 {
            let output_redaction_event = OutputRedactionEvent {
                event_type: "output.redaction",
                command: &command_text,
                count: outcome.redaction_alerts,
                alerts: &outcome.output_alerts,
            };
            audit_logs::append_event(LogKind::Alerts, output_redaction_event)
        } else {
            Ok(())
        };

        handle_post_run_logging_result(outcome.exit_code, finish_result.and(alert_result))?;
        warn_anomaly_failure(anomaly_result);

        if outcome.exit_code != 0 {
            return Err(ChildExit::new(outcome.exit_code).into());
        }

        Ok(())
    }
}

fn reject_misplaced_run_flags(command: &[String]) -> Result<bool> {
    if !command.iter().any(|arg| arg == "--no-prompt") {
        return Ok(false);
    }
    let response = InvalidInvocationResponse {
        status: "invalid_invocation",
        reason: "ward_flags_after_separator",
        message: "Move Ward flags before --.",
        correct_example: "ward run --json --no-prompt --env DATABASE_URI -- <command>",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(true)
}
