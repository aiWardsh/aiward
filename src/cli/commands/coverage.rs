#[cfg(all(coverage, not(test)))]
#[doc(hidden)]
pub fn coverage_exercise_cli_edges() -> Result<()> {
    let old_cwd = env::current_dir()?;
    let home = tempfile::tempdir()?;
    env::set_var("WARD_HOME", home.path());
    env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");

    let project = tempfile::tempdir()?;
    env::set_current_dir(project.path())?;
    fs::write(project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let project_env = project.path().join(".env");
    fs::write(&project_env, "DATABASE_URL=postgres://coverage\n")?;
    let main_setup = SetupOptions {
        yes: true,
        project: Some("coverage-main".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(main_setup)?;
    dispatch(Cli {
        command: Commands::Broker {
            command: BrokerCommand::SocketPath,
        },
    })
    .expect("coverage broker socket dispatch should succeed");
    dispatch(Cli {
        command: Commands::Worktrees {
            command: WorktreesCommand::List {
                project: "coverage-main".to_string(),
            },
        },
    })
    .expect("coverage worktree list dispatch should succeed");
    broker_command(BrokerCommand::SocketPath)?;
    broker_command(BrokerCommand::Status)?;
    broker_command(BrokerCommand::Stop)?;
    let allowed_root = tempfile::tempdir()?;
    worktrees_command(WorktreesCommand::AllowRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage allow-root should succeed");
    worktrees_command(WorktreesCommand::List {
        project: "coverage-main".to_string(),
    })
    .expect("coverage list should succeed");
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage remove-root should succeed");
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage missing remove-root should succeed");
    worktrees_command(WorktreesCommand::Approve {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .expect("coverage missing worktree approval should succeed");
    worktrees_command(WorktreesCommand::Deny {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .expect("coverage missing worktree denial should succeed");

    let absolute_export = EnvCommand::Export {
        project: None,
        app: None,
        output: Some(project.path().join(".env.absolute.export")),
        force: false,
        unsafe_stdout: false,
    };
    env_command(absolute_export)?;
    let stdout_export = EnvCommand::Export {
        project: None,
        app: None,
        output: None,
        force: false,
        unsafe_stdout: true,
    };
    env_command(stdout_export)?;

    let access = AccessRequest {
        project: "coverage-main".to_string(),
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Coverage".to_string()),
        command: "sh -c true".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let clean = policy::PolicyEvaluation {
        matched_profile: None,
        matched_preset: None,
        approval_mode: ApprovalMode::Auto,
        requested_env: access.env.clone(),
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        requires_prompt: false,
        findings: Vec::new(),
    };
    let mut critical = clean.clone();
    critical.findings.push(detection::Finding::critical(
        "critical.coverage",
        "critical coverage finding",
    ));
    critical.requires_prompt = true;
    let _ = decide_access(&access, &clean, true)?;
    let _ = non_interactive_decision(&access, &clean)?;
    let mut denied = clean.clone();
    denied.approval_mode = ApprovalMode::Deny;
    let _ = non_interactive_decision(&access, &denied)?;
    let _ = non_interactive_decision(&access, &critical)?;
    let _ = run_risk_summary(&critical);
    let mut suspicious = clean.clone();
    suspicious.findings.push(detection::Finding::warning(
        "action.prompt_injection",
        "coverage suspicious action finding",
    ));
    suspicious.requires_prompt = true;
    let _ = decide_access(&access, &suspicious, true)?;
    let _ = signing_lookup_message(Ok(unlock::RunSigningLookup::Missing));
    let _ = signing_lookup_message(Ok(unlock::RunSigningLookup::MaterialUnavailable {
        reason: "coverage".to_string(),
    }));
    let _ = signing_lookup_message(Err(anyhow::anyhow!("coverage")));
    let _ = grant_integrity_messages(1, 1);
    let _ = grant_status_label(grants::GrantIntegrityStatus::Expired);
    let _ = grant_status_label(grants::GrantIntegrityStatus::LegacyUnsigned);
    let _ = grant_status_label(grants::GrantIntegrityStatus::Invalid);
    let resolved_main = registry::resolve_project(Some("coverage-main"), project.path())?;
    let missing_context = AgentContextOptions {
        agent: None,
        agent_key_id: None,
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &missing_context)?.is_none()
    );
    request_for_target(RequestTargetOptions {
        project: None,
        app: None,
        profile: None,
        context: missing_context.clone(),
        action: Some("Coverage missing context".to_string()),
        command: Some("sh -c true".to_string()),
        env_names: access.env.clone(),
        json: true,
        no_prompt: true,
    })
    .expect("coverage missing-context request should return structured JSON");
    let wrong_key_context = AgentContextOptions {
        agent: Some("codex".to_string()),
        agent_key_id: Some("agent:wrong".to_string()),
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &wrong_key_context)?.is_none()
    );
    let agent = agents::ensure_agent("coverage-main", "codex")?;
    let proof = agents::sign_payload("coverage-main", "codex", "coverage payload")?;
    let _ = agents::verify_proof("coverage-main", &proof)?;
    let _ = context::normalize_remote("https://example.test/demo.git/");
    let mut agent_state = agents::load_agents()?;
    let agent_record = agent_state
        .projects
        .get_mut("coverage-main")
        .and_then(|agents| agents.iter_mut().find(|agent| agent.agent_name == "codex"))
        .expect("coverage agent should exist");
    agent_record.private_seed = "AQID".to_string();
    agents::save_agents(&agent_state)?;
    assert!(agents::sign_payload("coverage-main", "codex", "coverage payload").is_err());
    let mut agent_state = agents::load_agents()?;
    let agent_record = agent_state
        .projects
        .get_mut("coverage-main")
        .and_then(|agents| agents.iter_mut().find(|agent| agent.agent_name == "codex"))
        .expect("coverage agent should exist");
    agent_record.public_key = "AQID".to_string();
    agents::save_agents(&agent_state)?;
    assert!(agents::verify_proof("coverage-main", &proof).is_err());
    let matching_key_context = AgentContextOptions {
        agent: Some("codex".to_string()),
        agent_key_id: Some(agent.agent_key_id),
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &matching_key_context)?
            .is_none()
    );
    let no_git_claim = context::ClaimedContext {
        agent: Some("codex".to_string()),
        agent_key_id: None,
        worktree: Some(project.path().to_path_buf()),
        branch: Some("main".to_string()),
        git_remote: Some("https://example.test/demo.git".to_string()),
        commit: Some("abc".to_string()),
    };
    assert!(context::verify_no_prompt_context(
        &no_git_claim,
        project.path(),
        &resolved_main,
        "agent:coverage".to_string(),
    )
    .is_err());
    let verified_worktree = |path: PathBuf, remote: &str| context::VerifiedContext {
        project: "coverage-main".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:coverage".to_string(),
        worktree: path,
        branch: "main".to_string(),
        git_remote: remote.to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    let unregistered = registry::ResolvedProject {
        name: "coverage-unregistered".to_string(),
        path: project.path().to_path_buf(),
        vault: project.path().join(".env.vault"),
    };
    let unregistered_context =
        verified_worktree(project.path().to_path_buf(), "https://example.test/demo");
    let unregistered_allowed =
        enforce_worktree_for_no_prompt(&unregistered, &unregistered_context, false, "30m")?;
    assert!(unregistered_allowed);
    let autobind_root = tempfile::tempdir()?;
    let autobind_worktree = autobind_root.path().join("agent-wt");
    fs::create_dir(&autobind_worktree)?;
    worktrees::allow_root("coverage-main", autobind_root.path())?;
    let missing_root = home.path().join("missing-root");
    let missing_worktree = missing_root.join("child");
    let _ = worktrees::allow_root("coverage-main", &missing_root)?;
    let autobind_context = verified_worktree(autobind_worktree, "https://example.test/demo");
    let autobind_allowed =
        enforce_worktree_for_no_prompt(&resolved_main, &autobind_context, false, "30m")?;
    assert!(autobind_allowed);
    let missing_autobind_context = verified_worktree(missing_worktree, "https://example.test/demo");
    let _ =
        enforce_worktree_for_no_prompt(&resolved_main, &missing_autobind_context, false, "30m")?;
    let _ = worktrees::remove_root("coverage-main", &missing_root)?;
    let approval_worktree = tempfile::tempdir()?;
    let approval_context = verified_worktree(
        approval_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let approval_allowed =
        enforce_worktree_for_no_prompt(&resolved_main, &approval_context, false, "30m")?;
    assert!(!approval_allowed);
    let registered_for_worktree = registry::load_registry()?
        .projects
        .get("coverage-main")
        .cloned()
        .context("coverage-main should be registered")?;
    let approve_pending_worktree = tempfile::tempdir()?;
    let approve_context = verified_worktree(
        approve_pending_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let decision =
        worktrees::evaluate_worktree(&registered_for_worktree, "coverage-main", &approve_context)?;
    assert!(matches!(
        decision,
        worktrees::WorktreeDecision::ApprovalRequired { .. }
    ));
    let request = worktrees::list_project("coverage-main")?
        .pending
        .last()
        .cloned()
        .context("coverage approve pending worktree missing")?;
    worktrees_command(WorktreesCommand::Approve {
        request_id: request.id,
        json: false,
    })
    .expect("coverage pending worktree approval should succeed");
    let deny_pending_worktree = tempfile::tempdir()?;
    let deny_context = verified_worktree(
        deny_pending_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let decision =
        worktrees::evaluate_worktree(&registered_for_worktree, "coverage-main", &deny_context)?;
    assert!(matches!(
        decision,
        worktrees::WorktreeDecision::ApprovalRequired { .. }
    ));
    let request = worktrees::list_project("coverage-main")?
        .pending
        .last()
        .cloned()
        .context("coverage deny pending worktree missing")?;
    worktrees_command(WorktreesCommand::Deny {
        request_id: request.id,
        json: false,
    })
    .expect("coverage pending worktree denial should succeed");
    let mut registry = registry::load_registry()?;
    registry
        .projects
        .get_mut("coverage-main")
        .expect("coverage-main should be registered")
        .git_remote = Some("https://example.test/expected.git".to_string());
    registry::save_registry(&registry)?;
    let denied_worktree = tempfile::tempdir()?;
    let denied_context = verified_worktree(
        denied_worktree.path().to_path_buf(),
        "https://example.test/other",
    );
    let denied_allowed =
        enforce_worktree_for_no_prompt(&resolved_main, &denied_context, false, "30m")?;
    assert!(!denied_allowed);
    registry
        .projects
        .get_mut("coverage-main")
        .expect("coverage-main should be registered")
        .git_remote = None;
    registry::save_registry(&registry)?;

    let missing_grant = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Once,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::Grant,
        grant_id: None,
    };
    consume_once_grant_if_reused(&missing_grant)?;
    handle_post_run_logging_result(7, Err(anyhow::anyhow!("coverage log failure")))?;

    let mut removed_files = Vec::new();
    let missing_file = project.path().join("missing");
    remove_project_file_if_exists(&missing_file, &mut removed_files)?;
    remove_locked_env_if_needed(&missing_file, &missing_file, &mut removed_files)?;
    let no_marker = project.path().join("AGENTS.no-marker.md");
    fs::write(&no_marker, "Intro\n")?;
    let _ = remove_agent_instruction_section(&no_marker)?;
    let retained = project.path().join("AGENTS.retained.md");
    let retained_contents = "Intro\n\n<!-- ward-agent-instructions -->\nGenerated\n";
    fs::write(&retained, retained_contents)?;
    let _ = remove_agent_instruction_section(&retained)?;

    let no_json = run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("No prompt without json".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: false,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    });
    assert!(no_json.is_err());
    let critical_run = RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Critical pending".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "printenv".to_string()],
        json: true,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    };
    run(critical_run)?;
    let grant_source = approvals::ApprovalSource::ManualAllow;
    unlock_vault("1h", None, false)?;
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(false));
    let scope = ApprovalScope::Always;
    let vault = &resolved_main.vault;
    let auto_context = context::VerifiedContext {
        project: "coverage-main".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:coverage".to_string(),
        worktree: project.path().to_path_buf(),
        branch: "main".to_string(),
        git_remote: "https://example.test/demo".to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    let session_grant = grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        None,
    )
    .expect("coverage default manual grant should persist");
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Always,
        approvals::ApprovalSource::Grant,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Deny,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Branch,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    let context_receipt = grants::GrantReceiptContext {
        request_id: uuid::Uuid::new_v4(),
        pending_request: false,
        critical_confirmation: false,
        verified_context: Some(auto_context.clone()),
    };
    let _ = grants::persist_manual_grant(
        &access,
        ApprovalScope::Once,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(context_receipt),
    )
    .expect("coverage context manual grant should persist");
    grants::persist_manual_grant(&access, scope, grant_source, vault, receipt_context.clone())?;
    let _ = grants::find_matching_grant(&access)?;
    let _ = grants::find_matching_grant_with_context(&access, &auto_context)?;
    let _ = grants::find_matching_non_always_grant(&access)?;
    let _ = grants::find_matching_non_always_grant_with_context(&access, &auto_context)?;
    let _ = grants::find_matching_once_grant(&access, false)?;
    let _ = grants::find_matching_once_grant_with_context(&access, false, &auto_context)?;
    let unlocked_run = RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Unlocked run".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: true,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    };
    run(unlocked_run)?;
    let suspicious_session = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Session,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::LocalTty,
        grant_id: None,
    };
    let _ = grants::persist_grant(&access, &suspicious_session, vault, receipt_context.clone())?;
    let _ = grants::persist_grant(&access, &suspicious_session, vault, None)?;
    let grants_edge_path = home.path().join("sessions").join("coverage-grants.jsonl");
    let grants_edge_parent = grants_edge_path
        .parent()
        .context("coverage grants edge path has no parent")?;
    fs::create_dir_all(grants_edge_parent)?;
    fs::write(&grants_edge_path, "\n")?;
    assert!(grants::load_grants_from_path(&grants_edge_path)?.is_empty());
    assert!(!grants::consume_once_grant(uuid::Uuid::new_v4())?);
    assert_eq!(grants::revoke_session_grants_at_path(&grants_edge_path)?, 0);
    let mut expired_grant = session_grant.clone();
    expired_grant.id = uuid::Uuid::new_v4();
    expired_grant.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    let mut future_grant = session_grant.clone();
    future_grant.id = uuid::Uuid::new_v4();
    future_grant.expires_at = Some(chrono::Utc::now() + chrono::Duration::minutes(1));
    let mut durable_grant = session_grant.clone();
    durable_grant.id = uuid::Uuid::new_v4();
    durable_grant.expires_at = None;
    grants::append_grant_to_path(&grants_edge_path, &expired_grant)?;
    grants::append_grant_to_path(&grants_edge_path, &future_grant)?;
    grants::append_grant_to_path(&grants_edge_path, &durable_grant)?;
    assert_eq!(
        grants::prune_expired_grants_at_path(&grants_edge_path, chrono::Utc::now())?,
        1
    );
    assert_eq!(
        grants::grant_integrity_status(&expired_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::Expired
    );
    let mut legacy_grant = future_grant.clone();
    legacy_grant.receipt = None;
    assert_eq!(
        grants::grant_integrity_status(&legacy_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::LegacyUnsigned
    );
    let mut invalid_grant = future_grant.clone();
    invalid_grant.project = "tampered".to_string();
    assert_eq!(
        grants::grant_integrity_status(&invalid_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::Invalid
    );
    let _ = non_interactive_decision(&access, &suspicious)?;
    let _ = non_interactive_decision_with_context(&access, &clean, None)?;
    let _ = non_interactive_decision_with_context(&access, &denied, Some(&auto_context))?;
    let fresh_access = AccessRequest {
        project: "coverage-main".to_string(),
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Fresh auto".to_string()),
        command: "sh -c echo fresh".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let _ = non_interactive_decision_with_context(&fresh_access, &clean, Some(&auto_context))?;
    let _ = non_interactive_decision_with_context(&access, &clean, Some(&auto_context))?;
    broker_command(BrokerCommand::Stop)?;
    let _ = unlock::clear_all_unlocks()?;
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    let unavailable_session = unlock::create_run_unlock(
        "coverage-main",
        vault,
        "coverage passphrase",
        chrono::Duration::hours(1),
    )
    .expect("coverage unavailable signing session should be created");
    crate::key_store::delete_secret(&unavailable_session.key_name)?;
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    unlock_vault("1h", None, false)?;
    let verify_logs = Some(LogsCommand::Verify {
        kind: Some(LogKind::Requests),
        full: true,
    });
    logs(verify_logs, None)?;
    let export_logs = Some(LogsCommand::Export {
        kind: LogKind::Requests,
        output: project.path().join("requests.export.jsonl"),
        force: false,
    });
    logs(export_logs, None)?;
    assert!(teardown(None, ".env.unused".into(), false, false).is_err());

    let remove_project = tempfile::tempdir()?;
    env::set_current_dir(remove_project.path())?;
    fs::write(remove_project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let remove_env = remove_project.path().join(".env");
    fs::write(&remove_env, "DATABASE_URL=postgres://remove\n")?;
    let remove_setup = SetupOptions {
        yes: true,
        project: Some("coverage-remove".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: true,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(remove_setup)?;

    let import_project = tempfile::tempdir()?;
    env::set_current_dir(import_project.path())?;
    init(Some("coverage-import".to_string()), false, false)?;
    let import_env = import_project.path().join(".env");
    fs::write(&import_env, "DATABASE_URL=postgres://import\n")?;
    import(".env".into(), Some("relative.vault".into()))?;

    let doctor_project = tempfile::tempdir()?;
    env::set_current_dir(doctor_project.path())?;
    fs::write(doctor_project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let doctor_env = doctor_project.path().join(".env");
    let doctor_vault = doctor_project.path().join(".env.vault");
    fs::write(&doctor_env, "DATABASE_URL=postgres://doctor\n")?;
    let doctor_setup = SetupOptions {
        yes: true,
        project: Some("coverage-doctor".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(doctor_setup)?;
    doctor()?;
    fs::write(&doctor_env, "DATABASE_URL=postgres://plaintext\n")?;
    doctor()?;
    env_file::lock_env_file(&doctor_env, &doctor_vault)?;
    fs::write(&doctor_vault, "changed")?;
    doctor()?;
    fs::remove_file(&doctor_env)?;
    doctor()?;
    fs::create_dir(&doctor_env)?;
    doctor()?;
    let grants_path = grants::grants_path();
    let grants_parent = grants_path.parent().context("grants path has no parent")?;
    fs::create_dir_all(grants_parent)?;
    fs::write(grants_path, "{bad-json}\n")?;
    doctor()?;
    crate::broker::coverage_exercise_broker_edges()?;

    env::set_current_dir(old_cwd)?;
    env::remove_var("WARD_HOME");
    env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    Ok(())
}
