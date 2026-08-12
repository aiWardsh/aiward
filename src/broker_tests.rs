use super::*;
use crate::{agents, approval_receipts, approvals::ApprovalScope, policy::AccessRequest};
use serial_test::serial;

fn broker_pair(request: BrokerRequest, state: Arc<Mutex<BrokerState>>) -> (bool, BrokerResponse) {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    write_request(&mut client, &request).unwrap();
    let stop = handle_client(&mut server, state).unwrap();
    let mut reader = BufReader::new(client);
    let response = read_response(&mut reader).unwrap();
    (stop, response)
}

struct TrustedClientGuard(bool);

impl Drop for TrustedClientGuard {
    fn drop(&mut self) {
        TEST_TRUSTED_CLIENT_ALLOWED.store(self.0, Ordering::SeqCst);
    }
}

fn set_trusted_client_allowed(allowed: bool) -> TrustedClientGuard {
    let previous = TEST_TRUSTED_CLIENT_ALLOWED.swap(allowed, Ordering::SeqCst);
    TrustedClientGuard(previous)
}

fn test_execute_payload(
    project: &str,
    vault: &Path,
    cwd: &Path,
    env_names: Vec<String>,
    command: Vec<String>,
) -> ExecuteAuthorizationPayload {
    ExecuteAuthorizationPayload::new(
        project.to_string(),
        vault.to_path_buf(),
        cwd.to_path_buf(),
        env_names,
        command,
        ApprovalScope::Once,
        ApprovalSource::ManualAllow,
    )
}

fn internal_authorization(
    project: &str,
    vault: &Path,
    cwd: &Path,
    env_names: Vec<String>,
    command: Vec<String>,
) -> ExecuteAuthorization {
    ExecuteAuthorization::Internal {
        payload: Box::new(test_execute_payload(
            project, vault, cwd, env_names, command,
        )),
    }
}

fn agent_authorization(
    project: &str,
    vault: &Path,
    cwd: &Path,
    env_names: Vec<String>,
    command: Vec<String>,
    agent: &str,
) -> ExecuteAuthorization {
    let mut payload = test_execute_payload(project, vault, cwd, env_names, command);
    payload.agent = Some(agent.to_string());
    payload.worktree = Some(cwd.to_path_buf());
    payload.branch = Some("main".to_string());
    payload.git_remote = Some(String::new());
    payload.commit = Some("abc123".to_string());
    let proof_payload = serde_json::to_string(&payload).unwrap();
    let proof = agents::sign_payload(project, agent, &proof_payload).unwrap();
    ExecuteAuthorization::Agent { proof }
}

fn test_vault(passphrase: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join(".env.vault");
    let envelope = vault::encrypt_env("DATABASE_URL=postgres://broker\n", passphrase).unwrap();
    vault::write_vault(&vault_path, &envelope).unwrap();
    (dir, vault_path)
}

#[test]
#[serial]
fn unlock_creates_memory_session_without_rewriting_vault() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let passphrase = "master-session-passphrase";
    let (_vault_dir, vault_path) = test_vault(passphrase);
    let before = std::fs::read(&vault_path).unwrap();
    let state = Arc::new(Mutex::new(BrokerState::default()));

    let (_, response) = broker_pair(
        BrokerRequest::Unlock {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            passphrase: passphrase.to_string(),
            ttl_seconds: 60,
            mode: None,
        },
        Arc::clone(&state),
    );

    assert!(matches!(response, BrokerResponse::Ok));
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);
    let status = status_from_state(&state.lock().unwrap());
    assert_eq!(status.sessions.len(), 1);
    assert_eq!(status.sessions[0].env_count, 1);
    assert_eq!(status.sessions[0].state, "active");
    assert!(status.sessions[0].vault_fingerprint.is_some());
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn human_list_keys_requires_project_bound_subsession() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let passphrase = "human-project-binding";
    let (_vault_dir, vault_path) = test_vault(passphrase);
    let mut state = BrokerState::default();
    state.sessions.insert(
        session_key("demo", &vault_path),
        build_project_session_with_expiry(
            "demo",
            &vault_path,
            passphrase,
            Utc::now() + Duration::hours(1),
            None,
        )
        .unwrap(),
    );
    state.human_sessions.insert(
        std::process::id(),
        HumanSessionEntry {
            session_token: "token".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            projects: ["other".to_string()].into_iter().collect(),
        },
    );

    let (_, response) = broker_pair(
        BrokerRequest::ListKeys {
            project: "demo".to_string(),
            vault: vault_path,
            authorization: ListKeysAuthorization::Human {
                shell_pid: std::process::id(),
            },
        },
        Arc::new(Mutex::new(state)),
    );

    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::HumanSessionRequired
    ));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn project_lock_removes_only_target_session_and_subsession_binding() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let passphrase = "lock-project";
    let (_demo_dir, demo_vault) = test_vault(passphrase);
    let (_other_dir, other_vault) = test_vault(passphrase);
    let mut state = BrokerState::default();
    state.sessions.insert(
        session_key("demo", &demo_vault),
        build_project_session_with_expiry(
            "demo",
            &demo_vault,
            passphrase,
            Utc::now() + Duration::hours(1),
            None,
        )
        .unwrap(),
    );
    state.sessions.insert(
        session_key("other", &other_vault),
        build_project_session_with_expiry(
            "other",
            &other_vault,
            passphrase,
            Utc::now() + Duration::hours(1),
            None,
        )
        .unwrap(),
    );
    state.human_sessions.insert(
        std::process::id(),
        HumanSessionEntry {
            session_token: "token".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            projects: ["demo".to_string(), "other".to_string()]
                .into_iter()
                .collect(),
        },
    );
    let state = Arc::new(Mutex::new(state));

    let (_, response) = broker_pair(
        BrokerRequest::LockProject {
            project: "demo".to_string(),
            vault: demo_vault.clone(),
        },
        Arc::clone(&state),
    );

    assert!(matches!(response, BrokerResponse::ProjectLock { .. }));
    let state = state.lock().unwrap();
    assert!(!state
        .sessions
        .contains_key(&session_key("demo", &demo_vault)));
    assert!(state
        .sessions
        .contains_key(&session_key("other", &other_vault)));
    let projects = &state.human_sessions[&std::process::id()].projects;
    assert!(!projects.contains("demo"));
    assert!(projects.contains("other"));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn setup_project_with_passphrase_creates_project_without_exposing_secret_values() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://dashboard\nPAYLOAD_SECRET=payload\n",
    )
    .unwrap();

    let status =
        setup_project_with_passphrase(project.path(), Some("dashboard-demo"), "1234").unwrap();

    assert_eq!(status.project, "dashboard-demo");
    assert!(project.path().join(".ward.json").exists());
    assert!(status.vault.exists());
    let cfg = config::read_project_config(project.path()).unwrap();
    assert!(!cfg.recovery_created);
    assert!(cfg.profiles["dev"]
        .env
        .contains(&"PAYLOAD_SECRET".to_string()));
    let locked = std::fs::read_to_string(project.path().join(".env")).unwrap();
    assert!(locked.contains("Ward managed locked .env"));
    assert!(!locked.contains("postgres://dashboard"));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn setup_project_request_requires_active_source_session() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let state = Arc::new(Mutex::new(BrokerState::default()));
    let (_, response) = broker_pair(
        BrokerRequest::SetupProject {
            source_project: "demo".to_string(),
            source_vault: home.path().join(".env.vault"),
            target_path: home.path().join("target"),
            project: None,
        },
        state,
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::UnlockRequired
    ));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn setup_project_with_existing_config_registers_without_overwriting() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let project = tempfile::tempdir().unwrap();
    let mut cfg =
        config::ProjectConfig::default_for_dir(project.path(), Some("existing".to_string()))
            .unwrap();
    cfg.profiles.get_mut("dev").unwrap().command = "custom dev".to_string();
    config::write_project_config(project.path(), &cfg, true).unwrap();

    let status = setup_project_with_passphrase(project.path(), None, "1234").unwrap();
    let after = config::read_project_config(project.path()).unwrap();

    assert_eq!(status.project, "existing");
    assert_eq!(after.profiles["dev"].command, "custom dev");
    assert!(registry::load_registry()
        .unwrap()
        .projects
        .contains_key("existing"));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn setup_project_with_missing_env_is_rejected() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let project = tempfile::tempdir().unwrap();
    let error = setup_project_with_passphrase(project.path(), Some("missing"), "1234")
        .unwrap_err()
        .to_string();
    assert!(error.contains("no .env"));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn setup_project_request_reuses_active_session_passphrase() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let source_vault = home.path().join("source.env.vault");
    let envelope = vault::encrypt_env("DATABASE_URL=postgres://source\n", "1234").unwrap();
    vault::write_vault(&source_vault, &envelope).unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(
        target.path().join(".env"),
        "DATABASE_URL=postgres://target\nPAYLOAD_SECRET=payload\n",
    )
    .unwrap();
    let mut state = BrokerState::default();
    state.sessions.insert(
        session_key("demo", &source_vault),
        build_project_session_with_expiry(
            "demo",
            &source_vault,
            "1234",
            Utc::now() + Duration::hours(1),
            None,
        )
        .unwrap(),
    );
    let state = Arc::new(Mutex::new(state));
    let (_, response) = broker_pair(
        BrokerRequest::SetupProject {
            source_project: "demo".to_string(),
            source_vault,
            target_path: target.path().to_path_buf(),
            project: Some("target-demo".to_string()),
        },
        Arc::clone(&state),
    );
    let BrokerResponse::ProjectSetup { status } = response else {
        panic!("unexpected setup response");
    };
    assert_eq!(status.project, "target-demo");
    assert!(state
        .lock()
        .unwrap()
        .sessions
        .contains_key(&session_key("target-demo", &status.vault)));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn provision_project_filters_envs_and_writes_store_snapshot() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let source = tempfile::tempdir().unwrap();
    let target = home.path().join("provisioned");
    let mut source_config =
        config::ProjectConfig::default_for_dir(source.path(), Some("source".to_string())).unwrap();
    source_config.profiles.get_mut("dev").unwrap().env =
        vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()];
    config::write_project_config(source.path(), &source_config, true).unwrap();
    let source_vault = source.path().join(".env.vault");
    let source_plaintext = "DATABASE_URL=postgres://selected-secret\nPAYLOAD_SECRET=not-selected\n";
    let envelope = vault::encrypt_env(source_plaintext, "1234").unwrap();
    vault::write_vault(&source_vault, &envelope).unwrap();
    registry::update_project_vault("source", source.path().to_path_buf(), source_vault.clone())
        .unwrap();
    let material = ActiveProjectMaterial {
        passphrase: "1234".to_string(),
        plaintext: source_plaintext.to_string(),
        env: env_file::parse_env_map(source_plaintext).unwrap(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    let (status, _) = provision_project_with_material(
        &ProjectProvisionRequest {
            source_project: "source".to_string(),
            source_vault,
            target_path: target,
            project: "target".to_string(),
            profiles: vec!["dev".to_string()],
            env_names: vec!["DATABASE_URL".to_string()],
            agents: vec!["codex".to_string()],
        },
        &material,
    )
    .unwrap();

    let target_plaintext = vault::decrypt_vault_file(&status.vault, "1234").unwrap();
    assert!(target_plaintext.contains("DATABASE_URL=postgres://selected-secret"));
    assert!(!target_plaintext.contains("PAYLOAD_SECRET"));
    let target_config = config::read_project_config(&status.path).unwrap();
    assert_eq!(target_config.profiles["dev"].env, vec!["DATABASE_URL"]);
    assert_eq!(
        target_config.agent_policies["codex"].env,
        vec!["DATABASE_URL"]
    );
    let locked = std::fs::read_to_string(status.path.join(".env")).unwrap();
    assert!(locked.contains("Ward managed locked .env"));
    assert!(!locked.contains("postgres://selected-secret"));
    let store = project_store::read_record("target").unwrap();
    let serialized = serde_json::to_string(&store).unwrap();
    assert!(serialized.contains("DATABASE_URL"));
    assert!(!serialized.contains("postgres://selected-secret"));
    assert!(!serialized.contains("not-selected"));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn broker_paths_live_under_ward_run_dir() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    assert!(socket_path().ends_with("run/ward.sock"));
    assert!(pid_path().ends_with("run/broker.pid"));
    ensure_running().unwrap();
    assert!(!broker_process_supported(Path::new(
        "target/debug/cli-test"
    )));
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn status_reports_not_running_without_socket() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let status = status().unwrap();
    assert!(!status.running);
    assert_eq!(status.version, BROKER_VERSION);
    assert!(status.sessions.is_empty());
    std::env::remove_var("WARD_HOME");
}

#[test]
fn broker_status_accepts_legacy_ping_without_version() {
    let body = serde_json::json!({
        "type": "status",
        "status": {
            "running": true,
            "socket": "/tmp/ward.sock",
            "pid": 123,
            "sessions": []
        }
    });
    let response: BrokerResponse = serde_json::from_value(body).unwrap();
    let BrokerResponse::Status { status } = response else {
        panic!("expected status response");
    };
    assert_eq!(status.version, "");
}

#[test]
fn matching_session_expiry_filters_project_vault_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join(".env.vault");
    std::fs::write(&vault, "vault").unwrap();
    let same_vault = dir.path().join(".").join(".env.vault");
    let now = Utc::now();
    let expires_at = now + Duration::minutes(30);
    let status = BrokerStatus {
        running: true,
        socket: socket_path(),
        pid: Some(123),
        ppid: Some(1),
        version: BROKER_VERSION.to_string(),
        started_at: Some(now),
        approval_count: 0,
        sessions: vec![
            BrokerSessionStatus {
                project: "other".to_string(),
                vault: vault.clone(),
                expires_at,
                active_mode: None,
                env_count: 1,
                subsession_count: 0,
                vault_fingerprint: None,
                workspace_root: None,
                workspace_name: None,
                app_slug: None,
                state: "active".to_string(),
            },
            BrokerSessionStatus {
                project: "demo".to_string(),
                vault: PathBuf::from("/missing/.env.vault"),
                expires_at,
                active_mode: None,
                env_count: 1,
                subsession_count: 0,
                vault_fingerprint: None,
                workspace_root: None,
                workspace_name: None,
                app_slug: None,
                state: "active".to_string(),
            },
            BrokerSessionStatus {
                project: "demo".to_string(),
                vault: same_vault,
                expires_at,
                active_mode: None,
                env_count: 1,
                subsession_count: 0,
                vault_fingerprint: None,
                workspace_root: None,
                workspace_name: None,
                app_slug: None,
                state: "active".to_string(),
            },
            BrokerSessionStatus {
                project: "demo".to_string(),
                vault: vault.clone(),
                expires_at: now - Duration::minutes(1),
                active_mode: None,
                env_count: 1,
                subsession_count: 0,
                vault_fingerprint: None,
                workspace_root: None,
                workspace_name: None,
                app_slug: None,
                state: "expired".to_string(),
            },
        ],
    };

    assert_eq!(
        matching_session_expiry(&status, "demo", &vault, now),
        Some(expires_at)
    );

    let stopped = BrokerStatus {
        running: false,
        ..status
    };
    assert_eq!(matching_session_expiry(&stopped, "demo", &vault, now), None);
}

#[test]
#[serial]
fn broker_client_protocol_handles_ping_stop_unlock_sign_and_execute() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let passphrase = "coverage passphrase";
    let (_vault_dir, vault_path) = test_vault(passphrase);
    let state = Arc::new(Mutex::new(BrokerState::default()));

    let (stop, response) = broker_pair(BrokerRequest::Ping, Arc::clone(&state));
    assert!(!stop);
    assert!(matches!(response, BrokerResponse::Status { .. }));
    let (stop, response) = broker_pair(BrokerRequest::Stop, Arc::clone(&state));
    assert!(stop);
    assert!(matches!(response, BrokerResponse::Ok));

    let (_, response) = broker_pair(
        BrokerRequest::Unlock {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            passphrase: "wrong".to_string(),
            ttl_seconds: 60,
            mode: None,
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::UnlockFailed
    ));

    let (_, response) = broker_pair(
        BrokerRequest::Unlock {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            passphrase: passphrase.to_string(),
            ttl_seconds: 60,
            mode: None,
        },
        Arc::clone(&state),
    );
    assert!(matches!(response, BrokerResponse::Ok));
    assert_eq!(
        status_from_state(&state.lock().unwrap()).sessions[0].project,
        "demo"
    );
    let cwd = std::env::current_dir().unwrap();
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];

    let (_, response) = broker_pair(
        BrokerRequest::Sign {
            project: "missing".to_string(),
            vault: vault_path.clone(),
            payload: approval_receipts::build_payload(approval_receipts::PayloadRequest {
                access: &AccessRequest {
                    project: "missing".to_string(),
                    agent: Some("codex".to_string()),
                    branch: Some("main".to_string()),
                    action: Some("Missing session".to_string()),
                    command: "sh -c true".to_string(),
                    env: vec!["DATABASE_URL".to_string()],
                },
                grant_id: uuid::Uuid::new_v4(),
                request_id: uuid::Uuid::new_v4(),
                approved_env: &["DATABASE_URL".to_string()],
                scope: ApprovalScope::Session,
                expires_at: None,
                critical_confirmation: false,
                created_at: Utc::now(),
                signer_key_id: String::new(),
                verified_context: None,
            }),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::SigningKeyUnavailable
    ));

    state.lock().unwrap().sessions.insert(
        session_key("expired", &vault_path),
        build_project_session_with_expiry(
            "expired",
            &vault_path,
            passphrase,
            Utc::now() - Duration::seconds(1),
            None,
        )
        .unwrap(),
    );
    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "expired".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: vec!["DATABASE_URL".to_string()],
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(internal_authorization(
                "expired",
                &vault_path,
                &cwd,
                vec!["DATABASE_URL".to_string()],
                command.clone(),
            )),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::UnlockRequired
    ));

    let access = AccessRequest {
        project: "demo".to_string(),
        agent: Some("codex".to_string()),
        branch: Some("main".to_string()),
        action: Some("Coverage sign".to_string()),
        command: "sh -c true".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let payload = approval_receipts::build_payload(approval_receipts::PayloadRequest {
        access: &access,
        grant_id: uuid::Uuid::new_v4(),
        request_id: uuid::Uuid::new_v4(),
        approved_env: &access.env,
        scope: ApprovalScope::Session,
        expires_at: Some(Utc::now() + Duration::hours(1)),
        critical_confirmation: false,
        created_at: Utc::now(),
        signer_key_id: String::new(),
        verified_context: None,
    });
    let (_, response) = broker_pair(
        BrokerRequest::Sign {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            payload,
        },
        Arc::clone(&state),
    );
    assert!(matches!(response, BrokerResponse::Signed { .. }));

    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: access.env.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(ExecuteAuthorization::Agent {
                proof: agents::sign_payload("demo", "codex", "tampered").unwrap(),
            }),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::ExecuteAuthorizationInvalid
    ));

    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "other".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: access.env.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(internal_authorization(
                "other",
                &vault_path,
                &cwd,
                access.env.clone(),
                command.clone(),
            )),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::UnlockRequired
    ));

    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: vec!["MISSING_ENV".to_string()],
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(internal_authorization(
                "demo",
                &vault_path,
                &cwd,
                vec!["MISSING_ENV".to_string()],
                command.clone(),
            )),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::VaultKeyMissing
    ));

    let (mut client, mut server) = UnixStream::pair().unwrap();
    write_request(
        &mut client,
        &BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: access.env.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(agent_authorization(
                "demo",
                &vault_path,
                &cwd,
                access.env.clone(),
                command.clone(),
                "codex",
            )),
        },
    )
    .unwrap();
    assert!(!handle_client(&mut server, Arc::clone(&state)).unwrap());
    let mut reader = BufReader::new(client);
    let finished = read_response(&mut reader).unwrap();
    assert!(matches!(
        finished,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::HumanApprovalRequired
    ));

    let mut forged_payload =
        test_execute_payload("demo", &vault_path, &cwd, access.env, command.clone());
    forged_payload.approval_source = ApprovalSource::AgentMediated;
    forged_payload.agent = Some("codex".to_string());
    forged_payload.worktree = Some(cwd.clone());
    forged_payload.branch = Some("main".to_string());
    forged_payload.git_remote = Some(String::new());
    forged_payload.commit = Some("abc123".to_string());
    let proof_payload = serde_json::to_string(&forged_payload).unwrap();
    let forged_proof = agents::sign_payload("demo", "codex", &proof_payload).unwrap();
    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: forged_payload.env_names.clone(),
            command,
            inherited_env: inherited_execution_env(),
            authorization: Some(ExecuteAuthorization::Agent {
                proof: forged_proof,
            }),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::AgentSelfApprovalRejected
    ));

    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn privileged_broker_requests_require_trusted_client_and_bound_authorization() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let passphrase = "coverage passphrase";
    let (_vault_dir, vault_path) = test_vault(passphrase);
    let state = Arc::new(Mutex::new(BrokerState::default()));
    let cwd = std::env::current_dir().unwrap();
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let env_names = vec!["DATABASE_URL".to_string()];

    let (_, response) = broker_pair(
        BrokerRequest::Unlock {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            passphrase: passphrase.to_string(),
            ttl_seconds: 60,
            mode: None,
        },
        Arc::clone(&state),
    );
    assert!(matches!(response, BrokerResponse::Ok));

    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: env_names.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: None,
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::ExecuteAuthorizationRequired
    ));

    let mut mismatched_payload = test_execute_payload(
        "demo",
        &vault_path,
        &cwd,
        vec!["CRON_SECRET".to_string()],
        command.clone(),
    );
    mismatched_payload.agent = Some("codex".to_string());
    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: env_names.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(ExecuteAuthorization::Internal {
                payload: Box::new(mismatched_payload),
            }),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::ExecuteAuthorizationMismatch
    ));

    let replay_authorization = internal_authorization(
        "demo",
        &vault_path,
        &cwd,
        env_names.clone(),
        command.clone(),
    );
    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: env_names.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(replay_authorization.clone()),
        },
        Arc::clone(&state),
    );
    assert!(matches!(response, BrokerResponse::Finished { .. }));
    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            cwd: cwd.clone(),
            env_names: env_names.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(replay_authorization),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::ExecuteAuthorizationReplayed
    ));

    let _guard = set_trusted_client_allowed(false);
    let (_, response) = broker_pair(
        BrokerRequest::ListKeys {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            authorization: ListKeysAuthorization::Internal {
                purpose: "test".to_string(),
            },
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::BrokerClientUntrusted
    ));

    let access = AccessRequest {
        project: "demo".to_string(),
        agent: Some("codex".to_string()),
        branch: Some("main".to_string()),
        action: Some("Coverage sign".to_string()),
        command: "sh -c true".to_string(),
        env: env_names.clone(),
    };
    let sign_payload = approval_receipts::build_payload(approval_receipts::PayloadRequest {
        access: &access,
        grant_id: uuid::Uuid::new_v4(),
        request_id: uuid::Uuid::new_v4(),
        approved_env: &env_names,
        scope: ApprovalScope::Session,
        expires_at: None,
        critical_confirmation: false,
        created_at: Utc::now(),
        signer_key_id: String::new(),
        verified_context: None,
    });
    let (_, response) = broker_pair(
        BrokerRequest::Sign {
            project: "demo".to_string(),
            vault: vault_path.clone(),
            payload: sign_payload,
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::BrokerClientUntrusted
    ));

    let (_, response) = broker_pair(
        BrokerRequest::Execute {
            project: "demo".to_string(),
            vault: vault_path,
            cwd,
            env_names: env_names.clone(),
            command: command.clone(),
            inherited_env: inherited_execution_env(),
            authorization: Some(internal_authorization(
                "demo",
                Path::new(".env.vault"),
                Path::new("."),
                env_names,
                command,
            )),
        },
        Arc::clone(&state),
    );
    assert!(matches!(
        response,
        BrokerResponse::Error {
            reason,
            ..
        } if reason == BrokerReason::BrokerClientUntrusted
    ));

    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial]
fn broker_helpers_report_closed_and_invalid_messages() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    let access = AccessRequest {
        project: "demo".to_string(),
        agent: Some("codex".to_string()),
        branch: Some("main".to_string()),
        action: Some("Unit broker stub".to_string()),
        command: "sh -c true".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let payload = approval_receipts::build_payload(approval_receipts::PayloadRequest {
        access: &access,
        grant_id: uuid::Uuid::new_v4(),
        request_id: uuid::Uuid::new_v4(),
        approved_env: &access.env,
        scope: ApprovalScope::Session,
        expires_at: None,
        critical_confirmation: false,
        created_at: Utc::now(),
        signer_key_id: String::new(),
        verified_context: None,
    });
    assert!(sign_receipt("demo", Path::new(".env.vault"), payload).is_err());

    fs_util::ensure_private_dir(&run_dir()).unwrap();
    fs_util::write_private_file(&pid_path(), b"bad-pid").unwrap();
    assert!(read_pid().is_err());
    cleanup_stale_files().unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    drop(client);
    let mut reader = BufReader::new(server);
    assert!(read_response(&mut reader).is_err());

    let (mut client, server) = UnixStream::pair().unwrap();
    writeln!(client, "not json").unwrap();
    let mut reader = BufReader::new(server);
    assert!(read_request(&mut reader).is_err());
    std::env::remove_var("WARD_HOME");
}
