#[cfg(all(coverage, not(test)))]
#[doc(hidden)]
pub fn coverage_exercise_broker_edges() -> Result<()> {
    let home = tempfile::tempdir()?;
    std::env::set_var("WARD_HOME", home.path());
    cleanup_stale_files()?;
    assert!(execute(
        "demo",
        &home.path().join(".env.vault"),
        home.path(),
        Vec::new(),
        vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        ExecuteAuthorization::Internal {
            payload: Box::new(ExecuteAuthorizationPayload::new(
                "demo".to_string(),
                home.path().join(".env.vault"),
                home.path().to_path_buf(),
                Vec::new(),
                vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
                ApprovalScope::Once,
                ApprovalSource::ManualAllow,
            )),
        },
    )
    .is_err());
    assert!(wait_until_ready(StdDuration::from_millis(0)).is_err());

    let broker_status = BrokerStatus {
        running: true,
        socket: socket_path(),
        pid: Some(1),
        ppid: Some(0),
        version: BROKER_VERSION.to_string(),
        started_at: Some(Utc::now()),
        sessions: Vec::new(),
        approval_count: 0,
    };
    let ping_result = with_fake_broker(vec![vec![BrokerResponse::Ok]], ping)?;
    assert!(ping_result.is_err());
    let responses = vec![vec![BrokerResponse::Status {
        status: broker_status.clone(),
    }]];
    let status_result = with_fake_broker(responses, status)?;
    assert!(status_result?.running);
    let status_result = with_fake_broker(vec![vec![BrokerResponse::Ok]], status)?;
    assert!(status_result.is_err());
    let responses = vec![vec![BrokerResponse::Error {
        reason: BrokerReason::StopFailed,
        message: "stop failed".to_string(),
    }]];
    let stop_result = with_fake_broker(responses, stop)?;
    assert!(stop_result.is_err());
    let responses = vec![vec![BrokerResponse::Status {
        status: broker_status.clone(),
    }]];
    let stop_result = with_fake_broker(responses, stop)?;
    assert!(stop_result.is_err());

    std::env::set_var("WARD_COVERAGE_ASSUME_BROKER_EXE", "1");
    let vault_path = home.path().join(".env.vault");
    let payload = ApprovalReceiptPayload {
        schema_version: 1,
        grant_id: uuid::Uuid::new_v4(),
        request_id: uuid::Uuid::new_v4(),
        project: "demo".to_string(),
        agent: Some("codex".to_string()),
        branch: Some("main".to_string()),
        command_hash: approval_receipts::command_hash("pnpm dev"),
        requested_env: vec!["DATABASE_URL".to_string()],
        approved_env: vec!["DATABASE_URL".to_string()],
        scope: crate::approvals::ApprovalScope::Session,
        expires_at: None,
        critical_confirmation: false,
        created_at: Utc::now(),
        signer_key_id: String::new(),
        agent_key_id: None,
        verified_worktree: None,
        verified_git_remote: None,
        verified_commit: None,
    };
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Error {
            reason: BrokerReason::UnlockFailed,
            message: "unlock failed".to_string(),
        }],
    ];
    let action = || unlock_project("demo", &vault_path, "1234", Duration::hours(1));
    let unlock_result = with_fake_broker(responses, action)?;
    assert!(unlock_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
    ];
    let action = || unlock_project("demo", &vault_path, "1234", Duration::hours(1));
    let unlock_result = with_fake_broker(responses, action)?;
    assert!(unlock_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Error {
            reason: BrokerReason::SigningKeyUnavailable,
            message: "sign failed".to_string(),
        }],
    ];
    let action = || sign_receipt("demo", &vault_path, payload.clone());
    let sign_result = with_fake_broker(responses, action)?;
    assert!(sign_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Ok],
    ];
    let action = || sign_receipt("demo", &vault_path, payload);
    let sign_result = with_fake_broker(responses, action)?;
    assert!(sign_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![
            BrokerResponse::Output {
                stream: "stderr".to_string(),
                line: "coverage stderr".to_string(),
            },
            BrokerResponse::Error {
                reason: BrokerReason::ExecutionFailed,
                message: "execution failed".to_string(),
            },
        ],
    ];
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let authorization = ExecuteAuthorization::Internal {
        payload: Box::new(ExecuteAuthorizationPayload::new(
            "demo".to_string(),
            vault_path.clone(),
            home.path().to_path_buf(),
            Vec::new(),
            command.clone(),
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
        )),
    };
    let action = || {
        execute(
            "demo",
            &vault_path,
            home.path(),
            Vec::new(),
            command,
            authorization,
        )
    };
    let execute_result = with_fake_broker(responses, action)?;
    assert!(execute_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Finished {
            outcome: RunCommandOutcome {
                exit_code: 0,
                duration_ms: 0,
                redaction_alerts: 0,
                output_alerts: Vec::new(),
            },
        }],
    ];
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let authorization = ExecuteAuthorization::Internal {
        payload: Box::new(ExecuteAuthorizationPayload::new(
            "demo".to_string(),
            vault_path.clone(),
            home.path().to_path_buf(),
            Vec::new(),
            command.clone(),
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
        )),
    };
    let action = || {
        execute(
            "demo",
            &vault_path,
            home.path(),
            Vec::new(),
            command,
            authorization,
        )
    };
    let execute_result = with_fake_broker(responses, action)?;
    let _ = execute_result?;
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status,
        }],
        vec![BrokerResponse::Ok],
    ];
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let authorization = ExecuteAuthorization::Internal {
        payload: Box::new(ExecuteAuthorizationPayload::new(
            "demo".to_string(),
            vault_path.clone(),
            home.path().to_path_buf(),
            Vec::new(),
            command.clone(),
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
        )),
    };
    let action = || {
        execute(
            "demo",
            &vault_path,
            home.path(),
            Vec::new(),
            command,
            authorization,
        )
    };
    let execute_result = with_fake_broker(responses, action)?;
    assert!(execute_result.is_err());

    std::env::remove_var("WARD_COVERAGE_ASSUME_BROKER_EXE");
    std::env::remove_var("WARD_HOME");
    Ok(())
}

#[cfg(all(coverage, not(test)))]
fn with_fake_broker<T>(
    responses: Vec<Vec<BrokerResponse>>,
    action: impl FnOnce() -> T,
) -> Result<T> {
    cleanup_stale_files()?;
    fs_util::ensure_private_dir(&run_dir())?;
    let listener = UnixListener::bind(socket_path()).context("failed to bind fake broker")?;
    let handle = thread::spawn(move || {
        for response_set in responses {
            let (mut stream, _) = listener.accept().expect("fake broker accept failed");
            {
                let mut reader = BufReader::new(stream.try_clone().expect("clone fake stream"));
                let _request = read_request(&mut reader).expect("fake broker request");
            }
            for response in response_set {
                write_response(&mut stream, &response).expect("fake broker response");
            }
        }
    });
    let result = action();
    handle.join().expect("fake broker thread panicked");
    cleanup_stale_files()?;
    Ok(result)
}
