pub fn serve() -> Result<()> {
    cleanup_stale_files()?;
    fs_util::ensure_private_dir(&run_dir())?;
    let listener = UnixListener::bind(socket_path()).context("failed to bind Ward broker")?;
    fs_util::set_private_file_permissions(&socket_path())
        .context("failed to restrict broker socket permissions")?;
    fs_util::write_private_file(&pid_path(), std::process::id().to_string().as_bytes())?;
    let state = Arc::new(Mutex::new(BrokerState::default()));
    install_shutdown_handler(Arc::clone(&state));
    for stream in listener.incoming() {
        let mut stream = stream.context("failed to accept broker client")?;
        let state = Arc::clone(&state);
        thread::spawn(move || {
            let stop = match handle_client(&mut stream, state) {
                Ok(stop) => stop,
                Err(error) => {
                    let response = broker_error(BrokerReason::InternalFailure, error.to_string());
                    let _ = write_response(&mut stream, &response);
                    false
                }
            };
            if stop {
                let _ = cleanup_stale_files();
                std::process::exit(0);
            }
        });
    }
    Ok(())
}

fn handle_client(stream: &mut UnixStream, state: Arc<Mutex<BrokerState>>) -> Result<bool> {
    let request = {
        let mut reader = BufReader::new(stream.try_clone()?);
        read_request(&mut reader)?
    };
    {
        let mut broker_state = state.lock().expect("broker state poisoned");
        cleanup_inactive_human_sessions(&mut broker_state);
        cleanup_expired_execute_nonces(&mut broker_state);
        cleanup_expired_approvals(&mut broker_state);
    }
    match request {
        BrokerRequest::Ping => {
            let status = status_from_state(&state.lock().expect("broker state poisoned"));
            write_response(stream, &BrokerResponse::Status { status })?;
        }
        BrokerRequest::Stop => {
            cancel_all_human_commands(&mut state.lock().expect("broker state poisoned"));
            write_response(stream, &BrokerResponse::Ok)?;
            return Ok(true);
        }
        BrokerRequest::LockProject { project, vault } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            match lock_project_in_state(&state, &project, &vault) {
                Ok(status) => {
                    write_response(stream, &BrokerResponse::ProjectLock { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_lock_failed", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::Unlock {
            project,
            vault,
            passphrase,
            ttl_seconds,
            mode,
        } => {
            match build_project_session(&project, &vault, &passphrase, ttl_seconds, mode.as_deref())
            {
                Ok(session) => {
                    let session_id = session_key(&project, &vault);
                    state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .insert(session_id, session);
                    write_response(stream, &BrokerResponse::Ok)?;
                }
                Err(error) => {
                    let response = broker_error("unlock_failed", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::Sign {
            project,
            vault,
            payload,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            if let Err(message) = validate_signing_payload(&project, &payload) {
                let response = broker_error("signing_payload_invalid", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let result = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault)
                    .and_then(|session| sign_with_session(session, payload))
            };
            match result {
                Ok(receipt) => write_response(stream, &BrokerResponse::Signed { receipt })?,
                Err(error) => {
                    let response = broker_error("signing_key_unavailable", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::ApproveRequest {
            request_id,
            scope,
            confirm_critical,
            channel,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            match approve_pending_request_in_state(
                &state,
                request_id,
                scope,
                confirm_critical,
                channel,
            ) {
                Ok(status) => write_response(stream, &BrokerResponse::Approval { status })?,
                Err(error) => {
                    let response = broker_error("approval_failed", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::DenyRequest {
            request_id,
            channel,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            match deny_pending_request_in_state(&state, request_id, channel) {
                Ok(status) => write_response(stream, &BrokerResponse::Approval { status })?,
                Err(error) => {
                    let response = broker_error("deny_failed", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::ListApprovals { project } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let mut state = state.lock().expect("broker state poisoned");
            cleanup_expired_approvals(&mut state);
            let approvals = state
                .approvals
                .values()
                .filter(|approval| {
                    project
                        .as_deref()
                        .is_none_or(|project| approval.project == project)
                })
                .map(BrokerApprovalRecord::status)
                .collect();
            write_response(stream, &BrokerResponse::Approvals { approvals })?;
        }
        BrokerRequest::RegisterHumanSession {
            shell_pid,
            session_token,
            ttl_seconds,
            projects,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
            let projects = projects.into_iter().collect::<BTreeSet<_>>();
            state
                .lock()
                .expect("broker state poisoned")
                .human_sessions
                .insert(
                    shell_pid,
                    HumanSessionEntry {
                        session_token,
                        expires_at,
                        projects,
                    },
                );
            write_response(stream, &BrokerResponse::Ok)?;
        }
        BrokerRequest::DeregisterHumanSession {
            shell_pid,
            session_token,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let mut state = state.lock().expect("broker state poisoned");
            match state.human_sessions.get(&shell_pid) {
                Some(entry) if entry.session_token == session_token => {
                    state.human_sessions.remove(&shell_pid);
                    cancel_human_commands(&mut state, shell_pid);
                    write_response(stream, &BrokerResponse::Ok)?;
                }
                Some(_) => {
                    let response = broker_error("invalid_token", "session token mismatch");
                    write_response(stream, &response)?;
                }
                None => {
                    write_response(stream, &BrokerResponse::Ok)?;
                }
            }
        }
        BrokerRequest::Execute {
            project,
            vault,
            cwd,
            env_names,
            command,
            inherited_env,
            authorization,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let cancellation = Arc::new(AtomicBool::new(false));
            let child_pid = Arc::new(AtomicU32::new(0));
            let human_shell_pid = {
                let mut broker_state = state.lock().expect("broker state poisoned");
                match validate_execute_authorization(
                    &mut broker_state,
                    &project,
                    &vault,
                    &cwd,
                    &env_names,
                    &command,
                    authorization.as_ref(),
                ) {
                    Ok(shell_pid) => shell_pid,
                    Err((reason, message)) => {
                        let response = broker_error(reason, message);
                        write_response(stream, &response)?;
                        return Ok(false);
                    }
                }
            };
            let session_material = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault)
                    .map(|session| (session.env.clone(), session.active_mode.clone()))
            };
            let (session_env, active_mode) = match session_material {
                Ok(material) => material,
                Err(error) => {
                    let response = broker_error("unlock_required", error.to_string());
                    write_response(stream, &response)?;
                    return Ok(false);
                }
            };

            // Mode enforcement — runs before any env decryption
            if let Some(ref mode) = active_mode {
                // Env scope is always enforced regardless of mode level
                for env_name in &env_names {
                    if !modes::mode_allows_env(mode, env_name) {
                        let response = broker_error(
                            "mode_env_violation",
                            format!(
                                "{env_name} is not allowed by active mode '{}' (allowedEnv: {})",
                                mode.config.name,
                                mode.config.allowed_env.join(", ")
                            ),
                        );
                        write_response(stream, &response)?;
                        return Ok(false);
                    }
                }
                // Command blocking only applies in supervised mode
                if mode.config.level == modes::ModeLevel::Supervised
                    && !modes::mode_allows_command(mode, &command.join(" "))
                {
                    let response = broker_error(
                        "mode_confirmation_required",
                        format!(
                            "supervised mode '{}': command not in allowedCommands — explicit confirmation required",
                            mode.config.name
                        ),
                    );
                    write_response(stream, &response)?;
                    return Ok(false);
                }
            }

            // Block commands with critical security findings regardless of caller.
            // Policy prompts live in the CLI but this last-resort check runs in the broker
            // so that raw-socket callers cannot bypass exfiltration detection.
            let cmd_str = command.join(" ");
            let security_findings = detection::preflight_findings(&cmd_str, &env_names, None);
            if detection::has_critical_findings(&security_findings) {
                let codes: Vec<&str> = security_findings
                    .iter()
                    .filter(|f| f.severity == detection::Severity::Critical)
                    .map(|f| f.code.as_str())
                    .collect();
                let response = broker_error(
                    "security_policy_violation",
                    format!("command blocked by security policy: {}", codes.join(", ")),
                );
                write_response(stream, &response)?;
                return Ok(false);
            }

            let output = Arc::new(Mutex::new(stream.try_clone()?));
            monitor_client_disconnect(stream.try_clone()?, Arc::clone(&cancellation));
            let emitter = {
                let output = Arc::clone(&output);
                let cancellation = Arc::clone(&cancellation);
                Arc::new(move |stream_name: &str, line: &str| {
                    if let Ok(mut stream) = output.lock() {
                        if write_response(
                            &mut stream,
                            &BrokerResponse::Output {
                                stream: stream_name.to_string(),
                                line: line.to_string(),
                            },
                        )
                        .is_err()
                        {
                            cancellation.store(true, Ordering::SeqCst);
                        }
                    }
                })
            };
            let outcome = runner::run_command_with_emitter(
                {
                    if let Some(shell_pid) = human_shell_pid {
                        register_human_command(
                            &mut state.lock().expect("broker state poisoned"),
                            shell_pid,
                            project.clone(),
                            Arc::clone(&cancellation),
                            Arc::clone(&child_pid),
                        );
                    }
                    RunCommandRequest {
                        cwd,
                        env_names,
                        env: session_env,
                        command,
                        inherited_env,
                        cancellation: Some(Arc::clone(&cancellation)),
                        human_shell_pid,
                        child_pid: Some(Arc::clone(&child_pid)),
                    }
                },
                emitter,
            );
            if let Some(shell_pid) = human_shell_pid {
                let mut broker_state = state.lock().expect("broker state poisoned");
                unregister_human_command(&mut broker_state, shell_pid, &cancellation);
            }
            match outcome {
                Ok(outcome) => {
                    let mut stream = output.lock().expect("broker output stream poisoned");
                    write_response(&mut stream, &BrokerResponse::Finished { outcome })?;
                }
                Err(error) => {
                    let mut stream = output.lock().expect("broker output stream poisoned");
                    let response = if let Some(missing) = runner::missing_vault_envs(&error) {
                        broker_error("vault_key_missing", missing.join(", "))
                    } else {
                        broker_error("execution_failed", error.to_string())
                    };
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::ListKeys {
            project,
            vault,
            authorization,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            if let Err((reason, message)) =
                validate_list_keys_authorization(&state, &project, &authorization)
            {
                let response = broker_error(reason, message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let key_result = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault)
                    .map(|session| session.env.keys().cloned().collect::<Vec<_>>())
            };
            match key_result {
                Ok(names) => write_response(stream, &BrokerResponse::Keys { names })?,
                Err(e) => {
                    let response = broker_error("list_keys_failed", e.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::SetupProject {
            source_project,
            source_vault,
            target_path,
            project,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let (passphrase, expires_at) = {
                let state = state.lock().expect("broker state poisoned");
                match active_session(&state, &source_project, &source_vault) {
                    Ok(session) => (session.passphrase.clone(), session.expires_at),
                    Err(error) => {
                        let response = broker_error("unlock_required", error.to_string());
                        write_response(stream, &response)?;
                        return Ok(false);
                    }
                }
            };

            match setup_project_with_passphrase(&target_path, project.as_deref(), &passphrase) {
                Ok(status) => {
                    match build_project_session_with_expiry(
                        &status.project,
                        &status.vault,
                        &passphrase,
                        expires_at,
                        None,
                    ) {
                        Ok(session) => {
                            state
                                .lock()
                                .expect("broker state poisoned")
                                .sessions
                                .insert(session_key(&status.project, &status.vault), session);
                        }
                        Err(error) => {
                            let response =
                                broker_error("project_session_failed", error.to_string());
                            write_response(stream, &response)?;
                            return Ok(false);
                        }
                    }
                    write_response(stream, &BrokerResponse::ProjectSetup { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_setup_failed", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::SnapshotProject { project, vault } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let material = {
                let state = state.lock().expect("broker state poisoned");
                active_project_material(&state, &project, &vault)
            };
            let material = match material {
                Ok(material) => material,
                Err(error) => {
                    let response = broker_error("unlock_required", error.to_string());
                    write_response(stream, &response)?;
                    return Ok(false);
                }
            };
            match snapshot_project_with_material(&project, &vault, &material) {
                Ok(status) => {
                    write_response(stream, &BrokerResponse::ProjectSnapshot { status })?
                }
                Err(error) => {
                    let response = broker_error("project_snapshot_failed", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::ProvisionProject {
            source_project,
            source_vault,
            target_path,
            project,
            profiles,
            env_names,
            agents,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let material = {
                let state = state.lock().expect("broker state poisoned");
                active_project_material(&state, &source_project, &source_vault)
            };
            let material = match material {
                Ok(material) => material,
                Err(error) => {
                    let response = broker_error("unlock_required", error.to_string());
                    write_response(stream, &response)?;
                    return Ok(false);
                }
            };
            let request = ProjectProvisionRequest {
                source_project,
                source_vault,
                target_path,
                project,
                profiles,
                env_names,
                agents,
            };
            let provision_result = {
                let passphrase = material.passphrase.clone();
                provision_project_with_material(&request, &material)
                    .map(|(status, expires_at)| (status, expires_at, passphrase))
            };
            match provision_result {
                Ok((status, expires_at, passphrase)) => {
                    match build_project_session_with_expiry(
                        &status.project,
                        &status.vault,
                        &passphrase,
                        expires_at,
                        None,
                    ) {
                        Ok(session) => {
                            state
                                .lock()
                                .expect("broker state poisoned")
                                .sessions
                                .insert(session_key(&status.project, &status.vault), session);
                        }
                        Err(error) => {
                            let response =
                                broker_error("project_session_failed", error.to_string());
                            write_response(stream, &response)?;
                            return Ok(false);
                        }
                    }
                    write_response(stream, &BrokerResponse::ProjectProvision { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_provision_failed", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
        BrokerRequest::RemoveProject {
            project,
            vault,
            export_path,
            restore_env,
        } => {
            if let Err(message) = require_trusted_client(stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(stream, &response)?;
                return Ok(false);
            }
            let material = {
                let state = state.lock().expect("broker state poisoned");
                active_project_material(&state, &project, &vault)
            };
            match material.and_then(|material| {
                let registry = registry::list_projects()?;
                let registered = registry
                    .projects
                    .get(&project)
                    .with_context(|| format!("project {project} is not registered"))?;
                project_teardown::teardown_project(project_teardown::ProjectTeardownRequest {
                    project: project.clone(),
                    path: registered.path.clone(),
                    vault: vault.clone(),
                    export_path,
                    restore_env,
                    decrypt_key: material.passphrase,
                })
            }) {
                Ok(status) => {
                    discard_project_runtime_after_teardown(&state, &project, &vault);
                    write_response(stream, &BrokerResponse::ProjectTeardown { status })?;
                }
                Err(error) => {
                    let response = broker_error("unlock_required", error.to_string());
                    write_response(stream, &response)?;
                }
            }
        }
    }
    Ok(false)
}
