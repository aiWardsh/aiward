fn active_session<'a>(
    state: &'a BrokerState,
    project: &str,
    vault: &Path,
) -> Result<&'a BrokerSession> {
    let key = session_key(project, vault);
    let session = state
        .sessions
        .get(&key)
        .context("missing broker unlock session")?;
    if session.expires_at <= Utc::now() {
        anyhow::bail!("expired broker unlock session");
    }
    Ok(session)
}

fn validate_human_session(
    state: &BrokerState,
    project: &str,
    shell_pid: u32,
) -> std::result::Result<(), String> {
    let Some(entry) = state.human_sessions.get(&shell_pid) else {
        return Err(format!(
            "Ward human mode is not active for project {project} in this terminal; run ward human (shell pid: {shell_pid})"
        ));
    };
    if entry.expires_at <= Utc::now() {
        return Err(format!(
            "Ward human mode expired for this terminal; run ward human (shell pid: {shell_pid})"
        ));
    }
    if !process_exists(shell_pid) {
        return Err(format!(
            "Ward human shell is no longer running; run ward human in the active terminal (shell pid: {shell_pid})"
        ));
    }
    if !entry.projects.contains(project) {
        return Err(format!(
            "Ward human mode in this terminal is not attached to project {project}; run ward human --project {project} (shell pid: {shell_pid})"
        ));
    }
    Ok(())
}

fn validate_execute_authorization(
    state: &mut BrokerState,
    project: &str,
    vault: &Path,
    cwd: &Path,
    env_names: &[String],
    command: &[String],
    authorization: Option<&ExecuteAuthorization>,
) -> std::result::Result<Option<u32>, (BrokerReason, String)> {
    let Some(authorization) = authorization else {
        return Err((
            BrokerReason::ExecuteAuthorizationRequired,
            "execution authorization is required".to_string(),
        ));
    };
    match authorization {
        ExecuteAuthorization::Human { shell_pid } => {
            cleanup_inactive_human_sessions(state);
            validate_human_session(state, project, *shell_pid)
                .map_err(|message| (BrokerReason::HumanSessionRequired, message))?;
            Ok(Some(*shell_pid))
        }
        ExecuteAuthorization::Agent { proof } => {
            let valid = agents::verify_proof(project, proof).map_err(|error| {
                (
                    BrokerReason::AgentProofInvalid,
                    format!("agent proof verification failed: {error}"),
                )
            })?;
            if !valid {
                return Err((
                    BrokerReason::AgentProofInvalid,
                    "agent proof verification failed".to_string(),
                ));
            }
            let payload = serde_json::from_str::<ExecuteAuthorizationPayload>(&proof.payload)
                .map_err(|error| {
                    (
                        BrokerReason::ExecuteAuthorizationInvalid,
                        format!(
                            "agent proof payload is not valid execution authorization: {error}"
                        ),
                    )
                })?;
            if payload.agent.as_deref() != Some(proof.agent_name.as_str())
                || payload.worktree.is_none()
                || payload.branch.is_none()
                || payload.git_remote.is_none()
                || payload.commit.is_none()
            {
                return Err((
                    BrokerReason::ExecuteAuthorizationMismatch,
                    "agent execution authorization is missing verified context".to_string(),
                ));
            }
            validate_execute_payload(state, project, vault, cwd, env_names, command, &payload)?;
            validate_agent_execute_authority(state, &payload, proof)?;
            Ok(None)
        }
        ExecuteAuthorization::Internal { payload } => {
            validate_execute_payload(state, project, vault, cwd, env_names, command, payload)?;
            Ok(None)
        }
    }
}

fn validate_execute_payload(
    state: &mut BrokerState,
    project: &str,
    vault: &Path,
    cwd: &Path,
    env_names: &[String],
    command: &[String],
    payload: &ExecuteAuthorizationPayload,
) -> std::result::Result<(), (BrokerReason, String)> {
    if payload.expires_at <= Utc::now() {
        return Err((
            BrokerReason::ExecuteAuthorizationExpired,
            "execution authorization expired".to_string(),
        ));
    }
    if payload.project != project
        || !same_vault_path(&payload.vault, vault)
        || !same_vault_path(&payload.cwd, cwd)
        || payload.env_names != env_names
        || payload.command != command
    {
        return Err((
            BrokerReason::ExecuteAuthorizationMismatch,
            "execution authorization does not match requested command/env scope".to_string(),
        ));
    }
    if payload.nonce.trim().is_empty() {
        return Err((
            BrokerReason::ExecuteAuthorizationInvalid,
            "execution authorization nonce is empty".to_string(),
        ));
    }
    let nonce_key = format!("{}:{}", payload.project, payload.nonce);
    if state.execute_nonces.contains_key(&nonce_key) {
        return Err((
            BrokerReason::ExecuteAuthorizationReplayed,
            "execution authorization nonce was already used".to_string(),
        ));
    }
    state.execute_nonces.insert(nonce_key, payload.expires_at);
    Ok(())
}

fn validate_agent_execute_authority(
    state: &mut BrokerState,
    payload: &ExecuteAuthorizationPayload,
    proof: &AgentProof,
) -> std::result::Result<(), (BrokerReason, String)> {
    match payload.approval_source {
        ApprovalSource::PolicyAuto => validate_policy_auto_authority(state, payload),
        ApprovalSource::Grant | ApprovalSource::BrokerApproval => {
            validate_grant_authority(state, payload, proof)
        }
        ApprovalSource::AgentMediated => Err((
            BrokerReason::AgentSelfApprovalRejected,
            "agent-mediated approvals are no longer accepted; wait for dashboard or human approval"
                .to_string(),
        )),
        ApprovalSource::LocalTty | ApprovalSource::ManualAllow => Err((
            BrokerReason::HumanApprovalRequired,
            "agent executions cannot claim terminal or manual approval authority".to_string(),
        )),
        ApprovalSource::PolicyDeny => Err((
            BrokerReason::PolicyDenied,
            "Ward policy denied this execution".to_string(),
        )),
    }
}

fn validate_policy_auto_authority(
    state: &BrokerState,
    payload: &ExecuteAuthorizationPayload,
) -> std::result::Result<(), (BrokerReason, String)> {
    let access = access_from_execute_payload(payload);
    let resolved = registry::resolve_project(Some(&payload.project), Path::new("."))
        .map_err(|error| (BrokerReason::ProjectUnresolved, error.to_string()))?;
    if !same_vault_path(&resolved.vault, &payload.vault) {
        return Err((
            BrokerReason::ExecuteAuthorizationMismatch,
            "execution vault does not match the registered project vault".to_string(),
        ));
    }
    let config = config::read_project_config(&resolved.path)
        .map_err(|error| (BrokerReason::ProjectConfigUnavailable, error.to_string()))?;
    let findings =
        detection::preflight_findings(&access.command, &access.env, access.action.as_deref());
    let active_mode = active_session(state, &payload.project, &payload.vault)
        .ok()
        .and_then(|session| session.active_mode.as_ref());
    let evaluation = policy::evaluate_request(&config, &access, active_mode, findings);
    if evaluation.approval_mode == policy::ApprovalMode::Deny
        || evaluation.requires_prompt
        || !evaluation.denied_env.is_empty()
        || !access
            .env
            .iter()
            .all(|env_name| evaluation.approved_env.contains(env_name))
    {
        return Err((
            BrokerReason::ApprovalRequired,
            "broker policy evaluation requires human approval".to_string(),
        ));
    }
    Ok(())
}

fn validate_grant_authority(
    state: &mut BrokerState,
    payload: &ExecuteAuthorizationPayload,
    proof: &AgentProof,
) -> std::result::Result<(), (BrokerReason, String)> {
    let grant_id = payload.grant_id.ok_or_else(|| {
        (
            BrokerReason::ExecuteAuthorizationMismatch,
            "approved execution is missing a grant id".to_string(),
        )
    })?;
    match payload.approval_scope {
        ApprovalScope::Once | ApprovalScope::Session => {
            validate_live_broker_approval(state, payload, grant_id)
        }
        ApprovalScope::Branch | ApprovalScope::Always => {
            validate_durable_grant(payload, proof, grant_id)
        }
        ApprovalScope::Deny => Err((
            BrokerReason::PolicyDenied,
            "denied approvals cannot authorize execution".to_string(),
        )),
    }
}

fn validate_live_broker_approval(
    state: &mut BrokerState,
    payload: &ExecuteAuthorizationPayload,
    grant_id: uuid::Uuid,
) -> std::result::Result<(), (BrokerReason, String)> {
    cleanup_expired_approvals(state);
    let Some(record) = state.approvals.values_mut().find(|approval| {
        approval.grant_id == grant_id
            && approval.project == payload.project
            && same_vault_path(&approval.vault, &payload.vault)
    }) else {
        return Err((
            BrokerReason::ApprovalRequired,
            "no active broker approval matched this once/session execution".to_string(),
        ));
    };
    if record.scope != payload.approval_scope
        || record.access.agent != payload.agent
        || record.access.branch != payload.branch
        || record.access.action != payload.action
        || record.access.command != payload.command.join(" ")
        || record.access.env != payload.env_names
        || record.approval_receipt_hash != payload.approval_receipt_hash
        || record.uses_remaining.unwrap_or(1) == 0
    {
        return Err((
            BrokerReason::ExecuteAuthorizationMismatch,
            "active broker approval does not match requested command/env scope".to_string(),
        ));
    }
    if let Some(uses_remaining) = record.uses_remaining.as_mut() {
        *uses_remaining = uses_remaining.saturating_sub(1);
    }
    Ok(())
}

fn validate_durable_grant(
    payload: &ExecuteAuthorizationPayload,
    proof: &AgentProof,
    grant_id: uuid::Uuid,
) -> std::result::Result<(), (BrokerReason, String)> {
    let access = access_from_execute_payload(payload);
    let critical = detection::has_critical_findings(&detection::preflight_findings(
        &access.command,
        &access.env,
        access.action.as_deref(),
    ));
    let verified_context = verified_context_from_payload(payload, proof);
    let matched = match verified_context.as_ref() {
        Some(context) => grants::find_matching_grant_with_context(&access, context),
        None => grants::find_matching_grant(&access),
    }
    .map_err(|error| (BrokerReason::GrantLookupFailed, error.to_string()))?;
    let Some(grant) = matched else {
        return Err((
            BrokerReason::ApprovalRequired,
            "no durable grant matched this execution".to_string(),
        ));
    };
    let receipt_hash = grant
        .receipt
        .as_ref()
        .map(|receipt| receipt.payload_hash.clone());
    if grant.id != grant_id
        || grant.scope != payload.approval_scope
        || receipt_hash != payload.approval_receipt_hash
        || critical
    {
        return Err((
            BrokerReason::ExecuteAuthorizationMismatch,
            "durable grant does not match requested command/env scope".to_string(),
        ));
    }
    Ok(())
}

fn access_from_execute_payload(payload: &ExecuteAuthorizationPayload) -> AccessRequest {
    AccessRequest {
        project: payload.project.clone(),
        agent: payload.agent.clone(),
        branch: payload.branch.clone(),
        action: payload.action.clone(),
        command: payload.command.join(" "),
        env: payload.env_names.clone(),
    }
}

fn verified_context_from_payload(
    payload: &ExecuteAuthorizationPayload,
    proof: &AgentProof,
) -> Option<crate::context::VerifiedContext> {
    Some(crate::context::VerifiedContext {
        project: payload.project.clone(),
        agent: payload.agent.clone()?,
        agent_key_id: proof.agent_key_id.clone(),
        worktree: payload.worktree.clone()?,
        branch: payload.branch.clone()?,
        git_remote: payload.git_remote.clone()?,
        commit: payload.commit.clone()?,
        git_common_dir: None,
    })
}

fn validate_list_keys_authorization(
    state: &Arc<Mutex<BrokerState>>,
    project: &str,
    authorization: &ListKeysAuthorization,
) -> std::result::Result<(), (BrokerReason, String)> {
    match authorization {
        ListKeysAuthorization::Human { shell_pid } => {
            let mut state = state.lock().expect("broker state poisoned");
            cleanup_inactive_human_sessions(&mut state);
            validate_human_session(&state, project, *shell_pid)
                .map_err(|message| (BrokerReason::HumanSessionRequired, message))
        }
        ListKeysAuthorization::Internal { purpose } => {
            if purpose.trim().is_empty() {
                Err((
                    BrokerReason::ListKeysAuthorizationRequired,
                    "list keys authorization purpose is required".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn validate_signing_payload(
    project: &str,
    payload: &ApprovalReceiptPayload,
) -> std::result::Result<(), String> {
    if payload.schema_version != 1 {
        return Err("unsupported approval receipt payload schema".to_string());
    }
    if payload.project != project {
        return Err("approval receipt project does not match broker request".to_string());
    }
    if payload.command_hash.trim().is_empty() {
        return Err("approval receipt command hash is required".to_string());
    }
    if payload.approved_env.is_empty() && payload.requested_env.is_empty() {
        return Err("approval receipt env scope is required".to_string());
    }
    Ok(())
}

fn cleanup_expired_execute_nonces(state: &mut BrokerState) {
    let now = Utc::now();
    state
        .execute_nonces
        .retain(|_, expires_at| *expires_at > now);
}

fn cleanup_expired_approvals(state: &mut BrokerState) {
    let now = Utc::now();
    let active_sessions = state
        .sessions
        .iter()
        .filter(|(_, session)| session.expires_at > now)
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    state.approvals.retain(|_, approval| {
        approval
            .expires_at
            .is_none_or(|expires_at| expires_at > now)
            && approval.uses_remaining.unwrap_or(1) > 0
            && active_sessions.contains(&session_key(&approval.project, &approval.vault))
    });
}

#[cfg(test)]
static TEST_TRUSTED_CLIENT_ALLOWED: AtomicBool = AtomicBool::new(true);

#[cfg(test)]
fn require_trusted_client(_stream: &UnixStream) -> std::result::Result<(), String> {
    if TEST_TRUSTED_CLIENT_ALLOWED.load(Ordering::SeqCst) {
        Ok(())
    } else {
        Err("broker client process is not trusted".to_string())
    }
}

#[cfg(not(test))]
fn require_trusted_client(stream: &UnixStream) -> std::result::Result<(), String> {
    let peer_pid = peer_pid(stream).map_err(|error| error.to_string())?;
    let peer_path = peer_executable_path(peer_pid).map_err(|error| error.to_string())?;
    let current_path = std::env::current_exe()
        .map_err(|error| format!("failed to resolve broker executable: {error}"))?;
    let peer_path = peer_path
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize peer executable: {error}"))?;
    let current_path = current_path
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize broker executable: {error}"))?;
    if peer_path != current_path {
        return Err(format!(
            "broker client executable mismatch: {}",
            peer_path.display()
        ));
    }
    let peer_hash = executable_hash(&peer_path)
        .map_err(|error| format!("failed to hash peer executable: {error}"))?;
    let current_hash = executable_hash(&current_path)
        .map_err(|error| format!("failed to hash broker executable: {error}"))?;
    if peer_hash != current_hash {
        return Err("broker client executable hash mismatch".to_string());
    }
    Ok(())
}

#[cfg(all(not(test), target_os = "linux"))]
fn peer_pid(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes a libc::ucred into the provided buffer for a valid Unix socket fd.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to read peer credentials");
    }
    // SAFETY: getsockopt succeeded and initialized the credentials buffer.
    let credentials = unsafe { credentials.assume_init() };
    u32::try_from(credentials.pid).context("peer pid is invalid")
}

#[cfg(all(not(test), target_os = "macos"))]
fn peer_pid(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: getsockopt writes a pid_t into the provided buffer for a valid Unix socket fd.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to read peer pid");
    }
    u32::try_from(pid).context("peer pid is invalid")
}

#[cfg(all(not(test), not(any(target_os = "linux", target_os = "macos"))))]
fn peer_pid(_stream: &UnixStream) -> Result<u32> {
    anyhow::bail!("broker peer authentication is unsupported on this platform")
}

#[cfg(all(not(test), target_os = "linux"))]
fn peer_executable_path(pid: u32) -> Result<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).context("failed to resolve peer executable")
}

#[cfg(all(not(test), target_os = "macos"))]
fn peer_executable_path(pid: u32) -> Result<PathBuf> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most the provided buffer length for the target pid.
    let len = unsafe {
        libc::proc_pidpath(
            i32::try_from(pid).context("peer pid is too large")?,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if len <= 0 {
        return Err(std::io::Error::last_os_error()).context("failed to resolve peer executable");
    }
    buffer.truncate(len as usize);
    Ok(PathBuf::from(String::from_utf8_lossy(&buffer).into_owned()))
}

#[cfg(all(not(test), not(any(target_os = "linux", target_os = "macos"))))]
fn peer_executable_path(_pid: u32) -> Result<PathBuf> {
    anyhow::bail!("broker peer authentication is unsupported on this platform")
}

#[cfg(not(test))]
fn executable_hash(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Sha256::digest(bytes).to_vec())
}
