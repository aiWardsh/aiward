fn register_human_command(
    state: &mut BrokerState,
    shell_pid: u32,
    project: String,
    cancellation: Arc<AtomicBool>,
    child_pid: Arc<AtomicU32>,
) {
    let command_id = state.next_human_command_id;
    state.next_human_command_id = state.next_human_command_id.saturating_add(1);
    state.human_commands.entry(shell_pid).or_default().insert(
        command_id,
        ActiveHumanCommand {
            project,
            cancellation,
            child_pid,
        },
    );
}

fn unregister_human_command(
    state: &mut BrokerState,
    shell_pid: u32,
    cancellation: &Arc<AtomicBool>,
) {
    let Some(commands) = state.human_commands.get_mut(&shell_pid) else {
        return;
    };
    let remove_id = commands.iter().find_map(|(id, active)| {
        if Arc::ptr_eq(&active.cancellation, cancellation) {
            Some(*id)
        } else {
            None
        }
    });
    if let Some(id) = remove_id {
        commands.remove(&id);
    }
    if commands.is_empty() {
        state.human_commands.remove(&shell_pid);
    }
}

fn cancel_human_commands(state: &mut BrokerState, shell_pid: u32) {
    if let Some(commands) = state.human_commands.remove(&shell_pid) {
        for command in commands.values() {
            command.cancellation.store(true, Ordering::SeqCst);
            let child_pid = command.child_pid.load(Ordering::SeqCst);
            if child_pid != 0 {
                terminate_process_group(child_pid);
            }
        }
    }
}

fn cancel_project_human_commands(state: &mut BrokerState, project: &str) -> usize {
    let mut cancelled = 0;
    let shell_pids = state.human_commands.keys().copied().collect::<Vec<_>>();
    let mut empty_shells = Vec::new();
    for shell_pid in shell_pids {
        let Some(commands) = state.human_commands.get_mut(&shell_pid) else {
            continue;
        };
        let command_ids = commands
            .iter()
            .filter_map(|(id, command)| (command.project == project).then_some(*id))
            .collect::<Vec<_>>();
        for command_id in command_ids {
            if let Some(command) = commands.remove(&command_id) {
                cancelled += 1;
                command.cancellation.store(true, Ordering::SeqCst);
                let child_pid = command.child_pid.load(Ordering::SeqCst);
                if child_pid != 0 {
                    terminate_process_group(child_pid);
                }
            }
        }
        if commands.is_empty() {
            empty_shells.push(shell_pid);
        }
    }
    for shell_pid in empty_shells {
        state.human_commands.remove(&shell_pid);
    }
    cancelled
}

fn cancel_all_human_commands(state: &mut BrokerState) {
    let shell_pids = state.human_commands.keys().copied().collect::<Vec<_>>();
    for shell_pid in shell_pids {
        cancel_human_commands(state, shell_pid);
    }
}

fn cleanup_inactive_human_sessions(state: &mut BrokerState) {
    let now = Utc::now();
    let stale = state
        .human_sessions
        .iter()
        .filter_map(|(shell_pid, entry)| {
            if entry.expires_at <= now || !process_exists(*shell_pid) {
                Some(*shell_pid)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for shell_pid in stale {
        state.human_sessions.remove(&shell_pid);
        cancel_human_commands(state, shell_pid);
    }
}

fn status_from_state(state: &BrokerState) -> BrokerStatus {
    let now = Utc::now();
    BrokerStatus {
        running: true,
        socket: socket_path(),
        pid: Some(std::process::id()),
        ppid: current_parent_pid(),
        version: BROKER_VERSION.to_string(),
        started_at: Some(state.started_at),
        sessions: state
            .sessions
            .values()
            .filter(|session| session.expires_at > now)
            .map(|session| BrokerSessionStatus {
                project: session.project.clone(),
                vault: session.vault.clone(),
                expires_at: session.expires_at,
                active_mode: session.active_mode.as_ref().map(|m| m.config.name.clone()),
                env_count: session.env.len(),
                subsession_count: project_subsession_count(state, &session.project),
                vault_fingerprint: Some(session.vault_fingerprint.clone()),
                workspace_root: session.workspace_root.clone(),
                workspace_name: session.workspace_name.clone(),
                app_slug: session.app_slug.clone(),
                state: "active".to_string(),
            })
            .collect(),
        approval_count: state.approvals.len(),
    }
}

fn current_parent_pid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: getppid has no preconditions and does not mutate memory.
        let ppid = unsafe { libc::getppid() };
        (ppid > 0).then_some(ppid as u32)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn session_key(project: &str, vault: &Path) -> String {
    format!("{}|{}", project, vault.display())
}

fn project_subsession_count(state: &BrokerState, project: &str) -> usize {
    state
        .human_sessions
        .values()
        .filter(|entry| entry.expires_at > Utc::now() && entry.projects.contains(project))
        .count()
}

fn build_project_session(
    project: &str,
    vault: &Path,
    passphrase: &str,
    ttl_seconds: i64,
    mode: Option<&str>,
) -> Result<BrokerSession> {
    let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
    build_project_session_with_expiry(project, vault, passphrase, expires_at, mode)
}

fn build_project_session_with_expiry(
    project: &str,
    vault: &Path,
    passphrase: &str,
    expires_at: DateTime<Utc>,
    mode: Option<&str>,
) -> Result<BrokerSession> {
    let plaintext = vault::decrypt_vault_file(vault, passphrase)
        .with_context(|| format!("failed to decrypt {}", vault.display()))?;
    let env = env_file::parse_env_map(&plaintext)
        .with_context(|| format!("failed to parse {}", vault.display()))?;
    let signing_key = {
        let ciphertext =
            approval_receipts::session_signing_key_ciphertext(project, passphrase, passphrase)?;
        approval_receipts::decrypt_session_signing_key(&ciphertext, passphrase)?
    };
    let active_mode = load_active_mode(project, passphrase, expires_at, mode)?;
    let (workspace_root, workspace_name, app_slug) = session_workspace_metadata(project);
    Ok(BrokerSession {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        env,
        vault_fingerprint: vault_fingerprint(vault)?,
        signing_key,
        passphrase: passphrase.to_string(),
        expires_at,
        active_mode,
        workspace_root,
        workspace_name,
        app_slug,
    })
}

fn load_active_mode(
    project: &str,
    passphrase: &str,
    expires_at: DateTime<Utc>,
    mode: Option<&str>,
) -> Result<Option<modes::ActiveMode>> {
    let Some(mode_name) = mode else {
        return Ok(None);
    };
    let mode_configs = modes::load_broker_modes(project, passphrase).map_err(|error| {
        anyhow::anyhow!("could not load modes vault: {error} — run `ward modes push` first")
    })?;
    let config = modes::find_mode(&mode_configs, mode_name)
        .with_context(|| format!("mode '{mode_name}' not found — run `ward modes push` first"))?;
    Ok(Some(modes::ActiveMode {
        config: config.clone(),
        expires_at,
    }))
}

fn session_workspace_metadata(project: &str) -> (Option<PathBuf>, Option<String>, Option<String>) {
    registry::list_projects()
        .ok()
        .and_then(|registry| registry.projects.get(project).cloned())
        .map(|registered| {
            (
                registered.workspace_root,
                registered.workspace_name,
                registered.app_slug,
            )
        })
        .unwrap_or((None, None, None))
}

fn vault_fingerprint(vault: &Path) -> Result<String> {
    let vault = fs_util::resolve_existing_external_file(vault, "vault fingerprint")?;
    let bytes = fs::read(&vault).with_context(|| format!("failed to read {}", vault.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) checks process visibility without sending a signal.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

fn terminate_process_group(pid: u32) {
    #[cfg(unix)]
    {
        let pgid = pid as libc::pid_t;
        // SAFETY: sends SIGTERM to the process group created for a human-mode child.
        let _ = unsafe { libc::kill(-pgid, libc::SIGTERM) };
        thread::sleep(StdDuration::from_millis(100));
        // SAFETY: best-effort hard stop if the process group ignored SIGTERM.
        let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn monitor_client_disconnect(mut stream: UnixStream, cancellation: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    cancellation.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    cancellation.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });
}

fn install_shutdown_handler(state: Arc<Mutex<BrokerState>>) {
    #[cfg(test)]
    {
        let _ = state;
    }
    #[cfg(not(test))]
    {
        if let Err(error) = ctrlc::set_handler(move || {
            cancel_all_human_commands(&mut state.lock().expect("broker state poisoned"));
            let _ = cleanup_stale_files();
            std::process::exit(0);
        }) {
            eprintln!("ward broker warning: failed to install shutdown handler: {error}");
        }
    }
}

fn lock_project_in_state(
    state: &Arc<Mutex<BrokerState>>,
    project: &str,
    vault: &Path,
) -> Result<BrokerProjectLockStatus> {
    let key = session_key(project, vault);
    let (broker_session_removed, cancelled_human_commands) = {
        let mut state = state.lock().expect("broker state poisoned");
        let removed = state.sessions.remove(&key).is_some();
        state
            .approvals
            .retain(|_, approval| !approval.project.eq(project));
        let cancelled = cancel_project_human_commands(&mut state, project);
        detach_project_human_sessions(&mut state, project);
        (removed, cancelled)
    };
    let revoked_session_grants = grants::revoke_project_session_grants(project)?;
    let cleared_unlock_sessions = unlock::clear_project_unlocks(project)?;
    Ok(BrokerProjectLockStatus {
        project: project.to_string(),
        broker_session_removed,
        revoked_session_grants,
        cleared_unlock_sessions,
        cancelled_human_commands,
    })
}

fn discard_project_runtime_after_teardown(
    state: &Arc<Mutex<BrokerState>>,
    project: &str,
    vault: &Path,
) {
    let mut state = state.lock().expect("broker state poisoned");
    state.sessions.remove(&session_key(project, vault));
    state
        .approvals
        .retain(|_, approval| !approval.project.eq(project));
    cancel_project_human_commands(&mut state, project);
    detach_project_human_sessions(&mut state, project);
}

fn detach_project_human_sessions(state: &mut BrokerState, project: &str) {
    state.human_sessions.retain(|_, entry| {
        entry.projects.remove(project);
        !entry.projects.is_empty()
    });
}
