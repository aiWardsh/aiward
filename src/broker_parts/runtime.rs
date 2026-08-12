pub fn run_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new("run"), "broker run directory")
        .expect("broker run directory should stay inside Ward home")
}

pub fn socket_path() -> PathBuf {
    run_dir().join("ward.sock")
}

pub fn pid_path() -> PathBuf {
    run_dir().join("broker.pid")
}

pub fn peer_auth_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos LOCAL_PEERPID"
    } else if cfg!(target_os = "linux") {
        "linux SO_PEERCRED"
    } else {
        "unsupported"
    }
}

pub fn privileged_rpc_peer_auth_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux"))
}

#[cfg(test)]
pub fn ensure_running() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
pub fn ensure_running() -> Result<()> {
    if crate::global_disable::is_disabled() {
        anyhow::bail!("Ward is globally disabled; run `ward on` to re-enable it");
    }
    match ping_status() {
        Ok(status) if broker_is_current(&status) => return Ok(()),
        Ok(status) if status.running => {
            eprintln!(
                "Ward broker restart: running broker version '{}' does not match CLI version '{}'.",
                status.version, BROKER_VERSION
            );
            let _ = crate::unlock::clear_run_unlocks();
            stop_existing_broker(&status);
            cleanup_stale_files()?;
        }
        _ => {
            if read_pid().is_ok() || socket_path().exists() {
                eprintln!("Ward broker restart: removing stale broker runtime files.");
                let _ = crate::unlock::clear_run_unlocks();
            }
            cleanup_stale_files()?;
        }
    }
    fs_util::ensure_private_dir(&run_dir())?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        return Ok(());
    }
    let mut broker = Command::new(exe);
    broker
        .arg("__broker")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    broker.stderr(Stdio::null());
    broker.spawn().context("failed to start Ward broker")?;
    wait_until_ready(StdDuration::from_secs(2))
}

#[cfg(not(test))]
fn wait_until_ready(timeout: StdDuration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if ping().is_ok() {
            return Ok(());
        }
        thread::sleep(StdDuration::from_millis(25));
    }
    anyhow::bail!("Ward broker did not become ready");
}

#[cfg(not(test))]
fn broker_is_current(status: &BrokerStatus) -> bool {
    status.running && status.version == BROKER_VERSION
}

#[cfg(not(test))]
fn stop_existing_broker(status: &BrokerStatus) {
    let pid = status.pid.or_else(|| read_pid().ok());
    if send_simple(BrokerRequest::Stop).is_ok() {
        if let Some(pid) = pid {
            let deadline = Instant::now() + StdDuration::from_secs(2);
            while Instant::now() < deadline {
                if !process_exists(pid) {
                    return;
                }
                thread::sleep(StdDuration::from_millis(50));
            }
        } else {
            return;
        }
    }
    if let Some(pid) = pid {
        terminate_broker_process(pid);
    }
}

#[cfg(not(test))]
fn terminate_broker_process(pid: u32) {
    if !is_broker_process(pid) {
        return;
    }
    #[cfg(unix)]
    {
        // SAFETY: target pid is selected by command-line inspection.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + StdDuration::from_secs(1);
        while Instant::now() < deadline {
            if !process_exists(pid) {
                return;
            }
            thread::sleep(StdDuration::from_millis(50));
        }
        // SAFETY: best-effort hard stop for the same broker process if SIGTERM was ignored.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
}

#[cfg(not(test))]
fn is_broker_process(pid: u32) -> bool {
    command_line(pid)
        .map(|line| line.contains("__broker") && line.contains("ward"))
        .unwrap_or(false)
}

#[cfg(not(test))]
fn command_line(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(not(test))]
fn broker_process_supported(exe: &Path) -> bool {
    #[cfg(coverage)]
    if std::env::var_os("WARD_COVERAGE_ASSUME_BROKER_EXE").is_some() {
        return true;
    }
    exe.file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "ward")
}

#[cfg(test)]
fn broker_process_supported(_exe: &Path) -> bool {
    false
}

#[cfg(test)]
pub fn unlock_project(
    _project: &str,
    _vault: &Path,
    _passphrase: &str,
    _ttl: Duration,
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub fn unlock_project_with_mode(
    _project: &str,
    _vault: &Path,
    _passphrase: &str,
    _ttl: Duration,
    _mode: Option<String>,
) -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
pub fn unlock_project(project: &str, vault: &Path, passphrase: &str, ttl: Duration) -> Result<()> {
    unlock_project_with_mode(project, vault, passphrase, ttl, None)
}

#[cfg(not(test))]
pub fn unlock_project_with_mode(
    project: &str,
    vault: &Path,
    passphrase: &str,
    ttl: Duration,
    mode: Option<String>,
) -> Result<()> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    let ttl_seconds = ttl.num_seconds();
    match send_simple(BrokerRequest::Unlock {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        passphrase: passphrase.to_string(),
        ttl_seconds,
        mode,
    })? {
        BrokerResponse::Ok => Ok(()),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(test)]
pub fn sign_receipt(
    _project: &str,
    _vault: &Path,
    _payload: ApprovalReceiptPayload,
) -> Result<ApprovalReceipt> {
    anyhow::bail!("broker signing is disabled in unit tests")
}

#[cfg(not(test))]
pub fn sign_receipt(
    project: &str,
    vault: &Path,
    payload: ApprovalReceiptPayload,
) -> Result<ApprovalReceipt> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::Sign {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        payload,
    })? {
        BrokerResponse::Signed { receipt } => Ok(receipt),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn execute(
    project: &str,
    vault: &Path,
    cwd: &Path,
    env_names: Vec<String>,
    command: Vec<String>,
    authorization: ExecuteAuthorization,
) -> Result<RunCommandOutcome> {
    ensure_running()
        .map_err(|error| BrokerError::new(BrokerReason::BrokerUnavailable, error.to_string()))?;
    let exe = std::env::current_exe()
        .map_err(|error| BrokerError::new(BrokerReason::InternalFailure, error.to_string()))?;
    if !broker_process_supported(&exe) {
        return Err(BrokerError::new(
            BrokerReason::BrokerUnavailable,
            "Ward broker is unavailable from this executable",
        )
        .into());
    }
    let mut stream = connect()
        .map_err(|error| BrokerError::new(BrokerReason::BrokerUnavailable, error.to_string()))?;
    let inherited_env = inherited_execution_env();
    let request = BrokerRequest::Execute {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        cwd: cwd.to_path_buf(),
        env_names,
        command,
        inherited_env,
        authorization: Some(authorization),
    };
    write_request(&mut stream, &request)
        .map_err(|error| BrokerError::new(BrokerReason::ProtocolFailure, error.to_string()))?;
    let mut reader = BufReader::new(stream);
    loop {
        let response = read_response(&mut reader)
            .map_err(|error| BrokerError::new(BrokerReason::ProtocolFailure, error.to_string()))?;
        match response {
            BrokerResponse::Output { stream, line } if stream == "stderr" => eprintln!("{line}"),
            BrokerResponse::Output { line, .. } => println!("{line}"),
            BrokerResponse::Finished { outcome } => return Ok(outcome),
            BrokerResponse::Error { reason, message } => {
                return Err(BrokerError::new(reason, message).into());
            }
            other => {
                return Err(BrokerError::new(
                    BrokerReason::ProtocolFailure,
                    format!("unexpected broker response: {other:?}"),
                )
                .into())
            }
        }
    }
}

fn inherited_execution_env() -> BTreeMap<String, String> {
    ["PATH", "HOME", "SHELL", "USER", "TMPDIR"]
        .into_iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| (name.to_string(), value))
        })
        .collect()
}

pub fn status() -> Result<BrokerStatus> {
    match ping_status() {
        Ok(status) => Ok(status),
        Err(_) => Ok(BrokerStatus {
            running: false,
            socket: socket_path(),
            pid: read_pid().ok(),
            ppid: None,
            version: BROKER_VERSION.to_string(),
            started_at: None,
            sessions: Vec::new(),
            approval_count: 0,
        }),
    }
}

fn ping_status() -> Result<BrokerStatus> {
    match send_simple(BrokerRequest::Ping)? {
        BrokerResponse::Status { status } => Ok(status),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn active_session_expiry(project: &str, vault: &Path) -> Result<Option<DateTime<Utc>>> {
    let status = status()?;
    Ok(matching_session_expiry(&status, project, vault, Utc::now()))
}

pub fn active_session_fingerprint(project: &str, vault: &Path) -> Result<Option<String>> {
    let status = status()?;
    Ok(status
        .sessions
        .iter()
        .find(|session| session.project == project && same_vault_path(&session.vault, vault))
        .and_then(|session| session.vault_fingerprint.clone()))
}

fn matching_session_expiry(
    status: &BrokerStatus,
    project: &str,
    vault: &Path,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !status.running {
        return None;
    }
    status
        .sessions
        .iter()
        .filter(|session| {
            session.project == project
                && session.expires_at > now
                && same_vault_path(&session.vault, vault)
        })
        .map(|session| session.expires_at)
        .max()
}

fn same_vault_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

pub fn stop() -> Result<()> {
    match send_simple(BrokerRequest::Stop) {
        Ok(BrokerResponse::Ok) | Err(_) => {
            cleanup_stale_files()?;
            Ok(())
        }
        Ok(BrokerResponse::Error { message, .. }) => anyhow::bail!("{message}"),
        Ok(other) => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn lock_project(project: &str, vault: &Path) -> Result<BrokerProjectLockStatus> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::LockProject {
        project: project.to_string(),
        vault: vault.to_path_buf(),
    })? {
        BrokerResponse::ProjectLock { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn approve_pending_request(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    channel: ApprovalChannel,
) -> Result<BrokerApprovalStatus> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::ApproveRequest {
        request_id,
        scope,
        confirm_critical,
        channel,
    })? {
        BrokerResponse::Approval { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn deny_pending_request(
    request_id: uuid::Uuid,
    channel: ApprovalChannel,
) -> Result<BrokerApprovalStatus> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::DenyRequest {
        request_id,
        channel,
    })? {
        BrokerResponse::Approval { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn list_approvals(project: Option<String>) -> Result<Vec<BrokerApprovalStatus>> {
    ensure_running()?;
    match send_simple(BrokerRequest::ListApprovals { project })? {
        BrokerResponse::Approvals { approvals } => Ok(approvals),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn remove_project_from_active_session(
    project: &str,
    vault: &Path,
    export_path: PathBuf,
    restore_env: bool,
) -> Result<project_teardown::ProjectTeardownOutcome> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::RemoveProject {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        export_path,
        restore_env,
    })? {
        BrokerResponse::ProjectTeardown { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn setup_project_with_active_passphrase(
    source_project: &str,
    source_vault: &Path,
    target_path: &Path,
    project: Option<String>,
) -> Result<BrokerProjectSetupStatus> {
    ensure_running()?;
    match send_simple(BrokerRequest::SetupProject {
        source_project: source_project.to_string(),
        source_vault: source_vault.to_path_buf(),
        target_path: target_path.to_path_buf(),
        project,
    })? {
        BrokerResponse::ProjectSetup { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn snapshot_project_from_active_session(
    project: &str,
    vault: &Path,
) -> Result<BrokerProjectSnapshotStatus> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::SnapshotProject {
        project: project.to_string(),
        vault: vault.to_path_buf(),
    })? {
        BrokerResponse::ProjectSnapshot { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn provision_project_from_active_session(
    request: ProjectProvisionRequest,
) -> Result<BrokerProjectProvisionStatus> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::ProvisionProject {
        source_project: request.source_project,
        source_vault: request.source_vault,
        target_path: request.target_path,
        project: request.project,
        profiles: request.profiles,
        env_names: request.env_names,
        agents: request.agents,
    })? {
        BrokerResponse::ProjectProvision { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(test)]
pub fn list_vault_keys_for_human(
    _project: &str,
    _vault: &Path,
    _shell_pid: u32,
) -> Result<Vec<String>> {
    Ok(Vec::new())
}

#[cfg(not(test))]
pub fn list_vault_keys_for_human(
    project: &str,
    vault: &Path,
    shell_pid: u32,
) -> Result<Vec<String>> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::ListKeys {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        authorization: ListKeysAuthorization::Human { shell_pid },
    })? {
        BrokerResponse::Keys { names } => Ok(names),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(test)]
pub fn list_vault_keys_from_active_session(_project: &str, _vault: &Path) -> Result<Vec<String>> {
    Ok(Vec::new())
}

#[cfg(not(test))]
pub fn list_vault_keys_from_active_session(project: &str, vault: &Path) -> Result<Vec<String>> {
    let status = ping_status().context("Ward broker is not running")?;
    if !broker_is_current(&status) {
        anyhow::bail!("Ward broker is not current");
    }
    if matching_session_expiry(&status, project, vault, Utc::now()).is_none() {
        anyhow::bail!("missing broker unlock session");
    }
    match send_simple(BrokerRequest::ListKeys {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        authorization: ListKeysAuthorization::Internal {
            purpose: "dashboard".to_string(),
        },
    })? {
        BrokerResponse::Keys { names } => Ok(names),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(test)]
pub fn register_human_session(
    _shell_pid: u32,
    _session_token: &str,
    _ttl_seconds: i64,
    _projects: &[String],
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub fn deregister_human_session(_shell_pid: u32, _session_token: &str) -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
pub fn register_human_session(
    shell_pid: u32,
    session_token: &str,
    ttl_seconds: i64,
    projects: &[String],
) -> Result<()> {
    match send_simple(BrokerRequest::RegisterHumanSession {
        shell_pid,
        session_token: session_token.to_string(),
        ttl_seconds,
        projects: projects.to_vec(),
    })? {
        BrokerResponse::Ok => Ok(()),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(not(test))]
pub fn deregister_human_session(shell_pid: u32, session_token: &str) -> Result<()> {
    match send_simple(BrokerRequest::DeregisterHumanSession {
        shell_pid,
        session_token: session_token.to_string(),
    }) {
        Ok(BrokerResponse::Ok) | Err(_) => Ok(()),
        Ok(BrokerResponse::Error { message, .. }) => anyhow::bail!("{message}"),
        Ok(other) => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}
