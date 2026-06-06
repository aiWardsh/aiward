use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
    thread,
};
#[cfg(not(test))]
use std::{
    os::unix::io::AsRawFd,
    process::{Command, Stdio},
    time::{Duration as StdDuration, Instant},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
#[cfg(not(test))]
use sha2::{Digest, Sha256};

use crate::{
    agents::{self, AgentProof},
    approval_receipts::{self, ApprovalReceipt, ApprovalReceiptPayload},
    approvals::{ApprovalScope, ApprovalSource},
    config, detection, env_file, fs_util, logs, modes, process_util, project_store, recovery,
    registry,
    runner::{self, RunCommandOutcome, RunCommandRequest},
    vault,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerStatus {
    pub running: bool,
    pub socket: PathBuf,
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(default)]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    pub sessions: Vec<BrokerSessionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerSessionStatus {
    pub project: String,
    pub vault: PathBuf,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerProjectSetupStatus {
    pub project: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub created: bool,
    pub registered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerProjectSnapshotStatus {
    pub store: project_store::ProjectStoreSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerProjectProvisionStatus {
    pub project: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub env_names: Vec<String>,
    pub profiles: Vec<String>,
    pub agents: Vec<String>,
    pub store: project_store::ProjectStoreSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteAuthorizationPayload {
    pub project: String,
    pub vault: PathBuf,
    pub cwd: PathBuf,
    pub env_names: Vec<String>,
    pub command: Vec<String>,
    pub agent: Option<String>,
    pub worktree: Option<PathBuf>,
    pub branch: Option<String>,
    pub git_remote: Option<String>,
    pub commit: Option<String>,
    pub action: Option<String>,
    pub grant_id: Option<uuid::Uuid>,
    pub approval_receipt_hash: Option<String>,
    pub approval_scope: ApprovalScope,
    pub approval_source: ApprovalSource,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
}

impl ExecuteAuthorizationPayload {
    pub fn new(
        project: String,
        vault: PathBuf,
        cwd: PathBuf,
        env_names: Vec<String>,
        command: Vec<String>,
        approval_scope: ApprovalScope,
        approval_source: ApprovalSource,
    ) -> Self {
        Self {
            project,
            vault,
            cwd,
            env_names,
            command,
            agent: None,
            worktree: None,
            branch: None,
            git_remote: None,
            commit: None,
            action: None,
            grant_id: None,
            approval_receipt_hash: None,
            approval_scope,
            approval_source,
            expires_at: Utc::now() + Duration::seconds(60),
            nonce: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecuteAuthorization {
    Agent {
        proof: AgentProof,
    },
    Human {
        shell_pid: u32,
    },
    Internal {
        payload: Box<ExecuteAuthorizationPayload>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListKeysAuthorization {
    Human { shell_pid: u32 },
    Internal { purpose: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrokerRequest {
    Ping,
    Stop,
    Unlock {
        project: String,
        vault: PathBuf,
        passphrase: String,
        ttl_seconds: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
    },
    Sign {
        project: String,
        vault: PathBuf,
        payload: ApprovalReceiptPayload,
    },
    RegisterHumanSession {
        shell_pid: u32,
        session_token: String,
        ttl_seconds: i64,
    },
    DeregisterHumanSession {
        shell_pid: u32,
        session_token: String,
    },
    Execute {
        project: String,
        vault: PathBuf,
        cwd: PathBuf,
        env_names: Vec<String>,
        command: Vec<String>,
        inherited_env: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authorization: Option<ExecuteAuthorization>,
    },
    ListKeys {
        project: String,
        vault: PathBuf,
        authorization: ListKeysAuthorization,
    },
    SetupProject {
        source_project: String,
        source_vault: PathBuf,
        target_path: PathBuf,
        project: Option<String>,
    },
    SnapshotProject {
        project: String,
        vault: PathBuf,
    },
    ProvisionProject {
        source_project: String,
        source_vault: PathBuf,
        target_path: PathBuf,
        project: String,
        profiles: Vec<String>,
        env_names: Vec<String>,
        agents: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrokerResponse {
    Ok,
    Status {
        status: BrokerStatus,
    },
    Signed {
        receipt: ApprovalReceipt,
    },
    Output {
        stream: String,
        line: String,
    },
    Finished {
        outcome: RunCommandOutcome,
    },
    Keys {
        names: Vec<String>,
    },
    ProjectSetup {
        status: BrokerProjectSetupStatus,
    },
    ProjectSnapshot {
        status: BrokerProjectSnapshotStatus,
    },
    ProjectProvision {
        status: BrokerProjectProvisionStatus,
    },
    Error {
        reason: String,
        message: String,
    },
}

#[derive(Debug, Clone)]
pub struct BrokerError {
    reason: String,
    message: String,
}

impl BrokerError {
    fn new(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason, self.message)
    }
}

impl std::error::Error for BrokerError {}

struct HumanSessionEntry {
    session_token: String,
    expires_at: DateTime<Utc>,
}

struct ActiveHumanCommand {
    cancellation: Arc<AtomicBool>,
    child_pid: Arc<AtomicU32>,
}

struct BrokerState {
    sessions: BTreeMap<String, BrokerSession>,
    human_sessions: HashMap<u32, HumanSessionEntry>,
    human_commands: HashMap<u32, BTreeMap<u64, ActiveHumanCommand>>,
    execute_nonces: HashMap<String, DateTime<Utc>>,
    next_human_command_id: u64,
    started_at: DateTime<Utc>,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            human_sessions: HashMap::new(),
            human_commands: HashMap::new(),
            execute_nonces: HashMap::new(),
            next_human_command_id: 0,
            started_at: Utc::now(),
        }
    }
}

const BROKER_VERSION: &str = env!("CARGO_PKG_VERSION");

struct BrokerSession {
    project: String,
    vault: PathBuf,
    passphrase: String,
    /// Ephemeral key used to re-encrypt the vault on disk while the session is active.
    /// If Some, the vault file is encrypted with this key (not passphrase) until lock.
    session_key: Option<String>,
    expires_at: DateTime<Utc>,
    active_mode: Option<modes::ActiveMode>,
}

pub fn run_dir() -> PathBuf {
    logs::ward_home().join("run")
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
    Command::new(exe)
        .arg("__broker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start Ward broker")?;
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
                if !process_util::process_exists(pid) {
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
    process_util::terminate_if_matches(pid, StdDuration::from_secs(1), is_broker_process);
}

#[cfg(not(test))]
fn is_broker_process(pid: u32) -> bool {
    process_util::command_line(pid)
        .map(|line| line.contains("__broker") && line.contains("ward"))
        .unwrap_or(false)
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
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    let mut stream = connect()?;
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
    write_request(&mut stream, &request)?;
    let mut reader = BufReader::new(stream);
    loop {
        let response = read_response(&mut reader)?;
        match response {
            BrokerResponse::Output { stream, line } if stream == "stderr" => eprintln!("{line}"),
            BrokerResponse::Output { line, .. } => println!("{line}"),
            BrokerResponse::Finished { outcome } => return Ok(outcome),
            BrokerResponse::Error { reason, message } => {
                return Err(BrokerError::new(reason, message).into());
            }
            other => anyhow::bail!("unexpected broker response: {other:?}"),
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
    source_project: &str,
    source_vault: &Path,
    target_path: &Path,
    project: String,
    profiles: Vec<String>,
    env_names: Vec<String>,
    agents: Vec<String>,
) -> Result<BrokerProjectProvisionStatus> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::ProvisionProject {
        source_project: source_project.to_string(),
        source_vault: source_vault.to_path_buf(),
        target_path: target_path.to_path_buf(),
        project,
        profiles,
        env_names,
        agents,
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
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub fn deregister_human_session(_shell_pid: u32, _session_token: &str) -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
pub fn register_human_session(shell_pid: u32, session_token: &str, ttl_seconds: i64) -> Result<()> {
    match send_simple(BrokerRequest::RegisterHumanSession {
        shell_pid,
        session_token: session_token.to_string(),
        ttl_seconds,
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
        let stream = stream.context("failed to accept broker client")?;
        let state = Arc::clone(&state);
        thread::spawn(move || {
            let stop = handle_client(stream, state).unwrap_or(false);
            if stop {
                let _ = cleanup_stale_files();
                std::process::exit(0);
            }
        });
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream, state: Arc<Mutex<BrokerState>>) -> Result<bool> {
    let request = {
        let mut reader = BufReader::new(stream.try_clone()?);
        read_request(&mut reader)?
    };
    {
        let mut broker_state = state.lock().expect("broker state poisoned");
        cleanup_inactive_human_sessions(&mut broker_state);
        cleanup_expired_execute_nonces(&mut broker_state);
    }
    match request {
        BrokerRequest::Ping => {
            let status = status_from_state(&state.lock().expect("broker state poisoned"));
            write_response(&mut stream, &BrokerResponse::Status { status })?;
        }
        BrokerRequest::Stop => {
            cancel_all_human_commands(&mut state.lock().expect("broker state poisoned"));
            if let Err(error) = restore_all_sessions(&state) {
                let response = broker_error(
                    "restore_failed",
                    format!("failed to restore vaults before broker shutdown: {error}"),
                );
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            write_response(&mut stream, &BrokerResponse::Ok)?;
            return Ok(true);
        }
        BrokerRequest::Unlock {
            project,
            vault,
            passphrase,
            ttl_seconds,
            mode,
        } => {
            // If the vault is currently session-encrypted (active session exists),
            // restore it to passphrase-encrypted form before attempting to decrypt.
            {
                let state = state.lock().expect("broker state poisoned");
                if let Some(session) = state.sessions.get(&session_key(&project, &vault)) {
                    if let Some(ref ek) = session.session_key {
                        if let Err(error) =
                            restore_vault_from_session(&vault, ek, &session.passphrase)
                        {
                            let response = broker_error(
                                "restore_failed",
                                format!("failed to restore active session before unlock: {error}"),
                            );
                            write_response(&mut stream, &response)?;
                            return Ok(false);
                        }
                    }
                }
            }
            match vault::decrypt_vault_file(&vault, &passphrase).and_then(|plaintext| {
                approval_receipts::ensure_project_key(&project, &passphrase).map(|_| plaintext)
            }) {
                Ok(plaintext) => {
                    let expires_at = Utc::now() + Duration::seconds(ttl_seconds);

                    // Re-encrypt vault with ephemeral key so passphrase-encrypted
                    // form does not exist on disk while the session is active.
                    let ephemeral_key = generate_session_key();
                    let ephemeral_key = match vault::encrypt_env(&plaintext, &ephemeral_key) {
                        Ok(envelope) => match vault::write_vault(&vault, &envelope) {
                            Ok(()) => Some(ephemeral_key),
                            Err(_) => None,
                        },
                        Err(_) => None,
                    };
                    let session_id = session_key(&project, &vault);
                    state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .insert(
                            session_id.clone(),
                            BrokerSession {
                                project: project.clone(),
                                vault: vault.clone(),
                                passphrase: passphrase.clone(),
                                session_key: ephemeral_key.clone(),
                                expires_at,
                                active_mode: None,
                            },
                        );

                    // Load active mode config from broker vault if requested
                    let active_mode = if let Some(mode_name) = &mode {
                        match modes::load_broker_modes(&project, &passphrase) {
                            Ok(mode_configs) => match modes::find_mode(&mode_configs, mode_name) {
                                Some(config) => Some(modes::ActiveMode {
                                    config: config.clone(),
                                    expires_at,
                                }),
                                None => {
                                    if let Some(ref ek) = ephemeral_key {
                                        if let Err(error) =
                                            restore_vault_from_session(&vault, ek, &passphrase)
                                        {
                                            let response = broker_error(
                                                "restore_failed",
                                                format!(
                                                    "failed to restore vault after mode lookup failure: {error}"
                                                ),
                                            );
                                            write_response(&mut stream, &response)?;
                                            return Ok(false);
                                        }
                                    }
                                    state
                                        .lock()
                                        .expect("broker state poisoned")
                                        .sessions
                                        .remove(&session_id);
                                    let response = broker_error(
                                            "mode_not_found",
                                            format!("mode '{mode_name}' not found — run `ward modes push` first"),
                                        );
                                    write_response(&mut stream, &response)?;
                                    return Ok(false);
                                }
                            },
                            Err(error) => {
                                if let Some(ref ek) = ephemeral_key {
                                    if let Err(restore_error) =
                                        restore_vault_from_session(&vault, ek, &passphrase)
                                    {
                                        let response = broker_error(
                                            "restore_failed",
                                            format!(
                                                "failed to restore vault after mode load failure: {restore_error}"
                                            ),
                                        );
                                        write_response(&mut stream, &response)?;
                                        return Ok(false);
                                    }
                                }
                                state
                                    .lock()
                                    .expect("broker state poisoned")
                                    .sessions
                                    .remove(&session_id);
                                let response = broker_error(
                                    "modes_vault_unavailable",
                                    format!("could not load modes vault: {error} — run `ward modes push` first"),
                                );
                                write_response(&mut stream, &response)?;
                                return Ok(false);
                            }
                        }
                    } else {
                        None
                    };

                    if let Some(session) = state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .get_mut(&session_id)
                    {
                        session.active_mode = active_mode;
                    }
                    write_response(&mut stream, &BrokerResponse::Ok)?;
                }
                Err(error) => {
                    let response = broker_error("unlock_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::Sign {
            project,
            vault,
            payload,
        } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            if let Err(message) = validate_signing_payload(&project, &payload) {
                let response = broker_error("signing_payload_invalid", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            let result = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault)
                    .and_then(|session| sign_with_session(session, payload))
            };
            match result {
                Ok(receipt) => write_response(&mut stream, &BrokerResponse::Signed { receipt })?,
                Err(error) => {
                    let response = broker_error("signing_key_unavailable", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::RegisterHumanSession {
            shell_pid,
            session_token,
            ttl_seconds,
        } => {
            let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
            state
                .lock()
                .expect("broker state poisoned")
                .human_sessions
                .insert(
                    shell_pid,
                    HumanSessionEntry {
                        session_token,
                        expires_at,
                    },
                );
            write_response(&mut stream, &BrokerResponse::Ok)?;
        }
        BrokerRequest::DeregisterHumanSession {
            shell_pid,
            session_token,
        } => {
            let mut state = state.lock().expect("broker state poisoned");
            match state.human_sessions.get(&shell_pid) {
                Some(entry) if entry.session_token == session_token => {
                    state.human_sessions.remove(&shell_pid);
                    cancel_human_commands(&mut state, shell_pid);
                    write_response(&mut stream, &BrokerResponse::Ok)?;
                }
                Some(_) => {
                    let response = broker_error("invalid_token", "session token mismatch");
                    write_response(&mut stream, &response)?;
                }
                None => {
                    write_response(&mut stream, &BrokerResponse::Ok)?;
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
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
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
                        write_response(&mut stream, &response)?;
                        return Ok(false);
                    }
                }
            };
            let passphrase = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault).map(|session| {
                    // Use ephemeral session key if vault is currently session-encrypted
                    session
                        .session_key
                        .clone()
                        .unwrap_or_else(|| session.passphrase.clone())
                })
            };
            let (passphrase, active_mode) = match passphrase {
                Ok(passphrase) => {
                    let active_mode = {
                        let state = state.lock().expect("broker state poisoned");
                        active_session(&state, &project, &vault)
                            .ok()
                            .and_then(|s| s.active_mode.clone())
                    };
                    (passphrase, active_mode)
                }
                Err(error) => {
                    let response = broker_error("unlock_required", error.to_string());
                    write_response(&mut stream, &response)?;
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
                        write_response(&mut stream, &response)?;
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
                    write_response(&mut stream, &response)?;
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
                write_response(&mut stream, &response)?;
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
                            Arc::clone(&cancellation),
                            Arc::clone(&child_pid),
                        );
                    }
                    RunCommandRequest {
                        cwd,
                        vault,
                        env_names,
                        command,
                        passphrase,
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
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            if let Err((reason, message)) = validate_list_keys_authorization(&state, &authorization)
            {
                let response = broker_error(reason, message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            let key_result = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault).and_then(|session| {
                    let decrypt_key = session
                        .session_key
                        .clone()
                        .unwrap_or_else(|| session.passphrase.clone());
                    let plaintext = vault::decrypt_vault_file(&vault, &decrypt_key)?;
                    let names = plaintext
                        .lines()
                        .filter_map(|line| {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                return None;
                            }
                            line.split('=').next().map(str::to_string)
                        })
                        .collect::<Vec<_>>();
                    Ok(names)
                })
            };
            match key_result {
                Ok(names) => write_response(&mut stream, &BrokerResponse::Keys { names })?,
                Err(e) => {
                    let response = broker_error("list_keys_failed", e.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::SetupProject {
            source_project,
            source_vault,
            target_path,
            project,
        } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            let (passphrase, expires_at) = {
                let state = state.lock().expect("broker state poisoned");
                match active_session(&state, &source_project, &source_vault) {
                    Ok(session) => (session.passphrase.clone(), session.expires_at),
                    Err(error) => {
                        let response = broker_error("unlock_required", error.to_string());
                        write_response(&mut stream, &response)?;
                        return Ok(false);
                    }
                }
            };

            match setup_project_with_passphrase(&target_path, project.as_deref(), &passphrase) {
                Ok(status) => {
                    let new_session_key =
                        reencrypt_vault_with_session_key(&status.vault, &passphrase);
                    state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .insert(
                            session_key(&status.project, &status.vault),
                            BrokerSession {
                                project: status.project.clone(),
                                vault: status.vault.clone(),
                                passphrase,
                                session_key: new_session_key,
                                expires_at,
                                active_mode: None,
                            },
                        );
                    write_response(&mut stream, &BrokerResponse::ProjectSetup { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_setup_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::SnapshotProject { project, vault } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
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
                    write_response(&mut stream, &response)?;
                    return Ok(false);
                }
            };
            match snapshot_project_with_material(&project, &vault, &material) {
                Ok(status) => {
                    write_response(&mut stream, &BrokerResponse::ProjectSnapshot { status })?
                }
                Err(error) => {
                    let response = broker_error("project_snapshot_failed", error.to_string());
                    write_response(&mut stream, &response)?;
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
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
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
                    write_response(&mut stream, &response)?;
                    return Ok(false);
                }
            };
            let provision_result = {
                let passphrase = material.passphrase.clone();
                provision_project_with_material(ProjectProvisionMaterialRequest {
                    source_project: &source_project,
                    source_vault: &source_vault,
                    target_path: &target_path,
                    project: &project,
                    profiles,
                    env_names,
                    agents,
                    material: &material,
                })
                .map(|(status, expires_at)| (status, expires_at, passphrase))
            };
            match provision_result {
                Ok((status, expires_at, passphrase)) => {
                    let new_session_key =
                        reencrypt_vault_with_session_key(&status.vault, &passphrase);
                    state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .insert(
                            session_key(&status.project, &status.vault),
                            BrokerSession {
                                project: status.project.clone(),
                                vault: status.vault.clone(),
                                passphrase,
                                session_key: new_session_key,
                                expires_at,
                                active_mode: None,
                            },
                        );
                    write_response(&mut stream, &BrokerResponse::ProjectProvision { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_provision_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
    }
    Ok(false)
}

fn sign_with_session(
    session: &BrokerSession,
    mut payload: ApprovalReceiptPayload,
) -> Result<ApprovalReceipt> {
    let passphrase = &session.passphrase;
    let project = &session.project;
    let ciphertext =
        approval_receipts::session_signing_key_ciphertext(project, passphrase, passphrase)?;
    let signing_key = approval_receipts::decrypt_session_signing_key(&ciphertext, passphrase)?;
    payload.signer_key_id = signing_key.signer_key_id.clone();
    approval_receipts::sign_payload(payload, &signing_key)
}

struct ActiveProjectMaterial {
    passphrase: String,
    decrypt_key: String,
    expires_at: DateTime<Utc>,
}

fn active_project_material(
    state: &BrokerState,
    project: &str,
    vault: &Path,
) -> Result<ActiveProjectMaterial> {
    let session = active_session(state, project, vault)?;
    Ok(ActiveProjectMaterial {
        passphrase: session.passphrase.clone(),
        decrypt_key: session
            .session_key
            .clone()
            .unwrap_or_else(|| session.passphrase.clone()),
        expires_at: session.expires_at,
    })
}

fn snapshot_project_with_material(
    project: &str,
    vault: &Path,
    material: &ActiveProjectMaterial,
) -> Result<BrokerProjectSnapshotStatus> {
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let config = config::read_project_config(&registered.path)?;
    let plaintext = vault::decrypt_vault_file(vault, &material.decrypt_key)?;
    let store = project_store::refresh_from_plaintext(
        project,
        &registered.path,
        vault,
        &config,
        &plaintext,
        &material.passphrase,
    )?;
    Ok(BrokerProjectSnapshotStatus { store })
}

struct ProjectProvisionMaterialRequest<'a> {
    source_project: &'a str,
    source_vault: &'a Path,
    target_path: &'a Path,
    project: &'a str,
    profiles: Vec<String>,
    env_names: Vec<String>,
    agents: Vec<String>,
    material: &'a ActiveProjectMaterial,
}

fn provision_project_with_material(
    request: ProjectProvisionMaterialRequest<'_>,
) -> Result<(BrokerProjectProvisionStatus, DateTime<Utc>)> {
    let ProjectProvisionMaterialRequest {
        source_project,
        source_vault,
        target_path,
        project,
        profiles,
        env_names,
        agents,
        material,
    } = request;
    validate_project_name(project)?;
    let selected_env = normalize_env_names(env_names)?;
    if selected_env.is_empty() {
        anyhow::bail!("at least one env name is required");
    }
    let selected_agents = normalize_agent_names(agents)?;

    let registry = registry::list_projects()?;
    let source_registered = registry
        .projects
        .get(source_project)
        .with_context(|| format!("source project {source_project} is not registered"))?;
    let source_config = config::read_project_config(&source_registered.path)?;
    let source_plaintext = vault::decrypt_vault_file(source_vault, &material.decrypt_key)?;
    let source_env = env_file::parse_env_map(&source_plaintext)?;
    let missing = selected_env
        .iter()
        .filter(|name| !source_env.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "source vault is missing selected env(s): {}",
            missing.join(", ")
        );
    }

    let selected_env_set = selected_env.iter().cloned().collect::<BTreeSet<_>>();
    let profile_names = normalize_profile_names(if profiles.is_empty() {
        source_config.profiles.keys().cloned().collect()
    } else {
        profiles
    })?;
    let mut target_profiles = BTreeMap::new();
    for profile_name in &profile_names {
        let mut profile = source_config
            .profiles
            .get(profile_name)
            .with_context(|| format!("source profile {profile_name} does not exist"))?
            .clone();
        profile
            .env
            .retain(|env_name| selected_env_set.contains(env_name));
        target_profiles.insert(profile_name.clone(), profile);
    }

    let target_path = prepare_provision_target(target_path)?;
    let vault_path = target_path.join(config::DEFAULT_VAULT_FILE);
    let mut target_config =
        config::ProjectConfig::default_for_dir(&target_path, Some(project.to_string()))?;
    target_config.vault = PathBuf::from(config::DEFAULT_VAULT_FILE);
    target_config.profiles = target_profiles;
    target_config.agent_policies = selected_agents
        .iter()
        .map(|agent| {
            (
                agent.clone(),
                config::AgentPolicyConfig {
                    profiles: profile_names.clone(),
                    env: selected_env.clone(),
                },
            )
        })
        .collect();

    let mut selected_map = BTreeMap::new();
    for env_name in &selected_env {
        if let Some(value) = source_env.get(env_name) {
            selected_map.insert(env_name.clone(), value.clone());
        }
    }
    let selected_plaintext = env_file::serialize_env_map(&selected_map);
    vault::validate_dotenv(&selected_plaintext)?;

    config::write_project_config(&target_path, &target_config, true)?;
    config::ensure_env_example(&target_path)?;
    config::ensure_agent_instructions(&target_path, project)?;
    config::ensure_gitignore(&target_path, true)?;
    let envelope = vault::encrypt_env(&selected_plaintext, &material.passphrase)?;
    vault::write_vault(&vault_path, &envelope)?;
    env_file::lock_env_file(&target_path.join(".env"), &vault_path)?;
    approval_receipts::ensure_project_key(project, &material.passphrase)?;
    if recovery::create_recovery_files_with_material(
        project,
        &material.passphrase,
        &material.passphrase,
        Some(&selected_plaintext),
    )
    .is_ok()
    {
        target_config.recovery_created = true;
        let _ = config::write_project_config(&target_path, &target_config, true);
    }

    registry::update_project_vault(project, target_path.clone(), vault_path.clone())?;
    let store = project_store::refresh_from_plaintext(
        project,
        &target_path,
        &vault_path,
        &target_config,
        &selected_plaintext,
        &material.passphrase,
    )?;

    Ok((
        BrokerProjectProvisionStatus {
            project: project.to_string(),
            path: target_path,
            vault: vault_path,
            env_names: selected_env,
            profiles: profile_names,
            agents: selected_agents,
            store,
        },
        material.expires_at,
    ))
}

pub(crate) fn setup_project_with_passphrase(
    target_path: &Path,
    project: Option<&str>,
    passphrase: &str,
) -> Result<BrokerProjectSetupStatus> {
    let target_path = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf());
    if !target_path.is_dir() {
        anyhow::bail!(
            "selected path is not a directory: {}",
            target_path.display()
        );
    }

    if let Ok(config) = config::read_project_config(&target_path) {
        let project_name = project.unwrap_or(&config.project).to_string();
        let vault_path =
            config::resolve_vault_path_with_passphrase(&target_path, &config, passphrase);
        registry::update_project_vault(&project_name, target_path.clone(), vault_path.clone())?;
        if let Ok(plaintext) = vault::decrypt_vault_file(&vault_path, passphrase) {
            let _ = project_store::refresh_from_plaintext(
                &project_name,
                &target_path,
                &vault_path,
                &config,
                &plaintext,
                passphrase,
            );
        }
        return Ok(BrokerProjectSetupStatus {
            project: project_name,
            path: target_path,
            vault: vault_path,
            created: false,
            registered: true,
        });
    }

    let source = target_path.join(".env");
    if !source.exists() {
        anyhow::bail!(
            "selected folder has no .env file; add a dotenv file or run ward setup in that project"
        );
    }
    if env_file::is_locked_env_file(&source)? {
        anyhow::bail!(
            "{} is already a Ward locked marker but no .ward.json exists",
            source.display()
        );
    }

    let project_name = project
        .map(str::to_string)
        .or_else(|| {
            target_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
        .context("could not infer project name from selected folder")?;
    let env_keys = config::env_keys_from_dotenv_file(&source)?;
    let mut project_config =
        config::ProjectConfig::default_for_dir(&target_path, Some(project_name.clone()))?;
    project_config.vault = PathBuf::from(config::DEFAULT_VAULT_FILE);
    project_config.profiles = config::default_profiles(&env_keys, &target_path);

    config::write_project_config(&target_path, &project_config, true)?;
    config::ensure_env_example(&target_path)?;
    config::ensure_agent_instructions(&target_path, &project_config.project)?;
    config::ensure_gitignore(&target_path, true)?;

    let vault_path = target_path.join(config::DEFAULT_VAULT_FILE);
    vault::import_env_file(&source, &vault_path, passphrase)?;
    let plaintext = vault::decrypt_vault_file(&vault_path, passphrase)?;
    env_file::lock_env_file(&source, &vault_path)?;
    approval_receipts::ensure_project_key(&project_config.project, passphrase)?;

    if recovery::create_recovery_files_with_material(
        &project_config.project,
        passphrase,
        passphrase,
        Some(&plaintext),
    )
    .is_ok()
    {
        project_config.recovery_created = true;
        let _ = config::write_project_config(&target_path, &project_config, true);
    }

    registry::update_project_vault(
        &project_config.project,
        target_path.clone(),
        vault_path.clone(),
    )?;
    let _ = project_store::refresh_from_plaintext(
        &project_config.project,
        &target_path,
        &vault_path,
        &project_config,
        &plaintext,
        passphrase,
    );
    Ok(BrokerProjectSetupStatus {
        project: project_config.project,
        path: target_path,
        vault: vault_path,
        created: true,
        registered: true,
    })
}

fn prepare_provision_target(target_path: &Path) -> Result<PathBuf> {
    if !target_path.exists() {
        fs::create_dir_all(target_path)
            .with_context(|| format!("failed to create {}", target_path.display()))?;
    }
    let target_path = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf());
    if !target_path.is_dir() {
        anyhow::bail!("target path is not a directory: {}", target_path.display());
    }
    let config_path = config::config_path(&target_path);
    if config_path.exists() {
        anyhow::bail!(
            "{} already exists; provisioning does not overwrite existing Ward projects",
            config_path.display()
        );
    }
    let env_path = target_path.join(".env");
    if env_path.exists() {
        if env_file::is_locked_env_file(&env_path)? {
            anyhow::bail!(
                "{} is a locked Ward marker but no .ward.json exists",
                env_path.display()
            );
        }
        anyhow::bail!(
            "{} already exists; provisioning does not overwrite plaintext env files",
            env_path.display()
        );
    }
    Ok(target_path)
}

fn normalize_env_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let name = name.trim();
        if !is_valid_env_name(name) {
            anyhow::bail!("invalid env name: {name}");
        }
        normalized.insert(name.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_profile_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let name = name.trim();
        if !is_valid_policy_name(name) {
            anyhow::bail!("invalid profile name: {name}");
        }
        normalized.insert(name.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_agent_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let name = name.trim();
        if !is_valid_agent_name(name) {
            anyhow::bail!("invalid agent name: {name}");
        }
        normalized.insert(name.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn validate_project_name(name: &str) -> Result<()> {
    if name.trim() != name || name.is_empty() || name.len() > 128 {
        anyhow::bail!("invalid project name: {name}");
    }
    if !name
        .chars()
        .all(|ch| ch == ':' || ch == '_' || ch == '-' || ch == '.' || ch.is_ascii_alphanumeric())
    {
        anyhow::bail!("invalid project name: {name}");
    }
    Ok(())
}

fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_valid_policy_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|ch| ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
}

fn is_valid_agent_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|ch| ch == '_' || ch == '-' || ch == '.' || ch.is_ascii_alphanumeric())
}

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

fn validate_human_session(state: &BrokerState, shell_pid: u32) -> std::result::Result<(), String> {
    let Some(entry) = state.human_sessions.get(&shell_pid) else {
        return Err(format!(
            "Ward human mode is not active for this terminal; run ward human (shell pid: {shell_pid})"
        ));
    };
    if entry.expires_at <= Utc::now() {
        return Err(format!(
            "Ward human mode expired for this terminal; run ward human (shell pid: {shell_pid})"
        ));
    }
    if !process_util::process_exists(shell_pid) {
        return Err(format!(
            "Ward human shell is no longer running; run ward human in the active terminal (shell pid: {shell_pid})"
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
) -> std::result::Result<Option<u32>, (String, String)> {
    let Some(authorization) = authorization else {
        return Err((
            "execute_authorization_required".to_string(),
            "execution authorization is required".to_string(),
        ));
    };
    match authorization {
        ExecuteAuthorization::Human { shell_pid } => {
            cleanup_inactive_human_sessions(state);
            validate_human_session(state, *shell_pid)
                .map_err(|message| ("human_session_required".to_string(), message))?;
            Ok(Some(*shell_pid))
        }
        ExecuteAuthorization::Agent { proof } => {
            let valid = agents::verify_proof(project, proof).map_err(|error| {
                (
                    "agent_proof_invalid".to_string(),
                    format!("agent proof verification failed: {error}"),
                )
            })?;
            if !valid {
                return Err((
                    "agent_proof_invalid".to_string(),
                    "agent proof verification failed".to_string(),
                ));
            }
            let payload = serde_json::from_str::<ExecuteAuthorizationPayload>(&proof.payload)
                .map_err(|error| {
                    (
                        "execute_authorization_invalid".to_string(),
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
                    "execute_authorization_mismatch".to_string(),
                    "agent execution authorization is missing verified context".to_string(),
                ));
            }
            validate_execute_payload(state, project, vault, cwd, env_names, command, &payload)?;
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
) -> std::result::Result<(), (String, String)> {
    if payload.expires_at <= Utc::now() {
        return Err((
            "execute_authorization_expired".to_string(),
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
            "execute_authorization_mismatch".to_string(),
            "execution authorization does not match requested command/env scope".to_string(),
        ));
    }
    if payload.nonce.trim().is_empty() {
        return Err((
            "execute_authorization_invalid".to_string(),
            "execution authorization nonce is empty".to_string(),
        ));
    }
    let nonce_key = format!("{}:{}", payload.project, payload.nonce);
    if state.execute_nonces.contains_key(&nonce_key) {
        return Err((
            "execute_authorization_replayed".to_string(),
            "execution authorization nonce was already used".to_string(),
        ));
    }
    state.execute_nonces.insert(nonce_key, payload.expires_at);
    Ok(())
}

fn validate_list_keys_authorization(
    state: &Arc<Mutex<BrokerState>>,
    authorization: &ListKeysAuthorization,
) -> std::result::Result<(), (String, String)> {
    match authorization {
        ListKeysAuthorization::Human { shell_pid } => {
            let mut state = state.lock().expect("broker state poisoned");
            cleanup_inactive_human_sessions(&mut state);
            validate_human_session(&state, *shell_pid)
                .map_err(|message| ("human_session_required".to_string(), message))
        }
        ListKeysAuthorization::Internal { purpose } => {
            if purpose.trim().is_empty() {
                Err((
                    "list_keys_authorization_required".to_string(),
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

fn register_human_command(
    state: &mut BrokerState,
    shell_pid: u32,
    cancellation: Arc<AtomicBool>,
    child_pid: Arc<AtomicU32>,
) {
    let command_id = state.next_human_command_id;
    state.next_human_command_id = state.next_human_command_id.saturating_add(1);
    state.human_commands.entry(shell_pid).or_default().insert(
        command_id,
        ActiveHumanCommand {
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
                process_util::terminate_process_group(child_pid);
            }
        }
    }
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
            if entry.expires_at <= now || !process_util::process_exists(*shell_pid) {
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
            .filter(|session| session.expires_at > Utc::now())
            .map(|session| BrokerSessionStatus {
                project: session.project.clone(),
                vault: session.vault.clone(),
                expires_at: session.expires_at,
                active_mode: session.active_mode.as_ref().map(|m| m.config.name.clone()),
            })
            .collect(),
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

fn generate_session_key() -> String {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    hex::encode(key)
}

fn reencrypt_vault_with_session_key(vault: &Path, passphrase: &str) -> Option<String> {
    vault::decrypt_vault_file(vault, passphrase)
        .and_then(|plaintext| {
            let ephemeral_key = generate_session_key();
            let envelope = vault::encrypt_env(&plaintext, &ephemeral_key)?;
            vault::write_vault(vault, &envelope)?;
            Ok(ephemeral_key)
        })
        .ok()
}

fn install_shutdown_handler(state: Arc<Mutex<BrokerState>>) {
    #[cfg(test)]
    {
        let _ = state;
    }
    #[cfg(not(test))]
    {
        if let Err(error) = ctrlc::set_handler(move || {
            let _ = restore_all_sessions(&state);
            let _ = cleanup_stale_files();
            std::process::exit(0);
        }) {
            eprintln!("ward broker warning: failed to install shutdown handler: {error}");
        }
    }
}

fn restore_all_sessions(state: &Arc<Mutex<BrokerState>>) -> Result<()> {
    let state = state.lock().expect("broker state poisoned");
    for session in state.sessions.values() {
        if let Some(ref ek) = session.session_key {
            restore_vault_from_session(&session.vault, ek, &session.passphrase).context(
                format!(
                    "failed to restore {} before broker shutdown",
                    session.vault.display()
                ),
            )?;
        }
    }
    Ok(())
}

/// Decrypts the session-encrypted vault and re-writes it with the original passphrase.
fn restore_vault_from_session(vault: &Path, session_key: &str, passphrase: &str) -> Result<()> {
    let plaintext = vault::decrypt_vault_file(vault, session_key)?;
    let envelope = vault::encrypt_env(&plaintext, passphrase)?;
    vault::write_vault(vault, &envelope)
}

fn send_simple(request: BrokerRequest) -> Result<BrokerResponse> {
    let mut stream = connect()?;
    write_request(&mut stream, &request)?;
    let mut reader = BufReader::new(stream);
    read_response(&mut reader)
}

fn broker_error(reason: impl Into<String>, message: impl Into<String>) -> BrokerResponse {
    BrokerResponse::Error {
        reason: reason.into(),
        message: message.into(),
    }
}

#[cfg(not(test))]
fn ping() -> Result<()> {
    ping_status().map(|_| ())
}

fn connect() -> Result<UnixStream> {
    UnixStream::connect(socket_path()).context("failed to connect to Ward broker")
}

fn read_request(reader: &mut BufReader<UnixStream>) -> Result<BrokerRequest> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read broker request")?;
    serde_json::from_str(line.trim()).context("failed to parse broker request")
}

fn read_response(reader: &mut BufReader<UnixStream>) -> Result<BrokerResponse> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read broker response")?;
    if line.is_empty() {
        anyhow::bail!("broker closed the connection");
    }
    serde_json::from_str(line.trim()).context("failed to parse broker response")
}

fn write_request(stream: &mut UnixStream, request: &BrokerRequest) -> Result<()> {
    let line = serde_json::to_string(request).expect("broker request should serialize");
    writeln!(stream, "{line}").context("failed to write broker request")
}

fn write_response(stream: &mut UnixStream, response: &BrokerResponse) -> Result<()> {
    let line = serde_json::to_string(response).expect("broker response should serialize");
    writeln!(stream, "{line}").context("failed to write broker response")
}

fn cleanup_stale_files() -> Result<()> {
    let socket = socket_path();
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }
    let pid = pid_path();
    if pid.exists() {
        let _ = std::fs::remove_file(pid);
    }
    Ok(())
}

fn read_pid() -> Result<u32> {
    let contents = std::fs::read_to_string(pid_path()).context("failed to read broker pid")?;
    contents
        .trim()
        .parse::<u32>()
        .context("failed to parse broker pid")
}

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
        reason: "stop_failed".to_string(),
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
            reason: "unlock_failed".to_string(),
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
            reason: "signing_key_unavailable".to_string(),
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
                reason: "execution_failed".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agents, approval_receipts, approvals::ApprovalScope, policy::AccessRequest};
    use serial_test::serial;

    fn broker_pair(
        request: BrokerRequest,
        state: Arc<Mutex<BrokerState>>,
    ) -> (bool, BrokerResponse) {
        let (mut client, server) = UnixStream::pair().unwrap();
        write_request(&mut client, &request).unwrap();
        let stop = handle_client(server, state).unwrap();
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
        assert!(cfg.recovery_created);
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
            } if reason == "unlock_required"
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
            BrokerSession {
                project: "demo".to_string(),
                vault: source_vault.clone(),
                passphrase: "1234".to_string(),
                session_key: None,
                expires_at: Utc::now() + Duration::hours(1),
                active_mode: None,
            },
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
            config::ProjectConfig::default_for_dir(source.path(), Some("source".to_string()))
                .unwrap();
        source_config.profiles.get_mut("dev").unwrap().env =
            vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()];
        config::write_project_config(source.path(), &source_config, true).unwrap();
        let source_vault = source.path().join(".env.vault");
        let source_plaintext =
            "DATABASE_URL=postgres://selected-secret\nPAYLOAD_SECRET=not-selected\n";
        let envelope = vault::encrypt_env(source_plaintext, "1234").unwrap();
        vault::write_vault(&source_vault, &envelope).unwrap();
        registry::update_project_vault("source", source.path().to_path_buf(), source_vault.clone())
            .unwrap();
        let material = ActiveProjectMaterial {
            passphrase: "1234".to_string(),
            decrypt_key: "1234".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        let (status, _) = provision_project_with_material(ProjectProvisionMaterialRequest {
            source_project: "source",
            source_vault: &source_vault,
            target_path: &target,
            project: "target",
            profiles: vec!["dev".to_string()],
            env_names: vec!["DATABASE_URL".to_string()],
            agents: vec!["codex".to_string()],
            material: &material,
        })
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
            sessions: vec![
                BrokerSessionStatus {
                    project: "other".to_string(),
                    vault: vault.clone(),
                    expires_at,
                    active_mode: None,
                },
                BrokerSessionStatus {
                    project: "demo".to_string(),
                    vault: PathBuf::from("/missing/.env.vault"),
                    expires_at,
                    active_mode: None,
                },
                BrokerSessionStatus {
                    project: "demo".to_string(),
                    vault: same_vault,
                    expires_at,
                    active_mode: None,
                },
                BrokerSessionStatus {
                    project: "demo".to_string(),
                    vault: vault.clone(),
                    expires_at: now - Duration::minutes(1),
                    active_mode: None,
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
            } if reason == "unlock_failed"
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
                payload: approval_receipts::build_payload(approval_receipts::PayloadBuildRequest {
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
            } if reason == "signing_key_unavailable"
        ));

        state.lock().unwrap().sessions.insert(
            session_key("expired", &vault_path),
            BrokerSession {
                project: "expired".to_string(),
                vault: vault_path.clone(),
                passphrase: passphrase.to_string(),
                session_key: None,
                expires_at: Utc::now() - Duration::seconds(1),
                active_mode: None,
            },
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
            } if reason == "unlock_required"
        ));

        let access = AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("main".to_string()),
            action: Some("Coverage sign".to_string()),
            command: "sh -c true".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        };
        let payload = approval_receipts::build_payload(approval_receipts::PayloadBuildRequest {
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
            } if reason == "execute_authorization_invalid"
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
            } if reason == "unlock_required"
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
            } if reason == "vault_key_missing"
        ));

        let (mut client, server) = UnixStream::pair().unwrap();
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
                    access.env,
                    command,
                    "codex",
                )),
            },
        )
        .unwrap();
        assert!(!handle_client(server, state).unwrap());
        let mut reader = BufReader::new(client);
        let finished = read_response(&mut reader).unwrap();
        assert!(matches!(finished, BrokerResponse::Finished { .. }));

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
            } if reason == "execute_authorization_required"
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
            } if reason == "execute_authorization_mismatch"
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
            } if reason == "execute_authorization_replayed"
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
            } if reason == "broker_client_untrusted"
        ));

        let access = AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("main".to_string()),
            action: Some("Coverage sign".to_string()),
            command: "sh -c true".to_string(),
            env: env_names.clone(),
        };
        let sign_payload =
            approval_receipts::build_payload(approval_receipts::PayloadBuildRequest {
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
            } if reason == "broker_client_untrusted"
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
            } if reason == "broker_client_untrusted"
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
        let payload = approval_receipts::build_payload(approval_receipts::PayloadBuildRequest {
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
}
