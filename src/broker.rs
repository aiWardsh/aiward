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
    time::Duration as StdDuration,
};
#[cfg(not(test))]
use std::{
    os::unix::io::AsRawFd,
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    agents::{self, AgentProof},
    approval_receipts::{self, ApprovalReceipt, ApprovalReceiptPayload},
    approvals::{ApprovalChannel, ApprovalDecision, ApprovalScope, ApprovalSource},
    config, detection, env_file, fs_util, grants, modes, pending_requests,
    policy::{self, AccessRequest},
    project_store, project_teardown, registry,
    runner::{self, RunCommandOutcome, RunCommandRequest},
    unlock, vault,
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
    #[serde(default)]
    pub approval_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerSessionStatus {
    pub project: String,
    pub vault: PathBuf,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_mode: Option<String>,
    #[serde(default)]
    pub env_count: usize,
    #[serde(default)]
    pub subsession_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_slug: Option<String>,
    #[serde(default)]
    pub state: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerProjectLockStatus {
    pub project: String,
    pub broker_session_removed: bool,
    pub revoked_session_grants: usize,
    pub cleared_unlock_sessions: usize,
    pub cancelled_human_commands: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerApprovalStatus {
    pub request_id: uuid::Uuid,
    pub project: String,
    pub scope: ApprovalScope,
    pub channel: ApprovalChannel,
    pub grant_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_receipt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses_remaining: Option<u32>,
    #[serde(default)]
    pub critical_confirmation: bool,
    pub access: AccessRequest,
}

#[derive(Debug, Clone)]
pub struct ProjectProvisionRequest {
    pub source_project: String,
    pub source_vault: PathBuf,
    pub target_path: PathBuf,
    pub project: String,
    pub profiles: Vec<String>,
    pub env_names: Vec<String>,
    pub agents: Vec<String>,
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
        payload: ExecuteAuthorizationPayload,
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
    LockProject {
        project: String,
        vault: PathBuf,
    },
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
    ApproveRequest {
        request_id: uuid::Uuid,
        scope: ApprovalScope,
        confirm_critical: bool,
        channel: ApprovalChannel,
    },
    DenyRequest {
        request_id: uuid::Uuid,
        channel: ApprovalChannel,
    },
    ListApprovals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<String>,
    },
    RegisterHumanSession {
        shell_pid: u32,
        session_token: String,
        ttl_seconds: i64,
        projects: Vec<String>,
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
    RemoveProject {
        project: String,
        vault: PathBuf,
        export_path: PathBuf,
        restore_env: bool,
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
    Approval {
        status: BrokerApprovalStatus,
    },
    Approvals {
        approvals: Vec<BrokerApprovalStatus>,
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
    ProjectLock {
        status: BrokerProjectLockStatus,
    },
    ProjectTeardown {
        status: project_teardown::ProjectTeardownOutcome,
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
    projects: BTreeSet<String>,
}

struct ActiveHumanCommand {
    project: String,
    cancellation: Arc<AtomicBool>,
    child_pid: Arc<AtomicU32>,
}

#[derive(Debug, Clone)]
struct BrokerApprovalRecord {
    request_id: uuid::Uuid,
    project: String,
    vault: PathBuf,
    access: AccessRequest,
    scope: ApprovalScope,
    channel: ApprovalChannel,
    grant_id: uuid::Uuid,
    approval_receipt_hash: Option<String>,
    signer_key_id: Option<String>,
    signature_algorithm: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    uses_remaining: Option<u32>,
    critical_confirmation: bool,
}

impl BrokerApprovalRecord {
    fn status(&self) -> BrokerApprovalStatus {
        BrokerApprovalStatus {
            request_id: self.request_id,
            project: self.project.clone(),
            scope: self.scope,
            channel: self.channel,
            grant_id: self.grant_id,
            approval_receipt_hash: self.approval_receipt_hash.clone(),
            signer_key_id: self.signer_key_id.clone(),
            signature_algorithm: self.signature_algorithm.clone(),
            expires_at: self.expires_at,
            uses_remaining: self.uses_remaining,
            critical_confirmation: self.critical_confirmation,
            access: self.access.clone(),
        }
    }
}

struct BrokerState {
    sessions: BTreeMap<String, BrokerSession>,
    approvals: BTreeMap<uuid::Uuid, BrokerApprovalRecord>,
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
            approvals: BTreeMap::new(),
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
    env: BTreeMap<String, String>,
    vault_fingerprint: String,
    signing_key: approval_receipts::SessionSigningKey,
    passphrase: String,
    expires_at: DateTime<Utc>,
    active_mode: Option<modes::ActiveMode>,
    workspace_root: Option<PathBuf>,
    workspace_name: Option<String>,
    app_slug: Option<String>,
}

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
        cleanup_expired_approvals(&mut broker_state);
    }
    match request {
        BrokerRequest::Ping => {
            let status = status_from_state(&state.lock().expect("broker state poisoned"));
            write_response(&mut stream, &BrokerResponse::Status { status })?;
        }
        BrokerRequest::Stop => {
            cancel_all_human_commands(&mut state.lock().expect("broker state poisoned"));
            write_response(&mut stream, &BrokerResponse::Ok)?;
            return Ok(true);
        }
        BrokerRequest::LockProject { project, vault } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            match lock_project_in_state(&state, &project, &vault) {
                Ok(status) => {
                    write_response(&mut stream, &BrokerResponse::ProjectLock { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_lock_failed", error.to_string());
                    write_response(&mut stream, &response)?;
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
        BrokerRequest::ApproveRequest {
            request_id,
            scope,
            confirm_critical,
            channel,
        } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            match approve_pending_request_in_state(
                &state,
                request_id,
                scope,
                confirm_critical,
                channel,
            ) {
                Ok(status) => write_response(&mut stream, &BrokerResponse::Approval { status })?,
                Err(error) => {
                    let response = broker_error("approval_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::DenyRequest {
            request_id,
            channel,
        } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            match deny_pending_request_in_state(&state, request_id, channel) {
                Ok(status) => write_response(&mut stream, &BrokerResponse::Approval { status })?,
                Err(error) => {
                    let response = broker_error("deny_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::ListApprovals { project } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
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
            write_response(&mut stream, &BrokerResponse::Approvals { approvals })?;
        }
        BrokerRequest::RegisterHumanSession {
            shell_pid,
            session_token,
            ttl_seconds,
            projects,
        } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
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
            write_response(&mut stream, &BrokerResponse::Ok)?;
        }
        BrokerRequest::DeregisterHumanSession {
            shell_pid,
            session_token,
        } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
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
            let session_material = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault)
                    .map(|session| (session.env.clone(), session.active_mode.clone()))
            };
            let (session_env, active_mode) = match session_material {
                Ok(material) => material,
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
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            if let Err((reason, message)) =
                validate_list_keys_authorization(&state, &project, &authorization)
            {
                let response = broker_error(reason, message);
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            let key_result = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault)
                    .map(|session| session.env.keys().cloned().collect::<Vec<_>>())
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
                            write_response(&mut stream, &response)?;
                            return Ok(false);
                        }
                    }
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
                            write_response(&mut stream, &response)?;
                            return Ok(false);
                        }
                    }
                    write_response(&mut stream, &BrokerResponse::ProjectProvision { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_provision_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::RemoveProject {
            project,
            vault,
            export_path,
            restore_env,
        } => {
            if let Err(message) = require_trusted_client(&stream) {
                let response = broker_error("broker_client_untrusted", message);
                write_response(&mut stream, &response)?;
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
                    write_response(&mut stream, &BrokerResponse::ProjectTeardown { status })?;
                }
                Err(error) => {
                    let response = broker_error("unlock_required", error.to_string());
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
    payload.signer_key_id = session.signing_key.signer_key_id.clone();
    approval_receipts::sign_payload(payload, &session.signing_key)
}

fn approve_pending_request_in_state(
    state: &Arc<Mutex<BrokerState>>,
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    channel: ApprovalChannel,
) -> Result<BrokerApprovalStatus> {
    if scope == ApprovalScope::Deny {
        anyhow::bail!("use DenyRequest for denied requests");
    }

    let pending = pending_requests::load_pending_request(request_id)?;
    let critical = detection::has_critical_findings(&pending.policy.findings);
    if critical && !confirm_critical {
        anyhow::bail!("critical request requires explicit critical confirmation");
    }
    crate::approvals::validate_scope_for_findings(scope, &pending.policy.findings)?;

    let resolved = registry::resolve_project(Some(&pending.access.project), Path::new("."))?;
    let mut decision = ApprovalDecision {
        approved: true,
        scope,
        approved_env: pending.access.env.clone(),
        denied_env: Vec::new(),
        source: ApprovalSource::BrokerApproval,
        grant_id: None,
    };
    let now = Utc::now();
    let mut grant = grants::grant_from_decision(&pending.access, &decision, now)?;
    grant.request_id = Some(request_id);
    let payload = approval_receipts::build_payload_with_context(
        &pending.access,
        grant.id,
        request_id,
        &grant.approved_env,
        grant.scope,
        grant.expires_at,
        critical && confirm_critical,
        grant.created_at,
        String::new(),
        pending.verified_context.as_ref(),
    );
    let receipt = {
        let state = state.lock().expect("broker state poisoned");
        let session = active_session(&state, &pending.access.project, &resolved.vault)?;
        sign_with_session(session, payload)?
    };
    grant.receipt = Some(receipt);
    grants::append_grant_to_path(&grants::grants_path(), &grant)?;
    pending_requests::consume_pending_request(request_id)?;
    pending_requests::record_resolution(request_id, "approved", &pending.access.project)?;

    let receipt = grant
        .receipt
        .as_ref()
        .expect("broker-created grant should have a receipt");
    decision.grant_id = Some(grant.id);
    let record = BrokerApprovalRecord {
        request_id,
        project: pending.access.project.clone(),
        vault: resolved.vault,
        access: pending.access,
        scope,
        channel,
        grant_id: grant.id,
        approval_receipt_hash: Some(receipt.payload_hash.clone()),
        signer_key_id: Some(receipt.signer_key_id.clone()),
        signature_algorithm: Some(receipt.signature_algorithm.clone()),
        expires_at: grant.expires_at,
        uses_remaining: grant.uses_remaining,
        critical_confirmation: critical && confirm_critical,
    };
    let status = record.status();
    if matches!(scope, ApprovalScope::Once | ApprovalScope::Session) {
        state
            .lock()
            .expect("broker state poisoned")
            .approvals
            .insert(request_id, record);
    }
    Ok(status)
}

fn deny_pending_request_in_state(
    _state: &Arc<Mutex<BrokerState>>,
    request_id: uuid::Uuid,
    channel: ApprovalChannel,
) -> Result<BrokerApprovalStatus> {
    let pending = pending_requests::consume_pending_request(request_id)?;
    pending_requests::record_resolution(request_id, "denied", &pending.access.project)?;
    Ok(BrokerApprovalStatus {
        request_id,
        project: pending.access.project.clone(),
        scope: ApprovalScope::Deny,
        channel,
        grant_id: uuid::Uuid::nil(),
        approval_receipt_hash: None,
        signer_key_id: None,
        signature_algorithm: None,
        expires_at: None,
        uses_remaining: None,
        critical_confirmation: false,
        access: pending.access,
    })
}

struct ActiveProjectMaterial {
    passphrase: String,
    plaintext: String,
    env: BTreeMap<String, String>,
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
        plaintext: env_file::serialize_env_map(&session.env),
        env: session.env.clone(),
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
    let store = project_store::refresh_from_plaintext(
        project,
        &registered.path,
        vault,
        &config,
        &material.plaintext,
        &material.passphrase,
    )?;
    Ok(BrokerProjectSnapshotStatus { store })
}

fn provision_project_with_material(
    request: &ProjectProvisionRequest,
    material: &ActiveProjectMaterial,
) -> Result<(BrokerProjectProvisionStatus, DateTime<Utc>)> {
    validate_project_name(&request.project)?;
    let selected_env = normalize_env_names(request.env_names.clone())?;
    if selected_env.is_empty() {
        anyhow::bail!("at least one env name is required");
    }
    let selected_agents = normalize_agent_names(request.agents.clone())?;

    let registry = registry::list_projects()?;
    let source_registered = registry
        .projects
        .get(&request.source_project)
        .with_context(|| {
            format!(
                "source project {} is not registered",
                request.source_project
            )
        })?;
    let source_config = config::read_project_config(&source_registered.path)?;
    let source_env = material.env.clone();
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
    let profile_names = normalize_profile_names(if request.profiles.is_empty() {
        source_config.profiles.keys().cloned().collect()
    } else {
        request.profiles.clone()
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

    let target_path = prepare_provision_target(&request.target_path)?;
    let vault_path = target_path.join(config::DEFAULT_VAULT_FILE);
    let mut target_config =
        config::ProjectConfig::default_for_dir(&target_path, Some(request.project.clone()))?;
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
    config::ensure_agent_instructions(&target_path, &request.project)?;
    config::ensure_gitignore(&target_path, true)?;
    let envelope = vault::encrypt_env(&selected_plaintext, &material.passphrase)?;
    vault::write_vault(&vault_path, &envelope)?;
    env_file::lock_env_file(&target_path.join(".env"), &vault_path)?;
    approval_receipts::ensure_project_key_after_vault_unlock(
        &request.project,
        &material.passphrase,
    )?;

    registry::update_project_vault(&request.project, target_path.clone(), vault_path.clone())?;
    let store = project_store::refresh_from_plaintext(
        &request.project,
        &target_path,
        &vault_path,
        &target_config,
        &selected_plaintext,
        &material.passphrase,
    )?;

    Ok((
        BrokerProjectProvisionStatus {
            project: request.project.clone(),
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
    let target_path = fs_util::resolve_existing_external_dir(target_path, "selected project path")?;

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
    approval_receipts::ensure_project_key_after_vault_unlock(&project_config.project, passphrase)?;

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
    let target_path =
        fs_util::resolve_external_directory_output(target_path, "project target path")?;
    if !target_path.exists() {
        fs::create_dir_all(&target_path)
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
            validate_human_session(state, project, *shell_pid)
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

fn validate_agent_execute_authority(
    state: &mut BrokerState,
    payload: &ExecuteAuthorizationPayload,
    proof: &AgentProof,
) -> std::result::Result<(), (String, String)> {
    match payload.approval_source {
        ApprovalSource::PolicyAuto => validate_policy_auto_authority(state, payload),
        ApprovalSource::Grant | ApprovalSource::BrokerApproval => {
            validate_grant_authority(state, payload, proof)
        }
        ApprovalSource::AgentMediated => Err((
            "agent_self_approval_rejected".to_string(),
            "agent-mediated approvals are no longer accepted; wait for dashboard or human approval"
                .to_string(),
        )),
        ApprovalSource::LocalTty | ApprovalSource::ManualAllow => Err((
            "human_approval_required".to_string(),
            "agent executions cannot claim terminal or manual approval authority".to_string(),
        )),
        ApprovalSource::PolicyDeny => Err((
            "policy_denied".to_string(),
            "Ward policy denied this execution".to_string(),
        )),
    }
}

fn validate_policy_auto_authority(
    state: &BrokerState,
    payload: &ExecuteAuthorizationPayload,
) -> std::result::Result<(), (String, String)> {
    let access = access_from_execute_payload(payload);
    let resolved = registry::resolve_project(Some(&payload.project), Path::new("."))
        .map_err(|error| ("project_unresolved".to_string(), error.to_string()))?;
    if !same_vault_path(&resolved.vault, &payload.vault) {
        return Err((
            "execute_authorization_mismatch".to_string(),
            "execution vault does not match the registered project vault".to_string(),
        ));
    }
    let config = config::read_project_config(&resolved.path)
        .map_err(|error| ("project_config_unavailable".to_string(), error.to_string()))?;
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
            "approval_required".to_string(),
            "broker policy evaluation requires human approval".to_string(),
        ));
    }
    Ok(())
}

fn validate_grant_authority(
    state: &mut BrokerState,
    payload: &ExecuteAuthorizationPayload,
    proof: &AgentProof,
) -> std::result::Result<(), (String, String)> {
    let grant_id = payload.grant_id.ok_or_else(|| {
        (
            "execute_authorization_mismatch".to_string(),
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
            "policy_denied".to_string(),
            "denied approvals cannot authorize execution".to_string(),
        )),
    }
}

fn validate_live_broker_approval(
    state: &mut BrokerState,
    payload: &ExecuteAuthorizationPayload,
    grant_id: uuid::Uuid,
) -> std::result::Result<(), (String, String)> {
    cleanup_expired_approvals(state);
    let Some(record) = state.approvals.values_mut().find(|approval| {
        approval.grant_id == grant_id
            && approval.project == payload.project
            && same_vault_path(&approval.vault, &payload.vault)
    }) else {
        return Err((
            "approval_required".to_string(),
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
            "execute_authorization_mismatch".to_string(),
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
) -> std::result::Result<(), (String, String)> {
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
    .map_err(|error| ("grant_lookup_failed".to_string(), error.to_string()))?;
    let Some(grant) = matched else {
        return Err((
            "approval_required".to_string(),
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
            "execute_authorization_mismatch".to_string(),
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
) -> std::result::Result<(), (String, String)> {
    match authorization {
        ListKeysAuthorization::Human { shell_pid } => {
            let mut state = state.lock().expect("broker state poisoned");
            cleanup_inactive_human_sessions(&mut state);
            validate_human_session(&state, project, *shell_pid)
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
        return (ppid > 0).then_some(ppid as u32);
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
            payload: ExecuteAuthorizationPayload::new(
                "demo".to_string(),
                home.path().join(".env.vault"),
                home.path().to_path_buf(),
                Vec::new(),
                vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
                ApprovalScope::Once,
                ApprovalSource::ManualAllow,
            ),
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
        payload: ExecuteAuthorizationPayload::new(
            "demo".to_string(),
            vault_path.clone(),
            home.path().to_path_buf(),
            Vec::new(),
            command.clone(),
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
        ),
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
        payload: ExecuteAuthorizationPayload::new(
            "demo".to_string(),
            vault_path.clone(),
            home.path().to_path_buf(),
            Vec::new(),
            command.clone(),
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
        ),
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
        payload: ExecuteAuthorizationPayload::new(
            "demo".to_string(),
            vault_path.clone(),
            home.path().to_path_buf(),
            Vec::new(),
            command.clone(),
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
        ),
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
            payload: test_execute_payload(project, vault, cwd, env_names, command),
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
            } if reason == "human_session_required"
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
                payload: approval_receipts::build_payload(
                    &AccessRequest {
                        project: "missing".to_string(),
                        agent: Some("codex".to_string()),
                        branch: Some("main".to_string()),
                        action: Some("Missing session".to_string()),
                        command: "sh -c true".to_string(),
                        env: vec!["DATABASE_URL".to_string()],
                    },
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4(),
                    &["DATABASE_URL".to_string()],
                    ApprovalScope::Session,
                    None,
                    false,
                    Utc::now(),
                    String::new(),
                ),
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
        let payload = approval_receipts::build_payload(
            &access,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &access.env,
            ApprovalScope::Session,
            Some(Utc::now() + Duration::hours(1)),
            false,
            Utc::now(),
            String::new(),
        );
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
                    access.env.clone(),
                    command.clone(),
                    "codex",
                )),
            },
        )
        .unwrap();
        assert!(!handle_client(server, Arc::clone(&state)).unwrap());
        let mut reader = BufReader::new(client);
        let finished = read_response(&mut reader).unwrap();
        assert!(matches!(
            finished,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "human_approval_required"
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
            } if reason == "agent_self_approval_rejected"
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
                    payload: mismatched_payload,
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
        let sign_payload = approval_receipts::build_payload(
            &access,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &env_names,
            ApprovalScope::Session,
            None,
            false,
            Utc::now(),
            String::new(),
        );
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
        let payload = approval_receipts::build_payload(
            &access,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &access.env,
            ApprovalScope::Session,
            None,
            false,
            Utc::now(),
            String::new(),
        );
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
