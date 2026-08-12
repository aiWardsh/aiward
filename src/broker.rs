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
        reason: BrokerReason,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerFailureKind {
    Denied,
    Unavailable,
    ProtocolFailure,
    InternalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerReason {
    AgentProofInvalid,
    AgentSelfApprovalRejected,
    ApprovalFailed,
    ApprovalRequired,
    BrokerClientUntrusted,
    DenyFailed,
    ExecuteAuthorizationExpired,
    ExecuteAuthorizationInvalid,
    ExecuteAuthorizationMismatch,
    ExecuteAuthorizationReplayed,
    ExecuteAuthorizationRequired,
    ExecutionFailed,
    GrantLookupFailed,
    HumanApprovalRequired,
    HumanSessionRequired,
    InvalidToken,
    ListKeysAuthorizationRequired,
    ListKeysFailed,
    ModeConfirmationRequired,
    ModeEnvViolation,
    PolicyDenied,
    ProjectConfigUnavailable,
    ProjectLockFailed,
    ProjectProvisionFailed,
    ProjectSessionFailed,
    ProjectSetupFailed,
    ProjectSnapshotFailed,
    ProjectUnresolved,
    SecurityPolicyViolation,
    SigningKeyUnavailable,
    SigningPayloadInvalid,
    StopFailed,
    UnlockFailed,
    VaultKeyMissing,
    UnlockRequired,
    BrokerUnavailable,
    ProtocolFailure,
    InternalFailure,
    Other(String),
}

impl BrokerReason {
    pub fn as_str(&self) -> &str {
        match self {
            Self::AgentProofInvalid => "agent_proof_invalid",
            Self::AgentSelfApprovalRejected => "agent_self_approval_rejected",
            Self::ApprovalFailed => "approval_failed",
            Self::ApprovalRequired => "approval_required",
            Self::BrokerClientUntrusted => "broker_client_untrusted",
            Self::DenyFailed => "deny_failed",
            Self::ExecuteAuthorizationExpired => "execute_authorization_expired",
            Self::ExecuteAuthorizationInvalid => "execute_authorization_invalid",
            Self::ExecuteAuthorizationMismatch => "execute_authorization_mismatch",
            Self::ExecuteAuthorizationReplayed => "execute_authorization_replayed",
            Self::ExecuteAuthorizationRequired => "execute_authorization_required",
            Self::ExecutionFailed => "execution_failed",
            Self::GrantLookupFailed => "grant_lookup_failed",
            Self::HumanApprovalRequired => "human_approval_required",
            Self::HumanSessionRequired => "human_session_required",
            Self::InvalidToken => "invalid_token",
            Self::ListKeysAuthorizationRequired => "list_keys_authorization_required",
            Self::ListKeysFailed => "list_keys_failed",
            Self::ModeConfirmationRequired => "mode_confirmation_required",
            Self::ModeEnvViolation => "mode_env_violation",
            Self::PolicyDenied => "policy_denied",
            Self::ProjectConfigUnavailable => "project_config_unavailable",
            Self::ProjectLockFailed => "project_lock_failed",
            Self::ProjectProvisionFailed => "project_provision_failed",
            Self::ProjectSessionFailed => "project_session_failed",
            Self::ProjectSetupFailed => "project_setup_failed",
            Self::ProjectSnapshotFailed => "project_snapshot_failed",
            Self::ProjectUnresolved => "project_unresolved",
            Self::SecurityPolicyViolation => "security_policy_violation",
            Self::SigningKeyUnavailable => "signing_key_unavailable",
            Self::SigningPayloadInvalid => "signing_payload_invalid",
            Self::StopFailed => "stop_failed",
            Self::UnlockFailed => "unlock_failed",
            Self::VaultKeyMissing => "vault_key_missing",
            Self::UnlockRequired => "unlock_required",
            Self::BrokerUnavailable => "broker_unavailable",
            Self::ProtocolFailure => "protocol_failure",
            Self::InternalFailure => "internal_failure",
            Self::Other(reason) => reason,
        }
    }

    pub fn kind(&self) -> BrokerFailureKind {
        match self {
            Self::AgentProofInvalid
            | Self::AgentSelfApprovalRejected
            | Self::ApprovalRequired
            | Self::BrokerClientUntrusted
            | Self::ExecuteAuthorizationExpired
            | Self::ExecuteAuthorizationInvalid
            | Self::ExecuteAuthorizationMismatch
            | Self::ExecuteAuthorizationReplayed
            | Self::ExecuteAuthorizationRequired
            | Self::GrantLookupFailed
            | Self::HumanApprovalRequired
            | Self::HumanSessionRequired
            | Self::InvalidToken
            | Self::ListKeysAuthorizationRequired
            | Self::ModeConfirmationRequired
            | Self::ModeEnvViolation
            | Self::PolicyDenied
            | Self::SecurityPolicyViolation
            | Self::VaultKeyMissing => BrokerFailureKind::Denied,
            Self::SigningKeyUnavailable
            | Self::UnlockFailed
            | Self::UnlockRequired
            | Self::BrokerUnavailable => BrokerFailureKind::Unavailable,
            Self::ProtocolFailure => BrokerFailureKind::ProtocolFailure,
            Self::ApprovalFailed
            | Self::DenyFailed
            | Self::ExecutionFailed
            | Self::ListKeysFailed
            | Self::ProjectConfigUnavailable
            | Self::ProjectLockFailed
            | Self::ProjectProvisionFailed
            | Self::ProjectSessionFailed
            | Self::ProjectSetupFailed
            | Self::ProjectSnapshotFailed
            | Self::ProjectUnresolved
            | Self::SigningPayloadInvalid
            | Self::StopFailed
            | Self::InternalFailure
            | Self::Other(_) => BrokerFailureKind::InternalFailure,
        }
    }
}

impl From<String> for BrokerReason {
    fn from(reason: String) -> Self {
        Self::from(reason.as_str())
    }
}

impl From<&str> for BrokerReason {
    fn from(reason: &str) -> Self {
        match reason {
            "agent_proof_invalid" => Self::AgentProofInvalid,
            "agent_self_approval_rejected" => Self::AgentSelfApprovalRejected,
            "approval_failed" => Self::ApprovalFailed,
            "approval_required" => Self::ApprovalRequired,
            "broker_client_untrusted" => Self::BrokerClientUntrusted,
            "deny_failed" => Self::DenyFailed,
            "execute_authorization_expired" => Self::ExecuteAuthorizationExpired,
            "execute_authorization_invalid" => Self::ExecuteAuthorizationInvalid,
            "execute_authorization_mismatch" => Self::ExecuteAuthorizationMismatch,
            "execute_authorization_replayed" => Self::ExecuteAuthorizationReplayed,
            "execute_authorization_required" => Self::ExecuteAuthorizationRequired,
            "execution_failed" => Self::ExecutionFailed,
            "grant_lookup_failed" => Self::GrantLookupFailed,
            "human_approval_required" => Self::HumanApprovalRequired,
            "human_session_required" => Self::HumanSessionRequired,
            "invalid_token" => Self::InvalidToken,
            "list_keys_authorization_required" => Self::ListKeysAuthorizationRequired,
            "list_keys_failed" => Self::ListKeysFailed,
            "mode_confirmation_required" => Self::ModeConfirmationRequired,
            "mode_env_violation" => Self::ModeEnvViolation,
            "policy_denied" => Self::PolicyDenied,
            "project_config_unavailable" => Self::ProjectConfigUnavailable,
            "project_lock_failed" => Self::ProjectLockFailed,
            "project_provision_failed" => Self::ProjectProvisionFailed,
            "project_session_failed" => Self::ProjectSessionFailed,
            "project_setup_failed" => Self::ProjectSetupFailed,
            "project_snapshot_failed" => Self::ProjectSnapshotFailed,
            "project_unresolved" => Self::ProjectUnresolved,
            "security_policy_violation" => Self::SecurityPolicyViolation,
            "signing_key_unavailable" => Self::SigningKeyUnavailable,
            "signing_payload_invalid" => Self::SigningPayloadInvalid,
            "stop_failed" => Self::StopFailed,
            "unlock_failed" => Self::UnlockFailed,
            "vault_key_missing" => Self::VaultKeyMissing,
            "unlock_required" => Self::UnlockRequired,
            "broker_unavailable" => Self::BrokerUnavailable,
            "protocol_failure" => Self::ProtocolFailure,
            "internal_failure" => Self::InternalFailure,
            other => Self::Other(other.to_string()),
        }
    }
}

impl Serialize for BrokerReason {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BrokerReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Debug, Clone)]
pub struct BrokerError {
    reason: BrokerReason,
    message: String,
}

impl BrokerError {
    fn new(reason: impl Into<BrokerReason>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
        }
    }

    pub fn reason(&self) -> &BrokerReason {
        &self.reason
    }

    pub fn kind(&self) -> BrokerFailureKind {
        self.reason.kind()
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason.as_str(), self.message)
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

include!("broker_parts/runtime.rs");
include!("broker_parts/routing.rs");
include!("broker_parts/project_ops.rs");
include!("broker_parts/authorization.rs");
include!("broker_parts/sessions.rs");
include!("broker_parts/transport.rs");
include!("broker_parts/coverage.rs");

#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;
