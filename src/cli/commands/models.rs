#[derive(Serialize)]
struct VaultImportEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    source: &'a Path,
    vault: &'a Path,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvFileEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    env_file: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
}

#[derive(Serialize)]
struct RequestEvent<'a> {
    #[serde(rename = "correlationId")]
    correlation_id: uuid::Uuid,
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    expires_at: Option<&'a chrono::DateTime<chrono::Utc>>,
    access: &'a AccessRequest,
    policy: &'a policy::PolicyEvaluation,
    git: &'a git_context::GitContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestAuditSnapshot<'a> {
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    action: &'a Option<String>,
    command: &'a str,
    env: &'a [String],
    requested_env: &'a [String],
    matched_profile: &'a Option<String>,
    matched_preset: &'a Option<String>,
    matched_mode: &'a Option<String>,
    policy_findings: &'a [detection::Finding],
    git: &'a git_context::GitContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalEvent<'a> {
    correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    project: &'a str,
    approval_channel: ApprovalChannel,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_snapshot: Option<RequestAuditSnapshot<'a>>,
    decision: &'a ApprovalDecision,
    persisted_grant: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<&'a str>,
    critical_confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    human_proof: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionStartedEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    declared_action: &'a Option<String>,
    requested_command: &'a str,
    cwd: &'a Path,
    execution_cwd: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_root: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_relative_path: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mounted_command: Option<&'a str>,
    git: &'a git_context::GitContext,
    requested_env: &'a [String],
    injected_env: &'a [String],
    policy_findings: &'a [detection::Finding],
    approval_scope: ApprovalScope,
    approval_source: approvals::ApprovalSource,
    approval_channel: ApprovalChannel,
    grant_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_origin_request_id: Option<uuid::Uuid>,
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    declared_action: &'a Option<String>,
    requested_command: &'a str,
    cwd: &'a Path,
    execution_cwd: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_root: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_relative_path: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mounted_command: Option<&'a str>,
    git: &'a git_context::GitContext,
    requested_env: &'a [String],
    injected_env: &'a [String],
    policy_findings: &'a [detection::Finding],
    approval_scope: ApprovalScope,
    approval_source: approvals::ApprovalSource,
    approval_channel: ApprovalChannel,
    grant_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_origin_request_id: Option<uuid::Uuid>,
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
    outcome: &'a runner::RunCommandOutcome,
}

#[derive(Serialize)]
struct OutputRedactionEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    command: &'a str,
    count: usize,
    alerts: &'a [runner::OutputAlert],
}

#[derive(Serialize)]
struct VaultEditEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
}

#[derive(Serialize)]
struct VaultUnlockEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    status: &'a str,
    project: &'a str,
    vault: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultLockEvent {
    #[serde(rename = "type")]
    event_type: &'static str,
    revoked_session_grants: usize,
    cleared_unlock_sessions: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogsUnlockEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
    expires_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WardOffEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    disabled_path: &'a Path,
    restored: usize,
    skipped: usize,
    failed: usize,
    revoked_session_grants: usize,
    cleared_unlock_sessions: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WardOnEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    disabled_path: &'a Path,
    removed_disabled_state: bool,
    locked: usize,
    skipped: usize,
    failed: usize,
}

#[derive(Debug, Clone)]
struct ProjectDiscoveryCandidate {
    display_name: String,
    path: PathBuf,
    vault: PathBuf,
    source: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectsDiscoverSummary {
    root: PathBuf,
    discovered: usize,
    registered: usize,
    updated: usize,
    projects: Vec<registry::DiscoveryRegistration>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WardOffSummary {
    disabled: bool,
    disabled_path: PathBuf,
    restored: usize,
    skipped: usize,
    failed: usize,
    revoked_session_grants: usize,
    cleared_unlock_sessions: usize,
    projects: Vec<WardOffProjectStatus>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WardOnSummary {
    disabled: bool,
    disabled_path: PathBuf,
    removed_disabled_state: bool,
    locked: usize,
    skipped: usize,
    failed: usize,
    projects: Vec<WardOnProjectStatus>,
}

#[derive(Debug, Clone)]
struct SetupOptions {
    yes: bool,
    project: Option<String>,
    source: PathBuf,
    vault: PathBuf,
    key_mode: vault::VaultKeyMode,
    commit_vault: bool,
    ignore_vault: bool,
    remove_plaintext: bool,
    keep_plaintext: bool,
    unlock_ttl: String,
    no_unlock: bool,
}

const SETUP_GUIDED_BODY: &str = "Ward will encrypt your local env, create a vault, and prepare this project for safe human and agent access.";
const WORKSPACE_SETUP_BODY: &str = "Ward detected a monorepo workspace. It will configure each app with its own encrypted vault and trust this workspace Git root for agent runs.";
const WORKSPACE_SETUP_PROMPT_HELP: &str =
    "Ward will create or refresh app-level .ward.json files, vaults, profiles, and workspace-root trust.";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceSetupResult {
    workspace: String,
    root: PathBuf,
    configured: Vec<WorkspaceSetupItem>,
    skipped: Vec<WorkspaceSetupItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceSetupItem {
    app: String,
    project: String,
    path: PathBuf,
    status: String,
    reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    source: &'a Path,
    vault: &'a Path,
    imported: bool,
    removed_plaintext: bool,
    locked_env: bool,
    committed_vault: bool,
    unlock_created: bool,
    unlock_expires_at: Option<String>,
}

struct RunOptions {
    profile: Option<String>,
    project: Option<String>,
    agent: Option<String>,
    branch: Option<String>,
    action: Option<String>,
    env_names: Vec<String>,
    command: Vec<String>,
    json: bool,
    no_prompt: bool,
    wait_for_approval: bool,
    approval_timeout: String,
}

#[derive(Debug, Clone, Default)]
struct AgentContextOptions {
    agent: Option<String>,
    agent_key_id: Option<String>,
    worktree: Option<PathBuf>,
    git_remote: Option<String>,
    commit: Option<String>,
    branch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunApprovalRequiredResponse<'a> {
    status: &'static str,
    unlock_required: bool,
    #[serde(flatten)]
    request: pending_requests::PendingRequestResponse<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunUnlockRequiredResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unlock_reason: Option<&'a str>,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    findings: &'a [detection::Finding],
    risk: String,
    unlock_command: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDeniedResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    findings: &'a [detection::Finding],
    risk: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunVaultKeyMissingResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    missing_env: Vec<String>,
    findings: &'a [detection::Finding],
    risk: String,
    message: &'static str,
    remediation: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvalidInvocationResponse {
    status: &'static str,
    reason: &'static str,
    message: &'static str,
    correct_example: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeRequiredResponse<'a> {
    status: &'static str,
    approval_required: bool,
    approval_type: &'static str,
    project: &'a str,
    worktree: &'a Path,
    git_remote: &'a str,
    branch: &'a str,
    commit: &'a str,
    reason: &'a str,
    approval_options: Vec<WorktreeApprovalOption>,
    approve_command: String,
    deny_command: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeApprovalOption {
    action: &'static str,
    label: &'static str,
    command: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeBoundResponse<'a> {
    status: &'static str,
    project: &'a str,
    worktree: &'a Path,
    match_kind: &'a str,
    continued: bool,
}

#[derive(Debug, Clone)]
struct ResolvedProfile {
    command: String,
    command_args: Vec<String>,
    env_names: Vec<String>,
    action: Option<String>,
    default_scope: ApprovalScope,
}

#[derive(Debug, Clone)]
struct PlannedProfile {
    profile: ResolvedProfile,
    policy_command: String,
    mounted: bool,
}
