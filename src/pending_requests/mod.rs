use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    approvals::ApprovalScope,
    context::VerifiedContext,
    detection::{self, Finding},
    fs_util,
    git_context::GitContext,
    logs,
    policy::{AccessRequest, PolicyEvaluation},
};

const PENDING_REQUEST_MINUTES: i64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingRequest {
    pub id: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub access: AccessRequest,
    pub policy: PolicyEvaluation,
    pub git: GitContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_context: Option<VerifiedContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingRequestResolution {
    pub request_id: uuid::Uuid,
    pub status: String,
    pub project: String,
    pub resolved_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingRequestResponse<'a> {
    pub approval_required: bool,
    pub request_id: uuid::Uuid,
    pub project: &'a str,
    pub command: &'a str,
    pub env: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_preset: Option<&'a str>,
    pub findings: &'a [Finding],
    pub risk: String,
    pub confirmation_required: bool,
    pub confirmation: Option<CriticalConfirmation>,
    pub approval_options: Vec<ApprovalScope>,
    pub approve_commands: Vec<ApprovalCommand>,
    pub deny_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalCommand {
    pub scope: ApprovalScope,
    pub command: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CriticalConfirmation {
    pub title: &'static str,
    pub body: String,
    pub recommended_action: &'static str,
    pub deny_command: String,
    pub approve_once_command: String,
}

pub fn requests_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(
        std::path::Path::new("requests"),
        "pending requests directory",
    )
    .expect("pending requests directory should stay inside Ward home")
}

pub fn pending_request_path(id: uuid::Uuid) -> PathBuf {
    request_path(id)
}

pub fn create_pending_request(
    access: AccessRequest,
    policy: PolicyEvaluation,
    git: GitContext,
) -> Result<PendingRequest> {
    create_pending_request_with_context(access, policy, git, None)
}

pub fn create_pending_request_with_context(
    access: AccessRequest,
    policy: PolicyEvaluation,
    git: GitContext,
    verified_context: Option<VerifiedContext>,
) -> Result<PendingRequest> {
    let now = Utc::now();
    let pending = PendingRequest {
        id: uuid::Uuid::new_v4(),
        created_at: now,
        expires_at: now + Duration::minutes(PENDING_REQUEST_MINUTES),
        access,
        policy,
        git,
        verified_context,
    };
    write_pending_request(&pending)?;
    Ok(pending)
}

pub fn load_pending_request(id: uuid::Uuid) -> Result<PendingRequest> {
    let path = request_path(id);
    let contents =
        fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    let pending = serde_json::from_str::<PendingRequest>(&contents)
        .context(format!("failed to parse {}", path.display()))?;
    if pending.expires_at <= Utc::now() {
        anyhow::bail!("pending request {id} expired");
    }
    Ok(pending)
}

pub fn list_pending_requests() -> Result<Vec<PendingRequest>> {
    let dir = requests_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut requests = Vec::new();
    for entry in fs::read_dir(&dir).context(format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let contents =
            fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
        let pending = serde_json::from_str::<PendingRequest>(&contents)
            .context(format!("failed to parse {}", path.display()))?;
        if pending.expires_at > Utc::now() {
            requests.push(pending);
        }
    }
    requests.sort_by_key(|request| std::cmp::Reverse(request.created_at));
    Ok(requests)
}

pub fn consume_pending_request(id: uuid::Uuid) -> Result<PendingRequest> {
    let pending = load_pending_request(id)?;
    let path = request_path(id);
    fs::remove_file(&path).context(format!("failed to remove {}", path.display()))?;
    Ok(pending)
}

pub fn record_resolution(id: uuid::Uuid, status: &str, project: &str) -> Result<()> {
    let resolution = PendingRequestResolution {
        request_id: id,
        status: status.to_string(),
        project: project.to_string(),
        resolved_at: Utc::now(),
    };
    let path = resolution_path(id);
    fs_util::ensure_private_parent_dir(&path)?;
    let contents =
        serde_json::to_string_pretty(&resolution).expect("resolution serialization is infallible");
    fs_util::write_private_file(&path, format!("{contents}\n").as_bytes())
}

pub fn load_resolution(id: uuid::Uuid) -> Result<Option<PendingRequestResolution>> {
    let path = resolution_path(id);
    if !path.exists() {
        return Ok(None);
    }
    let contents =
        fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    serde_json::from_str::<PendingRequestResolution>(&contents)
        .map(Some)
        .context(format!("failed to parse {}", path.display()))
}

pub fn remove_project_requests(project: &str) -> Result<usize> {
    let dir = requests_dir();
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(&dir).context(format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let contents =
            fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
        let pending = serde_json::from_str::<PendingRequest>(&contents)
            .context(format!("failed to parse {}", path.display()))?;
        if pending.access.project == project {
            fs::remove_file(&path).context(format!("failed to remove {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn response_for(pending: &PendingRequest) -> PendingRequestResponse<'_> {
    let confirmation_required = detection::has_critical_findings(&pending.policy.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&pending.policy.findings);
    let approval_options = approval_options(
        pending.access.branch.is_some(),
        confirmation_required,
        suspicious_action,
    );
    PendingRequestResponse {
        approval_required: true,
        request_id: pending.id,
        project: &pending.access.project,
        command: &pending.access.command,
        env: &pending.access.env,
        matched_profile: pending.policy.matched_profile.as_deref(),
        matched_preset: pending.policy.matched_preset.as_deref(),
        findings: &pending.policy.findings,
        risk: risk_summary(&pending.policy),
        confirmation_required,
        confirmation: confirmation_required.then(|| critical_confirmation(pending)),
        approve_commands: approve_commands(pending.id, &approval_options, confirmation_required),
        deny_command: format!("ward deny {}", pending.id),
        approval_options,
    }
}

fn write_pending_request(pending: &PendingRequest) -> Result<()> {
    let path = request_path(pending.id);
    fs_util::ensure_private_dir(&logs::ward_home())?;
    fs_util::ensure_private_parent_dir(&path)?;
    let contents =
        serde_json::to_string_pretty(pending).expect("pending request serialization is infallible");
    fs_util::write_private_file(&path, format!("{contents}\n").as_bytes())
}

fn request_path(id: uuid::Uuid) -> PathBuf {
    let relative = PathBuf::from("requests").join(format!("{id}.json"));
    fs_util::resolve_ward_home_path(&relative, "pending request path")
        .expect("pending request path should stay inside Ward home")
}

fn resolution_path(id: uuid::Uuid) -> PathBuf {
    let relative = PathBuf::from("requests")
        .join("resolved")
        .join(format!("{id}.json"));
    fs_util::resolve_ward_home_path(&relative, "pending request resolution path")
        .expect("pending request resolution path should stay inside Ward home")
}

fn critical_confirmation(pending: &PendingRequest) -> CriticalConfirmation {
    CriticalConfirmation {
        title: "Critical secret exposure warning",
        body: "This request matched deterministic secret-exfiltration patterns. Approve only if you explicitly expect this exact command to inspect, print, transform, copy, or transmit secrets.".to_string(),
        recommended_action: "deny",
        deny_command: format!("ward deny {}", pending.id),
        approve_once_command: format!(
            "ward approve {} --scope once --confirm-critical",
            pending.id
        ),
    }
}

fn approval_options(
    include_branch: bool,
    critical: bool,
    suspicious_action: bool,
) -> Vec<ApprovalScope> {
    if critical {
        return vec![ApprovalScope::Once, ApprovalScope::Deny];
    }

    let mut options = vec![ApprovalScope::Once, ApprovalScope::Session];
    if include_branch {
        options.insert(2, ApprovalScope::Branch);
    }
    if !suspicious_action {
        options.push(ApprovalScope::Always);
    }
    options.push(ApprovalScope::Deny);
    options
}

fn approve_commands(
    request_id: uuid::Uuid,
    scopes: &[ApprovalScope],
    critical: bool,
) -> Vec<ApprovalCommand> {
    scopes
        .iter()
        .copied()
        .filter(|scope| *scope != ApprovalScope::Deny)
        .map(|scope| {
            let confirm = if critical { " --confirm-critical" } else { "" };
            ApprovalCommand {
                scope,
                command: format!(
                    "ward approve {request_id} --scope {}{confirm}",
                    scope.as_cli_value()
                ),
            }
        })
        .collect()
}

fn risk_summary(policy: &PolicyEvaluation) -> String {
    if detection::has_critical_findings(&policy.findings) {
        "critical".to_string()
    } else if !policy.findings.is_empty() || !policy.denied_env.is_empty() {
        "warning".to_string()
    } else {
        "low".to_string()
    }
}

impl ApprovalScope {
    fn as_cli_value(self) -> &'static str {
        match self {
            ApprovalScope::Once => "once",
            ApprovalScope::Session => "session",
            ApprovalScope::Branch => "branch",
            ApprovalScope::Always => "always",
            ApprovalScope::Deny => "deny",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{git_context::GitContext, policy::ApprovalMode};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn env_lock() -> crate::test_support::TestEnvironment {
        crate::test_support::TestEnvironment::lock()
    }

    fn pending() -> PendingRequest {
        PendingRequest {
            id: uuid::Uuid::new_v4(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(30),
            access: AccessRequest {
                project: "demo".to_string(),
                agent: Some("codex".to_string()),
                branch: Some("feature/test".to_string()),
                action: Some("Run dev".to_string()),
                command: "pnpm dev".to_string(),
                env: vec!["DATABASE_URL".to_string()],
            },
            policy: PolicyEvaluation {
                matched_profile: None,
                matched_preset: None,
                matched_mode: None,
                approval_mode: ApprovalMode::Prompt,
                requested_env: vec!["DATABASE_URL".to_string()],
                approved_env: Vec::new(),
                denied_env: vec!["DATABASE_URL".to_string()],
                requires_prompt: true,
                findings: Vec::new(),
            },
            git: GitContext::default(),
            verified_context: None,
        }
    }

    #[test]
    #[serial_test::serial]
    fn creates_loads_consumes_and_summarizes_pending_request() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());

        let created =
            create_pending_request(pending().access, pending().policy, GitContext::default())
                .unwrap();
        let response = response_for(&created);
        assert_eq!(response.risk, "warning");
        assert!(!response.confirmation_required);
        assert!(response.confirmation.is_none());
        assert!(response.findings.is_empty());
        assert!(response.approval_options.contains(&ApprovalScope::Branch));

        assert_eq!(load_pending_request(created.id).unwrap().id, created.id);
        assert_eq!(consume_pending_request(created.id).unwrap().id, created.id);
        assert!(load_pending_request(created.id).is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn expired_pending_request_is_rejected() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        let mut pending = pending();
        pending.expires_at = Utc::now() - Duration::minutes(1);
        write_pending_request(&pending).unwrap();

        assert!(load_pending_request(pending.id).is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    fn response_reports_low_and_critical_risk_without_branch_option() {
        let mut pending = pending();
        pending.access.branch = None;
        pending.policy.denied_env.clear();
        let low = response_for(&pending);
        assert_eq!(low.risk, "low");
        assert!(!low.confirmation_required);
        assert!(!low.approval_options.contains(&ApprovalScope::Branch));

        pending
            .policy
            .findings
            .push(crate::detection::Finding::critical(
                "critical.test",
                "critical finding",
            ));
        let critical = response_for(&pending);
        assert_eq!(critical.risk, "critical");
        assert!(critical.confirmation_required);
        assert_eq!(
            critical.approval_options,
            vec![ApprovalScope::Once, ApprovalScope::Deny]
        );
        let confirmation = critical.confirmation.unwrap();
        assert_eq!(confirmation.recommended_action, "deny");
        assert!(confirmation
            .approve_once_command
            .contains("--confirm-critical"));
        assert!(confirmation.deny_command.contains("ward deny"));
    }

    #[test]
    fn response_omits_always_for_suspicious_action_warnings() {
        let mut pending = pending();
        pending.policy.denied_env.clear();
        pending
            .policy
            .findings
            .push(crate::detection::Finding::warning(
                "action.approval_coercion",
                "coercive action",
            ));

        let response = response_for(&pending);

        assert_eq!(response.risk, "warning");
        assert!(!response.approval_options.contains(&ApprovalScope::Always));
        assert!(response.approval_options.contains(&ApprovalScope::Session));
        assert!(!response
            .approve_commands
            .iter()
            .any(|command| command.scope == ApprovalScope::Always));
    }

    #[test]
    #[serial_test::serial]
    fn pending_request_storage_reports_write_and_parse_failures() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let blocked_home = tempdir.path().join("blocked-home");
        std::fs::write(&blocked_home, "").unwrap();
        std::env::set_var("WARD_HOME", &blocked_home);

        assert!(
            create_pending_request(pending().access, pending().policy, GitContext::default())
                .is_err()
        );

        std::env::set_var("WARD_HOME", tempdir.path());
        let invalid_id = uuid::Uuid::new_v4();
        let path = request_path(invalid_id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{bad-json}").unwrap();

        assert!(load_pending_request(invalid_id).is_err());
        assert!(consume_pending_request(uuid::Uuid::new_v4()).is_err());

        let directory_id = uuid::Uuid::new_v4();
        let directory_path = request_path(directory_id);
        std::fs::create_dir(&directory_path).unwrap();
        let mut directory_pending = pending();
        directory_pending.id = directory_id;
        assert!(write_pending_request(&directory_pending).is_err());

        #[cfg(unix)]
        {
            std::fs::remove_dir(&directory_path).unwrap();
            let remove_id = uuid::Uuid::new_v4();
            let remove_path = request_path(remove_id);
            let mut remove_pending = pending();
            remove_pending.id = remove_id;
            write_pending_request(&remove_pending).unwrap();
            let requests_dir = remove_path.parent().unwrap();
            let original_permissions = std::fs::metadata(requests_dir).unwrap().permissions();
            std::fs::set_permissions(requests_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let result = consume_pending_request(remove_id);
            std::fs::set_permissions(requests_dir, original_permissions).unwrap();
            assert!(result.is_err());
            std::fs::remove_file(remove_path).unwrap();
        }

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn removes_project_pending_requests_and_exposes_cli_scope_values() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());

        assert_eq!(remove_project_requests("demo").unwrap(), 0);

        let mut demo = pending();
        write_pending_request(&demo).unwrap();
        let mut other = pending();
        other.id = uuid::Uuid::new_v4();
        other.access.project = "other".to_string();
        write_pending_request(&other).unwrap();
        std::fs::write(requests_dir().join("ignored.txt"), "not-json").unwrap();

        assert_eq!(remove_project_requests("demo").unwrap(), 1);
        assert!(!request_path(demo.id).exists());
        assert!(request_path(other.id).exists());

        assert_eq!(ApprovalScope::Once.as_cli_value(), "once");
        assert_eq!(ApprovalScope::Session.as_cli_value(), "session");
        assert_eq!(ApprovalScope::Branch.as_cli_value(), "branch");
        assert_eq!(ApprovalScope::Always.as_cli_value(), "always");
        assert_eq!(ApprovalScope::Deny.as_cli_value(), "deny");

        demo.id = uuid::Uuid::new_v4();
        std::fs::write(request_path(demo.id), "{bad-json}").unwrap();
        assert!(remove_project_requests("demo").is_err());

        std::env::remove_var("WARD_HOME");
    }
}
