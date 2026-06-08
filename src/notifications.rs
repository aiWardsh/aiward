use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    approvals::ApprovalScope,
    detection::Finding,
    fs_util,
    pending_requests::{self, PendingRequest},
    worktrees::{self, PendingWorktree},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NotificationKind {
    RunApproval,
    CriticalApproval,
    WorktreeApproval,
    UnlockRequired,
    VaultKeyMissing,
    PolicyDenied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    pub id: String,
    pub kind: NotificationKind,
    pub title: String,
    pub project: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    pub risk: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_type: Option<String>,
    #[serde(default)]
    pub approval_options: Vec<ApprovalScope>,
    #[serde(default)]
    pub approve_commands: Vec<pending_requests::ApprovalCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default)]
    pub can_approve: bool,
    #[serde(default)]
    pub can_deny: bool,
    #[serde(default)]
    pub can_dismiss: bool,
    #[serde(default)]
    pub waiting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockNotification {
    pub id: uuid::Uuid,
    pub kind: NotificationKind,
    pub project: String,
    pub agent: Option<String>,
    pub command: Option<String>,
    pub env: Vec<String>,
    pub findings: Vec<Finding>,
    pub risk: String,
    pub message: String,
    pub fix_command: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub fn notification_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(
        std::path::Path::new("notifications"),
        "notifications directory",
    )
    .expect("notifications directory should stay inside Ward home")
}

pub fn create_block_notification(
    kind: NotificationKind,
    project: &str,
    agent: Option<&str>,
    command: Option<&str>,
    env: &[String],
    findings: &[Finding],
    risk: impl Into<String>,
    message: impl Into<String>,
    fix_command: Option<&str>,
) -> Result<BlockNotification> {
    let now = Utc::now();
    let notification = BlockNotification {
        id: uuid::Uuid::new_v4(),
        kind,
        project: project.to_string(),
        agent: agent.map(str::to_string),
        command: command.map(str::to_string),
        env: env.to_vec(),
        findings: findings.to_vec(),
        risk: risk.into(),
        message: message.into(),
        fix_command: fix_command.map(str::to_string),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(30),
    };
    write_block_notification(&notification)?;
    Ok(notification)
}

pub fn remove_block_notification(id: uuid::Uuid) -> Result<()> {
    let path = block_notification_path(id);
    if path.exists() {
        fs::remove_file(&path).context(format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

pub fn dismiss_notification(id: uuid::Uuid) -> Result<NotificationDismissal> {
    if block_notification_path(id).exists() {
        remove_block_notification(id)?;
        return Ok(NotificationDismissal {
            id,
            status: "dismissed".to_string(),
        });
    }
    if pending_requests::pending_request_path(id).exists() {
        anyhow::bail!("pending approval requests cannot be dismissed; approve or deny the request");
    }
    if worktrees::load_pending_worktree(id)?.is_some() {
        anyhow::bail!(
            "pending worktree bindings cannot be dismissed; approve or deny the worktree request"
        );
    }
    anyhow::bail!("notification not found: {id}")
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationDismissal {
    pub id: uuid::Uuid,
    pub status: String,
}

pub fn list_notifications() -> Result<Vec<Notification>> {
    let mut notifications = Vec::new();
    for pending in pending_requests::list_pending_requests()? {
        notifications.push(run_notification(&pending));
    }
    for pending in worktrees::list_pending_worktrees()? {
        notifications.push(worktree_notification(&pending));
    }
    for block in list_block_notifications()? {
        notifications.push(block_notification(&block));
    }
    notifications.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    Ok(notifications)
}

fn run_notification(pending: &PendingRequest) -> Notification {
    let response = pending_requests::response_for(pending);
    let critical = response.confirmation_required;
    Notification {
        id: pending.id.to_string(),
        kind: if critical {
            NotificationKind::CriticalApproval
        } else {
            NotificationKind::RunApproval
        },
        title: if critical {
            "Critical approval required".to_string()
        } else {
            "Approval required".to_string()
        },
        project: pending.access.project.clone(),
        agent: pending.access.agent.clone(),
        command: Some(pending.access.command.clone()),
        env: pending.access.env.clone(),
        findings: pending.policy.findings.clone(),
        risk: response.risk,
        created_at: pending.created_at,
        expires_at: Some(pending.expires_at),
        request_id: Some(pending.id),
        approval_type: Some("run".to_string()),
        approval_options: response.approval_options,
        approve_commands: response.approve_commands,
        deny_command: Some(response.deny_command),
        fix_command: None,
        message: None,
        worktree: pending
            .verified_context
            .as_ref()
            .map(|context| context.worktree.clone()),
        git_remote: pending
            .verified_context
            .as_ref()
            .map(|context| context.git_remote.clone()),
        branch: pending.access.branch.clone(),
        commit: pending
            .verified_context
            .as_ref()
            .map(|context| context.commit.clone()),
        can_approve: true,
        can_deny: true,
        can_dismiss: false,
        waiting: true,
    }
}

fn worktree_notification(pending: &PendingWorktree) -> Notification {
    Notification {
        id: pending.id.to_string(),
        kind: NotificationKind::WorktreeApproval,
        title: "Worktree approval required".to_string(),
        project: pending.project.clone(),
        agent: None,
        command: None,
        env: Vec::new(),
        findings: Vec::new(),
        risk: "warning".to_string(),
        created_at: pending.created_at,
        expires_at: None,
        request_id: Some(pending.id),
        approval_type: Some("worktreeBinding".to_string()),
        approval_options: Vec::new(),
        approve_commands: Vec::new(),
        deny_command: Some(format!("ward worktrees deny {}", pending.id)),
        fix_command: None,
        message: Some(pending.reason.clone()),
        worktree: Some(pending.path.clone()),
        git_remote: Some(pending.git_remote.clone()),
        branch: Some(pending.branch.clone()),
        commit: Some(pending.commit.clone()),
        can_approve: true,
        can_deny: true,
        can_dismiss: false,
        waiting: true,
    }
}

fn block_notification(block: &BlockNotification) -> Notification {
    Notification {
        id: block.id.to_string(),
        kind: block.kind.clone(),
        title: match block.kind {
            NotificationKind::UnlockRequired => "Unlock required",
            NotificationKind::VaultKeyMissing => "Vault key missing",
            NotificationKind::PolicyDenied => "Request denied by policy",
            NotificationKind::RunApproval
            | NotificationKind::CriticalApproval
            | NotificationKind::WorktreeApproval => "Ward notification",
        }
        .to_string(),
        project: block.project.clone(),
        agent: block.agent.clone(),
        command: block.command.clone(),
        env: block.env.clone(),
        findings: block.findings.clone(),
        risk: block.risk.clone(),
        created_at: block.created_at,
        expires_at: Some(block.expires_at),
        request_id: Some(block.id),
        approval_type: None,
        approval_options: Vec::new(),
        approve_commands: Vec::new(),
        deny_command: None,
        fix_command: block.fix_command.clone(),
        message: Some(block.message.clone()),
        worktree: None,
        git_remote: None,
        branch: None,
        commit: None,
        can_approve: false,
        can_deny: false,
        can_dismiss: true,
        waiting: false,
    }
}

fn list_block_notifications() -> Result<Vec<BlockNotification>> {
    let dir = notification_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let now = Utc::now();
    let mut notifications = Vec::new();
    for entry in fs::read_dir(&dir).context(format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let contents =
            fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
        let notification = serde_json::from_str::<BlockNotification>(&contents)
            .context(format!("failed to parse {}", path.display()))?;
        if notification.expires_at <= now {
            let _ = fs::remove_file(&path);
        } else {
            notifications.push(notification);
        }
    }
    Ok(notifications)
}

fn write_block_notification(notification: &BlockNotification) -> Result<()> {
    let path = block_notification_path(notification.id);
    fs_util::ensure_private_parent_dir(&path)?;
    let contents = serde_json::to_string_pretty(notification)
        .expect("block notification serialization is infallible");
    fs_util::write_private_file(&path, format!("{contents}\n").as_bytes())
}

fn block_notification_path(id: uuid::Uuid) -> PathBuf {
    let relative = PathBuf::from("notifications").join(format!("{id}.json"));
    fs_util::resolve_ward_home_path(&relative, "notification path")
        .expect("notification path should stay inside Ward home")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        git_context::GitContext,
        policy::{AccessRequest, ApprovalMode, PolicyEvaluation},
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn access() -> AccessRequest {
        AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("main".to_string()),
            action: Some("Run dev server".to_string()),
            command: "pnpm dev".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        }
    }

    fn evaluation() -> PolicyEvaluation {
        PolicyEvaluation {
            matched_profile: Some("dev".to_string()),
            matched_preset: None,
            matched_mode: None,
            approval_mode: ApprovalMode::Prompt,
            requested_env: vec!["DATABASE_URL".to_string()],
            approved_env: Vec::new(),
            denied_env: Vec::new(),
            requires_prompt: true,
            findings: vec![Finding::warning("test.warning", "warning only")],
        }
    }

    #[test]
    #[serial_test::serial]
    fn list_notifications_normalizes_pending_requests_and_blocks() {
        let _guard = env_lock();
        let previous_home = std::env::var_os("WARD_HOME");
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let pending =
            pending_requests::create_pending_request(access(), evaluation(), GitContext::default())
                .unwrap();
        create_block_notification(
            NotificationKind::UnlockRequired,
            "demo",
            Some("codex"),
            Some("pnpm dev"),
            &["DATABASE_URL".to_string()],
            &[],
            "warning",
            "unlock needed",
            Some("ward unlock --ttl 8h"),
        )
        .unwrap();

        let notifications = list_notifications().unwrap();
        assert_eq!(notifications.len(), 2);
        let run = notifications
            .iter()
            .find(|notification| notification.id == pending.id.to_string())
            .unwrap();
        assert_eq!(run.kind, NotificationKind::RunApproval);
        assert!(run.can_approve);
        assert!(run.can_deny);
        assert!(run.approval_options.contains(&ApprovalScope::Once));
        assert!(run.approval_options.contains(&ApprovalScope::Session));
        assert!(run.approval_options.contains(&ApprovalScope::Deny));
        assert_eq!(run.env, vec!["DATABASE_URL"]);
        let serialized = serde_json::to_string(&notifications).unwrap();
        assert!(serialized.contains("DATABASE_URL"));
        assert!(!serialized.contains("postgres://"));

        match previous_home {
            Some(value) => std::env::set_var("WARD_HOME", value),
            None => std::env::remove_var("WARD_HOME"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn dismiss_notification_only_removes_block_notifications() {
        let _guard = env_lock();
        let previous_home = std::env::var_os("WARD_HOME");
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let pending =
            pending_requests::create_pending_request(access(), evaluation(), GitContext::default())
                .unwrap();
        let block = create_block_notification(
            NotificationKind::VaultKeyMissing,
            "demo",
            Some("codex"),
            Some("pnpm dev"),
            &["DATABASE_URL".to_string()],
            &[],
            "warning",
            "missing key",
            Some("ward env request-set --key DATABASE_URL"),
        )
        .unwrap();

        assert!(dismiss_notification(pending.id)
            .unwrap_err()
            .to_string()
            .contains("cannot be dismissed"));
        assert_eq!(dismiss_notification(block.id).unwrap().status, "dismissed");
        assert!(!block_notification_path(block.id).exists());

        match previous_home {
            Some(value) => std::env::set_var("WARD_HOME", value),
            None => std::env::remove_var("WARD_HOME"),
        }
    }
}
