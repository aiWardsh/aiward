use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    approvals::{self, ApprovalChannel, ApprovalDecision, ApprovalScope},
    config::ProjectConfig,
    context, detection, git_context, logs,
    logs::LogKind,
    policy::{self, AccessRequest},
    registry::{self, RegisteredProject},
    runner,
};

#[derive(Serialize)]
pub struct RequestEvent<'a> {
    #[serde(rename = "correlationId")]
    pub correlation_id: uuid::Uuid,
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<uuid::Uuid>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<&'a chrono::DateTime<chrono::Utc>>,
    pub access: &'a AccessRequest,
    pub policy: &'a policy::PolicyEvaluation,
    pub git: &'a git_context::GitContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAuditSnapshot<'a> {
    pub project: &'a str,
    pub agent: &'a Option<String>,
    pub branch: &'a Option<String>,
    pub action: &'a Option<String>,
    pub command: &'a str,
    pub env: &'a [String],
    pub requested_env: &'a [String],
    pub matched_profile: &'a Option<String>,
    pub matched_preset: &'a Option<String>,
    pub matched_mode: &'a Option<String>,
    pub policy_findings: &'a [detection::Finding],
    pub git: &'a git_context::GitContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalEvent<'a> {
    pub correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<uuid::Uuid>,
    pub project: &'a str,
    pub approval_channel: ApprovalChannel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_snapshot: Option<RequestAuditSnapshot<'a>>,
    pub decision: &'a ApprovalDecision,
    pub persisted_grant: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<&'a str>,
    pub critical_confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_proof: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionStartedEvent<'a> {
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<uuid::Uuid>,
    pub project: &'a str,
    pub agent: &'a Option<String>,
    pub branch: &'a Option<String>,
    pub declared_action: &'a Option<String>,
    pub requested_command: &'a str,
    pub cwd: &'a Path,
    pub git: &'a git_context::GitContext,
    pub requested_env: &'a [String],
    pub injected_env: &'a [String],
    pub policy_findings: &'a [detection::Finding],
    pub approval_scope: ApprovalScope,
    pub approval_source: approvals::ApprovalSource,
    pub approval_channel: ApprovalChannel,
    pub grant_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_origin_request_id: Option<uuid::Uuid>,
    pub approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionEvent<'a> {
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<uuid::Uuid>,
    pub project: &'a str,
    pub agent: &'a Option<String>,
    pub branch: &'a Option<String>,
    pub declared_action: &'a Option<String>,
    pub requested_command: &'a str,
    pub cwd: &'a Path,
    pub git: &'a git_context::GitContext,
    pub requested_env: &'a [String],
    pub injected_env: &'a [String],
    pub policy_findings: &'a [detection::Finding],
    pub approval_scope: ApprovalScope,
    pub approval_source: approvals::ApprovalSource,
    pub approval_channel: ApprovalChannel,
    pub grant_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_origin_request_id: Option<uuid::Uuid>,
    pub approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_context: Option<&'a context::VerifiedContext>,
    pub outcome: &'a runner::RunCommandOutcome,
}

pub fn request_snapshot<'a>(
    access: &'a AccessRequest,
    evaluation: &'a policy::PolicyEvaluation,
    git: &'a git_context::GitContext,
    verified_context: Option<&'a context::VerifiedContext>,
) -> RequestAuditSnapshot<'a> {
    RequestAuditSnapshot {
        project: &access.project,
        agent: &access.agent,
        branch: &access.branch,
        action: &access.action,
        command: &access.command,
        env: &access.env,
        requested_env: &evaluation.requested_env,
        matched_profile: &evaluation.matched_profile,
        matched_preset: &evaluation.matched_preset,
        matched_mode: &evaluation.matched_mode,
        policy_findings: &evaluation.findings,
        git,
        verified_context,
    }
}

pub fn channel_for_source(source: approvals::ApprovalSource) -> ApprovalChannel {
    match source {
        approvals::ApprovalSource::LocalTty => ApprovalChannel::LocalPrompt,
        approvals::ApprovalSource::ManualAllow => ApprovalChannel::ManualAllow,
        approvals::ApprovalSource::AgentMediated => ApprovalChannel::AgentMediatedCli,
        approvals::ApprovalSource::Grant => ApprovalChannel::GrantReuse,
        approvals::ApprovalSource::PolicyAuto => ApprovalChannel::PolicyAuto,
        approvals::ApprovalSource::PolicyDeny => ApprovalChannel::PolicyDeny,
    }
}

pub fn terminal_channel(agent_mediated: bool) -> ApprovalChannel {
    if agent_mediated {
        ApprovalChannel::AgentMediatedCli
    } else {
        ApprovalChannel::TerminalApprove
    }
}

pub fn should_log_approval_event(decision: &ApprovalDecision) -> bool {
    decision.source != approvals::ApprovalSource::Grant
}

pub fn human_proof(source: approvals::ApprovalSource) -> Option<&'static str> {
    match source {
        approvals::ApprovalSource::AgentMediated => Some("external-agent-ui"),
        approvals::ApprovalSource::LocalTty => Some("local-tty"),
        approvals::ApprovalSource::ManualAllow => Some("local-cli"),
        _ => None,
    }
}

pub fn critical_confirmation_for_decision(
    decision: &ApprovalDecision,
    evaluation: &policy::PolicyEvaluation,
) -> bool {
    decision.approved
        && decision.scope == ApprovalScope::Once
        && detection::has_critical_findings(&evaluation.findings)
}

pub fn load_dashboard_events(project_filter: Option<&str>) -> Vec<Value> {
    let registry = registry::list_projects().unwrap_or_default();
    let mut all = Vec::new();
    for &kind in LogKind::all() {
        if let Ok(events) = logs::decrypt_events(kind) {
            for mut event in events {
                scrub_sensitive_fields(&mut event);
                let project = infer_event_project(&event, &registry.projects);
                if let Some(filter) = project_filter {
                    if project.as_deref() != Some(filter) {
                        continue;
                    }
                }
                if let Some(obj) = event.as_object_mut() {
                    obj.insert(
                        "_kind".to_string(),
                        Value::String(event_kind_str(kind).to_string()),
                    );
                    if let Some(project) = project {
                        obj.insert("_project".to_string(), Value::String(project));
                    }
                }
                all.push(event);
            }
        }
    }
    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(Value::as_str).unwrap_or("");
        let tb = b.get("timestamp").and_then(Value::as_str).unwrap_or("");
        tb.cmp(ta)
    });
    all
}

pub fn scrub_sensitive_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                if should_redact_key(key) {
                    *nested = Value::String("[redacted]".to_string());
                } else {
                    scrub_sensitive_fields(nested);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_sensitive_fields(item);
            }
        }
        _ => {}
    }
}

pub fn store_diagnostics(config: &ProjectConfig) -> crate::project_store::ProjectStoreDiagnostics {
    crate::project_store::diagnostics(&config.project).unwrap_or_else(|_| {
        crate::project_store::ProjectStoreDiagnostics {
            path: crate::project_store::record_path(&config.project),
            exists: false,
            stale: true,
            env_count: 0,
            profile_count: 0,
            agent_policy_count: 0,
        }
    })
}

fn event_kind_str(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Executions => "execution",
        LogKind::Requests => "request",
        LogKind::Approvals => "approval",
        LogKind::Alerts => "alert",
        LogKind::Sessions => "session",
    }
}

fn infer_event_project(
    event: &Value,
    projects: &BTreeMap<String, RegisteredProject>,
) -> Option<String> {
    let payload = event.get("payload").unwrap_or(event);
    for path in [
        vec!["project"],
        vec!["access", "project"],
        vec!["verifiedContext", "project"],
        vec!["payload", "project"],
    ] {
        if let Some(project) = nested_str(payload, &path) {
            return Some(project.to_string());
        }
    }

    for path in [
        vec!["cwd"],
        vec!["worktree"],
        vec!["git", "worktreePath"],
        vec!["access", "worktree"],
    ] {
        if let Some(candidate) = nested_str(payload, &path) {
            if let Some(project) = project_for_path(candidate, projects) {
                return Some(project);
            }
        }
    }
    None
}

fn nested_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_str)
}

fn project_for_path(path: &str, projects: &BTreeMap<String, RegisteredProject>) -> Option<String> {
    let candidate = PathBuf::from(path);
    projects
        .iter()
        .filter(|(_, project)| candidate.starts_with(&project.path))
        .max_by_key(|(_, project)| project.path.components().count())
        .map(|(name, _)| name.clone())
}

fn should_redact_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("passphrase")
        || lower.contains("sessiontoken")
        || lower == "token"
        || lower.contains("plaintext")
        || lower == "secret"
}
