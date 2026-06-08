use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[cfg(not(test))]
use crate::broker;
#[cfg(test)]
use crate::unlock;
use crate::{
    approval_receipts::{self, ApprovalReceipt},
    approvals::{ApprovalDecision, ApprovalScope, ApprovalSource},
    context, fs_util, logs,
    policy::AccessRequest,
};

const SESSION_GRANT_HOURS: i64 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalGrant {
    pub id: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<uuid::Uuid>,
    pub project: String,
    pub agent: Option<String>,
    pub branch: Option<String>,
    pub command: String,
    pub approved_env: Vec<String>,
    pub scope: ApprovalScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses_remaining: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ApprovalReceipt>,
}

#[derive(Debug, Clone)]
pub struct GrantReceiptContext {
    pub request_id: uuid::Uuid,
    pub pending_request: bool,
    pub critical_confirmation: bool,
    pub verified_context: Option<context::VerifiedContext>,
}

impl GrantReceiptContext {
    pub fn synthetic(critical_confirmation: bool) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4(),
            pending_request: false,
            critical_confirmation,
            verified_context: None,
        }
    }

    pub fn pending(
        request_id: uuid::Uuid,
        critical_confirmation: bool,
        verified_context: Option<context::VerifiedContext>,
    ) -> Self {
        Self {
            request_id,
            pending_request: true,
            critical_confirmation,
            verified_context,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantIntegrityStatus {
    Valid,
    Expired,
    LegacyUnsigned,
    Invalid,
}

pub fn grants_path() -> PathBuf {
    let relative = PathBuf::from("sessions").join("grants.jsonl");
    fs_util::resolve_ward_home_path(&relative, "approval grants path")
        .expect("approval grants path should stay inside Ward home")
}

pub fn find_matching_grant(access: &AccessRequest) -> Result<Option<ApprovalGrant>> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    Ok(find_matching_grant_in(&grants, access, Utc::now()).cloned())
}

pub fn find_matching_grant_with_context(
    access: &AccessRequest,
    verified_context: &context::VerifiedContext,
) -> Result<Option<ApprovalGrant>> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    Ok(find_matching_grant_in_with_context(&grants, access, Utc::now(), verified_context).cloned())
}

pub fn find_matching_once_grant(
    access: &AccessRequest,
    critical_required: bool,
) -> Result<Option<ApprovalGrant>> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    Ok(find_matching_once_grant_in(&grants, access, Utc::now(), critical_required).cloned())
}

pub fn find_matching_once_grant_with_context(
    access: &AccessRequest,
    critical_required: bool,
    verified_context: &context::VerifiedContext,
) -> Result<Option<ApprovalGrant>> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    Ok(find_matching_once_grant_in_with_context(
        &grants,
        access,
        Utc::now(),
        critical_required,
        verified_context,
    )
    .cloned())
}

pub fn find_matching_non_always_grant(access: &AccessRequest) -> Result<Option<ApprovalGrant>> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    Ok(find_matching_non_always_grant_in(&grants, access, Utc::now()).cloned())
}

pub fn find_matching_non_always_grant_with_context(
    access: &AccessRequest,
    verified_context: &context::VerifiedContext,
) -> Result<Option<ApprovalGrant>> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    Ok(find_matching_non_always_grant_in_with_context(
        &grants,
        access,
        Utc::now(),
        verified_context,
    )
    .cloned())
}

pub fn load_grants() -> Result<Vec<ApprovalGrant>> {
    load_grants_from_path(&grants_path())
}

pub fn persist_grant(
    access: &AccessRequest,
    decision: &ApprovalDecision,
    vault: &Path,
    receipt_context: Option<GrantReceiptContext>,
) -> Result<Option<ApprovalGrant>> {
    if !decision.approved
        || !decision.source.is_persistable_approval()
        || !decision.scope.is_persisted_grant()
    {
        return Ok(None);
    }

    let path = grants_path();
    let mut grant = grant_from_decision(access, decision, Utc::now())?;
    let receipt_context = match receipt_context {
        Some(context) => context,
        None => GrantReceiptContext::synthetic(false),
    };
    sign_grant(access, vault, &mut grant, receipt_context)?;
    append_grant_to_path(&path, &grant)?;
    Ok(Some(grant))
}

pub fn persist_manual_grant(
    access: &AccessRequest,
    scope: ApprovalScope,
    source: ApprovalSource,
    vault: &Path,
    receipt_context: Option<GrantReceiptContext>,
) -> Result<ApprovalGrant> {
    if !source.is_persistable_approval() {
        anyhow::bail!("{source:?} cannot create approval grants");
    }
    if scope == ApprovalScope::Deny {
        anyhow::bail!("deny cannot be persisted as an approval grant");
    }
    let decision = ApprovalDecision {
        approved: true,
        scope,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source,
        grant_id: None,
    };
    let mut grant = grant_from_decision(access, &decision, Utc::now())?;
    sign_grant(
        access,
        vault,
        &mut grant,
        receipt_context.unwrap_or_else(|| GrantReceiptContext::synthetic(false)),
    )?;
    append_grant_to_path(&grants_path(), &grant)?;
    Ok(grant)
}

pub fn approval_from_grant(access: &AccessRequest, grant: &ApprovalGrant) -> ApprovalDecision {
    ApprovalDecision {
        approved: true,
        scope: grant.scope,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: ApprovalSource::Grant,
        grant_id: Some(grant.id),
    }
}

pub fn revoke_session_grants() -> Result<usize> {
    let path = grants_path();
    revoke_session_grants_at_path(&path)
}

pub fn revoke_project_session_grants(project: &str) -> Result<usize> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    let before = grants.len();
    let retained = grants
        .into_iter()
        .filter(|grant| grant.project != project || grant.scope != ApprovalScope::Session)
        .collect::<Vec<_>>();
    let revoked = before - retained.len();
    if revoked > 0 {
        write_grants_to_path(&path, &retained)?;
    }
    Ok(revoked)
}

pub fn revoke_grant(id: uuid::Uuid) -> Result<bool> {
    revoke_grant_at_path(&grants_path(), id)
}

pub fn prune_expired_grants() -> Result<usize> {
    prune_expired_grants_at_path(&grants_path(), Utc::now())
}

pub fn remove_project_grants(project: &str) -> Result<usize> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    let before = grants.len();
    let retained = grants
        .into_iter()
        .filter(|grant| grant.project != project)
        .collect::<Vec<_>>();
    let removed = before - retained.len();
    if removed > 0 {
        write_grants_to_path(&path, &retained)?;
    }
    Ok(removed)
}

pub fn consume_once_grant(id: uuid::Uuid) -> Result<bool> {
    let path = grants_path();
    let grants = load_grants_from_path(&path)?;
    let before = grants.len();
    let retained = grants
        .into_iter()
        .filter(|grant| !(grant.id == id && grant.scope == ApprovalScope::Once))
        .collect::<Vec<_>>();
    if retained.len() == before {
        return Ok(false);
    }
    write_grants_to_path(&path, &retained)?;
    Ok(true)
}

pub fn load_grants_from_path(path: &Path) -> Result<Vec<ApprovalGrant>> {
    fs_util::reject_parent_traversal(path, "approval grants path")?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = fs_util::read_file_to_string(path, "approval grants")?;
    let mut grants = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let grant = match serde_json::from_str::<ApprovalGrant>(&line) {
            Ok(grant) => grant,
            Err(error) => {
                anyhow::bail!(
                    "failed to parse grant on line {} of {}: {error}",
                    index + 1,
                    path.display()
                );
            }
        };
        grants.push(grant);
    }

    Ok(grants)
}

pub fn append_grant_to_path(path: &Path, grant: &ApprovalGrant) -> Result<()> {
    fs_util::reject_parent_traversal(path, "approval grants path")?;
    ensure_ward_home_for(path)?;
    let mut file = fs_util::open_private_append(path)?;
    let line = serde_json::to_string(grant).expect("approval grants should serialize");
    writeln!(file, "{line}").context(format!("failed to write {}", path.display()))
}

pub fn revoke_session_grants_at_path(path: &Path) -> Result<usize> {
    let grants = load_grants_from_path(path)?;
    if grants.is_empty() {
        return Ok(0);
    }

    let before = grants.len();
    let retained = grants
        .into_iter()
        .filter(|grant| grant.scope != ApprovalScope::Session)
        .collect::<Vec<_>>();
    let revoked = before - retained.len();

    write_grants_to_path(path, &retained)?;

    Ok(revoked)
}

pub fn revoke_grant_at_path(path: &Path, id: uuid::Uuid) -> Result<bool> {
    let grants = load_grants_from_path(path)?;
    let before = grants.len();
    let retained = grants
        .into_iter()
        .filter(|grant| grant.id != id)
        .collect::<Vec<_>>();
    if retained.len() == before {
        return Ok(false);
    }
    write_grants_to_path(path, &retained)?;
    Ok(true)
}

pub fn prune_expired_grants_at_path(path: &Path, now: DateTime<Utc>) -> Result<usize> {
    let grants = load_grants_from_path(path)?;
    let before = grants.len();
    let mut retained = Vec::new();
    for grant in grants {
        let retain = match grant.expires_at.as_ref() {
            Some(expires_at) => expires_at > &now,
            None => true,
        };
        if retain {
            retained.push(grant);
        }
    }
    let pruned = before - retained.len();
    if pruned > 0 {
        write_grants_to_path(path, &retained)?;
    }
    Ok(pruned)
}

fn write_grants_to_path(path: &Path, grants: &[ApprovalGrant]) -> Result<()> {
    fs_util::reject_parent_traversal(path, "approval grants path")?;
    ensure_ward_home_for(path)?;
    fs_util::ensure_private_parent_dir(path)?;
    let mut file = fs::File::create(path).context(format!("failed to write {}", path.display()))?;
    fs_util::set_private_file_permissions(path)?;
    for grant in grants {
        let line = serde_json::to_string(grant).expect("approval grants should serialize");
        writeln!(file, "{line}").context(format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

fn ensure_ward_home_for(path: &Path) -> Result<()> {
    let home = logs::ward_home();
    if path.starts_with(&home) {
        fs_util::ensure_private_dir(&home)?;
    }
    Ok(())
}

pub fn find_matching_grant_in<'a>(
    grants: &'a [ApprovalGrant],
    access: &AccessRequest,
    now: DateTime<Utc>,
) -> Option<&'a ApprovalGrant> {
    grants
        .iter()
        .rev()
        .find(|grant| grant_matches_access(grant, access, now, false))
}

pub fn find_matching_grant_in_with_context<'a>(
    grants: &'a [ApprovalGrant],
    access: &AccessRequest,
    now: DateTime<Utc>,
    verified_context: &context::VerifiedContext,
) -> Option<&'a ApprovalGrant> {
    grants.iter().rev().find(|grant| {
        grant_matches_access_with_context(grant, access, now, false, Some(verified_context))
    })
}

pub fn find_matching_once_grant_in<'a>(
    grants: &'a [ApprovalGrant],
    access: &AccessRequest,
    now: DateTime<Utc>,
    critical_required: bool,
) -> Option<&'a ApprovalGrant> {
    grants.iter().rev().find(|grant| {
        grant.scope == ApprovalScope::Once
            && grant_matches_access(grant, access, now, critical_required)
    })
}

pub fn find_matching_once_grant_in_with_context<'a>(
    grants: &'a [ApprovalGrant],
    access: &AccessRequest,
    now: DateTime<Utc>,
    critical_required: bool,
    verified_context: &context::VerifiedContext,
) -> Option<&'a ApprovalGrant> {
    grants.iter().rev().find(|grant| {
        grant.scope == ApprovalScope::Once
            && grant_matches_access_with_context(
                grant,
                access,
                now,
                critical_required,
                Some(verified_context),
            )
    })
}

pub fn find_matching_non_always_grant_in<'a>(
    grants: &'a [ApprovalGrant],
    access: &AccessRequest,
    now: DateTime<Utc>,
) -> Option<&'a ApprovalGrant> {
    grants.iter().rev().find(|grant| {
        grant.scope != ApprovalScope::Always && grant_matches_access(grant, access, now, false)
    })
}

pub fn find_matching_non_always_grant_in_with_context<'a>(
    grants: &'a [ApprovalGrant],
    access: &AccessRequest,
    now: DateTime<Utc>,
    verified_context: &context::VerifiedContext,
) -> Option<&'a ApprovalGrant> {
    grants.iter().rev().find(|grant| {
        grant.scope != ApprovalScope::Always
            && grant_matches_access_with_context(grant, access, now, false, Some(verified_context))
    })
}

pub fn grant_integrity_status(grant: &ApprovalGrant, now: DateTime<Utc>) -> GrantIntegrityStatus {
    if grant
        .expires_at
        .as_ref()
        .is_some_and(|expires_at| expires_at <= &now)
    {
        return GrantIntegrityStatus::Expired;
    }
    if grant.receipt.is_none() {
        return GrantIntegrityStatus::LegacyUnsigned;
    }
    if receipt_matches_grant(grant) {
        GrantIntegrityStatus::Valid
    } else {
        GrantIntegrityStatus::Invalid
    }
}

pub(crate) fn grant_from_decision(
    access: &AccessRequest,
    decision: &ApprovalDecision,
    now: DateTime<Utc>,
) -> Result<ApprovalGrant> {
    if decision.scope == ApprovalScope::Branch && access.branch.is_none() {
        anyhow::bail!("branch-scoped approval requires a git branch");
    }

    let expires_at = match decision.scope {
        ApprovalScope::Session => Some(now + Duration::hours(SESSION_GRANT_HOURS)),
        ApprovalScope::Once => Some(now + Duration::minutes(15)),
        ApprovalScope::Branch | ApprovalScope::Always => None,
        ApprovalScope::Deny => anyhow::bail!(
            "{} cannot be persisted as an approval grant",
            decision.scope
        ),
    };

    Ok(ApprovalGrant {
        id: uuid::Uuid::new_v4(),
        created_at: now,
        expires_at,
        request_id: None,
        project: access.project.clone(),
        agent: access.agent.clone(),
        branch: access.branch.clone(),
        command: access.command.clone(),
        approved_env: decision.approved_env.clone(),
        scope: decision.scope,
        uses_remaining: (decision.scope == ApprovalScope::Once).then_some(1),
        receipt: None,
    })
}

fn grant_matches_access(
    grant: &ApprovalGrant,
    access: &AccessRequest,
    now: DateTime<Utc>,
    critical_required: bool,
) -> bool {
    grant_matches_access_with_context(grant, access, now, critical_required, None)
}

fn grant_matches_access_with_context(
    grant: &ApprovalGrant,
    access: &AccessRequest,
    now: DateTime<Utc>,
    critical_required: bool,
    verified_context: Option<&context::VerifiedContext>,
) -> bool {
    if grant.scope == ApprovalScope::Deny {
        return false;
    }
    if grant.scope == ApprovalScope::Once && grant.uses_remaining.unwrap_or(0) == 0 {
        return false;
    }
    if grant
        .expires_at
        .as_ref()
        .is_some_and(|expires_at| expires_at <= &now)
    {
        return false;
    }
    if grant.project != access.project || grant.command != access.command {
        return false;
    }
    let Some(receipt) = grant.receipt.as_ref() else {
        return false;
    };
    if !receipt_matches_grant(grant) {
        return false;
    }
    if !receipt_matches_verified_context(receipt, verified_context) {
        return false;
    }
    if critical_required && !receipt.payload.critical_confirmation {
        return false;
    }
    let agent_mismatch = grant
        .agent
        .as_deref()
        .zip(access.agent.as_deref())
        .is_some_and(|(grant_agent, request_agent)| grant_agent != request_agent);
    if agent_mismatch {
        return false;
    }

    if grant.scope == ApprovalScope::Branch && grant.branch.as_deref() != access.branch.as_deref() {
        return false;
    }

    let approved = receipt
        .payload
        .approved_env
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    access
        .env
        .iter()
        .all(|env_name| approved.contains(env_name.as_str()))
}

fn receipt_matches_verified_context(
    receipt: &ApprovalReceipt,
    verified_context: Option<&context::VerifiedContext>,
) -> bool {
    let payload = &receipt.payload;
    let has_bound_context = payload.agent_key_id.is_some()
        || payload.verified_worktree.is_some()
        || payload.verified_git_remote.is_some()
        || payload.verified_commit.is_some();
    match (verified_context, has_bound_context) {
        (Some(verified), _) => {
            payload.agent_key_id.as_deref() == Some(verified.agent_key_id.as_str())
                && payload.verified_worktree.as_ref() == Some(&verified.worktree)
                && payload.verified_git_remote.as_deref() == Some(verified.git_remote.as_str())
                && payload.verified_commit.as_deref() == Some(verified.commit.as_str())
        }
        (None, true) => false,
        (None, false) => true,
    }
}

fn sign_grant(
    access: &AccessRequest,
    vault: &Path,
    grant: &mut ApprovalGrant,
    context: GrantReceiptContext,
) -> Result<()> {
    if context.pending_request {
        grant.request_id = Some(context.request_id);
    }

    #[cfg(not(any(test, coverage)))]
    {
        let broker_payload = approval_receipts::build_payload_with_context(
            access,
            grant.id,
            context.request_id,
            &grant.approved_env,
            grant.scope,
            grant.expires_at,
            context.critical_confirmation,
            grant.created_at,
            String::new(),
            context.verified_context.as_ref(),
        );
        let receipt = broker::sign_receipt(&access.project, vault, broker_payload)
            .map_err(|error| anyhow::anyhow!("signing_key_unavailable: {error}"))?;
        grant.receipt = Some(receipt);
        return Ok(());
    }

    #[cfg(any(test, coverage))]
    {
        let signing_key = match unlock::active_run_signing_key(&access.project, vault)? {
            unlock::RunSigningLookup::Available(signing_key) => signing_key,
            unlock::RunSigningLookup::Missing => anyhow::bail!(
                "signing_key_unavailable: run ward unlock --ttl 8h before creating approval grants"
            ),
            unlock::RunSigningLookup::MaterialUnavailable { reason } => {
                anyhow::bail!("{reason}")
            }
        };
        let payload = approval_receipts::build_payload_with_context(
            access,
            grant.id,
            context.request_id,
            &grant.approved_env,
            grant.scope,
            grant.expires_at,
            context.critical_confirmation,
            grant.created_at,
            signing_key.signer_key_id.clone(),
            context.verified_context.as_ref(),
        );
        let receipt = approval_receipts::sign_payload(payload, &signing_key)
            .expect("grant payload signer id is built from the active signing key");
        grant.receipt = Some(receipt);
        Ok(())
    }
}

fn receipt_matches_grant(grant: &ApprovalGrant) -> bool {
    let Some(receipt) = grant.receipt.as_ref() else {
        return false;
    };
    let payload = &receipt.payload;
    payload.schema_version == 1
        && payload.grant_id == grant.id
        && payload.project == grant.project
        && payload.agent == grant.agent
        && payload.branch == grant.branch
        && payload.command_hash == approval_receipts::command_hash(&grant.command)
        && payload.approved_env == sorted_strings(&grant.approved_env)
        && payload.scope == grant.scope
        && payload.expires_at == grant.expires_at
        && payload.created_at == grant.created_at
        && payload.signer_key_id == receipt.signer_key_id
        && payload
            .agent_key_id
            .as_ref()
            .map_or(true, |value| !value.is_empty())
        && approval_receipts::verify_receipt_signature(&grant.project, receipt)
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted
}

impl ApprovalScope {
    pub fn is_persisted_grant(self) -> bool {
        matches!(
            self,
            ApprovalScope::Session | ApprovalScope::Branch | ApprovalScope::Always
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        approvals::{ApprovalDecision, ApprovalSource},
        unlock,
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn access() -> AccessRequest {
        AccessRequest {
            project: "ambienta".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("feature/x".to_string()),
            action: Some("Run dev server".to_string()),
            command: "pnpm dev".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        }
    }

    fn setup_signing_home() -> (tempfile::TempDir, PathBuf) {
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");
        unlock::create_run_unlock("ambienta", &vault, "1234", Duration::hours(1)).unwrap();
        (tempdir, vault)
    }

    fn clear_signing_home() {
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    fn grant(scope: ApprovalScope, now: DateTime<Utc>, vault: &Path) -> ApprovalGrant {
        let mut grant = ApprovalGrant {
            id: uuid::Uuid::new_v4(),
            created_at: now,
            expires_at: None,
            request_id: None,
            project: "ambienta".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("feature/x".to_string()),
            command: "pnpm dev".to_string(),
            approved_env: vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()],
            scope,
            uses_remaining: (scope == ApprovalScope::Once).then_some(1),
            receipt: None,
        };
        let access = access();
        sign_grant(
            &access,
            vault,
            &mut grant,
            GrantReceiptContext::synthetic(false),
        )
        .unwrap();
        grant
    }

    fn verified_context() -> context::VerifiedContext {
        context::VerifiedContext {
            project: "ambienta".to_string(),
            agent: "codex".to_string(),
            agent_key_id: "agent:key".to_string(),
            worktree: PathBuf::from("/tmp/ambienta-worktree"),
            branch: "feature/x".to_string(),
            git_remote: "https://example.test/ambienta".to_string(),
            commit: "abc123".to_string(),
            git_common_dir: None,
        }
    }

    #[test]
    #[serial_test::serial]
    fn matches_session_branch_and_always_grants() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();

        for scope in [
            ApprovalScope::Session,
            ApprovalScope::Branch,
            ApprovalScope::Always,
        ] {
            let grant = grant(scope, now, &vault);
            assert!(grant_matches_access(&grant, &access, now, false));
        }
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn ignores_once_deny_and_expired_session_grants() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let mut expired = grant(ApprovalScope::Session, now, &vault);
        expired.expires_at = Some(now - Duration::minutes(1));
        let mut spent_once = grant(ApprovalScope::Once, now, &vault);
        spent_once.uses_remaining = Some(0);

        assert!(grant_matches_access(
            &grant(ApprovalScope::Once, now, &vault),
            &access,
            now,
            false
        ));
        assert!(!grant_matches_access(
            &grant(ApprovalScope::Deny, now, &vault),
            &access,
            now,
            false
        ));
        assert!(!grant_matches_access(&spent_once, &access, now, false));
        assert!(!grant_matches_access(&expired, &access, now, false));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn requires_requested_env_subset() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let mut access = access();
        access.env.push("OPENAI_API_KEY".to_string());

        assert!(!grant_matches_access(
            &grant(ApprovalScope::Always, now, &vault),
            &access,
            now,
            false
        ));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn finds_latest_matching_grant_or_once_only_grant() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let always = grant(ApprovalScope::Always, now, &vault);
        let once = grant(ApprovalScope::Once, now, &vault);
        let grants = vec![once.clone(), always.clone()];

        assert_eq!(
            find_matching_grant_in(&grants, &access, now).unwrap().id,
            always.id
        );
        assert_eq!(
            find_matching_once_grant_in(&grants, &access, now, false)
                .unwrap()
                .id,
            once.id
        );
        assert_eq!(
            find_matching_non_always_grant_in(&grants, &access, now)
                .unwrap()
                .id,
            once.id
        );
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn lock_revokes_only_session_grants() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("grants.jsonl");
        let now = Utc::now();

        append_grant_to_path(&path, &grant(ApprovalScope::Session, now, &vault)).unwrap();
        append_grant_to_path(&path, &grant(ApprovalScope::Branch, now, &vault)).unwrap();
        append_grant_to_path(&path, &grant(ApprovalScope::Always, now, &vault)).unwrap();

        let revoked = revoke_session_grants_at_path(&path).unwrap();
        let retained = load_grants_from_path(&path).unwrap();

        assert_eq!(revoked, 1);
        assert_eq!(retained.len(), 2);
        assert!(retained
            .iter()
            .all(|grant| grant.scope != ApprovalScope::Session));
        clear_signing_home();
    }

    #[test]
    fn load_grants_skips_blank_lines_and_reports_invalid_json() {
        let tempdir = tempfile::tempdir().unwrap();
        let blank_path = tempdir.path().join("blank.jsonl");
        let bad_path = tempdir.path().join("bad.jsonl");

        std::fs::write(&blank_path, "\n\n").unwrap();
        std::fs::write(&bad_path, "{not-json}\n").unwrap();

        assert!(load_grants_from_path(&tempdir.path().join("missing.jsonl"))
            .unwrap()
            .is_empty());
        assert!(load_grants_from_path(&blank_path).unwrap().is_empty());
        assert!(load_grants_from_path(&bad_path).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn persist_grant_writes_only_prompt_persisted_approvals() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let access = access();
        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        let grant = persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .unwrap();
        let found = find_matching_grant(&access).unwrap().unwrap();
        let default_context_grant = persist_grant(&access, &decision, &vault, None)
            .unwrap()
            .unwrap();
        assert!(default_context_grant.receipt.is_some());

        clear_signing_home();
        assert_eq!(grant.id, found.id);
    }

    #[test]
    #[serial_test::serial]
    fn persist_grant_reports_append_failures() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let sessions_path = tempdir.path().join("sessions");
        std::fs::write(&sessions_path, "").unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");
        assert!(unlock::create_run_unlock("ambienta", &vault, "1234", Duration::hours(1)).is_err());

        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        assert!(persist_grant(
            &access(),
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn persist_grant_writes_session_scope() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();

        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Session,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };
        let grant = persist_grant(
            &access(),
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .unwrap();

        assert_eq!(grant.scope, ApprovalScope::Session);
        assert!(grant.expires_at.is_some());
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn context_wrapper_lookups_and_default_manual_receipts_are_exercised() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let access = access();
        let context = verified_context();

        let default_grant = persist_manual_grant(
            &access,
            ApprovalScope::Session,
            ApprovalSource::ManualAllow,
            &vault,
            None,
        )
        .unwrap();
        assert!(default_grant.receipt.is_some());

        let receipt_context = GrantReceiptContext {
            request_id: uuid::Uuid::new_v4(),
            pending_request: false,
            critical_confirmation: false,
            verified_context: Some(context.clone()),
        };
        let once_grant = persist_manual_grant(
            &access,
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
            &vault,
            Some(receipt_context),
        )
        .unwrap();
        assert!(once_grant.receipt.is_some());
        assert!(
            find_matching_non_always_grant_with_context(&access, &context)
                .unwrap()
                .is_some()
        );
        assert!(
            find_matching_once_grant_with_context(&access, false, &context)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            prune_expired_grants_at_path(&grants_path(), Utc::now()).unwrap(),
            0
        );

        clear_signing_home();
    }

    #[test]
    fn append_grant_reports_open_failures() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let tempdir = tempfile::tempdir().unwrap();
        let directory = tempdir.path().join("grants.jsonl");
        std::fs::create_dir(&directory).unwrap();

        assert!(append_grant_to_path(
            &directory,
            &grant(ApprovalScope::Always, Utc::now(), &vault)
        )
        .is_err());
        clear_signing_home();
    }

    #[test]
    fn persist_grant_ignores_once_deny_policy_and_rejects_missing_branch_scope() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let access = AccessRequest {
            branch: None,
            ..access()
        };
        let mut decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .is_none());
        decision.scope = ApprovalScope::Deny;
        decision.approved = false;
        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .is_none());
        decision.scope = ApprovalScope::Always;
        decision.approved = true;
        decision.source = ApprovalSource::PolicyAuto;
        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .is_none());
        decision.scope = ApprovalScope::Branch;
        decision.source = ApprovalSource::LocalTty;
        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        clear_signing_home();
    }

    #[test]
    fn grant_from_decision_creates_once_grants_and_rejects_denials() {
        let access = access();
        let mut decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        let once = grant_from_decision(&access, &decision, Utc::now()).unwrap();
        assert_eq!(once.scope, ApprovalScope::Once);
        assert_eq!(once.uses_remaining, Some(1));
        assert!(once.expires_at.is_some());
        decision.scope = ApprovalScope::Deny;
        assert!(grant_from_decision(&access, &decision, Utc::now()).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn unsigned_and_modified_grants_are_not_reused() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let unsigned = grant_from_decision(
            &access,
            &ApprovalDecision {
                approved: true,
                scope: ApprovalScope::Always,
                approved_env: access.env.clone(),
                denied_env: Vec::new(),
                source: ApprovalSource::LocalTty,
                grant_id: None,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            grant_integrity_status(&unsigned, now),
            GrantIntegrityStatus::LegacyUnsigned
        );
        assert!(!receipt_matches_grant(&unsigned));
        assert!(!grant_matches_access(&unsigned, &access, now, false));

        let mut signed = grant(ApprovalScope::Always, now, &vault);
        assert_eq!(
            grant_integrity_status(&signed, now),
            GrantIntegrityStatus::Valid
        );
        let mut expired = signed.clone();
        expired.expires_at = Some(now - Duration::minutes(1));
        assert_eq!(
            grant_integrity_status(&expired, now),
            GrantIntegrityStatus::Expired
        );
        assert!(!grant_matches_access(&signed, &access, now, true));

        let mut broken_receipt = signed.clone();
        broken_receipt.receipt.as_mut().unwrap().payload_hash = "bad".to_string();
        assert!(!grant_matches_access(&broken_receipt, &access, now, false));

        signed.command = "pnpm build".to_string();
        assert_eq!(
            grant_integrity_status(&signed, now),
            GrantIntegrityStatus::Invalid
        );
        assert!(!grant_matches_access(&signed, &access, now, false));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn persist_manual_grant_reports_unavailable_signing_material() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let key_store_path = crate::logs::ward_home().join("cache").join("keystore.json");
        std::fs::remove_file(key_store_path).unwrap();

        let error = persist_manual_grant(
            &access(),
            ApprovalScope::Always,
            ApprovalSource::ManualAllow,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unlock_material_unavailable"));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn grant_matching_rejects_project_command_agent_and_branch_mismatches() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let grant = grant(ApprovalScope::Branch, now, &vault);

        let mut project_mismatch = access();
        project_mismatch.project = "other".to_string();
        assert!(!grant_matches_access(&grant, &project_mismatch, now, false));

        let mut command_mismatch = access();
        command_mismatch.command = "pnpm build".to_string();
        assert!(!grant_matches_access(&grant, &command_mismatch, now, false));

        let mut agent_mismatch = access();
        agent_mismatch.agent = Some("cursor".to_string());
        assert!(!grant_matches_access(&grant, &agent_mismatch, now, false));

        let mut branch_mismatch = access();
        branch_mismatch.branch = Some("feature/other".to_string());
        assert!(!grant_matches_access(&grant, &branch_mismatch, now, false));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn context_bound_grants_require_matching_verified_context() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let verified = verified_context();
        let mut grant = ApprovalGrant {
            id: uuid::Uuid::new_v4(),
            created_at: now,
            expires_at: Some(now + Duration::hours(1)),
            request_id: None,
            project: access.project.clone(),
            agent: access.agent.clone(),
            branch: access.branch.clone(),
            command: access.command.clone(),
            approved_env: access.env.clone(),
            scope: ApprovalScope::Session,
            uses_remaining: None,
            receipt: None,
        };
        sign_grant(
            &access,
            &vault,
            &mut grant,
            GrantReceiptContext {
                request_id: uuid::Uuid::new_v4(),
                pending_request: false,
                critical_confirmation: false,
                verified_context: Some(verified.clone()),
            },
        )
        .unwrap();
        assert!(find_matching_non_always_grant_in_with_context(
            std::slice::from_ref(&grant),
            &access,
            now,
            &verified
        )
        .is_some());
        assert!(!grant_matches_access(&grant, &access, now, false));
        clear_signing_home();
    }

    #[test]
    fn revoke_session_grants_handles_missing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        assert_eq!(
            revoke_session_grants_at_path(&tempdir.path().join("missing.jsonl")).unwrap(),
            0
        );
    }

    #[test]
    #[serial_test::serial]
    fn manual_revoke_prune_and_once_consumption_helpers_cover_edges() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();

        let access = access();
        assert!(persist_manual_grant(
            &access,
            ApprovalScope::Always,
            ApprovalSource::Grant,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        assert!(persist_manual_grant(
            &access,
            ApprovalScope::Once,
            ApprovalSource::AgentMediated,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        assert!(persist_manual_grant(
            &access,
            ApprovalScope::Deny,
            ApprovalSource::ManualAllow,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());

        let always = persist_manual_grant(
            &access,
            ApprovalScope::Always,
            ApprovalSource::ManualAllow,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap();
        let once = persist_manual_grant(
            &access,
            ApprovalScope::Once,
            ApprovalSource::BrokerApproval,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap();
        let session = persist_manual_grant(
            &access,
            ApprovalScope::Session,
            ApprovalSource::ManualAllow,
            &vault,
            None,
        )
        .unwrap();
        assert_eq!(session.scope, ApprovalScope::Session);

        assert!(!consume_once_grant(uuid::Uuid::new_v4()).unwrap());
        assert!(consume_once_grant(once.id).unwrap());
        assert!(!revoke_grant(uuid::Uuid::new_v4()).unwrap());
        assert!(revoke_grant(always.id).unwrap());

        let mut expired = grant(ApprovalScope::Session, Utc::now(), &vault);
        expired.expires_at = Some(Utc::now() - Duration::minutes(1));
        append_grant_to_path(&grants_path(), &expired).unwrap();
        assert_eq!(prune_expired_grants().unwrap(), 1);
        assert_eq!(prune_expired_grants().unwrap(), 0);

        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn global_grant_helpers_report_invalid_grant_file() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        let grants_dir = tempdir.path().join("sessions");
        std::fs::create_dir_all(&grants_dir).unwrap();
        std::fs::write(grants_dir.join("grants.jsonl"), "{bad-json}\n").unwrap();

        assert!(find_matching_grant(&access()).is_err());
        assert!(find_matching_once_grant(&access(), false).is_err());
        assert!(find_matching_non_always_grant(&access()).is_err());
        assert!(revoke_session_grants().is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn removes_project_grants_and_keeps_other_projects() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();

        let now = Utc::now();
        append_grant_to_path(&grants_path(), &grant(ApprovalScope::Always, now, &vault)).unwrap();
        let mut other = grant(ApprovalScope::Always, now, &vault);
        other.project = "other".to_string();
        append_grant_to_path(&grants_path(), &other).unwrap();

        assert_eq!(remove_project_grants("missing").unwrap(), 0);
        assert_eq!(remove_project_grants("ambienta").unwrap(), 1);
        let retained = load_grants().unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].project, "other");

        clear_signing_home();
    }
}
