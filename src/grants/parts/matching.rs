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
        let broker_payload = approval_receipts::build_payload(approval_receipts::PayloadRequest {
            access,
            grant_id: grant.id,
            request_id: context.request_id,
            approved_env: &grant.approved_env,
            scope: grant.scope,
            expires_at: grant.expires_at,
            critical_confirmation: context.critical_confirmation,
            created_at: grant.created_at,
            signer_key_id: String::new(),
            verified_context: context.verified_context.as_ref(),
        });
        let receipt = broker::sign_receipt(&access.project, vault, broker_payload)
            .map_err(|error| anyhow::anyhow!("signing_key_unavailable: {error}"))?;
        grant.receipt = Some(receipt);
        Ok(())
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
        let payload = approval_receipts::build_payload(approval_receipts::PayloadRequest {
            access,
            grant_id: grant.id,
            request_id: context.request_id,
            approved_env: &grant.approved_env,
            scope: grant.scope,
            expires_at: grant.expires_at,
            critical_confirmation: context.critical_confirmation,
            created_at: grant.created_at,
            signer_key_id: signing_key.signer_key_id.clone(),
            verified_context: context.verified_context.as_ref(),
        });
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
            .is_none_or(|value| !value.is_empty())
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
