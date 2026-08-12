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

        let grant = match serde_json::from_str::<ApprovalGrant>(line) {
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
