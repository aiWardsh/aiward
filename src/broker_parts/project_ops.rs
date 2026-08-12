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
    let payload = approval_receipts::build_payload(approval_receipts::PayloadRequest {
        access: &pending.access,
        grant_id: grant.id,
        request_id,
        approved_env: &grant.approved_env,
        scope: grant.scope,
        expires_at: grant.expires_at,
        critical_confirmation: critical && confirm_critical,
        created_at: grant.created_at,
        signer_key_id: String::new(),
        verified_context: pending.verified_context.as_ref(),
    });
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
    let envelope = vault::encrypt_env_with_key_mode(
        &selected_plaintext,
        &material.passphrase,
        vault::VaultKeyMode::ApiDerivedV1,
    )?;
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
    vault::import_env_file_with_key_mode(
        &source,
        &vault_path,
        passphrase,
        vault::VaultKeyMode::ApiDerivedV1,
    )?;
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
