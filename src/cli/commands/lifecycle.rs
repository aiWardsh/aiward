fn edit(project: Option<String>, app: Option<String>) -> Result<()> {
    let cwd = env::current_dir()?;
    let passphrase = vault::read_existing_passphrase()?;
    let target = workspace_target::resolve_one_with_passphrase(
        &workspace_target::TargetSelector::one(project, app),
        &cwd,
        &passphrase,
    )?;
    let resolved = target.resolved_project();
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::edit_vault_file(&resolved.vault, &passphrase)?;
        warn_store_refresh_failure(refresh_project_store_with_passphrase(
            &resolved,
            &passphrase,
        ));
        Ok(())
    })?;
    let event = VaultEditEvent {
        event_type: "vault.edit",
        project: &resolved.name,
        vault: &resolved.vault,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    term::emit_header(&term::Header {
        command: Some("edit"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail(
        "encrypted vault updated",
        &term::short_path(&resolved.vault),
    );
    Ok(())
}

pub(crate) fn create_run_unlock_session(
    project: &str,
    vault_path: &Path,
    passphrase: &str,
    ttl: &str,
    mode: Option<&str>,
) -> Result<unlock::UnlockSession> {
    let ttl = unlock::parse_ttl(ttl)?;

    // Send unlock to the broker first. The broker decrypts the stable vault once
    // and keeps the runtime env map in memory for command injection.
    broker::unlock_project_with_mode(
        project,
        vault_path,
        passphrase,
        ttl,
        mode.map(str::to_string),
    )
    .inspect_err(|error| {
        let error_message = error.to_string();
        let event = VaultUnlockEvent {
            event_type: "vault.unlock",
            status: "failure",
            project,
            vault: vault_path,
            error: Some(&error_message),
            expires_at: None,
        };
        let _ = audit_logs::append_event(LogKind::Sessions, event);
    })?;

    #[cfg(not(test))]
    let broker_expires_at = match broker::active_session_expiry(project, vault_path) {
        Ok(Some(expires_at)) => expires_at,
        Ok(None) => {
            let error_message =
                "broker unlock did not create an active session; run ward unlock again".to_string();
            let event = VaultUnlockEvent {
                event_type: "vault.unlock",
                status: "failure",
                project,
                vault: vault_path,
                error: Some(&error_message),
                expires_at: None,
            };
            audit_logs::append_event(LogKind::Sessions, event)?;
            anyhow::bail!("{error_message}");
        }
        Err(error) => {
            let error_message = error.to_string();
            let event = VaultUnlockEvent {
                event_type: "vault.unlock",
                status: "failure",
                project,
                vault: vault_path,
                error: Some(&error_message),
                expires_at: None,
            };
            audit_logs::append_event(LogKind::Sessions, event)?;
            anyhow::bail!("{error_message}");
        }
    };
    #[cfg(test)]
    let broker_expires_at = chrono::Utc::now() + ttl;

    let mut session = if let Some(mode_name) = mode {
        unlock::create_mode_unlock(project, vault_path, passphrase, ttl, mode_name)?
    } else {
        unlock::create_run_unlock(project, vault_path, passphrase, ttl)?
    };
    if broker_expires_at < session.expires_at {
        session.expires_at = broker_expires_at;
    }
    let event = VaultUnlockEvent {
        event_type: "vault.unlock",
        status: "success",
        project,
        vault: vault_path,
        error: None,
        expires_at: Some(session.expires_at.to_rfc3339()),
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    Ok(session)
}

#[cfg(any(test, coverage))]
fn unlock_vault(ttl: &str, mode: Option<&str>, verify_only: bool) -> Result<()> {
    unlock_vault_for_target(None, None, false, ttl, mode, verify_only)
}

fn unlock_vault_for_target(
    project: Option<String>,
    app: Option<String>,
    all: bool,
    ttl: &str,
    mode: Option<&str>,
    verify_only: bool,
) -> Result<()> {
    let cwd = env::current_dir()?;
    if verify_only {
        if mode.is_some() {
            anyhow::bail!("--verify-only cannot be combined with --mode");
        }
        let selector = workspace_target::TargetSelector { project, app, all };
        let targets = workspace_target::resolve_many(&selector, &cwd)?;
        for target in targets {
            let resolved = target.resolved_project();
            match broker::list_vault_keys_from_active_session(&resolved.name, &resolved.vault) {
                Ok(names) => {
                    let expires_at =
                        broker::active_session_expiry(&resolved.name, &resolved.vault)?
                            .context("broker session can serve env names but has no expiry")?;
                    term::emit_header(&term::Header {
                        command: Some("unlock"),
                        project: &resolved.name,
                        path: Some(&resolved.path),
                        mode: Some("verify"),
                    });
                    term::ok_detail(
                        "broker session",
                        &format!("expires {}", expires_at.to_rfc3339()),
                    );
                    term::ok_detail("env names in memory", &names.len().to_string());
                }
                Err(_) => anyhow::bail!(
                    "broker has no active session for {}; run ward unlock --ttl 8h",
                    resolved.name
                ),
            }
        }
        return Ok(());
    }
    let passphrase = vault::read_existing_passphrase()?;
    let selector = workspace_target::TargetSelector { project, app, all };
    let targets = workspace_target::resolve_many_with_passphrase(&selector, &cwd, &passphrase)?;
    for target in targets {
        let resolved = target.resolved_project();
        registry::update_project_vault(
            &resolved.name,
            resolved.path.clone(),
            resolved.vault.clone(),
        )?;
        let session =
            create_run_unlock_session(&resolved.name, &resolved.vault, &passphrase, ttl, mode)?;
        term::emit_header(&term::Header {
            command: Some("unlock"),
            project: &resolved.name,
            path: Some(&resolved.path),
            mode,
        });
        if let Some(mode_name) = mode {
            term::ok_detail("vault unlocked", &format!("mode {mode_name}"));
        } else {
            term::ok("vault unlocked");
        }
        term::ok_detail(
            "session active",
            &format!("expires {}", session.expires_at.to_rfc3339()),
        );
    }
    Ok(())
}

fn lock(
    project: Option<String>,
    app: Option<String>,
    workspace_scope: bool,
    all: bool,
) -> Result<()> {
    if project.is_some() && app.is_some() {
        anyhow::bail!("choose either --project or --app, not both");
    }
    if all && (project.is_some() || app.is_some() || workspace_scope) {
        anyhow::bail!("--all cannot be combined with --project, --app, or --workspace");
    }
    if workspace_scope && (project.is_some() || app.is_some()) {
        anyhow::bail!("--workspace cannot be combined with --project or --app");
    }

    if project.is_some() || app.is_some() || workspace_scope {
        let cwd = env::current_dir()?;
        let targets = if workspace_scope {
            let discovery = workspace::discover_containing(&cwd)?
                .context("--workspace requires running inside a Ward workspace")?;
            let targets = workspace_target::configured_workspace_targets(&discovery)?;
            if targets.is_empty() {
                anyhow::bail!("workspace has no configured Ward app projects");
            }
            targets
        } else {
            vec![workspace_target::resolve_one(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
            )?]
        };

        for target in targets {
            let status = broker::lock_project(&target.name, &target.vault)?;
            term::emit_header(&term::Header {
                command: Some("lock"),
                project: &status.project,
                path: Some(&target.path),
                mode: None,
            });
            term::ok_detail(
                "broker session removed",
                &status.broker_session_removed.to_string(),
            );
            term::ok_detail(
                "session grants revoked",
                &status.revoked_session_grants.to_string(),
            );
            term::ok_detail(
                "unlock metadata cleared",
                &status.cleared_unlock_sessions.to_string(),
            );
            term::ok_detail(
                "human commands cancelled",
                &status.cancelled_human_commands.to_string(),
            );
        }
        return Ok(());
    }

    let _ = all;
    if crate::human::is_human_terminal() {
        let _ = crate::human::send_guardian_shutdown();
    }
    let revoked = grants::revoke_session_grants()?;
    let cleared_unlocks = unlock::clear_all_unlocks()?;
    broker::stop()?;
    let event = VaultLockEvent {
        event_type: "vault.lock",
        revoked_session_grants: revoked,
        cleared_unlock_sessions: cleared_unlocks,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    term::emit_header(&term::Header {
        command: Some("lock"),
        project: "all projects",
        path: None,
        mode: None,
    });
    term::ok_detail("session grants revoked", &revoked.to_string());
    term::ok_detail("unlock metadata cleared", &cleared_unlocks.to_string());
    Ok(())
}

fn ward_off(discover: Option<PathBuf>, each: bool, json: bool) -> Result<()> {
    if crate::human::is_human_terminal() {
        let _ = crate::human::send_guardian_shutdown();
    }

    let revoked = grants::revoke_session_grants()?;
    let cleared_unlocks = unlock::clear_all_unlocks()?;
    broker::stop()?;
    global_disable::disable("ward off")?;

    let discovery_summary = match discover.as_deref() {
        Some(root) => Some(discover_and_register_projects(root)?),
        None => None,
    };
    let transitions = GlobalTransitionService::discover()?;
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let projects = transitions.run_off(
        if each {
            PinStrategy::PerProject
        } else {
            PinStrategy::Shared
        },
        &timestamp,
        restore_ward_off_target,
    )?;
    let counts = global_transition::off_counts(&projects);
    let restored = counts.succeeded;
    let skipped = counts.skipped;
    let failed = counts.failed;

    let summary = WardOffSummary {
        disabled: true,
        disabled_path: global_disable::disabled_path(),
        restored,
        skipped,
        failed,
        revoked_session_grants: revoked,
        cleared_unlock_sessions: cleared_unlocks,
        projects,
    };

    let event = WardOffEvent {
        event_type: "ward.off",
        disabled_path: &summary.disabled_path,
        restored,
        skipped,
        failed,
        revoked_session_grants: revoked,
        cleared_unlock_sessions: cleared_unlocks,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        term::section("Global");
        term::ok(&format!(
            "Ward disabled  {}",
            term::short_path(&summary.disabled_path)
        ));
        term::section("Runtime");
        term::ok(&format!("revoked {revoked} session grant(s)"));
        term::ok(&format!("cleared {cleared_unlocks} unlock session(s)"));
        term::section("Env files");
        if let Some(discovery_summary) = &discovery_summary {
            term::ok(&format!(
                "indexed {} discovered project(s)",
                discovery_summary.projects.len()
            ));
        }
        if summary.projects.is_empty() {
            term::warn("no known Ward projects found");
        }
        for project in &summary.projects {
            match project.status {
                WardOffOutcome::Restored => term::ok(&format!(
                    "{}  {}",
                    project.project,
                    project
                        .output
                        .as_deref()
                        .map(term::short_path)
                        .unwrap_or_else(|| "no output".to_string())
                )),
                WardOffOutcome::Skipped => {
                    term::warn(&format!("{}  {}", project.project, project.message))
                }
                WardOffOutcome::Failed => {
                    term::fail(&format!("{}  {}", project.project, project.message))
                }
            }
        }
        term::info(&format!(
            "{restored} restored, {skipped} skipped, {failed} failed"
        ));
    }

    Ok(())
}

fn ward_on(each: bool, json: bool) -> Result<()> {
    // Keep shell integration fail-open bypassed until every plaintext file has
    // either been re-encrypted or positively identified as unrelated to Ward.
    global_disable::disable("ward on in progress")?;
    let transitions = GlobalTransitionService::discover()?;
    let projects = transitions.run_on(
        if each {
            PinStrategy::PerProject
        } else {
            PinStrategy::Shared
        },
        lock_ward_on_target,
    )?;
    let counts = global_transition::on_counts(&projects);
    let locked = counts.succeeded;
    let skipped = counts.skipped;
    let failed = counts.failed;

    let removed = if failed == 0 {
        global_disable::enable()?
    } else {
        false
    };

    let summary = WardOnSummary {
        disabled: failed > 0,
        disabled_path: global_disable::disabled_path(),
        removed_disabled_state: removed,
        locked,
        skipped,
        failed,
        projects,
    };
    let event = WardOnEvent {
        event_type: "ward.on",
        disabled_path: &summary.disabled_path,
        removed_disabled_state: removed,
        locked,
        skipped,
        failed,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        term::section("Global");
        if removed {
            term::ok(&format!(
                "Ward enabled  removed {}",
                term::short_path(&summary.disabled_path)
            ));
        } else {
            term::fail("Ward remains disabled; unresolved plaintext env files require attention");
        }
        term::section("Env files");
        if summary.projects.is_empty() {
            term::warn("no known Ward projects found");
        }
        for project in &summary.projects {
            match project.status {
                WardOnOutcome::Locked => term::ok(&format!(
                    "{}  {} file(s) locked",
                    project.project,
                    project.locked_files.len()
                )),
                WardOnOutcome::Skipped => {
                    term::warn(&format!("{}  {}", project.project, project.message))
                }
                WardOnOutcome::Failed => {
                    term::fail(&format!("{}  {}", project.project, project.message))
                }
            }
        }
        term::info(&format!(
            "{locked} locked, {skipped} skipped, {failed} failed"
        ));
    }
    if failed > 0 {
        anyhow::bail!(
            "Ward remains disabled because {failed} project(s) could not be re-encrypted"
        );
    }
    Ok(())
}

fn lock_ward_on_target(
    target: &WardOffTarget,
    passphrase: &str,
    pin_attempts: usize,
) -> WardOnProjectStatus {
    if !target.path.is_dir() {
        return WardOnProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: None,
            locked_files: Vec::new(),
            status: WardOnOutcome::Skipped,
            failure: Some(UnlockFailure::ProjectMissing),
            message: "project path missing".to_string(),
            pin_attempts,
        };
    }
    let vault = match resolve_ward_off_vault_path(target, passphrase) {
        Ok(vault) => vault,
        Err(error) => {
            return WardOnProjectStatus {
                project: target.project.clone(),
                registry_key: target.registry_key.clone(),
                display_name: target.display_name.clone(),
                path: target.path.clone(),
                vault: None,
                locked_files: Vec::new(),
                status: WardOnOutcome::Failed,
                failure: Some(UnlockFailure::VaultResolution),
                message: error.to_string(),
                pin_attempts,
            }
        }
    };
    if !vault.exists() {
        let plaintext = match ward_plaintext_sources(target) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                return WardOnProjectStatus {
                    project: target.project.clone(),
                    registry_key: target.registry_key.clone(),
                    display_name: target.display_name.clone(),
                    path: target.path.clone(),
                    vault: Some(vault),
                    locked_files: Vec::new(),
                    status: WardOnOutcome::Failed,
                    failure: Some(UnlockFailure::PlaintextInspection),
                    message: error.to_string(),
                    pin_attempts,
                }
            }
        };
        if !plaintext.is_empty() {
            return WardOnProjectStatus {
                project: target.project.clone(),
                registry_key: target.registry_key.clone(),
                display_name: target.display_name.clone(),
                path: target.path.clone(),
                vault: Some(vault),
                locked_files: Vec::new(),
                status: WardOnOutcome::Failed,
                failure: Some(UnlockFailure::VaultMissing),
                message: format!(
                    "vault missing while {} Ward plaintext file(s) remain",
                    plaintext.len()
                ),
                pin_attempts,
            };
        }
        return WardOnProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: Some(vault),
            locked_files: Vec::new(),
            status: WardOnOutcome::Skipped,
            failure: Some(UnlockFailure::VaultMissing),
            message: "vault missing".to_string(),
            pin_attempts,
        };
    }

    let plan = match ward_on_lock_plan(target, &vault) {
        Ok(plan) => plan,
        Err(error) => {
            return WardOnProjectStatus {
                project: target.project.clone(),
                registry_key: target.registry_key.clone(),
                display_name: target.display_name.clone(),
                path: target.path.clone(),
                vault: Some(vault),
                locked_files: Vec::new(),
                status: WardOnOutcome::Failed,
                failure: Some(UnlockFailure::PlaintextInspection),
                message: error.to_string(),
                pin_attempts,
            }
        }
    };
    let Some(primary_source) = plan.primary_source else {
        return WardOnProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: Some(vault),
            locked_files: Vec::new(),
            status: WardOnOutcome::Skipped,
            failure: None,
            message: "no Ward off plaintext env files found".to_string(),
            pin_attempts,
        };
    };

    let mut locked_files = Vec::new();
    if let Err(error) = env_file::lock_plaintext_source(&primary_source, &vault, passphrase) {
        return WardOnProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: Some(vault),
            locked_files,
            status: WardOnOutcome::Failed,
            failure: Some(if vault::is_incorrect_passphrase(&error) {
                UnlockFailure::IncorrectPassphrase
            } else {
                UnlockFailure::Reencrypt
            }),
            message: error.to_string(),
            pin_attempts,
        };
    }
    locked_files.push(primary_source);

    let mut marker_errors = Vec::new();
    for stale_source in plan.marker_only_sources {
        match env_file::lock_env_file(&stale_source, &vault) {
            Ok(()) => locked_files.push(stale_source),
            Err(error) => marker_errors.push(error.to_string()),
        }
    }
    if !marker_errors.is_empty() {
        return WardOnProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: Some(vault),
            locked_files,
            status: WardOnOutcome::Failed,
            failure: Some(UnlockFailure::MarkerWrite),
            message: marker_errors.join("; "),
            pin_attempts,
        };
    }

    let _ =
        registry::refresh_project_vault(&target.registry_key, target.path.clone(), vault.clone());
    WardOnProjectStatus {
        project: target.project.clone(),
        registry_key: target.registry_key.clone(),
        display_name: target.display_name.clone(),
        path: target.path.clone(),
        vault: Some(vault),
        locked_files,
        status: WardOnOutcome::Locked,
        failure: None,
        message: "plaintext env re-encrypted".to_string(),
        pin_attempts,
    }
}

#[derive(Debug)]
struct WardOnLockPlan {
    primary_source: Option<PathBuf>,
    marker_only_sources: Vec<PathBuf>,
}

fn ward_on_lock_plan(target: &WardOffTarget, vault: &Path) -> Result<WardOnLockPlan> {
    let env_path = target.path.join(".env");
    let primary_env = if matches!(
        env_file::inspect_env_file(&env_path, vault)?,
        env_file::EnvFileState::Plaintext
    ) && env_file::is_ward_unlocked_plaintext_file(&env_path)?
    {
        Some(env_path)
    } else {
        None
    };

    let mut sidecars = Vec::new();
    for path in collect_ward_on_sidecar_files(target)? {
        if env_file::is_ward_unlocked_plaintext_file(&path)? {
            sidecars.push(path);
        }
    }
    let primary_sidecar = if primary_env.is_none() {
        sidecars.pop()
    } else {
        None
    };
    let primary_source = primary_env.or(primary_sidecar);

    Ok(WardOnLockPlan {
        primary_source,
        marker_only_sources: sidecars,
    })
}

fn ward_plaintext_sources(target: &WardOffTarget) -> Result<Vec<PathBuf>> {
    let mut sources = Vec::new();
    let env_path = target.path.join(".env");
    if env_file::is_ward_unlocked_plaintext_file(&env_path)? {
        sources.push(env_path);
    }
    for path in collect_ward_on_sidecar_files(target)? {
        if env_file::is_ward_unlocked_plaintext_file(&path)? {
            push_unique_path(&mut sources, path);
        }
    }
    Ok(sources)
}

fn collect_ward_on_sidecar_files(target: &WardOffTarget) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    push_ward_on_sidecars_from_dir(&mut paths, &ward_off_sidecar_dir(target))?;
    push_ward_on_sidecars_from_dir(&mut paths, &target.path)?;
    paths.sort();
    paths.dedup_by(|left, right| same_path(left, right));
    Ok(paths)
}

fn push_ward_on_sidecars_from_dir(paths: &mut Vec<PathBuf>, dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if file_name.starts_with(env_file::WARD_OFF_SIDECAR_PREFIX) {
            push_unique_path(paths, path);
        }
    }
    Ok(())
}

fn restore_ward_off_target(
    target: &WardOffTarget,
    passphrase: &str,
    timestamp: &str,
    pin_attempts: usize,
) -> WardOffProjectStatus {
    if !target.path.is_dir() {
        return WardOffProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: None,
            output: None,
            status: WardOffOutcome::Skipped,
            failure: Some(UnlockFailure::ProjectMissing),
            message: "project path missing".to_string(),
            pin_attempts,
        };
    }
    let vault = match resolve_ward_off_vault_path(target, passphrase) {
        Ok(vault) => vault,
        Err(error) => {
            return WardOffProjectStatus {
                project: target.project.clone(),
                registry_key: target.registry_key.clone(),
                display_name: target.display_name.clone(),
                path: target.path.clone(),
                vault: None,
                output: None,
                status: WardOffOutcome::Failed,
                failure: Some(UnlockFailure::VaultResolution),
                message: error.to_string(),
                pin_attempts,
            }
        }
    };
    if !vault.exists() {
        return WardOffProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: Some(vault),
            output: None,
            status: WardOffOutcome::Skipped,
            failure: Some(UnlockFailure::VaultMissing),
            message: "vault missing".to_string(),
            pin_attempts,
        };
    }

    let env_path = target.path.join(".env");
    let sidecar_dir = ward_off_sidecar_dir(target);
    match env_file::unlock_env_file_preserving_plaintext_with_sidecar_dir(
        &env_path,
        &vault,
        passphrase,
        timestamp,
        Some(&sidecar_dir),
    ) {
        Ok(output) => {
            let _ = registry::refresh_project_vault(
                &target.registry_key,
                target.path.clone(),
                vault.clone(),
            );
            WardOffProjectStatus {
                project: target.project.clone(),
                registry_key: target.registry_key.clone(),
                display_name: target.display_name.clone(),
                path: target.path.clone(),
                vault: Some(vault),
                output: Some(output),
                status: WardOffOutcome::Restored,
                failure: None,
                message: "plaintext env written".to_string(),
                pin_attempts,
            }
        }
        Err(error) => WardOffProjectStatus {
            project: target.project.clone(),
            registry_key: target.registry_key.clone(),
            display_name: target.display_name.clone(),
            path: target.path.clone(),
            vault: Some(vault),
            output: None,
            status: WardOffOutcome::Failed,
            failure: Some(if vault::is_incorrect_passphrase(&error) {
                UnlockFailure::IncorrectPassphrase
            } else {
                UnlockFailure::VaultWrite
            }),
            message: error.to_string(),
            pin_attempts,
        },
    }
}

fn ward_off_sidecar_dir(target: &WardOffTarget) -> PathBuf {
    let project_path = target
        .path
        .canonicalize()
        .unwrap_or_else(|_| target.path.clone());
    let mut hasher = Sha256::new();
    hasher.update(project_path.to_string_lossy().as_bytes());
    let hash = hex::encode(hasher.finalize());
    let dir_name = format!("{}-{}", safe_file_slug(&target.registry_key), &hash[..12]);
    let relative = PathBuf::from("ward-off-envs").join(dir_name);
    fs_util::resolve_ward_home_path(&relative, "ward off env directory")
        .expect("ward off env directory should stay inside Ward home")
}

fn resolve_ward_off_vault_path(target: &WardOffTarget, passphrase: &str) -> Result<PathBuf> {
    let mut candidates = Vec::new();
    let mut errors = Vec::new();
    if let Ok(project_config) = config::read_project_config(&target.path) {
        push_ward_off_config_vault_candidates(
            &mut candidates,
            &mut errors,
            &target.path,
            &project_config,
            passphrase,
        );
    }
    if let Some(project_config) = target.config.as_ref() {
        push_ward_off_config_vault_candidates(
            &mut candidates,
            &mut errors,
            &target.path,
            project_config,
            passphrase,
        );
    }
    if let Some(vault) = target.registered_vault.as_ref() {
        push_ward_off_vault_candidate(
            &mut candidates,
            &mut errors,
            fs_util::resolve_project_path(&target.path, vault, "registered vault path"),
        );
    }
    push_ward_off_vault_candidate(
        &mut candidates,
        &mut errors,
        fs_util::resolve_project_path(
            &target.path,
            Path::new(config::DEFAULT_VAULT_FILE),
            "default vault path",
        ),
    );

    if candidates.is_empty() {
        let detail = if errors.is_empty() {
            "no vault candidates found".to_string()
        } else {
            errors.join("; ")
        };
        anyhow::bail!("no usable vault path found: {detail}");
    }

    Ok(candidates
        .iter()
        .find(|candidate| candidate.exists())
        .cloned()
        .unwrap_or_else(|| {
            candidates
                .into_iter()
                .next()
                .unwrap_or_else(|| target.path.join(config::DEFAULT_VAULT_FILE))
        }))
}

fn push_ward_off_config_vault_candidates(
    candidates: &mut Vec<PathBuf>,
    errors: &mut Vec<String>,
    project_path: &Path,
    project_config: &config::ProjectConfig,
    passphrase: &str,
) {
    push_ward_off_vault_candidate(
        candidates,
        errors,
        config::resolve_vault_path_dynamic_checked(project_path, project_config, passphrase),
    );
    push_ward_off_vault_candidate(
        candidates,
        errors,
        config::resolve_vault_path_checked(project_path, project_config),
    );
}

fn push_ward_off_vault_candidate(
    candidates: &mut Vec<PathBuf>,
    errors: &mut Vec<String>,
    result: Result<PathBuf>,
) {
    match result {
        Ok(path) => push_unique_path(candidates, path),
        Err(error) => errors.push(error.to_string()),
    }
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| same_path(existing, &path)) {
        paths.push(path);
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right || left.canonicalize().ok() == right.canonicalize().ok()
}
