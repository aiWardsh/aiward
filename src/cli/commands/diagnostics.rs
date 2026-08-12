#[cfg(any(test, coverage))]
fn doctor() -> Result<()> {
    doctor_for_target(None, None, false)
}

fn doctor_for_target(project: Option<String>, app: Option<String>, all: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let selector = workspace_target::TargetSelector { project, app, all };
    if selector.all {
        return doctor_workspace(&cwd);
    }
    if selector.project.is_some() || selector.app.is_some() {
        let target = workspace_target::resolve_one(&selector, &cwd)?;
        return doctor_project_at(target.path);
    }
    if config::find_project_root(&cwd).is_none() && workspace::discover_containing(&cwd)?.is_some()
    {
        return doctor_workspace(&cwd);
    }
    doctor_project_at(cwd)
}

fn doctor_workspace(cwd: &Path) -> Result<()> {
    let discovery = workspace::discover_containing(cwd)?
        .context("no workspace manifest found; expected pnpm-workspace.yaml, package.json workspaces, or turbo.json")?;
    term::guided_context_header(
        "doctor",
        "Workspace",
        &discovery.workspace_name,
        &discovery.root,
        "Ward found a monorepo workspace. App folders are checked as separate Ward projects.",
    );
    let targets = workspace_target::configured_workspace_targets(&discovery)?;
    term::section("workspace");
    term::ok(&format!(
        "{} app package(s) detected",
        discovery.app_candidates().count()
    ));
    if let Some(manager) = discovery.package_manager.as_deref() {
        term::info(&format!("package manager {manager}"));
    }
    if discovery.turborepo {
        term::ok("turborepo detected");
    }
    term::section("apps");
    if targets.is_empty() {
        term::warn("no configured Ward app projects found");
        term::next("run: ward setup --workspace --all");
        return Ok(());
    }
    for target in targets {
        let cfg_status = if config::config_path(&target.path).is_file() {
            "config ok"
        } else {
            "config missing"
        };
        let vault_status = if target.vault.exists() {
            "vault ok"
        } else {
            "vault missing"
        };
        let session =
            broker::list_vault_keys_from_active_session(&target.name, &target.vault).is_ok();
        let session_status = if session { "session active" } else { "locked" };
        let app = target.app_slug.as_deref().unwrap_or(&target.name);
        term::info(&format!(
            "{app}  {}  {cfg_status}  {vault_status}  {session_status}",
            target.name
        ));
    }
    term::blank();
    Ok(())
}

fn doctor_project_at(cwd: PathBuf) -> Result<()> {
    let config_path = config::config_path(&cwd);
    let plaintext_env = cwd.join(".env");
    let project_name = cwd
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    term::header_cmd("doctor", &project_name);

    doctor_global_state();

    // ── config ────────────────────────────────────────────────────────────────
    term::section("config");

    if !config_path.exists() {
        match config::find_project_config_backup_for_path(&cwd)? {
            Some((backup_path, backup)) => {
                term::warn(&format!(
                    ".ward.json missing but recoverable for {}",
                    backup.project
                ));
                term::info(&format!("backup {}", term::short_path(&backup_path)));
                term::info("run ward config restore, or rerun ward setup to restore automatically");
            }
            None => term::fail(".ward.json missing — run ward setup"),
        }
        term::blank();
        return Ok(());
    }
    term::ok(&format!(".ward.json  {}", term::short_path(&config_path)));

    let project_config = config::read_project_config(&cwd);
    match &project_config {
        Ok(cfg) => {
            term::ok(&format!("project  {}", cfg.project));
            let vault_path = doctor_vault_path(&cwd, cfg);
            if vault_path.exists() {
                term::ok(&format!("vault  {}", term::short_path(&vault_path)));
            } else {
                term::fail(&format!(
                    "vault not found  {}",
                    term::short_path(&vault_path)
                ));
            }
            match config::find_project_config_backup_for_path(&cwd)? {
                Some((backup_path, _)) => {
                    term::ok(&format!(
                        "config backup  {}",
                        term::short_path(&backup_path)
                    ));
                }
                None => {
                    term::warn("config backup missing — rerun ward setup to refresh metadata");
                }
            }
        }
        Err(e) => {
            term::fail(&format!("config parse error — {e}"));
        }
    }

    // ── secrets ───────────────────────────────────────────────────────────────
    term::section("secrets");

    match &project_config {
        Ok(cfg) => {
            let vault_path = doctor_vault_path(&cwd, cfg);
            match env_file::inspect_env_file(&plaintext_env, &vault_path) {
                Ok(env_file::EnvFileState::Locked) => term::ok(".env  locked"),
                Ok(env_file::EnvFileState::StaleLocked) => {
                    term::warn(".env locked but stale — run ward env lock")
                }
                Ok(env_file::EnvFileState::Plaintext) => {
                    term::warn(".env is plaintext — run ward env lock")
                }
                Ok(env_file::EnvFileState::Missing) => term::warn(".env missing"),
                Err(e) => term::fail(&format!(".env check failed — {e}")),
            }
        }
        Err(_) if plaintext_env.exists() => {
            term::warn(".env is plaintext — run ward setup or ward import .env");
        }
        Err(_) => term::warn(".env missing"),
    }

    let secret_files = likely_secret_env_files(&cwd)?;
    if secret_files.is_empty() {
        term::ok("no .env.* secret variants found");
    } else {
        for path in &secret_files {
            term::warn(&format!(
                "plaintext env variant  {}",
                term::short_path(path)
            ));
        }
    }

    // ── gitignore ─────────────────────────────────────────────────────────────
    term::section("gitignore");
    check_gitignore(&cwd)?;

    let gitignore_path = cwd.join(".gitignore");
    if gitignore_path.exists() {
        match fs::read_to_string(&gitignore_path) {
            Ok(contents) if contents.contains(config::WARD_JSON_GITIGNORE_ENTRY) => {
                term::ok(".ward.json  excluded");
            }
            Ok(_) => {
                term::warn(".ward.json not in .gitignore — vault nonce may leak into git history");
            }
            Err(_) => {}
        }
    }

    // ── broker ────────────────────────────────────────────────────────────────
    term::section("broker");

    match registry::resolve_project(None, &cwd) {
        Ok(project) => {
            term::ok(&format!("project  {}", project.name));
            if !project.vault.exists() {
                term::warn(&format!(
                    "vault not found  {}",
                    term::short_path(&project.vault)
                ));
            }
            match broker::status() {
                Ok(status) if status.running => {
                    term::info(&format!("socket  {}", term::short_path(&status.socket)));
                    term::info(&format!("version  {}", status.version));
                    if broker::privileged_rpc_peer_auth_supported() {
                        term::ok(&format!(
                            "privileged RPC peer auth  {}",
                            broker::peer_auth_platform()
                        ));
                    } else {
                        term::warn("privileged RPC peer auth unsupported — privileged broker calls fail closed");
                    }
                    if let Some(pid) = status.pid {
                        match status.ppid {
                            Some(ppid) => term::info(&format!("pid={pid} ppid={ppid}")),
                            None => term::info(&format!("pid={pid}")),
                        }
                    }
                    if let Some(started_at) = status.started_at {
                        term::info(&format!("started  {}", started_at.to_rfc3339()));
                    }
                    term::info(&format!("sessions  {}", status.sessions.len()));
                    term::info(&format!("broker approvals  {}", status.approval_count));
                    match broker::list_vault_keys_from_active_session(&project.name, &project.vault)
                    {
                        Ok(names) => {
                            term::ok("active broker session can serve env names");
                            term::info(&format!("env names in memory  {}", names.len()));
                        }
                        Err(_) => warn_missing_broker_session(&project.name, &project.vault),
                    }
                }
                Ok(_) => warn_missing_broker_session(&project.name, &project.vault),
                Err(e) => term::fail(&format!("broker status failed — {e}")),
            }
        }
        Err(e) => term::fail(&format!("registry resolve failed — {e}")),
    }

    // ── project store ────────────────────────────────────────────────────────
    term::section("project store");
    match registry::resolve_project(None, &cwd) {
        Ok(project) => {
            match project_store::diagnostics(&project.name) {
                Ok(diagnostics) if diagnostics.exists => {
                    if diagnostics.stale {
                        term::warn(&format!(
                            "snapshot stale  {}",
                            term::short_path(&diagnostics.path)
                        ));
                    } else {
                        term::ok(&format!(
                            "snapshot  {}",
                            term::short_path(&diagnostics.path)
                        ));
                    }
                    term::info(&format!(
                        "env={} profiles={} agentPolicies={}",
                        diagnostics.env_count,
                        diagnostics.profile_count,
                        diagnostics.agent_policy_count
                    ));
                }
                Ok(diagnostics) => {
                    term::warn("no local project-store snapshot");
                    term::info(&format!("expected {}", term::short_path(&diagnostics.path)));
                }
                Err(error) => term::fail(&format!("project-store check failed — {error}")),
            }
            match broker::list_vault_keys_from_active_session(&project.name, &project.vault) {
                Ok(_) => term::ok("active broker session can refresh/provision"),
                Err(_) => {
                    term::warn("run ward unlock --ttl 8h to refresh/provision from this project")
                }
            }
        }
        Err(error) => term::fail(&format!("registry resolve failed — {error}")),
    }

    // ── human mode ───────────────────────────────────────────────────────────
    term::section("human mode");
    let human = crate::human::runtime_diagnostics();
    if human.shell_hooks_loaded {
        term::ok("shell hooks loaded");
    } else {
        term::warn("shell hooks not loaded — reload your shell, then run ward human");
    }
    if human.guardian_socket_exists {
        term::ok(&format!("guardian active for shell {}", human.shell_pid));
    } else {
        term::warn(&format!(
            "guardian missing for shell {} — run ward human",
            human.shell_pid
        ));
        term::info(&format!(
            "expected socket {}",
            term::short_path(&human.socket_path)
        ));
    }
    if human.stale_guardian_pids.is_empty() && human.stale_run_dirs.is_empty() {
        term::ok("no stale human runtime files");
    } else {
        if !human.stale_guardian_pids.is_empty() {
            term::warn(&format!(
                "stale guardian process(es): {}",
                human
                    .stale_guardian_pids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for dir in &human.stale_run_dirs {
            term::warn(&format!("stale runtime dir  {}", term::short_path(dir)));
        }
        term::info("run ward human to clean stale human runtime state");
    }

    // ── dashboard ───────────────────────────────────────────────────────────
    term::section("dashboard");
    match crate::webui::dashboard_diagnostics() {
        Ok(instances) if instances.is_empty() => {
            term::ok("no standalone browser dashboards running");
            term::info("run ward dashboard start to open the browser dashboard");
        }
        Ok(instances) => {
            term::ok(&format!(
                "{} standalone browser dashboard(s) running",
                instances.len()
            ));
            for instance in instances {
                term::info(&format!(
                    "pid={} port={} project={}",
                    instance.pid,
                    instance.port,
                    instance.started_project.as_deref().unwrap_or("-")
                ));
            }
        }
        Err(e) => term::fail(&format!("dashboard status failed — {e}")),
    }

    // ── grants ────────────────────────────────────────────────────────────────
    term::section("grants");

    match grants::load_grants() {
        Ok(loaded) => {
            let now = chrono::Utc::now();
            let unsigned = loaded
                .iter()
                .filter(|g| {
                    grants::grant_integrity_status(g, now)
                        == grants::GrantIntegrityStatus::LegacyUnsigned
                })
                .count();
            let invalid = loaded
                .iter()
                .filter(|g| {
                    grants::grant_integrity_status(g, now) == grants::GrantIntegrityStatus::Invalid
                })
                .count();
            if unsigned == 0 && invalid == 0 {
                term::ok("all approval grants signed and valid");
            }
            if unsigned > 0 {
                term::warn(&format!(
                    "{unsigned} legacy unsigned grant(s) — re-approve them"
                ));
            }
            if invalid > 0 {
                term::warn(&format!(
                    "{invalid} invalid grant signature(s) — revoke and re-approve"
                ));
            }
        }
        Err(e) => term::fail(&format!("grant check failed — {e}")),
    }

    // ── logs ──────────────────────────────────────────────────────────────────
    term::section("logs");

    match audit_logs::entry_count(LogKind::Alerts) {
        Ok(0) => term::ok("no alerts"),
        Ok(n) => term::warn(&format!("{n} alert(s) — run ward logs view alerts")),
        Err(e) => term::fail(&format!("alert log check failed — {e}")),
    }

    // ── recovery ──────────────────────────────────────────────────────────────
    term::section("recovery");

    if let Ok(cfg) = &project_config {
        let configured_vault = doctor_vault_path(&cwd, cfg);
        match vault::read_vault(&configured_vault) {
            Ok(envelope) => {
                term::ok_detail("vault key mode", envelope.key_mode().label());
                if envelope.key_mode() == vault::VaultKeyMode::ApiDerivedV1 {
                    term::ok("clone-anywhere recovery uses .env.vault + PIN/passphrase + Ward API");
                    term::info("offline fallback requires ward key export");
                } else {
                    term::ok("primary recovery uses .env.vault + PIN/passphrase");
                }
            }
            Err(_) => term::warn("unable to inspect vault key mode"),
        }
        if vault::test_passphrase().is_some() {
            let passphrase = vault::test_passphrase().unwrap();
            let vault_path = config::resolve_vault_path_with_passphrase(&cwd, cfg, &passphrase);
            if vault::decrypt_vault_file(&vault_path, &passphrase).is_ok() {
                term::ok("vault decrypts with configured PIN/passphrase");
            } else {
                term::fail("vault did not decrypt with configured PIN/passphrase");
            }
        }
        if cfg.recovery_created {
            term::info("legacy recovery file configured");
        }
    } else {
        term::warn("unable to check recovery — config not readable");
    }

    term::blank();
    Ok(())
}

fn doctor_global_state() {
    term::section("global");

    match global_disable::read() {
        Ok(Some(state)) => {
            term::warn("Ward globally disabled — run: ward on");
            term::info(&format!("disabled at {}", state.disabled_at.to_rfc3339()));
            term::info(&format!("reason {}", state.reason));
            term::info(&format!(
                "state {}",
                term::short_path(&global_disable::disabled_path())
            ));
        }
        Ok(None) => term::ok("Ward enabled"),
        Err(error) => term::fail(&format!("disabled state unreadable — {error}")),
    }
}

fn doctor_vault_path(cwd: &Path, cfg: &config::ProjectConfig) -> PathBuf {
    registry::resolve_project(Some(&cfg.project), cwd)
        .map(|resolved| resolved.vault)
        .unwrap_or_else(|_| config::resolve_vault_path(cwd, cfg))
}

#[cfg(any(test, coverage))]
fn signing_lookup_message(result: Result<unlock::RunSigningLookup>) -> String {
    match result {
        Ok(unlock::RunSigningLookup::Available(_)) => {
            "[ok] Active signing key session is readable.".to_string()
        }
        Ok(unlock::RunSigningLookup::Missing) => {
            "! No active signing key session. Run ward unlock --ttl 8h.".to_string()
        }
        Ok(unlock::RunSigningLookup::MaterialUnavailable { reason }) => {
            format!(
                "! Active signing key session is unavailable ({reason}). Run ward unlock --ttl 8h."
            )
        }
        Err(error) => format!("! Signing key session check failed: {error}"),
    }
}

fn logs(command: Option<LogsCommand>, kind: Option<LogKind>) -> Result<()> {
    match command {
        Some(LogsCommand::View { kind }) => {
            ensure_logs_passphrase()?;
            warn_log_view_access();
            let output = render_log_events(&audit_logs::decrypt_events(kind)?)?;
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Some(LogsCommand::Verify { kind, full }) => {
            let reports = if full {
                ensure_logs_passphrase()?;
                audit_logs::verify_logs_full(kind)?
            } else {
                audit_logs::verify_logs(kind)?
            };
            term::emit_header(&term::Header {
                command: Some("logs verify"),
                project: "audit logs",
                path: Some(&audit_logs::logs_dir()),
                mode: None,
            });
            for report in reports {
                term::ok_detail(
                    report.kind.as_str(),
                    &format!(
                        "entries={} path={}",
                        report.entries,
                        term::short_path(&report.path)
                    ),
                );
            }
        }
        Some(LogsCommand::Export {
            kind,
            output,
            force,
        }) => {
            if output.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite",
                    output.display()
                );
            }
            ensure_logs_passphrase()?;
            warn_log_view_access();
            let output_contents = render_log_events(&audit_logs::decrypt_events(kind)?)?;
            crate::fs_util::write_private_file(&output, output_contents.as_bytes())?;
            term::emit_header(&term::Header {
                command: Some("logs export"),
                project: kind.as_str(),
                path: Some(&output),
                mode: None,
            });
            term::ok("decrypted log exported");
        }
        Some(LogsCommand::Unlock { ttl }) => unlock_logs(&ttl)?,
        None => match kind {
            Some(kind) => println!("{}", audit_logs::log_path(kind).display()),
            None => println!("{}", audit_logs::logs_dir().display()),
        },
    }
    Ok(())
}

fn render_log_events(events: &[Value]) -> Result<String> {
    let mut lines = Vec::with_capacity(events.len());
    for event in events {
        lines.push(serde_json::to_string(event)?);
    }
    Ok(lines.join("\n"))
}
