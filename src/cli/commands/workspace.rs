fn setup_workspace(options: SetupOptions, apps: Vec<String>, all: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let discovery = workspace::discover(&cwd)?
        .context("no workspace manifest found; expected pnpm-workspace.yaml, package.json workspaces, or turbo.json")?;
    setup_workspace_with_discovery(options, apps, all, discovery)
}

fn setup_workspace_with_discovery(
    options: SetupOptions,
    apps: Vec<String>,
    all: bool,
    discovery: workspace::WorkspaceDiscovery,
) -> Result<()> {
    if options.commit_vault && options.ignore_vault {
        anyhow::bail!("choose either --commit-vault or --ignore-vault");
    }
    if options.remove_plaintext && options.keep_plaintext {
        anyhow::bail!("choose either --remove-plaintext or --keep-plaintext");
    }

    term::guided_context_header(
        "setup",
        "Workspace",
        &discovery.workspace_name,
        &discovery.root,
        WORKSPACE_SETUP_BODY,
    );
    print_workspace_setup_overview(&discovery);

    let project_prefix = options
        .project
        .as_deref()
        .unwrap_or(&discovery.workspace_name)
        .to_string();
    let selected = selected_workspace_apps(&discovery, &apps, all, options.yes)?;
    if selected.is_empty() {
        let refreshed = trust_workspace_root_for_configured_apps(&discovery, &project_prefix)?;
        if !refreshed.is_empty() {
            let result = WorkspaceSetupResult {
                workspace: discovery.workspace_name,
                root: discovery.root,
                configured: Vec::new(),
                skipped: refreshed,
            };
            print_workspace_setup_result(&result);
            return Ok(());
        }
        term::section("Next");
        term::info("No ready app env files were found.");
        term::next("add .env files to app folders, then run: ward setup --workspace --all");
        term::next("or choose one app: ward setup --workspace --app <name>");
        return Ok(());
    }

    let passphrase = vault::read_existing_passphrase()?;
    let mut configured = Vec::new();
    let mut skipped = Vec::new();

    for package in selected {
        let project_name = workspace_package_project_name(package, &project_prefix);
        if package.setup_status == workspace::WorkspaceSetupStatus::Configured {
            trust_workspace_root_for_project(&project_name, &discovery.root)?;
            workspace_target::register_workspace_metadata(&project_name, &discovery, package)?;
            skipped.push(WorkspaceSetupItem {
                app: package.slug.clone(),
                project: project_name,
                path: package.path.clone(),
                status: "configured".to_string(),
                reason: Some("app already has .ward.json".to_string()),
            });
            continue;
        }
        if !package.can_setup() {
            skipped.push(WorkspaceSetupItem {
                app: package.slug.clone(),
                project: project_name,
                path: package.path.clone(),
                status: workspace_setup_status_label(&package.setup_status).to_string(),
                reason: Some("app has no plaintext .env to import".to_string()),
            });
            continue;
        }

        match broker::setup_project_with_passphrase(&package.path, Some(&project_name), &passphrase)
        {
            Ok(status) => {
                trust_workspace_root_for_project(&status.project, &discovery.root)?;
                workspace_target::register_workspace_metadata(
                    &status.project,
                    &discovery,
                    package,
                )?;
                configured.push(WorkspaceSetupItem {
                    app: package.slug.clone(),
                    project: status.project,
                    path: status.path,
                    status: "configured".to_string(),
                    reason: None,
                });
            }
            Err(error) => {
                skipped.push(WorkspaceSetupItem {
                    app: package.slug.clone(),
                    project: project_name,
                    path: package.path.clone(),
                    status: "failed".to_string(),
                    reason: Some(error.to_string()),
                });
            }
        }
    }

    let result = WorkspaceSetupResult {
        workspace: discovery.workspace_name,
        root: discovery.root,
        configured,
        skipped,
    };
    print_workspace_setup_result(&result);
    Ok(())
}

fn print_workspace_setup_overview(discovery: &workspace::WorkspaceDiscovery) {
    let apps = discovery.app_candidates().collect::<Vec<_>>();
    let ready_apps = apps.iter().filter(|package| package.can_setup()).count();
    let configured_apps = apps
        .iter()
        .filter(|package| package.setup_status == workspace::WorkspaceSetupStatus::Configured)
        .count();
    let needs_env_apps = apps
        .iter()
        .filter(|package| package.setup_status == workspace::WorkspaceSetupStatus::NeedsEnv)
        .count();
    let library_count = discovery
        .packages
        .iter()
        .filter(|package| !package.app_candidate)
        .count();

    term::section("Workspace");
    if let Some(manager) = discovery.package_manager.as_deref() {
        term::ok(&format!("package manager {manager}"));
    }
    if discovery.turborepo {
        term::ok("turborepo detected");
    }
    term::ok(&format!("{} app project(s) detected", apps.len()));
    if ready_apps > 0 {
        term::ok(&format!("{ready_apps} app(s) ready to configure"));
    }
    if configured_apps > 0 {
        term::ok(&format!("{configured_apps} app(s) already configured"));
    }
    if needs_env_apps > 0 {
        term::warn(&format!(
            "{needs_env_apps} app(s) need a real .env before setup"
        ));
    }
    if library_count > 0 {
        term::info(&format!("{library_count} package(s) skipped by default"));
    }

    term::section("Apps");
    for package in &discovery.packages {
        print_workspace_package_line(package);
    }
}

fn print_workspace_package_line(package: &workspace::WorkspacePackage) {
    let path = term::short_path(&package.relative_path);
    if !package.app_candidate {
        term::info(&format!("{}  package skipped  {}", package.slug, path));
        return;
    }

    match package.setup_status {
        workspace::WorkspaceSetupStatus::Configured => term::ok(&format!(
            "{}  already configured  {}  {}",
            package.slug, package.project_name, path
        )),
        workspace::WorkspaceSetupStatus::NeedsEnv => term::warn(&format!(
            "{}  needs .env  {}  {}",
            package.slug, package.project_name, path
        )),
        workspace::WorkspaceSetupStatus::NotConfigured => {
            if package.env_status == workspace::WorkspaceEnvStatus::Present {
                term::ok(&format!(
                    "{}  .env ready  {}  {}",
                    package.slug, package.project_name, path
                ));
            } else {
                term::info(&format!(
                    "{}  no .env  {}  {}",
                    package.slug, package.project_name, path
                ));
            }
        }
    }
}

fn print_workspace_setup_result(result: &WorkspaceSetupResult) {
    term::section("Setup");
    if result.configured.is_empty() && result.skipped.is_empty() {
        term::info("No app projects changed.");
    }
    for item in &result.configured {
        term::ok(&format!("{} configured as {}", item.app, item.project));
        term::info(&format!("path {}", term::short_path(&item.path)));
    }
    for item in &result.skipped {
        match item.reason.as_deref() {
            Some("workspace Git root trusted") => {
                term::ok(&format!("{} refreshed as {}", item.app, item.project));
                term::info("workspace Git root trusted");
            }
            Some("app already has .ward.json") => {
                term::ok(&format!(
                    "{} already configured as {}",
                    item.app, item.project
                ));
                term::info("workspace Git root trusted");
            }
            Some(reason) => {
                term::warn(&format!("{} skipped — {reason}", item.app));
            }
            None => {
                term::info(&format!("{} skipped", item.app));
            }
        }
    }

    term::section("Next");
    if !result.configured.is_empty() {
        term::next("open the dashboard: ward dashboard start");
        term::next("activate an app terminal: cd apps/<app> && ward human");
        term::next("or from the workspace root: ward human --app <app>");
    } else {
        term::next("open the dashboard: ward dashboard start");
    }
}

fn trust_workspace_root_for_configured_apps(
    discovery: &workspace::WorkspaceDiscovery,
    project_prefix: &str,
) -> Result<Vec<WorkspaceSetupItem>> {
    let mut refreshed = Vec::new();
    for package in discovery
        .app_candidates()
        .filter(|package| package.setup_status == workspace::WorkspaceSetupStatus::Configured)
    {
        let project_name = workspace_package_project_name(package, project_prefix);
        trust_workspace_root_for_project(&project_name, &discovery.root)?;
        workspace_target::register_workspace_metadata(&project_name, discovery, package)?;
        refreshed.push(WorkspaceSetupItem {
            app: package.slug.clone(),
            project: project_name,
            path: package.path.clone(),
            status: "configured".to_string(),
            reason: Some("workspace Git root trusted".to_string()),
        });
    }
    Ok(refreshed)
}

fn workspace_package_project_name(
    package: &workspace::WorkspacePackage,
    project_prefix: &str,
) -> String {
    config::read_project_config(&package.path)
        .map(|config| config.project)
        .unwrap_or_else(|_| format!("{project_prefix}:{}", package.slug))
}

fn trust_workspace_root_for_project(project: &str, workspace_root: &Path) -> Result<()> {
    let git = git_context::collect_git_context(workspace_root);
    let git_remote = git.remote.as_deref().unwrap_or_default();
    worktrees::trust_worktree(
        project,
        workspace_root,
        git_remote,
        git.common_dir,
        "workspace-root-setup",
    )?;
    Ok(())
}

fn should_auto_route_workspace_setup(options: &SetupOptions) -> bool {
    options.source == Path::new(".env")
        && options.vault == Path::new(config::DEFAULT_VAULT_FILE)
        && !options.commit_vault
        && !options.ignore_vault
        && !options.remove_plaintext
        && !options.keep_plaintext
}

fn selected_workspace_apps<'a>(
    discovery: &'a workspace::WorkspaceDiscovery,
    apps: &[String],
    all: bool,
    yes: bool,
) -> Result<Vec<&'a workspace::WorkspacePackage>> {
    if all || !apps.is_empty() {
        return discovery.selected_apps(apps, all);
    }

    let setup_capable = discovery
        .app_candidates()
        .filter(|package| package.can_setup())
        .collect::<Vec<_>>();
    if setup_capable.is_empty() {
        return Ok(Vec::new());
    }
    if yes {
        return Ok(setup_capable);
    }

    #[cfg(coverage)]
    {
        return Ok(setup_capable);
    }
    #[cfg(not(coverage))]
    {
        let prompt = format!(
            "Configure {} ready workspace app(s) now?",
            setup_capable.len()
        );
        let configure = inquire::Confirm::new(&prompt)
            .with_help_message(WORKSPACE_SETUP_PROMPT_HELP)
            .with_default(true)
            .prompt()
            .unwrap_or(false);
        if configure {
            Ok(setup_capable)
        } else {
            Ok(Vec::new())
        }
    }
}

fn workspace_setup_status_label(status: &workspace::WorkspaceSetupStatus) -> &'static str {
    match status {
        workspace::WorkspaceSetupStatus::Configured => "configured",
        workspace::WorkspaceSetupStatus::NeedsEnv => "needsEnv",
        workspace::WorkspaceSetupStatus::NotConfigured => "notConfigured",
    }
}

fn broker_command(command: BrokerCommand) -> Result<()> {
    match command {
        BrokerCommand::Status => {
            let status = broker::status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        BrokerCommand::Stop => {
            broker::stop()?;
            term::emit_header(&term::Header {
                command: Some("broker stop"),
                project: "runtime",
                path: None,
                mode: None,
            });
            term::ok("broker stopped");
        }
        BrokerCommand::SocketPath => println!("{}", broker::socket_path().display()),
    }
    Ok(())
}

fn dashboard_command(command: Option<DashboardCommand>) -> Result<()> {
    match command.unwrap_or(DashboardCommand::Tui) {
        DashboardCommand::Start {
            port,
            no_open,
            foreground,
            json,
        } => crate::webui::start_dashboard(crate::webui::DashboardStartOptions {
            port,
            open_browser: !no_open,
            foreground,
            json,
        }),
        DashboardCommand::Stop {
            all,
            pid,
            port,
            json,
        } => crate::webui::stop_dashboards(crate::webui::DashboardStopOptions {
            all,
            pid,
            port,
            json,
        }),
        DashboardCommand::Status { json } => crate::webui::print_dashboard_status(json),
        DashboardCommand::Tui => crate::dashboard::run_dashboard(),
    }
}

fn worktrees_command(command: WorktreesCommand) -> Result<()> {
    match command {
        WorktreesCommand::List { project } => {
            let state = worktrees::list_project(&project)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        WorktreesCommand::AllowRoot { project, path } => {
            let root = worktrees::allow_root(&project, &path)?;
            term::emit_header(&term::Header {
                command: Some("worktrees allow-root"),
                project: &project,
                path: None,
                mode: None,
            });
            term::ok_detail("allowed root", &term::short_path(&root));
        }
        WorktreesCommand::RemoveRoot { project, path } => {
            if worktrees::remove_root(&project, &path)? {
                term::emit_header(&term::Header {
                    command: Some("worktrees remove-root"),
                    project: &project,
                    path: None,
                    mode: None,
                });
                term::ok_detail("removed root", &term::short_path(&path));
            } else {
                term::warn_detail("worktree root not found", &term::short_path(&path));
            }
        }
        WorktreesCommand::Approve { request_id, json } => {
            require_human_terminal_confirmation("APPROVE-WORKTREE", request_id)?;
            if let Some(worktree) = worktrees::approve_pending(request_id)? {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "approved",
                            "requestId": request_id,
                            "worktree": worktree.path,
                        }))?
                    );
                    return Ok(());
                }
                term::emit_header(&term::Header {
                    command: Some("worktrees approve"),
                    project: "worktree binding",
                    path: Some(&worktree.path),
                    mode: None,
                });
                term::ok_detail("request approved", &request_id.to_string());
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "not_found",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                term::warn_detail("worktree request not found", &request_id.to_string());
            }
        }
        WorktreesCommand::Deny { request_id, json } => {
            require_human_terminal_confirmation("DENY-WORKTREE", request_id)?;
            if worktrees::deny_pending(request_id)? {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "denied",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                term::emit_header(&term::Header {
                    command: Some("worktrees deny"),
                    project: "worktree binding",
                    path: None,
                    mode: None,
                });
                term::ok_detail("request denied", &request_id.to_string());
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "not_found",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                term::warn_detail("worktree request not found", &request_id.to_string());
            }
        }
    }
    Ok(())
}
