fn init(project: Option<String>, force: bool, bare: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let source = cwd.join(".env");
    let vault_path = cwd.join(config::DEFAULT_VAULT_FILE);
    if !bare && (source.exists() || vault_path.exists()) {
        return setup(SetupOptions {
            yes: true,
            project,
            source: PathBuf::from(".env"),
            vault: PathBuf::from(config::DEFAULT_VAULT_FILE),
            key_mode: vault::VaultKeyMode::ApiDerivedV1,
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        });
    }

    init_bare(project, force)
}

fn init_bare(project: Option<String>, force: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let config = config::ProjectConfig::default_for_dir(&cwd, project)?;
    let config_path = config::write_project_config(&cwd, &config, force)?;
    let env_example = config::ensure_env_example(&cwd)?;
    let agent_instructions = config::ensure_agent_instructions(&cwd, &config.project)?;

    term::emit_header(&term::Header {
        command: Some("init"),
        project: &config.project,
        path: Some(&cwd),
        mode: None,
    });
    term::ok_detail(".ward.json ready", &term::short_path(&config_path));
    if let Some(path) = env_example {
        term::ok_detail(".env.example ready", &term::short_path(&path));
    }
    if let Some(path) = agent_instructions {
        term::ok_detail("AGENTS.md ready", &term::short_path(&path));
    }
    if cwd.join(".env").exists() {
        term::warn("plaintext .env exists");
        term::next("run: ward import .env");
    }
    if let Some(rc) = ensure_shell_integration() {
        term::section("shell");
        term::ok_detail("shell integration", &term::short_path(&rc));
        prompt_shell_reload(&rc);
    }

    Ok(())
}

fn import(
    source: PathBuf,
    explicit_vault: Option<PathBuf>,
    key_mode: vault::VaultKeyMode,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let source_path = fs_util::resolve_project_path(&cwd, &source, "import source")?;
    let mut config =
        config::read_project_config(&cwd).context("missing .ward.json; run ward init first")?;
    if env_file::is_locked_env_file(&source_path)? {
        anyhow::bail!(
            "{} is already an Ward locked marker; use ward env unlock to restore plaintext before importing",
            source_path.display()
        );
    }
    let passphrase = vault::read_new_passphrase()?;
    let vault_path = match explicit_vault {
        Some(vault) => {
            let resolved_vault = fs_util::resolve_project_path(&cwd, &vault, "import vault")?;
            config.vault = vault.clone();
            config::write_project_config(&cwd, &config, true)?;
            resolved_vault
        }
        None => registry::resolve_project(Some(&config.project), &cwd)
            .ok()
            .map(|resolved| resolved.vault)
            .filter(|path| path.exists())
            .unwrap_or_else(|| {
                config::resolve_vault_path_with_passphrase(&cwd, &config, &passphrase)
            }),
    };

    let written =
        vault::import_env_file_with_key_mode(&source_path, &vault_path, &passphrase, key_mode)?;
    vault::decrypt_vault_file(&written, &passphrase)?;
    env_file::lock_env_file(&source_path, &written)?;
    registry::update_project_vault(&config.project, cwd.clone(), written.clone())?;
    let resolved = registry::ResolvedProject {
        name: config.project.clone(),
        path: cwd.clone(),
        vault: written.clone(),
    };
    warn_store_refresh_failure(refresh_project_store_with_passphrase(
        &resolved,
        &passphrase,
    ));
    let event = VaultImportEvent {
        event_type: "vault.import",
        project: &config.project,
        source: &source_path,
        vault: &written,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;

    term::emit_header(&term::Header {
        command: Some("import"),
        project: &config.project,
        path: Some(&cwd),
        mode: None,
    });
    term::ok_detail("vault encrypted", &term::short_path(&written));
    term::ok_detail("locked marker", &source_path.display().to_string());
    Ok(())
}

fn register(project: String, path: Option<PathBuf>, explicit_vault: Option<PathBuf>) -> Result<()> {
    let cwd = env::current_dir()?;
    let project_path = path.unwrap_or(cwd.clone());
    let vault_path = match explicit_vault {
        Some(vault) if vault.is_absolute() => vault,
        Some(vault) => project_path.join(vault),
        None => {
            let project_config = config::read_project_config(&project_path)
                .context("missing .ward.json; run ward init first")?;
            config::resolve_vault_path(&project_path, &project_config)
        }
    };

    let registered = registry::register_project(project.clone(), project_path, vault_path)?;
    term::emit_header(&term::Header {
        command: Some("register"),
        project: &project,
        path: Some(&registered.path),
        mode: None,
    });
    term::ok("project registered");
    term::ok_detail("vault", &term::short_path(&registered.vault));
    Ok(())
}

fn projects_discover(path: PathBuf, json: bool) -> Result<()> {
    let summary = discover_and_register_projects(&path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        term::emit_header(&term::Header {
            command: Some("projects discover"),
            project: "registry",
            path: Some(&summary.root),
            mode: None,
        });
        if summary.projects.is_empty() {
            term::warn("no Ward projects discovered");
            return Ok(());
        }
        term::section("projects");
        for project in &summary.projects {
            let status = if project.already_registered {
                "updated"
            } else {
                "registered"
            };
            term::ok_detail(
                &project.project,
                &format!(
                    "{status} name={} path={} vault={} source={}",
                    project.display_name,
                    term::short_path(&project.path),
                    term::short_path(&project.vault),
                    project.source
                ),
            );
        }
        term::info(&format!(
            "{} discovered, {} registered, {} updated",
            summary.discovered, summary.registered, summary.updated
        ));
    }
    Ok(())
}

fn discover_and_register_projects(root: &Path) -> Result<ProjectsDiscoverSummary> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if !root.exists() {
        anyhow::bail!("discover root does not exist: {}", root.display());
    }
    let candidates = collect_project_discovery_candidates(&root)?;
    let discovered = candidates.len();
    let registrations = registry::upsert_discovered_projects(
        candidates
            .into_iter()
            .map(|candidate| registry::DiscoveredProject {
                display_name: candidate.display_name,
                path: candidate.path,
                vault: candidate.vault,
                source: candidate.source,
            })
            .collect(),
    )?;
    let registered = registrations
        .iter()
        .filter(|project| !project.already_registered)
        .count();
    let updated = registrations.len().saturating_sub(registered);
    Ok(ProjectsDiscoverSummary {
        root,
        discovered,
        registered,
        updated,
        projects: registrations,
    })
}

fn collect_project_discovery_candidates(root: &Path) -> Result<Vec<ProjectDiscoveryCandidate>> {
    let mut candidates: BTreeMap<PathBuf, ProjectDiscoveryCandidate> = BTreeMap::new();
    collect_config_backup_discovery_candidates(&mut candidates, root)?;
    collect_filesystem_discovery_candidates(&mut candidates, root)?;
    Ok(candidates.into_values().collect())
}

fn collect_config_backup_discovery_candidates(
    candidates: &mut BTreeMap<PathBuf, ProjectDiscoveryCandidate>,
    root: &Path,
) -> Result<()> {
    let dir = config::config_backups_dir();
    if !dir.exists() {
        return Ok(());
    }
    let Ok(entries) = fs::read_dir(&dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(backup) = serde_json::from_str::<config::ProjectConfigBackup>(&contents) else {
            continue;
        };
        if !path_is_under(&backup.project_path, root) {
            continue;
        }
        let Ok(vault) = config::resolve_vault_path_checked(&backup.project_path, &backup.config)
        else {
            continue;
        };
        add_project_discovery_candidate(
            candidates,
            ProjectDiscoveryCandidate {
                display_name: backup.project,
                path: backup.project_path,
                vault,
                source: "config-backup".to_string(),
            },
        );
    }
    Ok(())
}

fn collect_filesystem_discovery_candidates(
    candidates: &mut BTreeMap<PathBuf, ProjectDiscoveryCandidate>,
    root: &Path,
) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let config_path = config::config_path(&path);
        let default_vault = path.join(config::DEFAULT_VAULT_FILE);
        if let Ok(project_config) = config::read_project_config(&path) {
            let Ok(vault) = config::resolve_vault_path_checked(&path, &project_config) else {
                continue;
            };
            add_project_discovery_candidate(
                candidates,
                ProjectDiscoveryCandidate {
                    display_name: project_config.project,
                    path: path.clone(),
                    vault,
                    source: "config".to_string(),
                },
            );
        } else if default_vault.exists() && !config_path.exists() {
            let project = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("project")
                .to_string();
            add_project_discovery_candidate(
                candidates,
                ProjectDiscoveryCandidate {
                    display_name: project,
                    path: path.clone(),
                    vault: default_vault,
                    source: "vault".to_string(),
                },
            );
        }

        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git" | ".ward" | "node_modules" | "target" | ".next" | ".turbo"
            ) {
                continue;
            }
            stack.push(entry.path());
        }
    }
    Ok(())
}

fn add_project_discovery_candidate(
    candidates: &mut BTreeMap<PathBuf, ProjectDiscoveryCandidate>,
    candidate: ProjectDiscoveryCandidate,
) {
    let key = candidate
        .path
        .canonicalize()
        .unwrap_or_else(|_| candidate.path.clone());
    candidates
        .entry(key)
        .and_modify(|existing| {
            if discovery_source_priority(&candidate.source)
                < discovery_source_priority(&existing.source)
            {
                *existing = candidate.clone();
            }
        })
        .or_insert(candidate);
}

fn discovery_source_priority(source: &str) -> u8 {
    match source {
        "config" => 0,
        "config-backup" => 1,
        "vault" => 2,
        _ => 3,
    }
}

fn path_is_under(path: &Path, root: &Path) -> bool {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    path.starts_with(root)
}

fn use_project(project: &str) -> Result<()> {
    registry::set_active_project(project)?;
    term::emit_header(&term::Header {
        command: Some("use"),
        project,
        path: None,
        mode: None,
    });
    term::ok("active project selected");
    Ok(())
}

fn projects_command(command: ProjectsCommand) -> Result<()> {
    match command {
        ProjectsCommand::List => {
            let registry = registry::list_projects()?;
            term::emit_header(&term::Header {
                command: Some("projects list"),
                project: "registry",
                path: None,
                mode: None,
            });
            if registry.projects.is_empty() {
                term::info("no registered projects");
                return Ok(());
            }
            term::section("projects");
            for (name, project) in registry.projects {
                let active = if registry.active_project.as_deref() == Some(name.as_str()) {
                    "active"
                } else {
                    "registered"
                };
                let display_name = project.display_name.as_deref().unwrap_or(&name);
                let source = project.source.as_deref().unwrap_or("unknown");
                let last_seen = project.last_seen_at.as_deref().unwrap_or("unknown");
                term::ok_detail(
                    &name,
                    &format!(
                        "{active} name={} path={} vault={} source={} lastSeen={}",
                        display_name,
                        term::short_path(&project.path),
                        term::short_path(&project.vault),
                        source,
                        last_seen
                    ),
                );
            }
        }
        ProjectsCommand::Show { project } => {
            let cwd = env::current_dir()?;
            let resolved = registry::resolve_project(project.as_deref(), &cwd)?;
            let registry = registry::list_projects()?;
            let registered = registry.projects.get(&resolved.name);
            term::emit_header(&term::Header {
                command: Some("projects show"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            if let Some(display_name) =
                registered.and_then(|project| project.display_name.as_deref())
            {
                term::ok_detail("name", display_name);
            }
            term::ok_detail("vault", &term::short_path(&resolved.vault));
            if let Some(source) = registered.and_then(|project| project.source.as_deref()) {
                term::ok_detail("source", source);
            }
            if let Some(last_seen) = registered.and_then(|project| project.last_seen_at.as_deref())
            {
                term::ok_detail("last seen", last_seen);
            }
        }
        ProjectsCommand::Register {
            project,
            path,
            vault,
        } => register(project, path, vault)?,
        ProjectsCommand::Discover { path, json } => projects_discover(path, json)?,
        ProjectsCommand::Use { project } => use_project(&project)?,
        ProjectsCommand::Remove { project } => {
            let registry_removed = registry::remove_project(&project)?;
            let backup_removed = config::remove_project_config_backup(&project)?;
            if registry_removed || backup_removed {
                term::emit_header(&term::Header {
                    command: Some("projects remove"),
                    project: &project,
                    path: None,
                    mode: None,
                });
                if registry_removed {
                    term::ok("registry entry removed");
                }
                if backup_removed {
                    term::ok("config backup removed");
                }
            } else {
                term::warn_detail("project not found", &project);
            }
        }
        ProjectsCommand::Provision {
            from_project,
            path,
            name,
            profiles,
            env_names,
            agents,
            json,
        } => {
            let cwd = env::current_dir()?;
            let source = registry::resolve_project(Some(&from_project), &cwd)?;
            let status =
                broker::provision_project_from_active_session(broker::ProjectProvisionRequest {
                    source_project: source.name,
                    source_vault: source.vault,
                    target_path: path,
                    project: name,
                    profiles,
                    env_names,
                    agents,
                })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                term::emit_header(&term::Header {
                    command: Some("projects provision"),
                    project: &status.project,
                    path: Some(&status.path),
                    mode: None,
                });
                term::ok("project provisioned");
                term::ok_detail("vault", &term::short_path(&status.vault));
                term::ok_detail("env", &status.env_names.join(", "));
                term::ok_detail("profiles", &status.profiles.join(", "));
                if !status.agents.is_empty() {
                    term::ok_detail("agents", &status.agents.join(", "));
                }
            }
        }
    }
    Ok(())
}

fn store_command(command: StoreCommand) -> Result<()> {
    match command {
        StoreCommand::List { json } => {
            let summaries = project_store::list_summaries()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summaries)?);
            } else if summaries.is_empty() {
                term::emit_header(&term::Header {
                    command: Some("store list"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::info("no project-store snapshots");
            } else {
                term::emit_header(&term::Header {
                    command: Some("store list"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::section("snapshots");
                for summary in summaries {
                    let stale = if summary.stale { " stale" } else { "" };
                    term::ok_detail(
                        &summary.project_name,
                        &format!(
                            "env={} profiles={} agents={} updated={}{}",
                            summary.env_names.len(),
                            summary.profile_names.len(),
                            summary.agent_names.len(),
                            summary.updated_at,
                            stale
                        ),
                    );
                }
            }
        }
        StoreCommand::Show { project, json } => {
            let summary = project_store::show_summary(&project)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                term::emit_header(&term::Header {
                    command: Some("store show"),
                    project: &summary.project_name,
                    path: Some(&summary.path),
                    mode: None,
                });
                term::ok_detail("vault", &term::short_path(&summary.vault));
                term::ok_detail("env", &summary.env_names.join(", "));
                term::ok_detail("profiles", &summary.profile_names.join(", "));
                term::ok_detail("agents", &summary.agent_names.join(", "));
                term::ok_detail("updated", &summary.updated_at);
                if summary.stale {
                    term::warn("snapshot stale");
                } else {
                    term::ok("snapshot fresh");
                }
            }
        }
        StoreCommand::Refresh { project, json } => {
            let cwd = env::current_dir()?;
            let resolved = registry::resolve_project(project.as_deref(), &cwd)?;
            let status =
                broker::snapshot_project_from_active_session(&resolved.name, &resolved.vault)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                term::emit_header(&term::Header {
                    command: Some("store refresh"),
                    project: &status.store.project_name,
                    path: Some(&resolved.path),
                    mode: None,
                });
                term::ok_detail("snapshot refreshed", &status.store.updated_at);
            }
        }
    }
    Ok(())
}

fn config_command(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Restore { force, json } => {
            let cwd = env::current_dir()?;
            match config::restore_project_config_from_backup(&cwd, force)? {
                Some(restored) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&restored)?);
                    } else {
                        term::emit_header(&term::Header {
                            command: Some("config restore"),
                            project: &restored.project,
                            path: Some(&cwd),
                            mode: None,
                        });
                        term::ok_detail(
                            ".ward.json restored",
                            &term::short_path(&restored.config_path),
                        );
                        term::ok_detail("backup", &term::short_path(&restored.backup_path));
                    }
                }
                None => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "notFound",
                                "message": "No local .ward.json backup was found for this folder."
                            }))?
                        );
                    } else {
                        anyhow::bail!(
                            "no local .ward.json backup found for {}; run ward setup to create a new config",
                            cwd.display()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn workspace_command(command: WorkspaceCommand) -> Result<()> {
    match command {
        WorkspaceCommand::Discover { json } => {
            let cwd = env::current_dir()?;
            let discovery = workspace::discover_containing(&cwd)?
                .context("no workspace manifest found; expected pnpm-workspace.yaml, package.json workspaces, or turbo.json")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&discovery)?);
            } else {
                print_workspace_discovery(&discovery);
            }
        }
        WorkspaceCommand::Projects { json } => {
            let cwd = env::current_dir()?;
            let discovery = workspace::discover_containing(&cwd)?
                .context("no workspace manifest found; expected pnpm-workspace.yaml, package.json workspaces, or turbo.json")?;
            let targets = workspace_target::configured_workspace_targets(&discovery)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&targets_as_json(&targets))?
                );
            } else if targets.is_empty() {
                term::warn("no configured Ward app projects found");
            } else {
                term::emit_header(&term::Header {
                    command: Some("workspace projects"),
                    project: &discovery.workspace_name,
                    path: Some(&discovery.root),
                    mode: None,
                });
                term::section("apps");
                for target in &targets {
                    let app = target.app_slug.as_deref().unwrap_or(&target.name);
                    term::ok_detail(
                        app,
                        &format!("{} path={}", target.name, term::short_path(&target.path)),
                    );
                }
            }
        }
        WorkspaceCommand::Doctor => {
            doctor_for_target(None, None, true)?;
        }
    }
    Ok(())
}

fn targets_as_json(targets: &[workspace_target::WorkspaceTarget]) -> Vec<serde_json::Value> {
    targets
        .iter()
        .map(|target| {
            serde_json::json!({
                "project": target.name,
                "path": target.path,
                "vault": target.vault,
                "workspaceRoot": target.workspace_root,
                "workspaceName": target.workspace_name,
                "appSlug": target.app_slug,
                "packageName": target.package_name,
            })
        })
        .collect()
}

fn print_workspace_discovery(discovery: &workspace::WorkspaceDiscovery) {
    term::emit_header(&term::Header {
        command: Some("workspace discover"),
        project: &discovery.workspace_name,
        path: Some(&discovery.root),
        mode: None,
    });
    term::section("workspace");
    term::ok_detail(
        "package manager",
        discovery.package_manager.as_deref().unwrap_or("-"),
    );
    if discovery.turborepo {
        term::ok("turborepo detected");
    } else {
        term::info("turborepo not detected");
    }
    term::section("packages");
    for package in &discovery.packages {
        let app_marker = if package.app_candidate {
            "app"
        } else {
            "package"
        };
        let detail = format!(
            "kind={} project={} env={:?} setup={:?} envNames={} path={}",
            app_marker,
            package.project_name,
            package.env_status,
            package.setup_status,
            package.env_example_keys.len(),
            package.relative_path.display()
        );
        if package.app_candidate {
            term::ok_detail(&package.slug, &detail);
        } else {
            term::info_detail(&package.slug, &detail);
        }
    }
}
