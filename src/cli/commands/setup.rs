fn setup(options: SetupOptions) -> Result<()> {
    if options.commit_vault && options.ignore_vault {
        anyhow::bail!("choose either --commit-vault or --ignore-vault");
    }
    if options.remove_plaintext && options.keep_plaintext {
        anyhow::bail!("choose either --remove-plaintext or --keep-plaintext");
    }
    if !options.no_unlock {
        unlock::parse_ttl(&options.unlock_ttl)?;
    }

    let cwd = env::current_dir()?;
    let auto_restored_config = if !config::config_path(&cwd).exists() {
        config::restore_project_config_from_backup(&cwd, false)?
    } else {
        None
    };
    if should_auto_route_workspace_setup(&options) {
        if let Some(discovery) = workspace::discover(&cwd)? {
            if discovery.app_candidates().next().is_some() {
                return setup_workspace_with_discovery(options, Vec::new(), false, discovery);
            }
        }
    }

    let commit_vault = !options.ignore_vault;
    let remove_plaintext = options.remove_plaintext && !options.keep_plaintext;
    let source_path = fs_util::resolve_project_path(&cwd, &options.source, "setup source")?;
    let configured_vault_path = fs_util::resolve_project_path(&cwd, &options.vault, "setup vault")?;
    let source_exists = source_path.exists();
    let registered_vault_path = config::read_project_config(&cwd)
        .ok()
        .and_then(|existing| registry::resolve_project(Some(&existing.project), &cwd).ok())
        .and_then(|resolved| {
            let same_path = resolved.path == cwd
                || resolved.path.canonicalize().ok() == cwd.canonicalize().ok();
            same_path.then_some(resolved.vault)
        })
        .filter(|path| path.exists());
    let vault_path = registered_vault_path.unwrap_or(configured_vault_path);
    if !source_exists && options.source != Path::new(".env") && !vault_path.exists() {
        anyhow::bail!("{} does not exist", options.source.display());
    }
    let source_is_locked = if source_exists {
        env_file::is_locked_env_file(&source_path)?
    } else {
        false
    };

    let env_keys = if source_exists && !source_is_locked {
        config::env_keys_from_dotenv_file(&source_path)?
    } else if let Ok(existing) = config::read_project_config(&cwd) {
        let mut keys = std::collections::BTreeSet::new();
        for profile in existing.profiles.values() {
            keys.extend(profile.env.iter().cloned());
        }
        keys.into_iter().collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut project_config = match config::read_project_config(&cwd) {
        Ok(mut existing) => {
            existing.project = options.project.unwrap_or(existing.project);
            existing.vault = options.vault.clone();
            config::merge_default_profiles(&mut existing, &env_keys, &cwd);
            existing
        }
        Err(_) => {
            let mut created = config::ProjectConfig::default_for_dir(&cwd, options.project)?;
            created.vault = options.vault.clone();
            created.profiles = config::default_profiles(&env_keys, &cwd);
            created
        }
    };
    config::merge_default_profiles(&mut project_config, &env_keys, &cwd);

    config::write_project_config(&cwd, &project_config, true)?;
    let env_example = config::ensure_env_example(&cwd)?;
    let agent_instructions = config::ensure_agent_instructions(&cwd, &project_config.project)?;
    config::ensure_gitignore(&cwd, commit_vault)?;

    // Print header before any prompts so PIN input is visually grouped below it.
    term::guided_header("setup", &project_config.project, &cwd, SETUP_GUIDED_BODY);

    let mut imported = false;
    let mut locked_env = false;
    let mut setup_passphrase = None;
    let mut verified_env_keys = None;
    let mut recovery_plaintext = None;
    term::section("vault");
    if source_exists {
        if source_is_locked {
            if !vault_path.exists() {
                anyhow::bail!(
                    "{} is an Ward locked marker but {} is missing; restore a plaintext dotenv file or the vault before setup",
                    source_path.display(),
                    vault_path.display()
                );
            }
            env_file::lock_env_file(&source_path, &vault_path)?;
            locked_env = true;
            term::ok_detail("locked marker", "refreshed");
        } else {
            let passphrase = vault::read_new_passphrase()?;
            term::blank();
            let sp = term::spinner("Encrypting local env");
            vault::import_env_file_with_key_mode(
                &source_path,
                &vault_path,
                &passphrase,
                options.key_mode,
            )?;
            let plaintext = vault::decrypt_vault_file(&vault_path, &passphrase)?;
            verified_env_keys = Some(config::env_keys_from_dotenv_str(&plaintext)?);
            recovery_plaintext = Some(plaintext);
            setup_passphrase = Some(passphrase);
            imported = true;
            if !options.keep_plaintext && !remove_plaintext {
                env_file::lock_env_file(&source_path, &vault_path)?;
                locked_env = true;
            }
            term::done_detail(
                sp,
                "vault encrypted",
                &format!("{} -> {}", source_path.display(), vault_path.display()),
            );
        }
    } else if !vault_path.exists() {
        let passphrase = vault::read_new_passphrase()?;
        term::blank();
        let sp = term::spinner("Creating empty vault");
        let envelope = vault::encrypt_env_with_key_mode("", &passphrase, options.key_mode)?;
        vault::write_vault(&vault_path, &envelope)?;
        vault::decrypt_vault_file(&vault_path, &passphrase)?;
        env_file::lock_env_file(&source_path, &vault_path)?;
        verified_env_keys = Some(Vec::new());
        recovery_plaintext = Some(String::new());
        setup_passphrase = Some(passphrase);
        locked_env = true;
        term::done_detail(sp, "vault encrypted", "empty vault");
    } else {
        term::ok_detail("vault encrypted", &term::short_path(&vault_path));
    }
    if locked_env && !source_is_locked {
        term::ok_detail("locked marker", &source_path.display().to_string());
    }

    if let Some(env_keys) = verified_env_keys.as_deref() {
        config::replace_default_profiles(&mut project_config, env_keys, &cwd);
        config::write_project_config(&cwd, &project_config, true)?;
    }

    registry::update_project_vault(&project_config.project, cwd.clone(), vault_path.clone())?;
    term::section("project");
    term::ok_detail(".ward.json ready", "project policy");
    if let Some(restored) = auto_restored_config.as_ref() {
        term::ok_detail(
            ".ward.json restored",
            &format!("from {}", term::short_path(&restored.backup_path)),
        );
    }
    term::ok_detail("project registered", &project_config.project);
    term::ok_detail(".gitignore updated", ".env, .env.*, !.env.vault");
    if env_example.is_some() {
        term::ok(".env.example created");
    }
    if agent_instructions.is_some() {
        term::ok("AGENTS.md written");
    }

    let mut removed_plaintext = false;
    if source_exists && !source_is_locked && remove_plaintext {
        fs::remove_file(&source_path)
            .context(format!("failed to remove {}", source_path.display()))?;
        removed_plaintext = true;
    }

    // Resolve and validate the PIN/passphrase even when --no-unlock is used.
    // Reinstall recovery depends on `.env.vault` remaining decryptable by this value.
    let setup_passphrase_final: Option<String> = match setup_passphrase {
        Some(passphrase) => Some(passphrase),
        None if vault_path.exists() => Some(vault::read_existing_passphrase()?),
        None => None,
    };

    if recovery_plaintext.is_none() {
        if let Some(passphrase) = setup_passphrase_final.as_deref() {
            recovery_plaintext = vault::decrypt_vault_file(&vault_path, passphrase).ok();
        }
    }
    if let (Some(passphrase), Some(plaintext)) = (
        setup_passphrase_final.as_deref(),
        recovery_plaintext.as_deref(),
    ) {
        warn_store_refresh_failure(project_store::refresh_from_plaintext(
            &project_config.project,
            &cwd,
            &vault_path,
            &project_config,
            plaintext,
            passphrase,
        ));
    }

    let unlock_session = if options.no_unlock {
        term::section("session");
        term::warn_detail("session not started", "--no-unlock");
        None
    } else {
        let passphrase = setup_passphrase_final.as_deref().unwrap();
        term::section("session");
        let sp = term::spinner("Starting protected session");
        match create_run_unlock_session(
            &project_config.project,
            &vault_path,
            passphrase,
            &options.unlock_ttl,
            None,
        ) {
            Ok(session) => {
                let expires = session.expires_at.format("%H:%M").to_string();
                term::done_detail(sp, "session unlocked", &format!("expires {expires}"));
                Some(session)
            }
            Err(error) => {
                if vault::is_incorrect_passphrase(&error) {
                    term::warn_step(sp, "session failed");
                    return Err(error);
                }
                term::warn_step_detail(sp, "session failed", &error.to_string());
                term::next("run: ward unlock");
                None
            }
        }
    };

    let event = SetupEvent {
        event_type: "setup.completed",
        project: &project_config.project,
        source: &source_path,
        vault: &vault_path,
        imported,
        removed_plaintext,
        locked_env,
        committed_vault: commit_vault,
        unlock_created: unlock_session.is_some(),
        unlock_expires_at: unlock_session
            .as_ref()
            .map(|session| session.expires_at.to_rfc3339()),
    };
    audit_logs::append_event(LogKind::Sessions, event)?;

    term::section("Recovery");
    if setup_passphrase_final.is_some() {
        match options.key_mode {
            vault::VaultKeyMode::ApiDerivedV1 => {
                term::ok("vault recoverable with .env.vault + PIN/passphrase + Ward API");
                term::next("optional offline safety: ward key export");
            }
            vault::VaultKeyMode::LocalDerivedV1 => {
                term::ok("vault recoverable with .env.vault + PIN/passphrase");
            }
        }
    } else {
        term::warn("vault recovery not validated");
    }
    if options.ignore_vault {
        term::warn("backup .env.vault separately; it is ignored by git for this project");
    }
    term::info("Optional legacy backup: ward recovery create && ward recovery export");

    term::blank();
    if unlock_session.is_none() {
        term::next(&format!("ward unlock --ttl {}", options.unlock_ttl));
    }
    term::blank();

    if options.keep_plaintext {
        term::warn_detail("plaintext env kept", "--keep-plaintext");
    }
    term::section("shell");
    if let Some(rc) = ensure_shell_integration() {
        term::ok_detail("shell integration", &term::short_path(&rc));
        if options.yes {
            term::next("when ready: exec $SHELL && ward human");
        } else {
            prompt_shell_reload(&rc);
        }
    } else {
        term::ok_detail("shell integration", "ready");
    }
    Ok(())
}
