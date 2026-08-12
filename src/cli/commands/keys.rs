fn rotate_vault(project: Option<String>, app: Option<String>) -> Result<()> {
    let cwd = env::current_dir()?;
    let passphrase = vault::read_existing_passphrase()?;
    let target = workspace_target::resolve_one_with_passphrase(
        &workspace_target::TargetSelector::one(project, app),
        &cwd,
        &passphrase,
    )?;
    let cwd = target.path.clone();
    let mut config = config::read_project_config(&cwd)?;
    let project_name = target.name.clone();
    config.project = project_name.clone();

    // Find current vault — may be legacy static or already dynamic.
    let old_vault = config::resolve_vault_path_with_passphrase(&cwd, &config, &passphrase);
    anyhow::ensure!(
        old_vault.exists(),
        "vault not found at {}; unlock before rotating",
        old_vault.display()
    );

    let active_ttl = broker::active_session_expiry(&project_name, &old_vault)?
        .and_then(|expires_at| remaining_session_ttl(expires_at, chrono::Utc::now()));

    let existing_envelope = vault::read_vault(&old_vault)?;
    anyhow::ensure!(
        existing_envelope.key_mode() == vault::VaultKeyMode::LocalDerivedV1,
        "api-derived vaults use stable .env.vault; run `ward key migrate --to api-derived` to re-key"
    );
    let plaintext = vault::decrypt_env(&existing_envelope, &passphrase)?;
    let new_vault = loop {
        config.vault_nonce = vault::generate_vault_nonce();
        let candidate = config::resolve_vault_path_dynamic(&cwd, &config, &passphrase);
        if candidate != old_vault && !candidate.exists() {
            break candidate;
        }
    };

    let envelope = vault::encrypt_env(&plaintext, &passphrase)?;
    vault::write_vault(&new_vault, &envelope)?;
    fs::remove_file(&old_vault).context(format!(
        "failed to remove old vault {}",
        old_vault.display()
    ))?;

    config::write_project_config(&cwd, &config, true)?;
    registry::update_project_vault(&project_name, cwd.clone(), new_vault.clone())?;
    warn_store_refresh_failure(project_store::refresh_from_plaintext(
        &project_name,
        &cwd,
        &new_vault,
        &config,
        &plaintext,
        &passphrase,
    ));
    env_file::refresh_locked_env(&cwd, &new_vault)?;
    config::ensure_gitignore(&cwd, true)?;
    if let Some(ttl) = active_ttl {
        broker::unlock_project(&project_name, &new_vault, &passphrase, ttl)
            .context("vault rotated, but Ward could not refresh the active broker session")?;
        unlock::clear_project_unlocks(&project_name)?;
        let _ = unlock::create_run_unlock(&project_name, &new_vault, &passphrase, ttl);
    }
    term::emit_header(&term::Header {
        command: Some("rotate"),
        project: &project_name,
        path: Some(&cwd),
        mode: None,
    });
    term::ok_detail("vault rotated", &term::short_path(&new_vault));
    term::ok(".ward.json updated with new nonce");
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OfflineRecoveryKeyFile {
    version: u32,
    kind: String,
    created_at: String,
    encrypted: vault::VaultEnvelope,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OfflineRecoveryKeyBlob {
    version: u32,
    project: String,
    key_mode: String,
    passphrase: String,
    vault_plaintext: String,
}

fn key_command(project: Option<String>, app: Option<String>, command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Status { json } => key_status(project, app, json),
        KeyCommand::Migrate { to } => key_migrate(project, app, to.into()),
        KeyCommand::Export { output } => key_export(project, app, output),
        KeyCommand::Import { path } => key_import(project, app, path),
    }
}

fn key_status(project: Option<String>, app: Option<String>, json: bool) -> Result<()> {
    let resolved = resolve_env_project(project, app)?;
    let envelope = vault::read_vault(&resolved.vault)?;
    if json {
        let api = envelope.api_metadata();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "project": resolved.name,
                "path": resolved.path,
                "vault": resolved.vault,
                "keyMode": envelope.key_mode().label(),
                "version": envelope.version,
                "vaultId": api.map(|value| value.vault_id.clone()),
                "keyDerivationNonce": api.map(|value| value.key_derivation_nonce.clone()),
                "serverKeyId": api.map(|value| value.server_key_id.clone()),
            }))?
        );
        return Ok(());
    }

    term::emit_header(&term::Header {
        command: Some("key status"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("key mode", envelope.key_mode().label());
    term::ok_detail("vault", &term::short_path(&resolved.vault));
    if let Some(api) = envelope.api_metadata() {
        term::ok_detail("vault id", &api.vault_id);
        term::ok_detail("server key", &api.server_key_id);
        term::info(
            "api-derived vaults require Ward API unless an offline recovery key is exported",
        );
    }
    Ok(())
}

fn key_migrate(
    project: Option<String>,
    app: Option<String>,
    target_mode: vault::VaultKeyMode,
) -> Result<()> {
    let passphrase = vault::read_existing_passphrase()?;
    let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
    let mut config = config::read_project_config(&resolved.path)?;
    let current = vault::read_vault(&resolved.vault)?;
    let plaintext = vault::decrypt_env(&current, &passphrase)?;
    if current.key_mode() == target_mode {
        term::emit_header(&term::Header {
            command: Some("key migrate"),
            project: &resolved.name,
            path: Some(&resolved.path),
            mode: None,
        });
        term::ok_detail("already using", target_mode.label());
        return Ok(());
    }

    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let backup = key_backup_path(&resolved.vault, &timestamp);
    let old_bytes = fs_util::read_file(&resolved.vault, "vault backup source")?;
    fs_util::write_private_file(&backup, &old_bytes)?;

    let new_vault = match target_mode {
        vault::VaultKeyMode::ApiDerivedV1 => resolved.path.join(config::DEFAULT_VAULT_FILE),
        vault::VaultKeyMode::LocalDerivedV1 => {
            if config.vault_nonce.is_empty() {
                config.vault_nonce = vault::generate_vault_nonce();
            }
            config::resolve_vault_path_dynamic(&resolved.path, &config, &passphrase)
        }
    };
    let envelope = vault::encrypt_env_with_key_mode(&plaintext, &passphrase, target_mode)?;
    vault::write_vault(&new_vault, &envelope)?;
    if !same_path(&resolved.vault, &new_vault) && resolved.vault.exists() {
        fs::remove_file(&resolved.vault).context(format!(
            "failed to remove old vault {} after backup",
            resolved.vault.display()
        ))?;
    }
    config.vault = PathBuf::from(config::DEFAULT_VAULT_FILE);
    config::write_project_config(&resolved.path, &config, true)?;
    registry::update_project_vault(&resolved.name, resolved.path.clone(), new_vault.clone())?;
    env_file::refresh_locked_env(&resolved.path, &new_vault)?;
    warn_store_refresh_failure(project_store::refresh_from_plaintext(
        &resolved.name,
        &resolved.path,
        &new_vault,
        &config,
        &plaintext,
        &passphrase,
    ));

    term::emit_header(&term::Header {
        command: Some("key migrate"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("key mode", target_mode.label());
    term::ok_detail("vault", &term::short_path(&new_vault));
    term::ok_detail("backup", &term::short_path(&backup));
    Ok(())
}

fn key_export(project: Option<String>, app: Option<String>, output: Option<PathBuf>) -> Result<()> {
    let passphrase = vault::read_existing_passphrase()?;
    let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
    let envelope = vault::read_vault(&resolved.vault)?;
    let plaintext = vault::decrypt_env(&envelope, &passphrase)?;
    term::warn("offline recovery key can restore this vault without Ward API");
    let recovery_passphrase = vault::read_new_pin(
        "  New offline recovery PIN/passphrase: ",
        "  Confirm offline recovery PIN/passphrase: ",
    )?;
    let blob = OfflineRecoveryKeyBlob {
        version: 1,
        project: resolved.name.clone(),
        key_mode: envelope.key_mode().label().to_string(),
        passphrase,
        vault_plaintext: plaintext,
    };
    let encrypted = vault::encrypt_env_with_params(
        &serde_json::to_string(&blob)?,
        &recovery_passphrase,
        65_536,
        3,
    )?;
    let recovery_file = OfflineRecoveryKeyFile {
        version: 1,
        kind: "ward-offline-recovery-key".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        encrypted,
    };
    let output = output.unwrap_or_else(|| {
        resolved.path.join(format!(
            "ward-recovery-key-{}.json",
            safe_file_slug(&resolved.name)
        ))
    });
    let contents = serde_json::to_vec_pretty(&recovery_file)?;
    fs_util::write_private_file(&output, &contents)?;
    term::emit_header(&term::Header {
        command: Some("key export"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("offline recovery key", &term::short_path(&output));
    term::warn("store this file somewhere safe; it can recover env plaintext");
    Ok(())
}

fn key_import(project: Option<String>, app: Option<String>, path: PathBuf) -> Result<()> {
    let resolved = resolve_env_project(project, app)?;
    let path = fs_util::resolve_existing_external_file(&path, "offline recovery key")?;
    let contents = fs_util::read_file_to_string(&path, "offline recovery key")?;
    let recovery_file: OfflineRecoveryKeyFile =
        serde_json::from_str(&contents).context("invalid offline recovery key file")?;
    anyhow::ensure!(
        recovery_file.version == 1 && recovery_file.kind == "ward-offline-recovery-key",
        "unsupported offline recovery key file"
    );
    let recovery_passphrase = vault::read_existing_passphrase_for_project("offline recovery key")?;
    let plaintext = vault::decrypt_env(&recovery_file.encrypted, &recovery_passphrase)?;
    let blob: OfflineRecoveryKeyBlob =
        serde_json::from_str(&plaintext).context("invalid offline recovery key payload")?;
    anyhow::ensure!(
        blob.version == 1,
        "unsupported offline recovery key payload version {}",
        blob.version
    );
    anyhow::ensure!(
        blob.project == resolved.name,
        "offline recovery key belongs to project {}; current project is {}",
        blob.project,
        resolved.name
    );
    let mut config = config::read_project_config(&resolved.path)?;
    let target_vault = resolved.path.join(config::DEFAULT_VAULT_FILE);
    let envelope = vault::encrypt_env_with_key_mode(
        &blob.vault_plaintext,
        &blob.passphrase,
        vault::VaultKeyMode::LocalDerivedV1,
    )?;
    vault::write_vault(&target_vault, &envelope)?;
    config.vault = PathBuf::from(config::DEFAULT_VAULT_FILE);
    config::write_project_config(&resolved.path, &config, true)?;
    registry::update_project_vault(&resolved.name, resolved.path.clone(), target_vault.clone())?;
    env_file::refresh_locked_env(&resolved.path, &target_vault)?;
    term::emit_header(&term::Header {
        command: Some("key import"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("vault restored", &term::short_path(&target_vault));
    term::warn("vault was restored as local-derived; run ward key migrate --to api-derived when API access is available");
    Ok(())
}

fn key_backup_path(vault: &Path, timestamp: &str) -> PathBuf {
    let name = vault
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("env.vault");
    vault.with_file_name(format!("{name}.ward-key-backup.{timestamp}"))
}

fn safe_file_slug(value: &str) -> String {
    let mut slug = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "project".to_string()
    } else {
        slug.to_string()
    }
}

fn prompt_drag_drop_path() -> Result<std::path::PathBuf> {
    use std::io::{self, BufRead};
    eprint!("  Drag the recovery file here and press Enter: ");
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no input"))??;
    // macOS wraps paths with spaces in single quotes when dragged; strip them.
    let raw = line.trim().trim_matches('\'').trim_matches('"').trim();
    // Expand leading ~ manually since PathBuf doesn't do it.
    let path = if let Some(rest) = raw.strip_prefix("~/") {
        dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve home directory"))?
            .join(rest)
    } else {
        std::path::PathBuf::from(raw)
    };
    if !path.exists() {
        anyhow::bail!("file not found: {}", path.display());
    }
    Ok(path)
}

fn recovery_command(
    project: Option<String>,
    app: Option<String>,
    command: RecoveryCommand,
) -> Result<()> {
    match command {
        RecoveryCommand::Export { output } => {
            let cwd = env::current_dir()?;
            let passphrase = vault::read_existing_passphrase()?;
            let target = workspace_target::resolve_one_with_passphrase(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
                &passphrase,
            )?;
            let cwd = target.path;
            let mut config = config::read_project_config(&cwd)?;

            let dest = output.unwrap_or_else(|| {
                dirs::desktop_dir()
                    .or_else(dirs::home_dir)
                    .unwrap_or_else(|| PathBuf::from("."))
            });

            let out_path = recovery::export_recovery_file(&config.project, &passphrase, &dest)?;
            config.backup_exported = true;
            config::write_project_config(&cwd, &config, true)?;
            term::emit_header(&term::Header {
                command: Some("recovery export"),
                project: &config.project,
                path: Some(&cwd),
                mode: None,
            });
            term::ok_detail("backup exported", &term::short_path(&out_path));
            term::next(
                "store this file somewhere safe, such as a USB drive or secure cloud backup",
            );
        }
        RecoveryCommand::Import { path } => {
            let resolved_path = match path {
                Some(p) => p,
                None => prompt_drag_drop_path()?,
            };
            let dest = recovery::import_recovery_file(&resolved_path)?;
            term::emit_header(&term::Header {
                command: Some("recovery import"),
                project: "local recovery",
                path: Some(&dest),
                mode: None,
            });
            term::ok("recovery file imported");
        }
        RecoveryCommand::Create => {
            let cwd = env::current_dir()?;
            let passphrase = vault::read_existing_passphrase()?;
            let target = workspace_target::resolve_one_with_passphrase(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
                &passphrase,
            )?;
            let cwd = target.path;
            let mut config = config::read_project_config(&cwd)?;
            let vault_path = config::resolve_vault_path_with_passphrase(&cwd, &config, &passphrase);
            let plaintext = decrypt_vault_for_recovery(&config.project, &vault_path, &passphrase)?;

            let real_path = recovery::create_recovery_files_with_material(
                &config.project,
                &passphrase,
                &passphrase,
                Some(&plaintext),
            )?;
            config.recovery_created = true;
            config::write_project_config(&cwd, &config, true)?;
            term::emit_header(&term::Header {
                command: Some("recovery create"),
                project: &config.project,
                path: Some(&cwd),
                mode: None,
            });
            term::ok_detail("recovery key created", &term::short_path(&real_path));
            term::ok("decoys generated");
            term::next("run: ward recovery export");
        }
        RecoveryCommand::Restore { path } => {
            let cwd = env::current_dir()?;
            let passphrase = vault::read_existing_passphrase()?;
            let target = workspace_target::resolve_one_with_passphrase(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
                &passphrase,
            )?;
            let cwd = target.path;
            let mut config = config::read_project_config(&cwd)?;
            let vault_path = config::resolve_vault_path_with_passphrase(&cwd, &config, &passphrase);

            if let Some(source) = path {
                let recovery_file = recovery::import_recovery_file(&source)?;
                recovery::restore_vault_from_recovery_file(
                    &config.project,
                    &vault_path,
                    &recovery_file,
                    &passphrase,
                )?;
                term::emit_header(&term::Header {
                    command: Some("recovery restore"),
                    project: &config.project,
                    path: Some(&cwd),
                    mode: None,
                });
                term::ok_detail("recovery file imported", &term::short_path(&recovery_file));
            } else {
                recovery::restore_vault_from_recovery(
                    &config.project,
                    &vault_path,
                    Some(&passphrase),
                    &passphrase,
                )?;
                term::emit_header(&term::Header {
                    command: Some("recovery restore"),
                    project: &config.project,
                    path: Some(&cwd),
                    mode: None,
                });
            }

            config.recovery_created = true;
            config::write_project_config(&cwd, &config, true)?;
            env_file::refresh_locked_env(&cwd, &vault_path)?;
            registry::update_project_vault(&config.project, cwd.clone(), vault_path.clone())?;
            term::ok_detail("vault restored", &term::short_path(&vault_path));
            term::next("run: ward unlock --ttl 8h");
        }
    }
    Ok(())
}

fn decrypt_vault_for_recovery(
    project: &str,
    vault_path: &Path,
    passphrase: &str,
) -> Result<String> {
    let _ = project;
    vault::decrypt_vault_file(vault_path, passphrase)
}
