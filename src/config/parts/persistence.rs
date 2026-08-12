pub fn config_path(cwd: &Path) -> PathBuf {
    cwd.join(PROJECT_CONFIG_FILE)
}

pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    for dir in cwd.ancestors() {
        if config_path(dir).is_file() {
            return Some(dir.to_path_buf());
        }
        if is_project_search_boundary(dir) {
            return None;
        }
    }
    None
}

fn is_project_search_boundary(dir: &Path) -> bool {
    dir.join(".git").exists()
        || dir.join("pnpm-workspace.yaml").is_file()
        || dir.join("turbo.json").is_file()
        || package_json_has_workspaces(dir)
}

pub fn read_project_config(cwd: &Path) -> Result<ProjectConfig> {
    let path = config_path(cwd);
    let contents = fs_util::read_file_to_string(&path, "project config")?;
    let mut config: ProjectConfig =
        serde_json::from_str(&contents).context(format!("failed to parse {}", path.display()))?;
    // Backward compat: populate nonce for legacy configs that have none.
    if config.vault_nonce.is_empty() {
        config.vault_nonce = vault::generate_vault_nonce();
    }
    validate_project_config_paths(cwd, &config)?;
    Ok(config)
}

pub fn write_project_config(cwd: &Path, config: &ProjectConfig, force: bool) -> Result<PathBuf> {
    let path = config_path(cwd);
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }

    validate_project_config_paths(cwd, config)?;
    let contents = serde_json::to_string_pretty(config)?;
    fs::write(&path, format!("{contents}\n"))
        .context(format!("failed to write {}", path.display()))?;
    maybe_write_project_config_backup(cwd, config, &contents);
    Ok(path)
}

pub fn config_backups_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new(CONFIG_BACKUP_DIR), "config backup directory")
        .expect("config backup directory should stay inside Ward home")
}

pub fn config_backup_path(project: &str) -> PathBuf {
    let relative = PathBuf::from(CONFIG_BACKUP_DIR).join(format!("{}.json", slugify(project)));
    fs_util::resolve_ward_home_path(&relative, "config backup path")
        .expect("config backup path should stay inside Ward home")
}

pub fn read_project_config_backup(project: &str) -> Result<ProjectConfigBackup> {
    let path = config_backup_path(project);
    let contents = fs_util::read_file_to_string(&path, "project config backup")?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn remove_project_config_backup(project: &str) -> Result<bool> {
    let path = config_backup_path(project);
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(true)
}

pub fn find_project_config_backup_for_path(
    cwd: &Path,
) -> Result<Option<(PathBuf, ProjectConfigBackup)>> {
    let dir = config_backups_dir();
    if !dir.exists() {
        return Ok(None);
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(contents) = fs_util::read_file_to_string(&path, "project config backup") else {
            continue;
        };
        let Ok(backup) = serde_json::from_str::<ProjectConfigBackup>(&contents) else {
            continue;
        };
        if same_path(&backup.project_path, cwd) {
            matches.push((path, backup));
        }
    }

    matches.sort_by(|(_, left), (_, right)| right.updated_at.cmp(&left.updated_at));
    Ok(matches.into_iter().next())
}

pub fn restore_project_config_from_backup(
    cwd: &Path,
    force: bool,
) -> Result<Option<ProjectConfigRestore>> {
    let config_path = config_path(cwd);
    if config_path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            config_path.display()
        );
    }

    let Some((backup_path, backup)) = find_project_config_backup_for_path(cwd)? else {
        return Ok(None);
    };

    let contents = serde_json::to_string_pretty(&backup.config)?;
    let hash = sha256_hex(contents.as_bytes());
    if hash != backup.config_sha256 {
        anyhow::bail!(
            "config backup checksum mismatch for {}; refusing to restore",
            backup.project
        );
    }

    fs::write(&config_path, format!("{contents}\n"))
        .context(format!("failed to write {}", config_path.display()))?;
    maybe_write_project_config_backup(cwd, &backup.config, &contents);
    Ok(Some(ProjectConfigRestore {
        project: backup.project,
        project_path: cwd.to_path_buf(),
        config_path,
        backup_path,
        updated_at: backup.updated_at,
    }))
}

fn maybe_write_project_config_backup(cwd: &Path, config: &ProjectConfig, contents: &str) {
    if cfg!(test) && std::env::var_os("WARD_HOME").is_none() {
        return;
    }
    let _ = write_project_config_backup(cwd, config, contents);
}

fn write_project_config_backup(
    cwd: &Path,
    config: &ProjectConfig,
    contents: &str,
) -> Result<PathBuf> {
    let project_path = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let backup = ProjectConfigBackup {
        version: CONFIG_BACKUP_VERSION,
        project: config.project.clone(),
        project_path: project_path.clone(),
        config_path: project_path.join(PROJECT_CONFIG_FILE),
        config_sha256: sha256_hex(contents.as_bytes()),
        updated_at: chrono::Utc::now().to_rfc3339(),
        config: config.clone(),
    };
    let backup_path = config_backup_path(&backup.project);
    let backup_contents = serde_json::to_string_pretty(&backup)?;
    fs_util::write_private_file(&backup_path, format!("{backup_contents}\n").as_bytes())?;
    Ok(backup_path)
}
