pub fn resolve_vault_path(cwd: &Path, config: &ProjectConfig) -> PathBuf {
    resolve_vault_path_checked(cwd, config)
        .expect("project config vault path should be validated before resolving")
}

pub fn resolve_vault_path_checked(cwd: &Path, config: &ProjectConfig) -> Result<PathBuf> {
    fs_util::resolve_project_path(cwd, &config.vault, "vault path")
}

/// Derives the vault path from passphrase + project + nonce when dynamic naming is active.
/// Falls back to the static path for keychain mode or legacy configs.
pub fn resolve_vault_path_dynamic(cwd: &Path, config: &ProjectConfig, passphrase: &str) -> PathBuf {
    resolve_vault_path_dynamic_checked(cwd, config, passphrase)
        .expect("derived vault path should stay inside the project")
}

pub fn resolve_vault_path_dynamic_checked(
    cwd: &Path,
    config: &ProjectConfig,
    passphrase: &str,
) -> Result<PathBuf> {
    if config.storage_mode == StorageMode::Keychain || config.vault_nonce.is_empty() {
        return resolve_vault_path_checked(cwd, config);
    }
    let filename = vault::derive_vault_filename(passphrase, &config.project, &config.vault_nonce);
    fs_util::resolve_project_path(cwd, Path::new(&filename), "derived vault path")
}

/// Resolves the current vault path when a passphrase is available.
///
/// Legacy projects may still have a static `.env.vault` even after a nonce was
/// added to `.ward.json`. Prefer the derived path only once it exists, or when
/// the configured static path is absent.
pub fn resolve_vault_path_with_passphrase(
    cwd: &Path,
    config: &ProjectConfig,
    passphrase: &str,
) -> PathBuf {
    resolve_vault_path_with_passphrase_checked(cwd, config, passphrase)
        .expect("project config vault path should be validated before resolving")
}

pub fn resolve_vault_path_with_passphrase_checked(
    cwd: &Path,
    config: &ProjectConfig,
    passphrase: &str,
) -> Result<PathBuf> {
    let configured = resolve_vault_path_checked(cwd, config)?;
    let derived = resolve_vault_path_dynamic_checked(cwd, config, passphrase)?;
    if derived.exists() || !configured.exists() {
        Ok(derived)
    } else {
        Ok(configured)
    }
}

fn default_anomaly_detection() -> AnomalyDetectionConfig {
    AnomalyDetectionConfig {
        enabled: true,
        working_hours_start: 8,
        working_hours_end: 20,
        max_runs_per_hour_per_grant: 20,
        max_branches_per_grant: 3,
    }
}

fn validate_project_config_paths(cwd: &Path, config: &ProjectConfig) -> Result<()> {
    resolve_vault_path_checked(cwd, config)?;
    Ok(())
}

fn default_env_keys() -> Vec<String> {
    vec![
        "DATABASE_URL".to_string(),
        "DATABASE_URI".to_string(),
        "PAYLOAD_SECRET".to_string(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectedCommands {
    dev: String,
    migrate: String,
}

fn detected_commands(cwd: &Path) -> DetectedCommands {
    match detected_package_manager(cwd).as_deref() {
        Some("npm") => DetectedCommands {
            dev: "npm run dev".to_string(),
            migrate: "npm run payload -- migrate".to_string(),
        },
        Some("yarn") => DetectedCommands {
            dev: "yarn dev".to_string(),
            migrate: "yarn payload migrate".to_string(),
        },
        Some("bun") => DetectedCommands {
            dev: "bun run dev".to_string(),
            migrate: "bun run payload migrate".to_string(),
        },
        _ => DetectedCommands {
            dev: "pnpm dev".to_string(),
            migrate: "pnpm payload migrate".to_string(),
        },
    }
}

fn detected_package_manager(cwd: &Path) -> Option<String> {
    if let Some(manager) = package_manager_from_package_json(cwd) {
        return Some(manager);
    }
    for (file, manager) in [
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
        ("bun.lockb", "bun"),
        ("bun.lock", "bun"),
    ] {
        if cwd.join(file).exists() {
            return Some(manager.to_string());
        }
    }
    None
}

fn package_manager_from_package_json(cwd: &Path) -> Option<String> {
    let path =
        fs_util::resolve_project_path(cwd, Path::new("package.json"), "package metadata").ok()?;
    let contents = fs_util::read_file_to_string(&path, "package metadata").ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&contents).ok()?;
    let manager = value.get("packageManager")?.as_str()?;
    ["pnpm", "npm", "yarn", "bun"]
        .iter()
        .find(|candidate| manager.starts_with(&format!("{candidate}@")))
        .map(|candidate| (*candidate).to_string())
}

fn package_json_has_workspaces(cwd: &Path) -> bool {
    let Ok(path) =
        fs_util::resolve_project_path(cwd, Path::new("package.json"), "package metadata")
    else {
        return false;
    };
    let Ok(contents) = fs_util::read_file_to_string(&path, "package metadata") else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };
    match value.get("workspaces") {
        Some(serde_json::Value::Array(values)) => !values.is_empty(),
        Some(serde_json::Value::Object(map)) => map
            .get("packages")
            .and_then(|packages| packages.as_array())
            .is_some_and(|values| !values.is_empty()),
        _ => false,
    }
}

fn append_gitignore_line(lines: &mut Vec<String>, expected: &str) {
    if !lines.iter().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed == expected
    }) {
        lines.push(expected.to_string());
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn slugify(project: &str) -> String {
    let slug = project
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if slug.is_empty() {
        "project".to_string()
    } else {
        slug
    }
}
