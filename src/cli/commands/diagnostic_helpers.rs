fn warn_missing_broker_session(project: &str, vault: &Path) {
    match unlock::active_run_session_metadata(project, vault) {
        Ok(Some(_)) => term::warn(
            "stale local unlock metadata without an active session — run ward unlock again",
        ),
        Ok(None) => term::warn("no active session — run ward unlock --ttl 8h"),
        Err(e) => term::warn(&format!(
            "local unlock metadata unreadable without an active session — run ward unlock again ({e})"
        )),
    }
}

fn likely_secret_env_files(cwd: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(cwd)? {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy())
            .unwrap_or_default();
        if name.starts_with(".env.") && name != ".env.example" && name != config::DEFAULT_VAULT_FILE
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn check_gitignore(cwd: &Path) -> Result<()> {
    let path = cwd.join(".gitignore");
    if !path.exists() {
        term::warn(".gitignore missing — add .env and .env.*");
        return Ok(());
    }

    let contents =
        fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    let has_env = gitignore_contains(&contents, ".env");
    let has_env_variants = gitignore_contains(&contents, ".env.*");

    if has_env {
        term::ok(".gitignore  .env");
    } else {
        term::warn(".gitignore should include .env");
    }

    if has_env_variants {
        term::ok(".gitignore  .env.*");
        if gitignore_contains(&contents, "!.env.vault") {
            term::ok(".gitignore  !.env.vault");
        } else {
            term::info("tip: add !.env.vault after .env.* to commit encrypted vaults");
        }
    } else {
        term::warn(".gitignore should include .env.*");
    }

    Ok(())
}

fn gitignore_contains(contents: &str, expected: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed == expected
    })
}
