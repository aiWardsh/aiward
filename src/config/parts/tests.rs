#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_infers_project_and_profiles() {
        let tempdir = tempfile::tempdir().unwrap();
        let config = ProjectConfig::default_for_dir(tempdir.path(), None).unwrap();

        assert_eq!(
            config.project,
            tempdir.path().file_name().unwrap().to_string_lossy()
        );
        assert_eq!(config.vault, PathBuf::from(DEFAULT_VAULT_FILE));
        assert!(config.presets.is_empty());
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("\"presets\""));
        assert!(config.profiles.contains_key("dev"));
        assert!(config.anomaly_detection.enabled);
    }

    #[test]
    fn legacy_config_with_presets_still_parses() {
        let json = r#"{
          "version": 1,
          "project": "demo",
          "vault": ".env.vault",
          "presets": [
            {
              "name": "Raw dev",
              "match": ["pnpm dev"],
              "allowedEnv": ["DATABASE_URI"],
              "approval": "prompt"
            }
          ],
          "profiles": {}
        }"#;
        let config = serde_json::from_str::<ProjectConfig>(json).unwrap();
        assert_eq!(config.presets.len(), 1);
        assert_eq!(config.presets[0].allowed_env, vec!["DATABASE_URI"]);
    }

    #[test]
    fn write_project_config_refuses_overwrite_without_force() {
        let tempdir = tempfile::tempdir().unwrap();
        let config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

        write_project_config(tempdir.path(), &config, false).unwrap();
        assert!(write_project_config(tempdir.path(), &config, false).is_err());
        assert!(write_project_config(tempdir.path(), &config, true).is_ok());
        assert_eq!(read_project_config(tempdir.path()).unwrap().project, "demo");
    }

    #[test]
    #[serial_test::serial]
    fn config_backup_restores_missing_project_config() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let previous_home = std::env::var_os("WARD_HOME");
        std::env::set_var("WARD_HOME", home.path());

        let mut config =
            ProjectConfig::default_for_dir(project.path(), Some("demo".to_string())).unwrap();
        config.profiles.get_mut("dev").unwrap().env = vec!["DATABASE_URI".to_string()];
        write_project_config(project.path(), &config, false).unwrap();

        let backup_path = config_backup_path("demo");
        assert!(backup_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(backup_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }

        std::fs::remove_file(config_path(project.path())).unwrap();
        let restored = restore_project_config_from_backup(project.path(), false)
            .unwrap()
            .expect("backup should match project path");
        assert_eq!(restored.project, "demo");
        assert_eq!(read_project_config(project.path()).unwrap().project, "demo");
        assert_eq!(
            read_project_config(project.path()).unwrap().profiles["dev"].env,
            vec!["DATABASE_URI".to_string()]
        );

        match previous_home {
            Some(value) => std::env::set_var("WARD_HOME", value),
            None => std::env::remove_var("WARD_HOME"),
        }
    }

    #[test]
    fn ensure_env_example_is_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();

        let path = ensure_env_example(tempdir.path()).unwrap().unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("Ward managed environment"));
        assert!(ensure_env_example(tempdir.path()).unwrap().is_none());
    }

    #[test]
    fn ensure_env_example_prepends_existing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join(".env.example");
        std::fs::write(&path, "DATABASE_URL=\n").unwrap();

        assert_eq!(
            ensure_env_example(tempdir.path()).unwrap(),
            Some(path.clone())
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("# Ward managed environment."));
        assert!(contents.contains("DATABASE_URL="));
    }

    #[test]
    fn ensure_agent_instructions_creates_appends_and_is_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();
        let agents_path = tempdir.path().join(AGENT_INSTRUCTIONS_FILE);

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "demo").unwrap(),
            Some(agents_path.clone())
        );
        assert!(std::fs::read_to_string(&agents_path)
            .unwrap()
            .contains("Project: demo"));
        assert!(ensure_agent_instructions(tempdir.path(), "demo")
            .unwrap()
            .is_none());

        let tempdir = tempfile::tempdir().unwrap();
        let claude_path = tempdir.path().join(CLAUDE_INSTRUCTIONS_FILE);
        std::fs::write(&claude_path, "# Existing instructions\n").unwrap();

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "claude-demo").unwrap(),
            Some(claude_path.clone())
        );
        let contents = std::fs::read_to_string(&claude_path).unwrap();
        assert!(contents.contains("# Existing instructions"));
        assert!(contents.contains("Project: claude-demo"));
        assert!(contents.contains("Profiles are the user-facing command layer"));
        assert!(contents.contains("Presets may be added"));
        assert!(contents.contains("All Ward flags must appear before `--`"));
        assert!(contents.contains("worktree_approval_required"));
        assert!(contents.contains("approve/deny choice"));
        assert!(contents.contains("git rev-parse --show-toplevel"));
        assert!(contents.contains("ward approvals wait <request-id>"));
        assert!(contents.contains("passive wait primitive only"));
        assert!(contents.contains("approval authority belongs to the broker"));
        assert!(!contents.contains("--agent-mediated"));
        assert!(contents.contains("--app <app-name>"));
        assert!(
            contents.contains("Profile commands run from the resolved Ward project/app directory")
        );
        assert!(contents.contains("`--profile` is mutually exclusive with `--command` and `--env`"));
        assert!(contents.contains("ward env request-set --key <ENV_NAME>"));

        let tempdir = tempfile::tempdir().unwrap();
        let claude_path = tempdir.path().join(CLAUDE_INSTRUCTIONS_FILE);
        std::fs::write(&claude_path, "# Existing instructions").unwrap();

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "no-newline-demo").unwrap(),
            Some(claude_path.clone())
        );
        let contents = std::fs::read_to_string(&claude_path).unwrap();
        assert!(contents.contains("# Existing instructions\n\n<!-- ward-agent-instructions -->"));
    }

    #[test]
    fn resolves_absolute_and_relative_vault_paths() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

        assert_eq!(
            resolve_vault_path(tempdir.path(), &config),
            tempdir.path().join(DEFAULT_VAULT_FILE)
        );

        config.vault = tempdir.path().join("custom.vault");
        assert_eq!(resolve_vault_path(tempdir.path(), &config), config.vault);
    }

    #[test]
    fn project_config_rejects_vault_path_traversal() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.vault = PathBuf::from("../outside.vault");

        let error = write_project_config(tempdir.path(), &config, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("parent directory traversal"));

        std::fs::write(
            config_path(tempdir.path()),
            r#"{"version":1,"project":"demo","vault":"../outside.vault","profiles":{}}"#,
        )
        .unwrap();
        let error = read_project_config(tempdir.path()).unwrap_err().to_string();
        assert!(error.contains("parent directory traversal"));
    }

    #[test]
    fn project_config_rejects_absolute_vault_path_outside_project() {
        let tempdir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.vault = outside.path().join("outside.vault");

        let error = write_project_config(tempdir.path(), &config, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must stay inside"));
    }

    #[test]
    fn dotenv_keys_and_default_profiles_use_exact_env_names() {
        let tempdir = tempfile::tempdir().unwrap();
        let env_path = tempdir.path().join(".env");
        std::fs::write(
            &env_path,
            "DATABASE_URL=postgres://local\nPAYLOAD_SECRET=payload\nNEXT_PUBLIC_API_URL=http://localhost\nOPENAI_API_KEY=test\n",
        )
        .unwrap();

        let keys = env_keys_from_dotenv_file(&env_path).unwrap();
        let profiles = default_profiles(&keys, tempdir.path());

        assert_eq!(
            profiles["dev"].env,
            vec![
                "DATABASE_URL".to_string(),
                "PAYLOAD_SECRET".to_string(),
                "NEXT_PUBLIC_API_URL".to_string(),
            ]
        );
        assert_eq!(
            profiles["migrate"].env,
            vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()]
        );
        assert!(!profiles["dev"].env.iter().any(|name| name.contains('*')));

        let keys = env_keys_from_dotenv_str("DATABASE_URI=mongodb://local\n").unwrap();
        let profiles = default_profiles(&keys, tempdir.path());
        assert_eq!(profiles["dev"].env, vec!["DATABASE_URI".to_string()]);
        assert_eq!(profiles["migrate"].env, vec!["DATABASE_URI".to_string()]);
        assert!(!profiles["dev"].env.contains(&"DATABASE_URL".to_string()));
    }

    #[test]
    fn profile_generation_and_detection_use_package_metadata_and_lockfiles() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(
            tempdir.path().join("package.json"),
            r#"{"packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        assert_eq!(
            package_manager_from_package_json(tempdir.path()),
            Some("npm".to_string())
        );
        assert_eq!(detected_commands(tempdir.path()).dev, "npm run dev");

        std::fs::write(tempdir.path().join("package.json"), "{bad-json}").unwrap();
        std::fs::write(tempdir.path().join("yarn.lock"), "").unwrap();
        assert_eq!(
            detected_package_manager(tempdir.path()),
            Some("yarn".to_string())
        );
        assert_eq!(
            detected_commands(tempdir.path()).migrate,
            "yarn payload migrate"
        );

        let bun = tempfile::tempdir().unwrap();
        std::fs::write(bun.path().join("bun.lock"), "").unwrap();
        assert_eq!(detected_commands(bun.path()).dev, "bun run dev");

        let fallback = tempfile::tempdir().unwrap();
        assert_eq!(detected_commands(fallback.path()).dev, "pnpm dev");
    }

    #[test]
    fn project_root_lookup_stops_at_workspace_and_git_boundaries() {
        let home = tempfile::tempdir().unwrap();
        let home_config =
            ProjectConfig::default_for_dir(home.path(), Some("home-project".to_string())).unwrap();
        write_project_config(home.path(), &home_config, true).unwrap();

        let workspace = home.path().join("workspace");
        let app = workspace.join("apps").join("site");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            workspace.join("pnpm-workspace.yaml"),
            "packages:\n  - apps/*\n",
        )
        .unwrap();
        assert_eq!(find_project_root(&workspace), None);
        assert_eq!(find_project_root(&app), None);

        let app_config =
            ProjectConfig::default_for_dir(&app, Some("workspace:site".to_string())).unwrap();
        write_project_config(&app, &app_config, true).unwrap();
        assert_eq!(find_project_root(&app), Some(app.clone()));
        assert_eq!(find_project_root(&app.join("src")), Some(app.clone()));

        let git_repo = home.path().join("repo");
        std::fs::create_dir_all(git_repo.join("src")).unwrap();
        std::fs::create_dir(git_repo.join(".git")).unwrap();
        assert_eq!(find_project_root(&git_repo.join("src")), None);

        let package_workspace = home.path().join("package-workspace");
        std::fs::create_dir_all(package_workspace.join("apps").join("api")).unwrap();
        std::fs::write(
            package_workspace.join("package.json"),
            r#"{"workspaces":["apps/*"]}"#,
        )
        .unwrap();
        assert_eq!(
            find_project_root(&package_workspace.join("apps").join("api")),
            None
        );
    }

    #[test]
    fn merge_profiles_and_gitignore_updates_are_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.profiles.clear();

        merge_default_profiles(
            &mut config,
            &["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()],
            tempdir.path(),
        );
        assert!(config.profiles.contains_key("dev"));
        let original = config.profiles["dev"].clone();
        config.profiles.get_mut("dev").unwrap().command = "custom dev".to_string();
        merge_default_profiles(&mut config, &[], tempdir.path());
        assert_eq!(config.profiles["dev"].command, "custom dev");
        assert_ne!(config.profiles["dev"], original);

        let empty = tempfile::tempdir().unwrap();
        ensure_gitignore(empty.path(), true).unwrap();
        let contents = std::fs::read_to_string(empty.path().join(".gitignore")).unwrap();
        assert!(contents.contains(".env\n"));
        assert!(contents.contains(".env.*\n"));
        assert!(contents.contains("!.env.vault\n"));

        std::fs::write(tempdir.path().join(".gitignore"), "# existing\n.env\n").unwrap();
        ensure_gitignore(tempdir.path(), true).unwrap();
        let contents = std::fs::read_to_string(tempdir.path().join(".gitignore")).unwrap();
        assert!(contents.contains(".env\n"));
        assert!(contents.contains(".env.*\n"));
        assert!(contents.contains("!.env.vault\n"));

        ensure_gitignore(tempdir.path(), false).unwrap();
        let contents = std::fs::read_to_string(tempdir.path().join(".gitignore")).unwrap();
        assert!(!contents.contains("!.env.vault"));
    }

    #[test]
    fn env_key_parsing_reports_invalid_dotenv() {
        let tempdir = tempfile::tempdir().unwrap();
        let env_path = tempdir.path().join(".env");
        std::fs::write(&env_path, "DATABASE_URL='unterminated\n").unwrap();

        assert!(env_keys_from_dotenv_file(&env_path).is_err());
    }
}
