#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct WardHomeGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl WardHomeGuard {
        fn set(path: &Path) -> Self {
            let previous = std::env::var_os("WARD_HOME");
            std::env::set_var("WARD_HOME", path);
            Self { previous }
        }
    }

    impl Drop for WardHomeGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("WARD_HOME", value),
                None => std::env::remove_var("WARD_HOME"),
            }
        }
    }

    #[test]
    fn env_names_are_normalized_and_validated() {
        let names = normalize_env_names(vec![
            "PAYLOAD_SECRET".to_string(),
            "DATABASE_URL".to_string(),
            "PAYLOAD_SECRET".to_string(),
        ])
        .unwrap();
        assert_eq!(names, vec!["DATABASE_URL", "PAYLOAD_SECRET"]);
        assert!(normalize_env_names(vec!["bad-name".to_string()]).is_err());
        assert!(normalize_env_names(vec!["1BAD".to_string()]).is_err());
    }

    #[test]
    fn sensitive_event_fields_are_scrubbed_without_redacting_env_names() {
        let mut event = json!({
            "payload": {
                "sessionToken": "token",
                "requestedEnv": ["PAYLOAD_SECRET"],
                "nested": { "passphrase": "secret" }
            }
        });
        scrub_sensitive_fields(&mut event);
        assert_eq!(event["payload"]["sessionToken"], "[redacted]");
        assert_eq!(event["payload"]["nested"]["passphrase"], "[redacted]");
        assert_eq!(event["payload"]["requestedEnv"][0], "PAYLOAD_SECRET");
    }

    #[test]
    fn profile_env_route_matches_expected_api_shape() {
        assert_eq!(
            profile_env_route("/api/projects/demo/profiles/dev/env"),
            Some(("demo".to_string(), "dev".to_string()))
        );
        assert_eq!(
            profile_policy_route("/api/projects/demo/profiles/dev"),
            Some(("demo".to_string(), "dev".to_string()))
        );
        assert_eq!(
            profiles_collection_route("/api/projects/demo/profiles"),
            Some("demo".to_string())
        );
        assert_eq!(
            store_snapshot_route("/api/store/projects/demo/snapshot"),
            Some("demo".to_string())
        );
        assert!(is_dashboard_page_route("/"));
        assert!(is_dashboard_page_route("/logs"));
        assert!(is_dashboard_page_route("/projects/demo/logs"));
        assert!(!is_dashboard_page_route("/team"));
        assert!(!is_dashboard_page_route("/cloud"));
        assert!(!is_dashboard_page_route("/projects/demo/team"));
        assert!(profile_env_route("/api/projects/demo").is_none());
        let request_id = uuid::Uuid::new_v4();
        assert_eq!(
            approval_action_route(&format!("/api/approvals/{request_id}/approve")),
            Some((request_id, "approve".to_string()))
        );
        assert_eq!(
            worktree_action_route(&format!("/api/worktrees/{request_id}/deny")),
            Some((request_id, "deny".to_string()))
        );
        assert_eq!(
            notification_action_route(&format!("/api/notifications/{request_id}/dismiss")),
            Some((request_id, "dismiss".to_string()))
        );
        assert_eq!(
            project_action_route("/api/projects/demo/lock"),
            Some(("demo".to_string(), "lock".to_string()))
        );
        assert_eq!(
            project_action_route("/api/projects/demo/remove"),
            Some(("demo".to_string(), "remove".to_string()))
        );
    }

    #[test]
    fn dashboard_url_carries_local_token() {
        assert_eq!(
            dashboard_url(7777, "abc"),
            "http://127.0.0.1:7777/?token=abc"
        );
    }

    #[test]
    fn dashboard_html_restores_old_logs_shell() {
        assert!(DASHBOARD_HTML.contains("table-pane"));
        assert!(DASHBOARD_HTML.contains("detail-pane"));
        assert!(DASHBOARD_HTML.contains("data-kind=\"execution\""));
        assert!(DASHBOARD_HTML.contains("profile policies"));
        assert!(DASHBOARD_HTML.contains("dropdown-button"));
        assert!(DASHBOARD_HTML.contains("splitter"));
        assert!(DASHBOARD_HTML.contains("openProjectLogs"));
        assert!(DASHBOARD_HTML.contains("tablePaneWidth"));
        assert!(DASHBOARD_HTML.contains("notifications-btn"));
        assert!(!DASHBOARD_HTML.contains("id=\"team-link\""));
        assert!(!DASHBOARD_HTML.contains("id=\"cloud-link\""));
        assert!(!DASHBOARD_HTML.contains("renderCloud"));
        assert!(!DASHBOARD_HTML.contains("/api/cloud"));
        assert!(!DASHBOARD_HTML.contains("/api/teams/projects/"));
        assert!(!DASHBOARD_HTML.contains("renderTeam"));
        assert!(!DASHBOARD_HTML.contains("data-save-team-policy"));
        assert!(!DASHBOARD_HTML.contains("data-save-member"));
        assert!(DASHBOARD_HTML.contains("/api/notifications/stream"));
        assert!(DASHBOARD_HTML.contains("/api/approvals/"));
        assert!(DASHBOARD_HTML.contains("/api/worktrees/"));
        assert!(DASHBOARD_HTML.contains("/api/sessions/lock-all"));
        assert!(DASHBOARD_HTML.contains("data-lock-project"));
        assert!(DASHBOARD_HTML.contains("data-remove-project"));
        assert!(DASHBOARD_HTML.contains("data-dismiss-notification"));
        assert!(DASHBOARD_HTML.contains("isValidEnvName"));
        assert!(DASHBOARD_HTML.contains("data-dirty-scope"));
        assert!(DASHBOARD_HTML.contains("bindDirtyTracking"));
        assert!(DASHBOARD_HTML.contains("guardedLoad"));
        assert!(DASHBOARD_HTML.contains("startAutoRefresh"));
        assert!(DASHBOARD_HTML.contains("Discard unsaved changes?"));
        assert!(DASHBOARD_HTML.contains("refresh paused while editing"));
        assert!(DASHBOARD_HTML.contains("renderNotificationBadge();"));
        assert!(!DASHBOARD_HTML.contains("setInterval(load, 5000)"));
        assert!(DASHBOARD_HTML.contains("rel=\"icon\" href=\"/favicon.png\""));
        assert!(DASHBOARD_HTML.contains("/assets/ward-logo-dark.png"));
        assert!(WARD_LOGO_DARK_SVG.contains("<rect"));
        assert!(WARD_LOGO_TRANSPARENT_SVG.contains("<svg"));
        assert!(WARD_LOGO_DARK_PNG.starts_with(b"\x89PNG"));
        assert!(WARD_FAVICON_LIGHT_PNG.starts_with(b"\x89PNG"));
        assert!(!DASHBOARD_HTML.contains("<select"));
    }

    #[test]
    #[serial]
    fn project_api_reads_and_updates_profile_env_policy_without_values() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let project = tempfile::tempdir().unwrap();
        let mut cfg =
            config::ProjectConfig::default_for_dir(project.path(), Some("demo".to_string()))
                .unwrap();
        for profile in cfg.profiles.values_mut() {
            profile.env.clear();
        }
        cfg.profiles.get_mut("dev").unwrap().env = vec!["DATABASE_URL".to_string()];
        config::write_project_config(project.path(), &cfg, true).unwrap();
        registry::register_project(
            "demo".to_string(),
            project.path().to_path_buf(),
            project.path().join(".env.vault"),
        )
        .unwrap();

        let projects = dashboard_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].env_names, vec!["DATABASE_URL"]);
        assert!(!projects[0].vault_keys_verified);

        let updated = update_profile_env_for_project(
            "demo",
            "dev",
            vec!["PAYLOAD_SECRET".to_string(), "DATABASE_URL".to_string()],
        )
        .unwrap();
        let dev = updated
            .profiles
            .iter()
            .find(|profile| profile.name == "dev")
            .unwrap();
        assert_eq!(dev.env, vec!["DATABASE_URL", "PAYLOAD_SECRET"]);

        let serialized = serde_json::to_string(&updated).unwrap();
        assert!(serialized.contains("PAYLOAD_SECRET"));
        assert!(!serialized.contains("payload-secret-value"));
    }

    #[test]
    #[serial]
    fn profile_policy_crud_updates_project_config() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let project = tempfile::tempdir().unwrap();
        let mut cfg =
            config::ProjectConfig::default_for_dir(project.path(), Some("demo".to_string()))
                .unwrap();
        cfg.profiles.clear();
        config::write_project_config(project.path(), &cfg, true).unwrap();
        registry::register_project(
            "demo".to_string(),
            project.path().to_path_buf(),
            project.path().join(".env.vault"),
        )
        .unwrap();

        let created = create_profile_policy_for_project(
            "demo",
            ProfilePolicyRequest {
                name: Some("preview".to_string()),
                command: Some("pnpm preview".to_string()),
                action: Some("Run preview".to_string()),
                default_scope: Some(crate::approvals::ApprovalScope::Session),
                env: Some(vec!["PAYLOAD_SECRET".to_string()]),
            },
        )
        .unwrap();
        assert!(created
            .profiles
            .iter()
            .any(|profile| profile.name == "preview"));

        let updated = update_profile_policy_for_project(
            "demo",
            "preview",
            ProfilePolicyRequest {
                name: Some("prod".to_string()),
                command: Some("pnpm start".to_string()),
                action: Some("Run production".to_string()),
                default_scope: Some(crate::approvals::ApprovalScope::Branch),
                env: Some(vec![
                    "DATABASE_URL".to_string(),
                    "PAYLOAD_SECRET".to_string(),
                ]),
            },
        )
        .unwrap();
        let prod = updated
            .profiles
            .iter()
            .find(|profile| profile.name == "prod")
            .unwrap();
        assert_eq!(prod.command, "pnpm start");
        assert_eq!(prod.env, vec!["DATABASE_URL", "PAYLOAD_SECRET"]);

        let deleted = delete_profile_policy("demo", "prod").unwrap();
        assert!(deleted.profiles.is_empty());
    }

    #[test]
    #[serial]
    fn dashboard_projects_include_detected_workspace_apps_without_secret_values() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"cms-core","packageManager":"pnpm@9.15.9"}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "packages:\n  - \"apps/*\"\n  - \"packages/*\"\n",
        )
        .unwrap();
        std::fs::write(root.path().join("turbo.json"), "{}").unwrap();
        let app = root.path().join("apps/ambienta");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("package.json"),
            r#"{"name":"@cms-app/ambienta","scripts":{"dev":"next dev"}}"#,
        )
        .unwrap();
        std::fs::write(app.join(".env.example"), "PAYLOAD_SECRET=\nDATABASE_URI=\n").unwrap();
        let lib = root.path().join("packages/cms-core");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(
            lib.join("package.json"),
            r#"{"name":"@cms-core/platform","scripts":{"build":"tsc"}}"#,
        )
        .unwrap();

        let cfg = config::ProjectConfig::default_for_dir(root.path(), Some("cms-core".to_string()))
            .unwrap();
        config::write_project_config(root.path(), &cfg, true).unwrap();
        registry::register_project(
            "cms-core".to_string(),
            root.path().to_path_buf(),
            root.path().join(".env.vault"),
        )
        .unwrap();

        let projects = dashboard_projects().unwrap();
        let names = projects
            .iter()
            .map(|project| project.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"cms-core"));
        assert!(names.contains(&"cms-core:ambienta"));
        let discovered = projects
            .iter()
            .find(|project| project.name == "cms-core:ambienta")
            .unwrap();
        assert_eq!(discovered.config_status, "needs env");
        assert!(!discovered.setup_available);
        assert_eq!(discovered.parent_project.as_deref(), Some("cms-core"));
        assert!(discovered.env_names.contains(&"PAYLOAD_SECRET".to_string()));
        assert!(!serde_json::to_string(discovered)
            .unwrap()
            .contains("payload-secret-value"));
    }

    #[test]
    #[serial]
    fn dashboard_projects_hide_invalid_workspace_root_registry_entries() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"cms-core","packageManager":"pnpm@9.15.9"}"#,
        )
        .unwrap();
        std::fs::write(root.path().join("turbo.json"), "{}").unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "packages:\n  - \"apps/*\"\n",
        )
        .unwrap();
        let app = root.path().join("apps/aiward");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("package.json"),
            r#"{"name":"@cms-app/aiward","scripts":{"dev":"next dev"}}"#,
        )
        .unwrap();
        std::fs::write(app.join(".env.example"), "DATABASE_URI=\nPAYLOAD_SECRET=\n").unwrap();
        let cfg = config::ProjectConfig::default_for_dir(&app, Some("cms-core:ward".to_string()))
            .unwrap();
        config::write_project_config(&app, &cfg, true).unwrap();

        registry::register_project(
            "cms-core:ward-root".to_string(),
            root.path().to_path_buf(),
            root.path().join(".env.vault"),
        )
        .unwrap();
        registry::register_project(
            "cms-core:ward".to_string(),
            app.clone(),
            app.join(".env.vault"),
        )
        .unwrap();
        registry::update_project_workspace_metadata(
            "cms-core:ward",
            Some(root.path().to_path_buf()),
            Some("cms-core".to_string()),
            Some("aiward".to_string()),
            Some("cms-core".to_string()),
        )
        .unwrap();

        let projects = dashboard_projects().unwrap();
        let names = projects
            .iter()
            .map(|project| project.name.as_str())
            .collect::<Vec<_>>();
        assert!(!names.contains(&"cms-core:ward-root"));
        assert!(names.contains(&"cms-core:ward"));
        let child = projects
            .iter()
            .find(|project| project.name == "cms-core:ward")
            .unwrap();
        assert_eq!(child.parent_project.as_deref(), Some("cms-core"));
    }

    #[test]
    #[serial]
    fn logs_api_filters_by_project_and_uses_old_kind_labels() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        logs::append_event(
            LogKind::Requests,
            json!({ "project": "demo", "requestedEnv": ["PAYLOAD_SECRET"] }),
        )
        .unwrap();
        logs::append_event(LogKind::Requests, json!({ "project": "other" })).unwrap();

        let events = load_all_events(Some("demo"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["_kind"], "request");
        assert_eq!(events[0]["payload"]["project"], "demo");
        assert_eq!(events[0]["payload"]["requestedEnv"][0], "PAYLOAD_SECRET");
    }

    #[test]
    #[serial]
    fn logs_api_accepts_encoded_monorepo_project_names() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        logs::append_event(
            LogKind::Executions,
            json!({ "project": "cms-core:ward", "requestedCommand": "pnpm dev" }),
        )
        .unwrap();

        let project = query_param("project=cms-core%3Award", "project").unwrap();
        let events = load_all_events(Some(&project));
        assert_eq!(project, "cms-core:ward");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["_kind"], "execution");
        assert_eq!(events[0]["_project"], "cms-core:ward");
    }

    #[test]
    #[serial]
    fn logs_api_infers_project_from_verified_context() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        logs::append_event(
            LogKind::Requests,
            json!({
                "verifiedContext": {
                    "project": "cms-core:ward",
                    "worktree": "/tmp/cms-core"
                }
            }),
        )
        .unwrap();

        let events = load_all_events(Some("cms-core:ward"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["_project"], "cms-core:ward");
    }

    #[test]
    fn folder_picker_accepts_manual_fallback_path() {
        let response = pick_folder_from_request(PickFolderRequest {
            path: Some(PathBuf::from("/tmp/demo")),
        })
        .unwrap();
        assert_eq!(response.path, PathBuf::from("/tmp/demo"));
        assert!(pick_folder_from_request(PickFolderRequest { path: None }).is_err());
    }

    #[test]
    fn dashboard_setup_target_requires_env_or_config() {
        let project = tempfile::tempdir().unwrap();
        let error = validate_dashboard_setup_target(project.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("no .env or .ward.json"));

        config::write_project_config(
            project.path(),
            &config::ProjectConfig::default_for_dir(project.path(), Some("demo".to_string()))
                .unwrap(),
            true,
        )
        .unwrap();
        assert_eq!(
            validate_dashboard_setup_target(project.path()).unwrap(),
            project.path().canonicalize().unwrap()
        );
    }

    #[test]
    #[serial]
    fn cleanup_stale_instances_removes_dead_metadata() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let instance = DashboardInstance {
            pid: 999_999,
            port: 7777,
            url: dashboard_url(7777, "token"),
            token: "token".to_string(),
            started_project: Some("demo".to_string()),
            started_path: PathBuf::from("/tmp/demo"),
            started_at: chrono::Utc::now().to_rfc3339(),
            version: DASHBOARD_VERSION.to_string(),
        };
        write_instance(&instance).unwrap();
        assert!(metadata_path(instance.pid).exists());
        assert_eq!(cleanup_stale_instances().unwrap(), 1);
        assert!(!metadata_path(instance.pid).exists());
    }

    #[test]
    #[serial]
    fn cleanup_stale_instances_removes_old_version_metadata() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let instance = DashboardInstance {
            pid: std::process::id(),
            port: 7777,
            url: dashboard_url(7777, "token"),
            token: "token".to_string(),
            started_project: Some("demo".to_string()),
            started_path: PathBuf::from("/tmp/demo"),
            started_at: chrono::Utc::now().to_rfc3339(),
            version: "0.0.0".to_string(),
        };
        write_instance(&instance).unwrap();
        assert!(metadata_path(instance.pid).exists());
        assert_eq!(cleanup_stale_instances().unwrap(), 1);
        assert!(!metadata_path(instance.pid).exists());
    }
}
