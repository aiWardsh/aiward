use super::*;
use crate::{
    config::ProjectConfig,
    policy::{AccessRequest, ApprovalMode, PolicyEvaluation},
    project_teardown::{
        remove_agent_instruction_section, remove_locked_env_if_needed,
        remove_project_file_if_exists, ProjectTeardownRequest,
    },
};
use clap::CommandFactory;
use std::{
    path::{Path, PathBuf},
    process::Command as StdCommand,
};

fn cwd_lock() -> crate::test_support::TestEnvironment {
    crate::test_support::TestEnvironment::lock()
}

#[test]
fn remaining_session_ttl_only_returns_positive_duration() {
    let now = chrono::Utc::now();
    assert_eq!(
        remaining_session_ttl(now + chrono::Duration::seconds(30), now)
            .unwrap()
            .num_seconds(),
        30
    );
    assert!(remaining_session_ttl(now, now).is_none());
    assert!(remaining_session_ttl(now - chrono::Duration::seconds(1), now).is_none());
}

fn prepare_git_context(path: &Path, agent: &str, branch: Option<&str>) -> AgentContextOptions {
    StdCommand::new("git")
        .args(["init"])
        .current_dir(path)
        .output()
        .unwrap();
    StdCommand::new("git")
        .args(["config", "user.email", "tester@example.test"])
        .current_dir(path)
        .output()
        .unwrap();
    StdCommand::new("git")
        .args(["config", "user.name", "Tester"])
        .current_dir(path)
        .output()
        .unwrap();
    StdCommand::new("git")
        .args(["remote", "add", "origin", "https://example.test/demo.git"])
        .current_dir(path)
        .output()
        .unwrap();
    if let Some(branch_name) = branch {
        StdCommand::new("git")
            .args(["checkout", "-B", branch_name])
            .current_dir(path)
            .output()
            .unwrap();
    }
    StdCommand::new("git")
        .args(["add", "."])
        .current_dir(path)
        .output()
        .unwrap();
    StdCommand::new("git")
        .args(["commit", "--allow-empty", "-m", "init"])
        .env("GIT_AUTHOR_NAME", "Tester")
        .env("GIT_AUTHOR_EMAIL", "tester@example.test")
        .env("GIT_COMMITTER_NAME", "Tester")
        .env("GIT_COMMITTER_EMAIL", "tester@example.test")
        .current_dir(path)
        .output()
        .unwrap();
    let branch_name = branch.map(str::to_string).unwrap_or_else(|| {
        String::from_utf8(
            StdCommand::new("git")
                .args(["branch", "--show-current"])
                .current_dir(path)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string()
    });
    let commit = String::from_utf8(
        StdCommand::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(path)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    AgentContextOptions {
        agent: Some(agent.to_string()),
        agent_key_id: None,
        worktree: Some(path.to_path_buf()),
        git_remote: Some("https://example.test/demo.git".to_string()),
        commit: Some(commit),
        branch: Some(branch_name),
    }
}

#[test]
#[serial_test::serial]
fn broker_and_worktree_command_helpers_execute_all_branches() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());

    broker_command(BrokerCommand::SocketPath).unwrap();
    broker_command(BrokerCommand::Status).unwrap();
    broker_command(BrokerCommand::Stop).unwrap();

    let root = tempfile::tempdir().unwrap();
    worktrees_command(WorktreesCommand::AllowRoot {
        project: "demo".to_string(),
        path: root.path().to_path_buf(),
    })
    .unwrap();
    worktrees_command(WorktreesCommand::List {
        project: "demo".to_string(),
    })
    .unwrap();
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "demo".to_string(),
        path: root.path().to_path_buf(),
    })
    .unwrap();
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "demo".to_string(),
        path: root.path().to_path_buf(),
    })
    .unwrap();
    worktrees_command(WorktreesCommand::Approve {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .unwrap();
    worktrees_command(WorktreesCommand::Deny {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .unwrap();

    std::env::remove_var("WARD_HOME");
}

#[test]
fn verified_agent_key_id_extracts_optional_context() {
    assert_eq!(verified_agent_key_id(None), None);
    let context = context::VerifiedContext {
        project: "demo".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:demo".to_string(),
        worktree: PathBuf::from("/tmp/demo"),
        branch: "main".to_string(),
        git_remote: "https://example.test/demo.git".to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    assert_eq!(verified_agent_key_id(Some(&context)), Some("agent:demo"));
}

#[test]
#[serial_test::serial]
fn non_interactive_context_can_auto_approve_without_prompt_or_grant() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());

    let context = context::VerifiedContext {
        project: "demo".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:demo".to_string(),
        worktree: PathBuf::from("/tmp/demo"),
        branch: "main".to_string(),
        git_remote: "https://example.test/demo.git".to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    let decision = non_interactive_decision_with_context(
        &access(),
        &evaluation(ApprovalMode::Auto, false),
        Some(&context),
    )
    .unwrap()
    .unwrap();
    assert!(decision.approved);
    assert_eq!(decision.source, approvals::ApprovalSource::PolicyAuto);

    std::env::remove_var("WARD_HOME");
}

fn access() -> AccessRequest {
    AccessRequest {
        project: "demo".to_string(),
        agent: None,
        branch: None,
        action: None,
        command: "pnpm dev".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    }
}

fn evaluation(mode: ApprovalMode, requires_prompt: bool) -> PolicyEvaluation {
    PolicyEvaluation {
        matched_profile: None,
        matched_preset: None,
        matched_mode: None,
        approval_mode: mode,
        requested_env: vec!["DATABASE_URL".to_string()],
        approved_env: vec!["DATABASE_URL".to_string()],
        denied_env: Vec::new(),
        requires_prompt,
        findings: Vec::new(),
    }
}

fn setup_test_signing_unlock(home: &std::path::Path, project: &str) -> PathBuf {
    std::env::set_var("WARD_HOME", home);
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    let vault = home.join(format!("{project}.env.vault"));
    unlock::create_run_unlock(
        project,
        &vault,
        "coverage passphrase",
        chrono::Duration::hours(1),
    )
    .unwrap();
    vault
}

fn clear_test_signing_unlock() {
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
}

#[test]
fn prepare_git_context_reads_current_branch_when_not_supplied() {
    let _guard = cwd_lock();
    let project = tempfile::tempdir().unwrap();
    let context = prepare_git_context(project.path(), "codex", None);
    assert!(!context.branch.as_deref().unwrap_or_default().is_empty());
}

#[test]
#[serial_test::serial]
fn no_prompt_run_and_non_interactive_helpers_cover_json_edges() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let keep_project = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_current_dir(keep_project.path()).unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::fs::write(keep_project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
    std::fs::write(
        keep_project.path().join(".env"),
        "DATABASE_URL=postgres://kept\n",
    )
    .unwrap();

    dispatch(Cli {
        command: Commands::Setup {
            yes: true,
            project: Some("kept".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            key_mode: KeyModeArg::LocalDerived,
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: true,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
            workspace: false,
            apps: Vec::new(),
            all: false,
        },
    })
    .unwrap();
    assert!(keep_project.path().join(".env").exists());

    std::env::set_current_dir(project.path()).unwrap();
    std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://coverage\n",
    )
    .unwrap();

    setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap();

    let no_json_error = run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("No JSON".to_string()),
        env_names: vec!["DATABASE_URL".to_string()],
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: false,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    })
    .unwrap_err()
    .to_string();
    assert!(no_json_error.contains("--no-prompt requires --json"));

    run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Needs approval".to_string()),
        env_names: vec!["DATABASE_URL".to_string()],
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: true,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    })
    .unwrap();

    let mut project_config = config::read_project_config(project.path()).unwrap();
    project_config.presets.push(config::PresetConfig {
        name: "Deny shell".to_string(),
        match_commands: vec!["sh -c false".to_string()],
        allowed_env: Vec::new(),
        approval: ApprovalMode::Deny,
    });
    config::write_project_config(project.path(), &project_config, true).unwrap();
    run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Denied no prompt".to_string()),
        env_names: vec!["DATABASE_URL".to_string()],
        command: vec!["sh".to_string(), "-c".to_string(), "false".to_string()],
        json: true,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    })
    .unwrap();

    let access = access();
    let mut denied = evaluation(ApprovalMode::Deny, false);
    denied.denied_env = vec!["DATABASE_URL".to_string()];
    let denied_decision = non_interactive_decision(&access, &denied).unwrap().unwrap();
    assert!(!denied_decision.approved);
    print_run_denied(&access, &denied).unwrap();
    assert_eq!(run_risk_summary(&denied), "warning");

    let mut critical = evaluation(ApprovalMode::Prompt, true);
    critical.findings.push(crate::detection::Finding::critical(
        "critical.test",
        "critical finding",
    ));
    assert_eq!(run_risk_summary(&critical), "critical");

    let clean = evaluation(ApprovalMode::Auto, false);
    assert_eq!(run_risk_summary(&clean), "low");
    assert!(
        non_interactive_decision(&access, &clean)
            .unwrap()
            .unwrap()
            .approved
    );

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
#[serial_test::serial]
fn doctor_reports_stale_locked_env_and_env_state_errors() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://coverage\n",
    )
    .unwrap();

    setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap();
    std::fs::write(project.path().join(".env.vault"), "changed").unwrap();
    doctor().unwrap();

    std::fs::remove_file(project.path().join(".env")).unwrap();
    std::fs::create_dir(project.path().join(".env")).unwrap();
    doctor().unwrap();

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
fn remove_agent_instruction_section_handles_marker_edges() {
    let tempdir = tempfile::tempdir().unwrap();
    let missing = tempdir.path().join("missing.md");
    assert!(!remove_agent_instruction_section(&missing).unwrap());
    let mut removed_files = Vec::new();
    remove_project_file_if_exists(&missing, &mut removed_files).unwrap();
    assert!(removed_files.is_empty());
    remove_locked_env_if_needed(&missing, &missing, &mut removed_files).unwrap();
    assert!(removed_files.is_empty());

    let remove_me = tempdir.path().join("remove-me");
    std::fs::write(&remove_me, "temporary").unwrap();
    remove_project_file_if_exists(&remove_me, &mut removed_files).unwrap();
    assert!(!remove_me.exists());
    assert_eq!(removed_files.len(), 1);

    let vault = tempdir.path().join(".env.vault");
    std::fs::write(&vault, "encrypted").unwrap();
    let locked_env = tempdir.path().join(".env");
    env_file::lock_env_file(&locked_env, &vault).unwrap();
    remove_locked_env_if_needed(
        &locked_env,
        &tempdir.path().join(".env.export"),
        &mut removed_files,
    )
    .unwrap();
    assert!(!locked_env.exists());

    let no_marker = tempdir.path().join("no-marker.md");
    std::fs::write(&no_marker, "Intro\n").unwrap();
    assert!(!remove_agent_instruction_section(&no_marker).unwrap());

    let retained = tempdir.path().join("retained.md");
    std::fs::write(
        &retained,
        "Intro\n\n<!-- ward-agent-instructions -->\nGenerated\n",
    )
    .unwrap();
    assert!(remove_agent_instruction_section(&retained).unwrap());
    assert_eq!(std::fs::read_to_string(&retained).unwrap(), "Intro\n");
}

#[test]
#[serial_test::serial]
fn setup_reports_missing_source_and_registry_failures() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();
    std::env::set_var("WARD_HOME", home.path());

    let dispatch_conflict = dispatch(Cli {
        command: Commands::Setup {
            yes: true,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: "missing.vault".into(),
            key_mode: KeyModeArg::LocalDerived,
            commit_vault: true,
            ignore_vault: true,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: true,
            workspace: false,
            apps: Vec::new(),
            all: false,
        },
    })
    .unwrap_err()
    .to_string();
    assert!(dispatch_conflict.contains("choose either --commit-vault or --ignore-vault"));

    let plaintext_conflict = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: "missing.env".into(),
        vault: "missing.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: true,
        keep_plaintext: true,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap_err()
    .to_string();
    assert!(plaintext_conflict.contains("choose either --remove-plaintext or --keep-plaintext"));

    let missing = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: "missing.env".into(),
        vault: "missing.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap_err()
    .to_string();
    assert!(missing.contains("missing.env does not exist"));

    let absolute_vault = project.path().join("absolute.env.vault");
    std::fs::write(&absolute_vault, "placeholder").unwrap();
    let bad_home = project.path().join("not-a-dir");
    std::fs::write(&bad_home, "file").unwrap();
    std::env::set_var("WARD_HOME", &bad_home);

    let registry_error = setup(SetupOptions {
        yes: false,
        project: Some("demo".to_string()),
        source: "missing.env".into(),
        vault: absolute_vault,
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap_err()
    .to_string();
    assert!(registry_error.contains("failed to create"));

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial_test::serial]
fn setup_updates_existing_config_without_yes_output() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");

    let config =
        ProjectConfig::default_for_dir(project.path(), Some("old-demo".to_string())).unwrap();
    config::write_project_config(project.path(), &config, false).unwrap();
    let seed_env = project.path().join("seed.env");
    std::fs::write(&seed_env, "DATABASE_URL=postgres://coverage\n").unwrap();
    vault::import_env_file(
        &seed_env,
        &project.path().join(".env.vault"),
        "coverage passphrase",
    )
    .unwrap();

    setup(SetupOptions {
        yes: false,
        project: Some("new-demo".to_string()),
        source: "missing.env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap();
    assert_eq!(
        config::read_project_config(project.path()).unwrap().project,
        "new-demo"
    );

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
#[serial_test::serial]
fn setup_imports_source_env_in_unit_flow() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://coverage\nPAYLOAD_SECRET=payload\n",
    )
    .unwrap();

    setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap();
    assert!(env_file::is_locked_env_file(&project.path().join(".env")).unwrap());
    assert!(project.path().join(".env.vault").exists());
    setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap();
    assert!(
        vault::decrypt_vault_file(&project.path().join(".env.vault"), "coverage passphrase")
            .unwrap()
            .contains("postgres://coverage")
    );
    std::fs::remove_file(project.path().join(".env.vault")).unwrap();
    let missing_vault = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap_err()
    .to_string();
    assert!(missing_vault.contains("Ward locked marker"));

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
#[serial_test::serial]
fn setup_rejects_project_path_traversal_inputs() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();

    let bad_vault = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: "../outside.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: true,
    })
    .unwrap_err()
    .to_string();
    assert!(bad_vault.contains("parent directory traversal"));

    let bad_source = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: "../outside.env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: true,
    })
    .unwrap_err()
    .to_string();
    assert!(bad_source.contains("parent directory traversal"));

    std::env::set_current_dir(old_cwd).unwrap();
}

#[test]
#[serial_test::serial]
fn import_and_teardown_reject_project_path_traversal_inputs() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();

    let import_error = import(
        "../outside.env".into(),
        None,
        vault::VaultKeyMode::LocalDerivedV1,
    )
    .unwrap_err()
    .to_string();
    assert!(import_error.contains("parent directory traversal"));

    let teardown_error = crate::project_teardown::teardown_project(ProjectTeardownRequest {
        project: "demo".to_string(),
        path: project.path().to_path_buf(),
        vault: project.path().join(".env.vault"),
        export_path: "../export.env".into(),
        restore_env: false,
        decrypt_key: "unused".to_string(),
    })
    .unwrap_err()
    .to_string();
    assert!(teardown_error.contains("parent directory traversal"));

    std::env::set_current_dir(old_cwd).unwrap();
}

#[test]
#[serial_test::serial]
fn setup_can_still_remove_plaintext_when_deprecated_flag_is_explicit() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://coverage\n",
    )
    .unwrap();

    setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: true,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .unwrap();

    assert!(!project.path().join(".env").exists());
    assert!(project.path().join(".env.vault").exists());

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
#[serial_test::serial]
fn dispatch_covers_projects_env_unlock_required_and_teardown_paths() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_current_dir(project.path()).unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://coverage\nPAYLOAD_SECRET=payload\n",
    )
    .unwrap();

    dispatch(Cli {
        command: Commands::Setup {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            key_mode: KeyModeArg::LocalDerived,
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: true,
            workspace: false,
            apps: Vec::new(),
            all: false,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Projects {
            command: ProjectsCommand::List,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Projects {
            command: ProjectsCommand::Show {
                project: Some("demo".to_string()),
            },
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Projects {
            command: ProjectsCommand::Use {
                project: "demo".to_string(),
            },
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Projects {
            command: ProjectsCommand::Register {
                project: "temporary".to_string(),
                path: Some(project.path().to_path_buf()),
                vault: Some(".env.vault".into()),
            },
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Projects {
            command: ProjectsCommand::Remove {
                project: "temporary".to_string(),
            },
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Projects {
            command: ProjectsCommand::Remove {
                project: "missing".to_string(),
            },
        },
    })
    .unwrap();

    for command in [
        EnvCommand::List {
            project: None,
            app: None,
            all: false,
            json: false,
            no_prompt: false,
        },
        EnvCommand::Set {
            project: None,
            app: None,
            assignment: "OPENAI_API_KEY=sk-test".to_string(),
        },
        EnvCommand::Unset {
            project: None,
            app: None,
            key: "OPENAI_API_KEY".to_string(),
        },
        EnvCommand::Unset {
            project: None,
            app: None,
            key: "MISSING_ENV".to_string(),
        },
        EnvCommand::Unlock {
            project: None,
            app: None,
            all: false,
            output: ".env.manual".into(),
            force: false,
        },
        EnvCommand::Lock {
            project: None,
            app: None,
            source: ".env.manual".into(),
        },
        EnvCommand::Export {
            project: None,
            app: None,
            output: None,
            force: true,
            unsafe_stdout: false,
        },
        EnvCommand::Export {
            project: None,
            app: None,
            output: Some(".env.dispatch.export".into()),
            force: false,
            unsafe_stdout: false,
        },
    ] {
        dispatch(Cli {
            command: Commands::Env { command },
        })
        .unwrap();
    }

    let mut project_config = config::read_project_config(project.path()).unwrap();
    project_config
        .profiles
        .get_mut("dev")
        .expect("setup creates the dev profile")
        .command = "sh -c true".to_string();
    config::write_project_config(project.path(), &project_config, true).unwrap();

    unlock_vault("1h", None, false).unwrap();
    let agent_context = prepare_git_context(project.path(), "codex", Some("feature/dispatch"));

    dispatch(Cli {
        command: Commands::Allow {
            project: None,
            app: None,
            profile: Some("dev".to_string()),
            scope: Some(ApprovalScope::Always),
            agent: Some("codex".to_string()),
            branch: None,
            command: None,
            env_names: Vec::new(),
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Run {
            profile: Some("dev".to_string()),
            project: None,
            app: None,
            agent: Some("codex".to_string()),
            agent_key_id: agent_context.agent_key_id.clone(),
            worktree: agent_context.worktree.clone(),
            git_remote: agent_context.git_remote.clone(),
            commit: agent_context.commit.clone(),
            branch: agent_context.branch.clone(),
            action: None,
            env_names: Vec::new(),
            json: true,
            no_prompt: true,
            wait_for_approval: false,
            approval_timeout: "30m".to_string(),
            command: Vec::new(),
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Request {
            project: None,
            app: None,
            profile: None,
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: None,
            git_remote: None,
            commit: None,
            branch: None,
            action: Some("Leave pending".to_string()),
            command: Some("pnpm test".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            json: true,
            no_prompt: true,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Teardown {
            project: None,
            app: None,
            export_path: ".env.final".into(),
            yes: true,
            restore_env: false,
        },
    })
    .unwrap();

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
#[serial_test::serial]
fn setup_reports_source_config_import_and_log_failures() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");

    let invalid_project = tempfile::tempdir().unwrap();
    std::env::set_current_dir(invalid_project.path()).unwrap();
    std::fs::write(
        invalid_project.path().join(".env"),
        "DATABASE_URL='unterminated\n",
    )
    .unwrap();
    let invalid_source = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: true,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .expect_err("invalid dotenv should fail setup")
    .to_string();

    let config_blocked = tempfile::tempdir().unwrap();
    std::env::set_current_dir(config_blocked.path()).unwrap();
    std::fs::write(config_blocked.path().join(".env.vault"), "placeholder").unwrap();
    std::fs::create_dir(config_blocked.path().join(".ward.json")).unwrap();
    let config_error = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: "missing.env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .expect_err("blocked config path should fail setup")
    .to_string();

    let import_blocked = tempfile::tempdir().unwrap();
    std::env::set_current_dir(import_blocked.path()).unwrap();
    std::fs::write(
        import_blocked.path().join(".env"),
        "DATABASE_URL=postgres://coverage\n",
    )
    .unwrap();
    std::fs::create_dir(import_blocked.path().join(".env.vault")).unwrap();
    let import_error = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: true,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .expect_err("directory vault path should fail setup")
    .to_string();

    let env_example_blocked = tempfile::tempdir().unwrap();
    std::env::set_current_dir(env_example_blocked.path()).unwrap();
    std::fs::write(env_example_blocked.path().join(".env.vault"), "placeholder").unwrap();
    std::fs::create_dir(env_example_blocked.path().join(".env.example")).unwrap();
    let env_example_error = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: "missing.env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .expect_err("directory .env.example should fail setup")
    .to_string();

    let instructions_blocked = tempfile::tempdir().unwrap();
    std::env::set_current_dir(instructions_blocked.path()).unwrap();
    std::fs::write(
        instructions_blocked.path().join(".env.vault"),
        "placeholder",
    )
    .unwrap();
    std::fs::create_dir(instructions_blocked.path().join("AGENTS.md")).unwrap();
    let instructions_error = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: "missing.env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .expect_err("directory AGENTS.md should fail setup")
    .to_string();

    let gitignore_blocked = tempfile::tempdir().unwrap();
    std::env::set_current_dir(gitignore_blocked.path()).unwrap();
    std::fs::write(gitignore_blocked.path().join(".env.vault"), "placeholder").unwrap();
    std::fs::create_dir(gitignore_blocked.path().join(".gitignore")).unwrap();
    let gitignore_error = setup(SetupOptions {
        yes: true,
        project: Some("demo".to_string()),
        source: "missing.env".into(),
        vault: ".env.vault".into(),
        key_mode: vault::VaultKeyMode::LocalDerivedV1,
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    })
    .expect_err("directory .gitignore should fail setup")
    .to_string();

    #[cfg(unix)]
    let log_error = {
        let log_blocked = tempfile::tempdir().unwrap();
        std::env::set_current_dir(log_blocked.path()).unwrap();
        std::fs::write(
            log_blocked.path().join(".env"),
            "DATABASE_URL=postgres://coverage\n",
        )
        .unwrap();
        std::fs::create_dir_all(home.path().join("logs/sessions.jsonl")).unwrap();
        let error = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            key_mode: vault::VaultKeyMode::LocalDerivedV1,
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: true,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .expect_err("directory log file should fail setup")
        .to_string();
        std::fs::remove_dir_all(home.path().join("logs/sessions.jsonl")).unwrap();
        error
    };

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");

    assert!(invalid_source.contains("failed to parse"));
    assert!(config_error.contains("failed to write"));
    assert!(import_error.contains("failed to write"));
    assert!(env_example_error.contains("not a file"));
    assert!(instructions_error.contains("not a file"));
    assert!(gitignore_error.contains("not a file"));
    #[cfg(unix)]
    assert!(log_error.contains("not a file"));
}

#[test]
#[serial_test::serial]
fn dispatch_and_stateful_commands_cover_cli_paths() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::env::set_current_dir(project.path()).unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://coverage\nPAYLOAD_SECRET=payload\n",
    )
    .unwrap();
    std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();

    dispatch(Cli {
        command: Commands::Init {
            project: Some("demo".to_string()),
            force: false,
            bare: true,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Import {
            source: ".env".into(),
            vault: None,
            key_mode: KeyModeArg::LocalDerived,
        },
    })
    .unwrap();
    let imported_config = config::read_project_config(project.path()).unwrap();
    let primary_vault = config::resolve_vault_path_with_passphrase(
        project.path(),
        &imported_config,
        "coverage passphrase",
    )
    .strip_prefix(project.path())
    .unwrap()
    .to_path_buf();
    std::fs::write(
        project.path().join(".env.alt"),
        "DATABASE_URL=postgres://coverage-alt\nPAYLOAD_SECRET=payload-alt\n",
    )
    .unwrap();
    dispatch(Cli {
        command: Commands::Import {
            source: ".env.alt".into(),
            vault: Some(".env.alt.vault".into()),
            key_mode: KeyModeArg::LocalDerived,
        },
    })
    .unwrap();
    let mut config_after_alt_import = config::read_project_config(project.path()).unwrap();
    config_after_alt_import.vault = primary_vault.clone();
    config::write_project_config(project.path(), &config_after_alt_import, true).unwrap();
    std::fs::remove_file(project.path().join(".env")).unwrap();
    dispatch(Cli {
        command: Commands::Register {
            project: "demo".to_string(),
            path: None,
            vault: None,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Register {
            project: "demo-alt".to_string(),
            path: None,
            vault: Some(project.path().join(".env.alt.vault")),
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Use {
            project: "demo".to_string(),
        },
    })
    .unwrap();
    init(Some("demo".to_string()), true, true).unwrap();
    let mut project_config = config::read_project_config(project.path()).unwrap();
    project_config.vault = primary_vault;
    let dev_profile = project_config.profiles.get_mut("dev").unwrap();
    dev_profile.command = "sh -c true".to_string();
    dev_profile.env = vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()];
    let migrate_profile = project_config.profiles.get_mut("migrate").unwrap();
    migrate_profile.command = "sh -c true".to_string();
    migrate_profile.env = vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()];
    migrate_profile.default_scope = ApprovalScope::Always;
    config::write_project_config(project.path(), &project_config, true).unwrap();
    unlock_vault("1h", None, false).unwrap();
    let agent_context = prepare_git_context(project.path(), "codex", Some("feature/dispatch"));

    assert!(request(
        None,
        AgentContextOptions {
            agent: Some("codex".to_string()),
            branch: None,
            ..AgentContextOptions::default()
        },
        Some("No prompt without json".to_string()),
        Some("sh -c true".to_string()),
        vec!["DATABASE_URL".to_string()],
        false,
        true,
    )
    .is_err());

    dispatch(Cli {
        command: Commands::Request {
            project: None,
            app: None,
            profile: None,
            agent: Some("codex".to_string()),
            agent_key_id: agent_context.agent_key_id.clone(),
            worktree: agent_context.worktree.clone(),
            git_remote: agent_context.git_remote.clone(),
            commit: agent_context.commit.clone(),
            branch: agent_context.branch.clone(),
            action: Some("Run request".to_string()),
            command: Some("sh -c true".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            json: true,
            no_prompt: true,
        },
    })
    .unwrap();
    let pending_id = pending_requests::requests_dir()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .parse::<uuid::Uuid>()
        .unwrap();
    let agent_approval = dispatch(Cli {
        command: Commands::Approve {
            request_id: pending_id,
            scope: ApprovalScope::Once,
            confirm_critical: false,
            agent_mediated: true,
            json: false,
        },
    })
    .unwrap_err()
    .to_string();
    assert!(agent_approval.contains("can no longer create approvals"));

    let broker_approval = dispatch(Cli {
        command: Commands::Approve {
            request_id: pending_id,
            scope: ApprovalScope::Once,
            confirm_critical: false,
            agent_mediated: false,
            json: false,
        },
    })
    .unwrap_err()
    .to_string();
    assert!(broker_approval.contains("broker is unavailable"));

    dispatch(Cli {
        command: Commands::Allow {
            project: None,
            app: None,
            profile: None,
            scope: Some(ApprovalScope::Always),
            agent: Some("codex".to_string()),
            branch: None,
            command: Some("sh -c true".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
        },
    })
    .unwrap();
    assert!(allow(
        None,
        Some(ApprovalScope::Deny),
        None,
        None,
        Some("sh -c true".to_string()),
        vec!["DATABASE_URL".to_string()],
    )
    .is_err());
    assert!(allow(
        None,
        None,
        None,
        None,
        Some("sh -c true".to_string()),
        vec!["DATABASE_URL".to_string()],
    )
    .is_err());
    assert!(allow(
        Some("dev".to_string()),
        Some(ApprovalScope::Always),
        None,
        None,
        Some("sh -c true".to_string()),
        Vec::new(),
    )
    .is_err());
    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "deny");
    assert!(run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Denied run".to_string()),
        env_names: vec!["DATABASE_URL".to_string()],
        command: vec!["sh".to_string(), "-c".to_string(), "false".to_string()],
        json: false,
        no_prompt: false,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    })
    .is_err());
    std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
    allow(
        Some("dev".to_string()),
        None,
        Some("codex".to_string()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    allow(
        Some("migrate".to_string()),
        None,
        Some("codex".to_string()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();

    let run_failure = dispatch(Cli {
        command: Commands::Run {
            profile: None,
            project: None,
            app: None,
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: None,
            git_remote: None,
            commit: None,
            branch: None,
            action: Some("Run without cached unlock".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            json: false,
            no_prompt: false,
            wait_for_approval: false,
            approval_timeout: "30m".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        },
    })
    .unwrap_err()
    .to_string();
    assert!(run_failure.contains("broker execution failed closed"));
    dispatch(Cli {
        command: Commands::Unlock {
            project: None,
            app: None,
            all: false,
            ttl: "1h".to_string(),
            mode: None,
            verify_only: false,
        },
    })
    .unwrap();
    let allowed_run_failure = dispatch(Cli {
        command: Commands::Run {
            profile: None,
            project: None,
            app: None,
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: None,
            git_remote: None,
            commit: None,
            branch: None,
            action: Some("Run allowed command".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            json: false,
            no_prompt: false,
            wait_for_approval: false,
            approval_timeout: "30m".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        },
    })
    .unwrap_err()
    .to_string();
    assert!(allowed_run_failure.contains("broker execution failed closed"));
    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
    let broker_failure = run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Echo secret for redaction".to_string()),
        env_names: vec!["DATABASE_URL".to_string()],
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf '%s\\n' \"$DATABASE_URL\"".to_string(),
        ],
        json: false,
        no_prompt: false,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    })
    .unwrap_err()
    .to_string();
    assert!(broker_failure.contains("broker execution failed closed"));
    std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
    let child_error = run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Child failure".to_string()),
        env_names: vec!["DATABASE_URL".to_string()],
        command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
        json: false,
        no_prompt: false,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    })
    .unwrap_err();
    assert!(child_error
        .to_string()
        .contains("broker execution failed closed"));
    std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
    assert!(dispatch(Cli {
        command: Commands::Dev {
            project: None,
            app: None,
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: None,
            git_remote: None,
            commit: None,
            branch: None,
            json: false,
            no_prompt: false,
        },
    })
    .is_err());
    assert!(dispatch(Cli {
        command: Commands::Migrate {
            project: None,
            app: None,
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: None,
            git_remote: None,
            commit: None,
            branch: None,
            json: false,
            no_prompt: false,
        },
    })
    .is_err());
    assert!(dispatch(Cli {
        command: Commands::Run {
            profile: None,
            project: None,
            app: None,
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: None,
            git_remote: None,
            commit: None,
            branch: Some("feature/dispatch".to_string()),
            action: Some("Run once command".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            json: false,
            no_prompt: false,
            wait_for_approval: false,
            approval_timeout: "30m".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        },
    })
    .is_err());

    dispatch(Cli {
        command: Commands::Grants {
            command: GrantsCommand::List,
        },
    })
    .unwrap();
    let grant_id = grants::load_grants().unwrap()[0].id;
    dispatch(Cli {
        command: Commands::Grants {
            command: GrantsCommand::Revoke { grant_id },
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Grants {
            command: GrantsCommand::Revoke {
                grant_id: uuid::Uuid::new_v4(),
            },
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Grants {
            command: GrantsCommand::Prune,
        },
    })
    .unwrap();

    dispatch(Cli {
        command: Commands::Logs {
            command: None,
            kind: None,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Logs {
            command: None,
            kind: Some(LogKind::Requests),
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Logs {
            command: Some(LogsCommand::View {
                kind: LogKind::Executions,
            }),
            kind: None,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Logs {
            command: Some(LogsCommand::Unlock {
                ttl: "15m".to_string(),
            }),
            kind: None,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Logs {
            command: Some(LogsCommand::Verify {
                kind: None,
                full: false,
            }),
            kind: None,
        },
    })
    .unwrap();

    let editor = project.path().join("edit-env.sh");
    std::fs::write(
            &editor,
            "#!/bin/sh\ncat > \"$1\" <<'EOF'\nDATABASE_URL=postgres://edited\nPAYLOAD_SECRET=payload\nEOF\n",
        )
        .unwrap();
    make_executable(&editor);
    std::env::set_var("EDITOR", &editor);
    dispatch(Cli {
        command: Commands::Edit {
            project: None,
            app: None,
        },
    })
    .unwrap();

    dispatch(Cli {
        command: Commands::Doctor {
            project: None,
            app: None,
            all: false,
        },
    })
    .unwrap();
    dispatch(Cli {
        command: Commands::Lock {
            project: None,
            app: None,
            workspace: false,
            all: false,
        },
    })
    .unwrap();

    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("EDITOR");
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
#[serial_test::serial]
fn approve_deny_json_and_post_log_helpers_cover_edges() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "session");
    std::env::set_current_dir(project.path()).unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://coverage\n",
    )
    .unwrap();

    init(Some("demo".to_string()), false, true).unwrap();
    import(".env".into(), None, vault::VaultKeyMode::LocalDerivedV1).unwrap();
    std::fs::remove_file(project.path().join(".env")).unwrap();
    register("demo".to_string(), None, None).unwrap();
    unlock_vault("1h", None, false).unwrap();
    ensure_logs_passphrase().unwrap();
    ensure_logs_passphrase().unwrap();
    request(
        None,
        AgentContextOptions {
            agent: Some("codex".to_string()),
            branch: None,
            ..AgentContextOptions::default()
        },
        Some("Prompt text".to_string()),
        Some("pnpm dev".to_string()),
        vec!["DATABASE_URL".to_string()],
        false,
        false,
    )
    .unwrap();
    request(
        None,
        AgentContextOptions {
            agent: Some("codex".to_string()),
            branch: None,
            ..AgentContextOptions::default()
        },
        Some("Prompt json".to_string()),
        Some("sh -c true".to_string()),
        vec!["DATABASE_URL".to_string()],
        true,
        false,
    )
    .unwrap();
    let broker_failure = run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Prompt run".to_string()),
        env_names: vec!["DATABASE_URL".to_string()],
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf run >/dev/null".to_string(),
        ],
        json: false,
        no_prompt: false,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    })
    .unwrap_err()
    .to_string();
    assert!(broker_failure.contains("broker execution failed closed"));
    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "deny");
    request(
        None,
        AgentContextOptions {
            agent: Some("codex".to_string()),
            branch: None,
            ..AgentContextOptions::default()
        },
        Some("Prompt deny".to_string()),
        Some("sh -c false".to_string()),
        vec!["DATABASE_URL".to_string()],
        false,
        false,
    )
    .unwrap();
    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "session");
    let pending = pending_requests::create_pending_request(
        AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Deny pending".to_string()),
            command: "sh -c false".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        },
        evaluation(ApprovalMode::Prompt, true),
        git_context::GitContext::default(),
    )
    .unwrap();
    assert!(approve(pending.id, ApprovalScope::Deny, false, false, false).is_err());
    assert!(deny(pending.id, false, false).is_err());
    let missing_grant_id = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Once,
        approved_env: vec!["DATABASE_URL".to_string()],
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::Grant,
        grant_id: None,
    };
    consume_once_grant_if_reused(&missing_grant_id).unwrap();
    let non_once_grant = ApprovalDecision {
        scope: ApprovalScope::Always,
        ..missing_grant_id.clone()
    };
    consume_once_grant_if_reused(&non_once_grant).unwrap();
    warn_anomaly_failure(Ok(()));
    warn_anomaly_failure(Err(anyhow::anyhow!("anomaly fail")));
    let pending = pending_requests::create_pending_request(
        AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Approve pending".to_string()),
            command: "sh -c true".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        },
        evaluation(ApprovalMode::Prompt, true),
        git_context::GitContext::default(),
    )
    .unwrap();
    assert!(approve(pending.id, ApprovalScope::Session, false, false, false).is_err());
    let mut critical_policy = evaluation(ApprovalMode::Prompt, true);
    critical_policy
        .findings
        .push(detection::Finding::critical("critical.test", "critical"));
    let critical_pending = pending_requests::create_pending_request(
        AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Critical pending".to_string()),
            command: "sh -c printenv".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        },
        critical_policy,
        git_context::GitContext::default(),
    )
    .unwrap();
    assert!(approve(critical_pending.id, ApprovalScope::Once, false, true, false).is_err());
    assert!(pending_requests::load_pending_request(critical_pending.id).is_ok());
    assert!(approve(
        critical_pending.id,
        ApprovalScope::Session,
        true,
        true,
        false
    )
    .is_err());
    assert!(approve(critical_pending.id, ApprovalScope::Once, true, true, false).is_err());
    grants_command(GrantsCommand::List).unwrap();
    doctor().unwrap();
    let pending = pending_requests::create_pending_request(
        AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Deny pending via dispatch".to_string()),
            command: "sh -c true".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        },
        evaluation(ApprovalMode::Prompt, true),
        git_context::GitContext::default(),
    )
    .unwrap();
    let agent_denial = dispatch(Cli {
        command: Commands::Deny {
            request_id: pending.id,
            agent_mediated: true,
            json: false,
        },
    })
    .unwrap_err()
    .to_string();
    assert!(agent_denial.contains("can no longer deny requests"));
    assert!(handle_post_run_logging_result(0, Err(anyhow::anyhow!("log fail"))).is_err());
    assert!(handle_post_run_logging_result(7, Err(anyhow::anyhow!("log fail"))).is_ok());
    assert!(allow(
        None,
        Some(ApprovalScope::Always),
        None,
        None,
        Some("sh -c printenv".to_string()),
        vec!["DATABASE_URL".to_string()],
    )
    .is_err());
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "wrong passphrase");
    assert!(unlock_vault("1h", None, false).is_err());
    std::env::set_current_dir(old_cwd).unwrap();
    std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
}

#[test]
fn decide_access_handles_policy_deny_auto_and_no_grant_lookup() {
    let access = access();

    let denied = decide_access(&access, &evaluation(ApprovalMode::Deny, false), true).unwrap();
    assert!(!denied.approved);
    assert_eq!(denied.source, approvals::ApprovalSource::PolicyDeny);

    let auto = decide_access(&access, &evaluation(ApprovalMode::Auto, false), false).unwrap();
    assert!(auto.approved);
    assert_eq!(auto.source, approvals::ApprovalSource::PolicyAuto);
}

#[test]
#[serial_test::serial]
fn decide_access_reuses_matching_grant_and_prompts_without_grant() {
    let _guard = cwd_lock();
    let tempdir = tempfile::tempdir().unwrap();
    let vault = setup_test_signing_unlock(tempdir.path(), "demo");

    let access = access();
    let decision = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Always,
        approved_env: vec!["DATABASE_URL".to_string()],
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::LocalTty,
        grant_id: None,
    };
    grants::persist_grant(
        &access,
        &decision,
        &vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .unwrap();

    let reused = decide_access(&access, &evaluation(ApprovalMode::Prompt, true), true).unwrap();
    assert_eq!(reused.source, approvals::ApprovalSource::Grant);

    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
    let prompted = decide_access(&access, &evaluation(ApprovalMode::Prompt, true), false).unwrap();
    assert_eq!(prompted.source, approvals::ApprovalSource::LocalTty);

    std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
    clear_test_signing_unlock();
}

#[test]
#[serial_test::serial]
fn decide_access_bypasses_durable_grants_for_critical_findings() {
    let _guard = cwd_lock();
    let tempdir = tempfile::tempdir().unwrap();
    let vault = setup_test_signing_unlock(tempdir.path(), "demo");
    std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");

    let mut access = access();
    access.command = "sh -c printenv".to_string();
    let durable = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Always,
        approved_env: vec!["DATABASE_URL".to_string()],
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::LocalTty,
        grant_id: None,
    };
    grants::persist_grant(
        &access,
        &durable,
        &vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .unwrap();
    let mut evaluation = evaluation(ApprovalMode::Prompt, true);
    evaluation
        .findings
        .push(detection::Finding::critical("critical.test", "critical"));

    let prompted = decide_access(&access, &evaluation, true).unwrap();
    assert_eq!(prompted.source, approvals::ApprovalSource::LocalTty);
    assert_eq!(prompted.scope, ApprovalScope::Once);

    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Once,
        approvals::ApprovalSource::AgentMediated,
        &vault,
        Some(grants::GrantReceiptContext::synthetic(true)),
    )
    .is_err());
    let once = grants::persist_manual_grant(
        &access,
        ApprovalScope::Once,
        approvals::ApprovalSource::BrokerApproval,
        &vault,
        Some(grants::GrantReceiptContext::synthetic(true)),
    )
    .unwrap();
    let reused_once = decide_access(&access, &evaluation, true).unwrap();
    assert_eq!(reused_once.source, approvals::ApprovalSource::Grant);
    assert_eq!(reused_once.grant_id, Some(once.id));

    std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
    clear_test_signing_unlock();
}

#[test]
#[serial_test::serial]
fn decide_access_ignores_always_grants_for_suspicious_action_findings() {
    let _guard = cwd_lock();
    let tempdir = tempfile::tempdir().unwrap();
    let vault = setup_test_signing_unlock(tempdir.path(), "demo");

    let access = access();
    let always = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Always,
        approved_env: vec!["DATABASE_URL".to_string()],
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::LocalTty,
        grant_id: None,
    };
    grants::persist_grant(
        &access,
        &always,
        &vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .unwrap();
    let session = ApprovalDecision {
        scope: ApprovalScope::Session,
        ..always
    };
    let session_grant = grants::persist_grant(
        &access,
        &session,
        &vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .unwrap()
    .unwrap();
    let mut evaluation = evaluation(ApprovalMode::Prompt, true);
    evaluation.findings.push(detection::Finding::warning(
        "action.prompt_injection",
        "suspicious action",
    ));

    let reused = decide_access(&access, &evaluation, true).unwrap();

    assert_eq!(reused.source, approvals::ApprovalSource::Grant);
    assert_eq!(reused.scope, ApprovalScope::Session);
    assert_eq!(reused.grant_id, Some(session_grant.id));

    clear_test_signing_unlock();
}

#[test]
#[serial_test::serial]
fn decide_access_reports_grant_lookup_errors() {
    let _guard = cwd_lock();
    let tempdir = tempfile::tempdir().unwrap();
    let grants_dir = tempdir.path().join("sessions");
    std::fs::create_dir_all(&grants_dir).unwrap();
    std::fs::write(grants_dir.join("grants.jsonl"), "{bad-json}\n").unwrap();
    std::env::set_var("WARD_HOME", tempdir.path());

    assert!(decide_access(&access(), &evaluation(ApprovalMode::Prompt, true), true).is_err());

    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial_test::serial]
fn decide_access_continues_when_no_grant_matches() {
    let _guard = cwd_lock();
    let tempdir = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", tempdir.path());

    let decision = decide_access(&access(), &evaluation(ApprovalMode::Auto, false), true)
        .expect("empty grant registry should not block auto approval");

    assert_eq!(decision.source, approvals::ApprovalSource::PolicyAuto);
    std::env::remove_var("WARD_HOME");
}

#[test]
fn gitignore_contains_ignores_comments_and_whitespace() {
    let contents = "\n# .env\n .env \n.env.*\n";

    assert!(gitignore_contains(contents, ".env"));
    assert!(gitignore_contains(contents, ".env.*"));
    assert!(!gitignore_contains(contents, ".env.local"));
}

#[test]
fn likely_secret_env_files_finds_variants_except_example() {
    let tempdir = tempfile::tempdir().unwrap();
    std::fs::write(tempdir.path().join(".env.local"), "SECRET=value\n").unwrap();
    std::fs::write(tempdir.path().join(".env.example"), "SECRET=\n").unwrap();
    std::fs::write(tempdir.path().join(".env.vault"), "encrypted\n").unwrap();

    let files = likely_secret_env_files(tempdir.path()).unwrap();

    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".env.local"));
}

#[test]
fn likely_secret_env_files_reports_read_dir_errors() {
    let tempdir = tempfile::tempdir().unwrap();
    let file = tempdir.path().join("not-a-directory");
    std::fs::write(&file, "").unwrap();

    assert!(likely_secret_env_files(&file).is_err());
}

#[test]
#[serial_test::serial]
fn ward_off_target_collection_uses_registry_and_merges_matching_backup() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());

    let config = ProjectConfig::default_for_dir(project.path(), Some("demo".to_string())).unwrap();
    config::write_project_config(project.path(), &config, false).unwrap();
    registry::register_project(
        "demo".to_string(),
        project.path().to_path_buf(),
        project.path().join(config::DEFAULT_VAULT_FILE),
    )
    .unwrap();

    let service = GlobalTransitionService::discover().unwrap();
    let targets = service.targets();

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].project, "demo");
    assert_eq!(targets[0].registry_key, "demo");
    assert_eq!(targets[0].display_name, "demo");
    assert!(same_path(&targets[0].path, project.path()));
    assert!(targets[0].config.is_some());
    assert!(targets[0].registered_vault.is_some());

    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial_test::serial]
fn ward_off_target_collection_ignores_backup_only_projects() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());

    let config =
        ProjectConfig::default_for_dir(project.path(), Some("stale-demo".to_string())).unwrap();
    config::write_project_config(project.path(), &config, false).unwrap();
    assert!(config::config_backup_path("stale-demo").exists());

    assert!(GlobalTransitionService::discover()
        .unwrap()
        .targets()
        .is_empty());

    std::env::remove_var("WARD_HOME");
}

#[test]
#[serial_test::serial]
fn ward_on_keeps_disabled_state_when_ward_plaintext_has_no_vault() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "1234");
    let config = ProjectConfig::default_for_dir(project.path(), Some("demo".to_string())).unwrap();
    config::write_project_config(project.path(), &config, false).unwrap();
    registry::register_project(
        "demo".to_string(),
        project.path().to_path_buf(),
        project.path().join(config::DEFAULT_VAULT_FILE),
    )
    .unwrap();
    std::fs::write(
        project.path().join(".env"),
        "# Ward unlocked plaintext .env.\n\nDATABASE_URL=synthetic\n",
    )
    .unwrap();
    global_disable::disable("test").unwrap();

    let error = ward_on(false, true).unwrap_err();

    assert!(error.to_string().contains("Ward remains disabled"));
    assert!(global_disable::is_disabled());
}

#[test]
#[serial_test::serial]
fn ward_on_removes_disabled_state_only_after_plaintext_is_locked() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "1234");
    let vault_path = project.path().join(config::DEFAULT_VAULT_FILE);
    let config = ProjectConfig::default_for_dir(project.path(), Some("demo".to_string())).unwrap();
    config::write_project_config(project.path(), &config, false).unwrap();
    vault::write_vault(
        &vault_path,
        &vault::encrypt_env("DATABASE_URL=old-synthetic\n", "1234").unwrap(),
    )
    .unwrap();
    registry::register_project(
        "demo".to_string(),
        project.path().to_path_buf(),
        vault_path.clone(),
    )
    .unwrap();
    std::fs::write(
        project.path().join(".env"),
        "# Ward unlocked plaintext .env.\n\nDATABASE_URL=new-synthetic\n",
    )
    .unwrap();
    global_disable::disable("test").unwrap();

    ward_on(false, true).unwrap();

    assert!(!global_disable::is_disabled());
    assert!(env_file::is_locked_env_file(&project.path().join(".env")).unwrap());
    assert_eq!(
        vault::decrypt_vault_file(&vault_path, "1234").unwrap(),
        "\nDATABASE_URL=new-synthetic\n"
    );
}

#[test]
#[serial_test::serial]
fn projects_remove_deletes_backup_only_config_backup() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());

    let config =
        ProjectConfig::default_for_dir(project.path(), Some("stale-demo".to_string())).unwrap();
    config::write_project_config(project.path(), &config, false).unwrap();
    assert!(config::config_backup_path("stale-demo").exists());
    assert!(GlobalTransitionService::discover()
        .unwrap()
        .targets()
        .is_empty());

    projects_command(ProjectsCommand::Remove {
        project: "stale-demo".to_string(),
    })
    .unwrap();

    assert!(!config::config_backup_path("stale-demo").exists());
    assert!(GlobalTransitionService::discover()
        .unwrap()
        .targets()
        .is_empty());

    std::env::remove_var("WARD_HOME");
}

#[cfg(unix)]
#[test]
fn ward_off_restore_reports_symlinked_relative_vault_without_panicking() {
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_vault = outside.path().join(config::DEFAULT_VAULT_FILE);
    std::fs::write(&outside_vault, "not a vault").unwrap();
    std::os::unix::fs::symlink(
        &outside_vault,
        project.path().join(config::DEFAULT_VAULT_FILE),
    )
    .unwrap();

    let mut project_config =
        ProjectConfig::default_for_dir(project.path(), Some("demo".to_string())).unwrap();
    project_config.vault_nonce.clear();
    let target = WardOffTarget {
        project: "demo".to_string(),
        registry_key: "demo".to_string(),
        display_name: "demo".to_string(),
        path: project.path().to_path_buf(),
        config: Some(project_config),
        registered_vault: None,
    };

    let status = restore_ward_off_target(&target, "1234", "20260731", 1);

    assert_eq!(status.status, WardOffOutcome::Failed);
    assert!(status.message.contains("no usable vault path found"));
    assert!(status.message.contains("vault path must stay inside"));
}

#[test]
#[serial_test::serial]
fn shell_init_checks_disabled_state_before_project_detection() {
    let _guard = cwd_lock();
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());

    let posix = shell_init_code("zsh");
    let disabled_check = posix.find("if __ward_disabled").unwrap();
    let project_detection = posix
        .find("__ward_root=\"$(__ward_project_root)\"")
        .unwrap();
    assert!(disabled_check < project_detection);
    assert!(posix.contains("__ward_disabled()"));
    assert!(posix.contains("disabled.json"));
    assert!(posix.contains("command \"$@\""));
    assert!(posix.contains("WARD_HUMAN_SHELL_PID=$$ command ward \"$@\""));
    assert!(posix.contains("--filter|--workspace|-F|-w"));
    assert!(posix.contains("[ \"$__ward_manager\" = \"yarn\" ] && [ \"$1\" = \"workspace\" ]"));
    assert!(posix.contains("__ward_prompt_badge()"));
    assert!(posix.contains("if [ -f \""));

    let fish = shell_init_code("fish");
    let disabled_check = fish.find("if __ward_disabled").unwrap();
    let project_detection = fish.find("set project_root (__ward_project_root)").unwrap();
    assert!(disabled_check < project_detection);
    assert!(fish.contains("function __ward_disabled"));
    assert!(fish.contains("test -f \""));
    assert!(fish.contains("command $argv"));
    assert!(fish.contains("env WARD_HUMAN_SHELL_PID=$fish_pid command ward $argv"));
    assert!(fish.contains("test \"$manager\" = \"yarn\""));
    assert!(fish.contains("or test \"$arg\" = \"-F\"; or test \"$arg\" = \"-w\""));

    std::env::remove_var("WARD_HOME");
}

#[test]
fn check_gitignore_reports_read_errors() {
    let tempdir = tempfile::tempdir().unwrap();
    std::fs::create_dir(tempdir.path().join(".gitignore")).unwrap();

    assert!(check_gitignore(tempdir.path()).is_err());
}

#[test]
fn check_gitignore_allows_missing_file() {
    let tempdir = tempfile::tempdir().unwrap();

    assert!(check_gitignore(tempdir.path()).is_ok());
}

#[test]
fn check_gitignore_reads_complete_and_partial_files() {
    let tempdir = tempfile::tempdir().unwrap();
    let gitignore = tempdir.path().join(".gitignore");

    std::fs::write(&gitignore, ".env\n.env.*\n").unwrap();
    assert!(check_gitignore(tempdir.path()).is_ok());

    std::fs::write(&gitignore, ".env\n").unwrap();
    assert!(check_gitignore(tempdir.path()).is_ok());

    std::fs::write(&gitignore, ".env.*\n").unwrap();
    assert!(check_gitignore(tempdir.path()).is_ok());

    std::fs::write(&gitignore, ".env\n.env.*\n!.env.vault\n").unwrap();
    assert!(check_gitignore(tempdir.path()).is_ok());
}

#[test]
#[serial_test::serial]
fn init_handles_existing_env_example() {
    let _guard = cwd_lock();
    let tempdir = tempfile::tempdir().unwrap();
    let original = std::env::current_dir().unwrap();
    std::fs::write(tempdir.path().join(".env.example"), "DATABASE_URL=\n").unwrap();
    std::env::set_current_dir(tempdir.path()).unwrap();

    let result = init(Some("demo".to_string()), false, true);

    std::env::set_current_dir(original).unwrap();
    assert!(result.is_ok());
    assert!(tempdir
        .path()
        .join(config::AGENT_INSTRUCTIONS_FILE)
        .exists());
}

#[test]
#[serial_test::serial]
fn init_guided_setup_handles_plaintext_env() {
    let _guard = cwd_lock();
    let tempdir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
    std::fs::write(
        tempdir.path().join(".env"),
        "DATABASE_URL=postgres://local\n",
    )
    .unwrap();
    std::env::set_current_dir(tempdir.path()).unwrap();

    let result = init(Some("demo".to_string()), false, false);

    std::env::set_current_dir(original).unwrap();
    std::env::remove_var("WARD_HOME");
    std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    assert!(result.is_ok());
    assert!(tempdir.path().join(".env.example").exists());
    assert!(env_file::is_locked_env_file(&tempdir.path().join(".env")).unwrap());
}

#[test]
#[serial_test::serial]
fn doctor_covers_missing_invalid_plaintext_and_alert_error_paths() {
    let _guard = cwd_lock();
    let original = std::env::current_dir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("WARD_HOME", home.path());
    std::env::set_current_dir(project.path()).unwrap();

    doctor().unwrap();

    std::fs::write(project.path().join(".ward.json"), "{").unwrap();
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://local\n",
    )
    .unwrap();
    std::fs::write(project.path().join(".env.local"), "SECRET_KEY=value\n").unwrap();
    std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
    doctor().unwrap();

    let grants_dir = home.path().join("sessions");
    std::fs::create_dir_all(&grants_dir).unwrap();
    let now = chrono::Utc::now();
    let legacy_grant = grants::ApprovalGrant {
        id: uuid::Uuid::new_v4(),
        created_at: now,
        expires_at: None,
        request_id: None,
        project: "demo".to_string(),
        agent: None,
        branch: None,
        command: "pnpm dev".to_string(),
        approved_env: vec!["DATABASE_URL".to_string()],
        scope: approvals::ApprovalScope::Always,
        uses_remaining: None,
        receipt: None,
    };
    let mut invalid_grant = legacy_grant.clone();
    invalid_grant.id = uuid::Uuid::new_v4();
    let receipt_access = access();
    let receipt_env = ["DATABASE_URL".to_string()];
    invalid_grant.receipt = Some(crate::approval_receipts::ApprovalReceipt {
        payload: crate::approval_receipts::build_payload(
            crate::approval_receipts::PayloadRequest {
                access: &receipt_access,
                grant_id: invalid_grant.id,
                request_id: uuid::Uuid::new_v4(),
                approved_env: &receipt_env,
                scope: approvals::ApprovalScope::Always,
                expires_at: None,
                critical_confirmation: false,
                created_at: now,
                signer_key_id: "missing-signer".to_string(),
                verified_context: None,
            },
        ),
        payload_hash: "bad".to_string(),
        signer_key_id: "missing-signer".to_string(),
        signature_algorithm: "ed25519".to_string(),
        signature: "bad".to_string(),
    });
    std::fs::write(
        grants_dir.join("grants.jsonl"),
        format!(
            "{}\n{}\n",
            serde_json::to_string(&legacy_grant).unwrap(),
            serde_json::to_string(&invalid_grant).unwrap()
        ),
    )
    .unwrap();
    doctor().unwrap();
    std::fs::write(grants_dir.join("grants.jsonl"), "{bad-json}\n").unwrap();
    doctor().unwrap();

    std::fs::create_dir_all(home.path().join("logs/alerts.jsonl")).unwrap();
    doctor().unwrap();

    std::env::set_current_dir(original).unwrap();
    std::env::remove_var("WARD_HOME");
}

#[test]
fn marker_returns_expected_labels() {
    assert_eq!(marker(true), "[ok]");
    assert_eq!(marker(false), "!");
}

#[test]
fn grant_integrity_messages_cover_ok_legacy_and_invalid_states() {
    assert_eq!(
        grant_integrity_messages(0, 0),
        vec!["[ok] Approval grants are signed and valid.".to_string()]
    );
    assert_eq!(
        grant_integrity_messages(1, 1),
        vec![
            "! Legacy unsigned approval grants: 1. Re-approve them.".to_string(),
            "! Invalid signed approval grants: 1. Revoke and re-approve them.".to_string(),
        ]
    );
}

#[test]
fn grant_status_labels_cover_all_integrity_states() {
    assert_eq!(
        grant_status_label(grants::GrantIntegrityStatus::Valid),
        "valid-signed"
    );
    assert_eq!(
        grant_status_label(grants::GrantIntegrityStatus::Expired),
        "expired"
    );
    assert_eq!(
        grant_status_label(grants::GrantIntegrityStatus::LegacyUnsigned),
        "legacy-unsigned"
    );
    assert_eq!(
        grant_status_label(grants::GrantIntegrityStatus::Invalid),
        "invalid-signature"
    );
}

#[test]
fn signing_lookup_messages_cover_warning_variants() {
    assert!(
        signing_lookup_message(Ok(unlock::RunSigningLookup::Missing))
            .contains("No active signing key session")
    );
    assert!(
        signing_lookup_message(Ok(unlock::RunSigningLookup::MaterialUnavailable {
            reason: "missing".to_string(),
        }))
        .contains("missing")
    );
    assert!(signing_lookup_message(Err(anyhow::anyhow!("boom"))).contains("boom"));
}

#[test]
fn child_exit_formats_and_normalizes_exit_codes() {
    let exit = ChildExit::new(7);
    assert_eq!(exit.exit_code(), 7);
    assert_eq!(exit.to_string(), "child process exited with 7");

    let out_of_range = ChildExit::new(300);
    assert_eq!(out_of_range.exit_code(), 1);
}

#[test]
fn render_log_events_handles_empty_and_multiline_output() {
    assert_eq!(render_log_events(&[]).unwrap(), "");

    let events = vec![
        serde_json::json!({ "payload": { "eventType": "one" } }),
        serde_json::json!({ "payload": { "eventType": "two" } }),
    ];
    let rendered = render_log_events(&events).unwrap();
    assert!(rendered.contains("\"eventType\":\"one\""));
    assert!(rendered.contains('\n'));
    assert!(rendered.contains("\"eventType\":\"two\""));
}

#[test]
fn evaluate_access_combines_detection_and_policy() {
    let config = ProjectConfig {
        version: 1,
        project: "demo".to_string(),
        vault: ".env.vault".into(),
        presets: Vec::new(),
        profiles: std::collections::BTreeMap::new(),
        agent_policies: std::collections::BTreeMap::new(),
        anomaly_detection: config::AnomalyDetectionConfig {
            enabled: true,
            working_hours_start: 8,
            working_hours_end: 20,
            max_runs_per_hour_per_grant: 20,
            max_branches_per_grant: 3,
        },
        storage_mode: config::StorageMode::default(),
        vault_nonce: String::new(),
        backup_exported: false,
        recovery_created: false,
    };
    let mut access = access();
    access.action = Some("Run lint".to_string());

    let evaluation = evaluate_access(&config, &access);

    assert!(evaluation.requires_prompt);
    assert!(evaluation
        .findings
        .iter()
        .any(|finding| finding.code == "env.scope_deviation"));
}

#[test]
fn profile_resolution_expands_short_commands_and_validates_conflicts() {
    let tempdir = tempfile::tempdir().unwrap();
    let config = ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

    let resolved = resolve_profile(&config, Some("dev"), None, None, Vec::new()).unwrap();
    assert_eq!(resolved.command, "pnpm dev");
    assert_eq!(resolved.command_args, vec!["pnpm", "dev"]);
    assert_eq!(resolved.default_scope, ApprovalScope::Always);
    assert!(resolved.env_names.contains(&"DATABASE_URL".to_string()));

    let manual = resolve_profile(
        &config,
        None,
        Some("Manual".to_string()),
        Some("pnpm lint".to_string()),
        vec!["DATABASE_URL".to_string()],
    )
    .unwrap();
    assert_eq!(manual.command_args, vec!["pnpm", "lint"]);
    assert_eq!(manual.default_scope, ApprovalScope::Once);

    let run_profile = resolve_run_profile(
        &config,
        Some("migrate"),
        None,
        Vec::new(),
        Vec::new(),
        false,
    )
    .unwrap();
    assert_eq!(run_profile.command_args, vec!["pnpm", "payload", "migrate"]);
    assert_eq!(run_profile.default_scope, ApprovalScope::Branch);

    let run_profile_with_args = resolve_run_profile(
        &config,
        Some("migrate"),
        None,
        Vec::new(),
        vec!["--dry-run".to_string()],
        false,
    )
    .unwrap();
    assert_eq!(
        run_profile_with_args.command_args,
        vec!["pnpm", "payload", "migrate", "--dry-run"]
    );
    assert_eq!(
        run_profile_with_args.command,
        "pnpm payload migrate --dry-run"
    );

    let missing_profile = resolve_profile(&config, Some("missing"), None, None, Vec::new())
        .unwrap_err()
        .to_string();
    assert!(missing_profile.contains("profile missing is not defined"));

    let explicit_run = resolve_run_profile(
        &config,
        None,
        Some("Run".to_string()),
        vec!["DATABASE_URL".to_string()],
        vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        false,
    )
    .unwrap();
    assert_eq!(explicit_run.command, "sh -c true");

    assert!(resolve_profile(
        &config,
        Some("dev"),
        None,
        Some("pnpm dev".to_string()),
        Vec::new(),
    )
    .is_err());
    assert!(resolve_profile(&config, None, None, None, Vec::new()).is_err());
    assert!(resolve_profile(
        &config,
        None,
        None,
        Some("pnpm dev".to_string()),
        Vec::new(),
    )
    .is_err());
    assert!(resolve_run_profile(
        &config,
        Some("dev"),
        None,
        vec!["DATABASE_URL".to_string()],
        Vec::new(),
        false,
    )
    .is_err());
    assert!(resolve_run_profile(
        &config,
        Some("missing"),
        None,
        Vec::new(),
        Vec::new(),
        false
    )
    .is_err());
    assert!(resolve_run_profile(&config, None, None, Vec::new(), Vec::new(), false).is_err());
    assert!(resolve_run_profile(
        &config,
        None,
        None,
        Vec::new(),
        vec!["pnpm".to_string(), "dev".to_string()],
        false,
    )
    .is_err());
}

#[test]
fn effective_grant_id_prefers_reused_decision_then_persisted_grant() {
    let access = access();
    let grant = grants::ApprovalGrant {
        id: uuid::Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        request_id: None,
        project: access.project.clone(),
        agent: access.agent.clone(),
        branch: access.branch.clone(),
        command: access.command.clone(),
        approved_env: access.env.clone(),
        scope: ApprovalScope::Always,
        uses_remaining: None,
        receipt: None,
    };
    let decision = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Always,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::LocalTty,
        grant_id: None,
    };

    assert_eq!(effective_grant_id(&decision, Some(&grant)), Some(grant.id));

    let reused_id = uuid::Uuid::new_v4();
    let reused = ApprovalDecision {
        grant_id: Some(reused_id),
        source: approvals::ApprovalSource::Grant,
        ..decision
    };
    assert_eq!(effective_grant_id(&reused, Some(&grant)), Some(reused_id));
    assert_eq!(effective_grant_id(&reused, None), Some(reused_id));
}

#[test]
fn run_unlock_required_json_helper_renders_directly() {
    print_run_unlock_required(
        &access(),
        &evaluation(ApprovalMode::Prompt, true),
        Some("unlock_material_unavailable"),
    )
    .unwrap();
}

#[test]
fn clap_help_renders_all_public_command_metadata() {
    let mut command = Cli::command();
    let help = command.render_long_help().to_string();
    assert!(help.contains("AI secret firewall for local development"));
    assert!(help.contains("Select an already registered project"));
    assert!(help.contains("Manage stored approval grants"));

    for subcommand in [
        "setup",
        "request",
        "allow",
        "grants",
        "approve",
        "deny",
        "run",
        "dev",
        "migrate",
        "logs",
        "unlock",
        "workspace",
        "config",
        "store",
        "projects",
    ] {
        let rendered = command
            .find_subcommand_mut(subcommand)
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(rendered.contains(subcommand));
        if subcommand == "run" {
            assert!(rendered.contains("Put all Ward flags before --"));
        }
    }
}

#[test]
fn clap_parses_all_public_command_shapes() {
    let request_id = uuid::Uuid::nil().to_string();
    let command_sets = vec![
        vec![
            "ward",
            "setup",
            "--yes",
            "--project",
            "demo",
            "--source",
            ".env",
            "--vault",
            ".env.vault",
            "--commit-vault",
            "--remove-plaintext",
            "--unlock-ttl",
            "1h",
        ],
        vec!["ward", "setup", "--workspace", "--app", "ambienta"],
        vec![
            "ward",
            "setup",
            "--workspace",
            "--all",
            "--project",
            "cms-core",
        ],
        vec!["ward", "init", "--project", "demo", "--force", "--bare"],
        vec!["ward", "import", ".env", "--vault", ".env.vault"],
        vec![
            "ward",
            "register",
            "demo",
            "--path",
            ".",
            "--vault",
            ".env.vault",
        ],
        vec!["ward", "use", "demo"],
        vec!["ward", "projects", "list"],
        vec!["ward", "projects", "show", "demo"],
        vec!["ward", "projects", "discover", ".", "--json"],
        vec![
            "ward",
            "projects",
            "register",
            "demo",
            "--path",
            ".",
            "--vault",
            ".env.vault",
        ],
        vec!["ward", "projects", "use", "demo"],
        vec!["ward", "projects", "remove", "demo"],
        vec![
            "ward",
            "projects",
            "provision",
            "--from",
            "source",
            "--path",
            "./target",
            "--name",
            "target",
            "--profile",
            "dev",
            "--env",
            "DATABASE_URL",
            "--agent",
            "codex",
            "--json",
        ],
        vec!["ward", "store", "list"],
        vec!["ward", "store", "list", "--json"],
        vec!["ward", "store", "show", "demo", "--json"],
        vec!["ward", "store", "refresh", "--project", "demo", "--json"],
        vec!["ward", "workspace", "discover"],
        vec!["ward", "workspace", "discover", "--json"],
        vec!["ward", "env", "list", "--project", "demo"],
        vec!["ward", "env", "set", "--project", "demo", "KEY=value"],
        vec!["ward", "env", "unset", "--project", "demo", "KEY"],
        vec![
            "ward",
            "env",
            "unlock",
            "--project",
            "demo",
            "--output",
            ".env",
            "--force",
        ],
        vec![
            "ward",
            "env",
            "lock",
            "--project",
            "demo",
            "--source",
            ".env",
        ],
        vec![
            "ward",
            "env",
            "export",
            "--project",
            "demo",
            "--output",
            ".env.export",
            "--force",
        ],
        vec![
            "ward",
            "env",
            "export",
            "--project",
            "demo",
            "--unsafe-stdout",
        ],
        vec![
            "ward",
            "request",
            "--profile",
            "dev",
            "--agent",
            "codex",
            "--branch",
            "main",
            "--action",
            "Run dev",
            "--command",
            "pnpm dev",
            "--env",
            "DATABASE_URL",
            "--json",
            "--no-prompt",
        ],
        vec![
            "ward",
            "allow",
            "--profile",
            "dev",
            "--scope",
            "always",
            "--agent",
            "codex",
            "--branch",
            "main",
            "--command",
            "pnpm dev",
            "--env",
            "DATABASE_URL",
        ],
        vec!["ward", "grants", "list"],
        vec!["ward", "grants", "revoke", &request_id],
        vec!["ward", "grants", "prune"],
        vec!["ward", "config", "restore"],
        vec!["ward", "config", "restore", "--force", "--json"],
        vec![
            "ward",
            "approve",
            &request_id,
            "--scope",
            "once",
            "--confirm-critical",
        ],
        vec!["ward", "deny", &request_id],
        vec![
            "ward",
            "run",
            "--profile",
            "dev",
            "--project",
            "demo",
            "--agent",
            "codex",
            "--branch",
            "main",
            "--action",
            "Run dev",
            "--env",
            "DATABASE_URL",
            "--json",
            "--no-prompt",
            "--",
            "pnpm",
            "dev",
        ],
        vec![
            "ward",
            "dev",
            "--agent",
            "codex",
            "--branch",
            "main",
            "--json",
            "--no-prompt",
        ],
        vec![
            "ward",
            "migrate",
            "--agent",
            "codex",
            "--branch",
            "main",
            "--json",
            "--no-prompt",
        ],
        vec!["ward", "doctor"],
        vec!["ward", "logs", "requests"],
        vec!["ward", "logs", "view", "requests"],
        vec!["ward", "logs", "verify", "requests", "--full"],
        vec![
            "ward",
            "logs",
            "export",
            "requests",
            "--output",
            "requests.jsonl",
            "--force",
        ],
        vec!["ward", "logs", "unlock", "--ttl", "15m"],
        vec!["ward", "dashboard"],
        vec!["ward", "dashboard", "start", "--port", "7780", "--no-open"],
        vec!["ward", "dashboard", "start", "--foreground", "--json"],
        vec!["ward", "dashboard", "stop", "--all", "--json"],
        vec!["ward", "dashboard", "stop", "--pid", "1234"],
        vec!["ward", "dashboard", "stop", "--port", "7780"],
        vec!["ward", "dashboard", "status", "--json"],
        vec!["ward", "dashboard", "tui"],
        vec!["ward", "edit"],
        vec!["ward", "unlock", "--ttl", "1h"],
        vec!["ward", "lock"],
        vec!["ward", "key", "status"],
        vec!["ward", "key", "status", "--json"],
        vec!["ward", "key", "migrate", "--to", "api-derived"],
        vec!["ward", "key", "migrate", "--to", "local-derived"],
        vec!["ward", "key", "export"],
        vec![
            "ward",
            "key",
            "export",
            "--output",
            "ward-recovery-key.json",
        ],
        vec!["ward", "key", "import", "ward-recovery-key.json"],
        vec!["ward", "off"],
        vec!["ward", "off", "--discover", "."],
        vec!["ward", "on", "--json"],
        vec![
            "ward",
            "teardown",
            "--project",
            "demo",
            "--export",
            ".env.export",
            "--yes",
            "--restore-env",
        ],
    ];

    for args in command_sets {
        assert!(Cli::try_parse_from(args).is_ok());
    }

    for args in [
        vec!["ward", "auth", "login"],
        vec!["ward", "cloud", "dev", "start"],
        vec!["ward", "setup", "login"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn debug_formats_all_cli_command_variants() {
    let request_id = uuid::Uuid::nil();
    let commands = vec![
        format!(
            "{:?}",
            Cli {
                command: Commands::Lock {
                    project: None,
                    app: None,
                    workspace: false,
                    all: false,
                }
            }
        ),
        format!(
            "{:?}",
            Commands::Init {
                project: Some("demo".to_string()),
                force: true,
                bare: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Import {
                source: ".env".into(),
                vault: Some(".env.vault".into()),
                key_mode: KeyModeArg::LocalDerived,
            }
        ),
        format!(
            "{:?}",
            Commands::Key {
                project: Some("demo".to_string()),
                app: None,
                command: KeyCommand::Status { json: true },
            }
        ),
        format!(
            "{:?}",
            Commands::Register {
                project: "demo".to_string(),
                path: Some(".".into()),
                vault: Some(".env.vault".into()),
            }
        ),
        format!(
            "{:?}",
            Commands::Use {
                project: "demo".to_string(),
            }
        ),
        format!(
            "{:?}",
            Commands::Request {
                project: None,
                app: None,
                profile: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: Some("main".to_string()),
                action: Some("Run".to_string()),
                command: Some("pnpm dev".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
                json: true,
                no_prompt: true,
            }
        ),
        format!(
            "{:?}",
            Commands::Allow {
                project: None,
                app: None,
                profile: None,
                scope: Some(ApprovalScope::Always),
                agent: Some("codex".to_string()),
                branch: Some("main".to_string()),
                command: Some("pnpm dev".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
            }
        ),
        format!(
            "{:?}",
            Commands::Grants {
                command: GrantsCommand::List,
            }
        ),
        format!(
            "{:?}",
            Commands::Approve {
                request_id,
                scope: ApprovalScope::Session,
                confirm_critical: true,
                agent_mediated: true,
                json: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Deny {
                request_id,
                agent_mediated: true,
                json: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Run {
                profile: None,
                project: Some("demo".to_string()),
                app: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: Some("main".to_string()),
                action: Some("Run".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
                json: false,
                no_prompt: false,
                wait_for_approval: false,
                approval_timeout: "30m".to_string(),
                command: vec!["pnpm".to_string(), "dev".to_string()],
            }
        ),
        format!(
            "{:?}",
            Commands::Setup {
                yes: true,
                project: Some("demo".to_string()),
                source: ".env".into(),
                vault: ".env.vault".into(),
                key_mode: KeyModeArg::LocalDerived,
                commit_vault: true,
                ignore_vault: false,
                remove_plaintext: true,
                keep_plaintext: false,
                unlock_ttl: "8h".to_string(),
                no_unlock: false,
                workspace: false,
                apps: Vec::new(),
                all: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Workspace {
                command: WorkspaceCommand::Discover { json: true },
            }
        ),
        format!(
            "{:?}",
            Commands::Config {
                command: ConfigCommand::Restore {
                    force: true,
                    json: true,
                },
            }
        ),
        format!(
            "{:?}",
            Commands::Dev {
                project: None,
                app: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: Some("main".to_string()),
                json: false,
                no_prompt: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Migrate {
                project: None,
                app: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: Some("main".to_string()),
                json: false,
                no_prompt: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Doctor {
                project: None,
                app: None,
                all: false
            }
        ),
        format!(
            "{:?}",
            Commands::Logs {
                command: Some(LogsCommand::View {
                    kind: LogKind::Requests,
                }),
                kind: Some(LogKind::Requests),
            }
        ),
        format!(
            "{:?}",
            Commands::Edit {
                project: None,
                app: None
            }
        ),
        format!(
            "{:?}",
            Commands::Unlock {
                project: None,
                app: None,
                all: false,
                ttl: "1h".to_string(),
                mode: None,
                verify_only: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Lock {
                project: None,
                app: None,
                workspace: false,
                all: false,
            }
        ),
        format!(
            "{:?}",
            Commands::Off {
                discover: Some(".".into()),
                each: true,
                json: true,
            }
        ),
        format!(
            "{:?}",
            Commands::On {
                each: true,
                json: true,
            }
        ),
        format!(
            "{:?}",
            GrantsCommand::Revoke {
                grant_id: request_id
            }
        ),
        format!("{:?}", GrantsCommand::Prune),
        format!(
            "{:?}",
            LogsCommand::Verify {
                kind: None,
                full: false,
            }
        ),
        format!(
            "{:?}",
            LogsCommand::Unlock {
                ttl: "15m".to_string(),
            }
        ),
        format!(
            "{:?}",
            Commands::Dashboard {
                command: Some(DashboardCommand::Status { json: true }),
            }
        ),
        format!(
            "{:?}",
            DashboardCommand::Start {
                port: Some(7777),
                no_open: true,
                foreground: false,
                json: true,
            }
        ),
        format!(
            "{:?}",
            DashboardCommand::Stop {
                all: true,
                pid: None,
                port: None,
                json: false,
            }
        ),
        format!("{:?}", DashboardCommand::Tui),
    ];

    assert_eq!(commands.len(), 32);
    for value in commands {
        assert!(!value.is_empty());
    }
}

#[test]
fn setup_wizard_copy_is_product_ready() {
    assert!(SETUP_GUIDED_BODY.contains("encrypt your local env"));
    assert!(SETUP_GUIDED_BODY.contains("safe human and agent access"));
    assert!(WORKSPACE_SETUP_BODY.contains("monorepo workspace"));
    assert!(WORKSPACE_SETUP_PROMPT_HELP.contains("workspace-root trust"));
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
