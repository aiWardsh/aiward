use std::{
    collections::BTreeMap,
    env, fs,
    io::IsTerminal,
    path::{Path, PathBuf},
    thread,
    time::Duration as StdDuration,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use dirs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    agents, anomaly,
    approvals::{self, ApprovalChannel, ApprovalDecision, ApprovalScope},
    broker, config, context, detection, env_file, fs_util, git_context, global_disable,
    global_transition::{
        self, GlobalTransitionService, OffOutcome as WardOffOutcome,
        OffProjectStatus as WardOffProjectStatus, OnOutcome as WardOnOutcome,
        OnProjectStatus as WardOnProjectStatus, PinStrategy, ProjectTarget as WardOffTarget,
        UnlockFailure,
    },
    grants,
    logs::{self as audit_logs, LogKind},
    modes, notifications, pending_requests,
    policy::{self, AccessRequest, ApprovalMode},
    project_store, recovery, registry, runner, term, unlock, vault, workspace, workspace_target,
    worktrees,
};

#[cfg(all(coverage, not(test)))]
use crate::project_teardown::{
    remove_agent_instruction_section, remove_locked_env_if_needed, remove_project_file_if_exists,
};

#[derive(Debug)]
pub struct ChildExit {
    code: i32,
}

impl ChildExit {
    pub fn new(code: i32) -> Self {
        Self { code }
    }

    pub fn exit_code(&self) -> u8 {
        u8::try_from(self.code).unwrap_or(1)
    }
}

impl std::fmt::Display for ChildExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "child process exited with {}", self.code)
    }
}

impl std::error::Error for ChildExit {}

#[derive(Debug, Parser)]
#[command(
    name = "ward",
    version,
    about = "AI secret firewall for local development"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyModeArg {
    ApiDerived,
    LocalDerived,
}

impl From<KeyModeArg> for vault::VaultKeyMode {
    fn from(value: KeyModeArg) -> Self {
        match value {
            KeyModeArg::ApiDerived => vault::VaultKeyMode::ApiDerivedV1,
            KeyModeArg::LocalDerived => vault::VaultKeyMode::LocalDerivedV1,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize, import, register, and create short profiles.
    Setup {
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = ".env")]
        source: PathBuf,
        #[arg(long, default_value = config::DEFAULT_VAULT_FILE)]
        vault: PathBuf,
        #[arg(long, value_enum, default_value_t = KeyModeArg::ApiDerived)]
        key_mode: KeyModeArg,
        #[arg(long)]
        commit_vault: bool,
        #[arg(long)]
        ignore_vault: bool,
        #[arg(long)]
        remove_plaintext: bool,
        #[arg(long)]
        keep_plaintext: bool,
        #[arg(long, default_value = "8h")]
        unlock_ttl: String,
        #[arg(long)]
        no_unlock: bool,
        #[arg(long)]
        workspace: bool,
        #[arg(long = "app")]
        apps: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Create .ward.json and baseline local files.
    Init {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        bare: bool,
    },
    /// Encrypt an existing dotenv file into .env.vault.
    Import {
        source: PathBuf,
        #[arg(long)]
        vault: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = KeyModeArg::ApiDerived)]
        key_mode: KeyModeArg,
    },
    /// Register the current project in ~/.ward/registry.json.
    Register {
        project: String,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Select an already registered project as the active project.
    Use { project: String },
    /// Manage globally registered Ward projects.
    Projects {
        #[command(subcommand)]
        command: ProjectsCommand,
    },
    /// Manage the local project config manifest.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect the local encrypted project store.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Manage the current project's dotenv vault and locked .env file.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Request scoped secret access without running a command.
    Request {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long = "env")]
        env_names: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Create an approval grant directly for a known safe command.
    Allow {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, value_enum)]
        scope: Option<ApprovalScope>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long = "env")]
        env_names: Vec<String>,
    },
    /// Manage stored approval grants.
    Grants {
        #[command(subcommand)]
        command: GrantsCommand,
    },
    /// Inspect and wait for dashboard approval notifications.
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// Approve a pending non-interactive request.
    Approve {
        request_id: uuid::Uuid,
        #[arg(long, value_enum)]
        scope: ApprovalScope,
        #[arg(long)]
        confirm_critical: bool,
        #[arg(long)]
        agent_mediated: bool,
        #[arg(long)]
        json: bool,
    },
    /// Deny a pending non-interactive request.
    Deny {
        request_id: uuid::Uuid,
        #[arg(long)]
        agent_mediated: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run a command with only approved env vars injected.
    Run {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long = "env")]
        env_names: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
        #[arg(long)]
        wait_for_approval: bool,
        #[arg(long, default_value = "30m")]
        approval_timeout: String,
        #[arg(
            last = true,
            help = "Child command and args after --. Put all Ward flags before --."
        )]
        command: Vec<String>,
    },
    /// Run the dev profile.
    Dev {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Run the migrate profile.
    Migrate {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Validate the current Ward setup.
    Doctor {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Inspect and control the local Ward broker.
    Broker {
        #[command(subcommand)]
        command: BrokerCommand,
    },
    /// Manage trusted project worktrees.
    Worktrees {
        #[command(subcommand)]
        command: WorktreesCommand,
    },
    /// Discover and manage monorepo workspace apps.
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    /// Print encrypted audit log paths.
    Logs {
        #[command(subcommand)]
        command: Option<LogsCommand>,
        #[arg(value_enum)]
        kind: Option<LogKind>,
    },
    /// Safely edit the encrypted env vault.
    Edit {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
    },
    /// Create a short-lived run unlock session.
    #[command(visible_alias = "resume")]
    Unlock {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, default_value = "8h")]
        ttl: String,
        /// Activate a named session mode after unlocking (must be pushed first via `ward modes push`).
        #[arg(long)]
        mode: Option<String>,
        /// Verify that the broker currently has an active session for this project.
        #[arg(long)]
        verify_only: bool,
    },
    /// Manage session mode permission envelopes.
    Modes {
        #[command(subcommand)]
        command: ModesCommand,
    },
    /// Clear unlock sessions and revoke session-scoped approval grants.
    Lock {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        workspace: bool,
        #[arg(long)]
        all: bool,
    },
    /// Disable Ward globally and restore plaintext env files for known projects.
    Off {
        /// Add Ward projects discovered under this root before restoring env files.
        #[arg(long)]
        discover: Option<PathBuf>,
        /// Prompt separately for each project instead of reusing one PIN/passphrase for all projects.
        #[arg(long)]
        each: bool,
        /// Print machine-readable disable summary.
        #[arg(long)]
        json: bool,
    },
    /// Re-enable Ward globally and re-encrypt Ward-created plaintext env files.
    On {
        /// Prompt separately for each project instead of reusing one PIN/passphrase for all projects.
        #[arg(long)]
        each: bool,
        /// Print machine-readable enable summary.
        #[arg(long)]
        json: bool,
    },
    /// Export plaintext env and remove Ward files from a project.
    Teardown {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long = "export", default_value = ".env.export")]
        export_path: PathBuf,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        restore_env: bool,
    },
    #[cfg(all(coverage, not(test)))]
    #[command(hide = true, name = "__coverage")]
    Coverage,
    #[command(hide = true, name = "__broker")]
    BrokerServe,
    /// Print shell integration code. Add `eval "$(ward shell-init)"` to your shell config.
    ShellInit {
        /// Override shell detection (zsh, bash, fish).
        #[arg(long)]
        shell: Option<String>,
    },
    /// Activate human mode for this terminal window.
    Human {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        all: bool,
        /// Unlock duration (e.g. 8h, 30m).
        #[arg(long, default_value = "8h")]
        ttl: String,
    },
    /// Rotate the vault to a new derived filename (generates a new nonce).
    Rotate {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
    },
    /// Manage vault key mode, migration, and offline recovery keys.
    Key {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Manage recovery keys for this project.
    Recovery {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Manage Ward dashboards.
    Dashboard {
        #[command(subcommand)]
        command: Option<DashboardCommand>,
    },
    #[command(hide = true, name = "__dashboard-server")]
    DashboardServer {
        #[arg(long)]
        port: u16,
        #[arg(long)]
        token: String,
    },
    #[command(hide = true, name = "__human-guardian")]
    HumanGuardian {
        #[arg(long)]
        shell_pid: u32,
        #[arg(long)]
        session_token: String,
        #[arg(long)]
        ttl_seconds: i64,
        #[arg(long = "project")]
        projects: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProjectsCommand {
    /// List globally registered projects.
    List,
    /// Show one registered project, or the resolved current project.
    Show { project: Option<String> },
    /// Register a project in the global registry.
    Register {
        project: String,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Discover Ward projects under a root and add them to the global registry.
    Discover {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Select an already registered project as active.
    Use { project: String },
    /// Remove a project from the global registry.
    Remove { project: String },
    /// Provision a new project from selected envs in an unlocked source project.
    Provision {
        #[arg(long = "from")]
        from_project: String,
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long = "profile")]
        profiles: Vec<String>,
        #[arg(long = "env")]
        env_names: Vec<String>,
        #[arg(long = "agent")]
        agents: Vec<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum StoreCommand {
    /// List encrypted project-store snapshots.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one encrypted project-store snapshot summary.
    Show {
        project: String,
        #[arg(long)]
        json: bool,
    },
    /// Refresh a project-store snapshot from an active broker session.
    Refresh {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Restore a missing .ward.json from the local private metadata backup.
    Restore {
        /// Overwrite an existing .ward.json.
        #[arg(long)]
        force: bool,
        /// Print machine-readable restore status.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DashboardCommand {
    /// Start the local browser dashboard.
    Start {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        no_open: bool,
        #[arg(long)]
        foreground: bool,
        #[arg(long)]
        json: bool,
    },
    /// Stop standalone browser dashboard instances.
    Stop {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        json: bool,
    },
    /// Show standalone browser dashboard status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Open the terminal logs dashboard.
    Tui,
}

#[derive(Debug, Subcommand)]
pub enum BrokerCommand {
    /// Print broker status.
    Status,
    /// Stop the broker if it is running.
    Stop,
    /// Print the broker Unix socket path.
    SocketPath,
}

#[derive(Debug, Subcommand)]
pub enum WorktreesCommand {
    /// List trusted and pending worktrees for a project.
    List {
        #[arg(long)]
        project: String,
    },
    /// Allow worktrees under a root folder for a project.
    AllowRoot {
        #[arg(long)]
        project: String,
        path: PathBuf,
    },
    /// Remove an allowed worktree root for a project.
    RemoveRoot {
        #[arg(long)]
        project: String,
        path: PathBuf,
    },
    /// Approve a pending worktree binding.
    Approve {
        request_id: uuid::Uuid,
        #[arg(long)]
        json: bool,
    },
    /// Deny a pending worktree binding.
    Deny {
        request_id: uuid::Uuid,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum WorkspaceCommand {
    /// Discover apps and packages in the current monorepo workspace.
    Discover {
        #[arg(long)]
        json: bool,
    },
    /// Show configured workspace app projects.
    Projects {
        #[arg(long)]
        json: bool,
    },
    /// Run workspace-aware doctor diagnostics.
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// List env names in the encrypted vault.
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Ask a human to add a missing env key without exposing the value to the agent.
    RequestSet {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        key: String,
        #[arg(long)]
        wait_for_approval: bool,
        #[arg(long, default_value = "30m")]
        approval_timeout: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Set one encrypted env value with KEY=value syntax.
    Set {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        assignment: String,
    },
    /// Remove one encrypted env value.
    Unset {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        key: String,
    },
    /// Write plaintext .env for manual local development.
    Unlock {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, default_value = ".env")]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Re-encrypt a plaintext .env and restore the locked marker file.
    Lock {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long, default_value = ".env")]
        source: PathBuf,
    },
    /// Export plaintext dotenv contents.
    Export {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        unsafe_stdout: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum GrantsCommand {
    /// List stored approval grants.
    List,
    /// Revoke one approval grant by id.
    Revoke { grant_id: uuid::Uuid },
    /// Remove expired grants.
    Prune,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// List pending approval notifications.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Wait until a pending approval is resolved.
    Wait {
        request_id: uuid::Uuid,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = "30m")]
        timeout: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    /// Decrypt and print one encrypted log kind.
    View {
        #[arg(value_enum)]
        kind: LogKind,
    },
    /// Verify encrypted log hash chains.
    Verify {
        #[arg(value_enum)]
        kind: Option<LogKind>,
        #[arg(long)]
        full: bool,
    },
    /// Decrypt and write one encrypted log kind to a file.
    Export {
        #[arg(value_enum)]
        kind: LogKind,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Temporarily unlock encrypted log viewing.
    Unlock {
        #[arg(long, default_value = "15m")]
        ttl: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ModesCommand {
    /// List modes defined in .ward.modes.json.
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
    },
    /// Push local .ward.modes.json to broker vault (PIN required).
    Push {
        /// Apply globally across all projects.
        #[arg(long)]
        global: bool,
        /// Apply to a specific project by name.
        #[arg(long)]
        project: Option<String>,
        /// Apply to a specific workspace app.
        #[arg(long)]
        app: Option<String>,
    },
    /// Show the active session mode (if any).
    Status {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        app: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    /// Export the recovery file to a safe location (e.g. Desktop or USB).
    Export {
        /// Destination path or directory. Defaults to ~/Desktop.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Import a recovery file backup into ~/.ward/recovery/.
    /// Omit PATH to be prompted — drag and drop the file into the terminal.
    Import { path: Option<PathBuf> },
    /// Create a new recovery file using the vault passphrase.
    Create,
    /// Restore the vault file from recovery material.
    Restore {
        /// Recovery file to import and use. Defaults to the local recovery file.
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Show the current vault key mode and API-derived metadata.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Re-encrypt the vault into another key mode after validating the current PIN/passphrase.
    Migrate {
        #[arg(long, value_enum)]
        to: KeyModeArg,
    },
    /// Export an encrypted offline recovery key file for this vault.
    Export {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Import an encrypted offline recovery key file and rewrite the vault for local recovery.
    Import { path: PathBuf },
}

include!("commands/dispatch.rs");
include!("commands/models.rs");
include!("commands/setup.rs");
include!("commands/projects.rs");
include!("commands/workspace.rs");
include!("commands/env.rs");
include!("commands/access.rs");
include!("commands/execution.rs");
include!("commands/diagnostics.rs");
include!("commands/lifecycle.rs");
include!("commands/keys.rs");
include!("commands/shell.rs");
include!("commands/misc.rs");
include!("commands/execution_support.rs");
include!("commands/coverage.rs");
include!("commands/diagnostic_helpers.rs");

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
