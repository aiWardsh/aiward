use std::{
    env, fs,
    io::IsTerminal,
    path::{Path, PathBuf},
    thread,
    time::Duration as StdDuration,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dirs;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    agents, anomaly,
    approvals::{self, ApprovalChannel, ApprovalDecision, ApprovalScope},
    broker, cloud, config, context, detection, env_file, git_context, grants,
    logs::{self as audit_logs, self as logs, LogKind},
    modes, notifications, pending_requests,
    policy::{self, AccessRequest, ApprovalMode},
    project_store, recovery, registry,
    runner::{self, RunCommandRequest},
    term, unlock, vault, workspace, workspace_target, worktrees,
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

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize, import, register, and create short profiles.
    Setup {
        #[command(subcommand)]
        command: Option<SetupCommand>,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = ".env")]
        source: PathBuf,
        #[arg(long, default_value = config::DEFAULT_VAULT_FILE)]
        vault: PathBuf,
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
    /// Sign in to a Ward local-cloud account.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Manage the local cloud-shaped team backend.
    Cloud {
        #[command(subcommand)]
        command: CloudCommand,
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
    #[command(hide = true, name = "__cloud-dev-server")]
    CloudDevServer {
        #[arg(long)]
        port: u16,
        #[arg(long)]
        token: String,
        #[arg(long)]
        db: PathBuf,
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
pub enum SetupCommand {
    /// Import an invited cloud project/environment into this folder.
    Login {
        #[arg(long, default_value_t = cloud::default_cloud_url())]
        cloud_url: String,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        environment: Option<String>,
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
pub enum AuthCommand {
    /// Create or select a local cloud account and device.
    Login {
        #[arg(long, default_value_t = cloud::default_cloud_url())]
        cloud_url: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        device_name: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum CloudCommand {
    /// Manage the local cloud-shaped backend.
    Dev {
        #[command(subcommand)]
        command: CloudDevCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum CloudDevCommand {
    /// Start the localhost cloud-dev service.
    Start {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        foreground: bool,
        #[arg(long)]
        json: bool,
    },
    /// Stop the localhost cloud-dev service.
    Stop {
        #[arg(long)]
        json: bool,
    },
    /// Show localhost cloud-dev status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Publish selected envs from a local Ward project into the local cloud-dev database.
    Publish {
        #[arg(long, default_value_t = cloud::default_cloud_url())]
        cloud_url: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        team: String,
        #[arg(long)]
        cloud_project: Option<String>,
        #[arg(long, default_value = "development")]
        environment: String,
        #[arg(long = "env")]
        env_names: Vec<String>,
        #[arg(long = "profile")]
        profiles: Vec<String>,
        #[arg(long = "agent")]
        agents: Vec<String>,
        #[arg(long = "member")]
        members: Vec<String>,
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

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Setup {
            command,
            yes,
            project,
            source,
            vault,
            commit_vault,
            ignore_vault,
            remove_plaintext,
            keep_plaintext,
            unlock_ttl,
            no_unlock,
            workspace,
            apps,
            all,
        } => {
            if let Some(command) = command {
                return setup_command(command);
            }
            let options = SetupOptions {
                yes,
                project,
                source,
                vault,
                commit_vault,
                ignore_vault,
                remove_plaintext,
                keep_plaintext,
                unlock_ttl,
                no_unlock,
            };
            if workspace {
                setup_workspace(options, apps, all)
            } else {
                setup(options)
            }
        }
        Commands::Init {
            project,
            force,
            bare,
        } => init(project, force, bare),
        Commands::Import { source, vault } => import(source, vault),
        Commands::Register {
            project,
            path,
            vault,
        } => register(project, path, vault),
        Commands::Use { project } => use_project(&project),
        Commands::Projects { command } => projects_command(command),
        Commands::Config { command } => config_command(command),
        Commands::Store { command } => store_command(command),
        Commands::Auth { command } => auth_command(command),
        Commands::Cloud { command } => cloud_command(command),
        Commands::Env { command } => env_command(command),
        Commands::Request {
            project,
            app,
            profile,
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            action,
            command,
            env_names,
            json,
            no_prompt,
        } => request_for_target(
            project,
            app,
            profile,
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
            action,
            command,
            env_names,
            json,
            no_prompt,
        ),
        Commands::Allow {
            project,
            app,
            profile,
            scope,
            agent,
            branch,
            command,
            env_names,
        } => allow_for_target(
            project, app, profile, scope, agent, branch, command, env_names,
        ),
        Commands::Grants { command } => grants_command(command),
        Commands::Approvals { command } => approvals_command(command),
        Commands::Approve {
            request_id,
            scope,
            confirm_critical,
            agent_mediated,
            json,
        } => approve(request_id, scope, confirm_critical, agent_mediated, json),
        Commands::Deny {
            request_id,
            agent_mediated,
            json,
        } => deny(request_id, agent_mediated, json),
        Commands::Run {
            profile,
            project,
            app,
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            action,
            env_names,
            json,
            no_prompt,
            wait_for_approval,
            approval_timeout,
            command,
        } => run_with_context(
            RunOptions {
                profile,
                project,
                agent: agent.clone(),
                branch: branch.clone(),
                action,
                env_names,
                command,
                json,
                no_prompt,
                wait_for_approval,
                approval_timeout,
            },
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
            app,
        ),
        Commands::Dev {
            project,
            app,
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            json,
            no_prompt,
        } => run_with_context(
            RunOptions {
                profile: Some("dev".to_string()),
                project,
                agent: agent.clone(),
                branch: branch.clone(),
                action: None,
                env_names: Vec::new(),
                command: Vec::new(),
                json,
                no_prompt,
                wait_for_approval: false,
                approval_timeout: "30m".to_string(),
            },
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
            app,
        ),
        Commands::Migrate {
            project,
            app,
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            json,
            no_prompt,
        } => run_with_context(
            RunOptions {
                profile: Some("migrate".to_string()),
                project,
                agent: agent.clone(),
                branch: branch.clone(),
                action: None,
                env_names: Vec::new(),
                command: Vec::new(),
                json,
                no_prompt,
                wait_for_approval: false,
                approval_timeout: "30m".to_string(),
            },
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
            app,
        ),
        Commands::Doctor { project, app, all } => doctor_for_target(project, app, all),
        Commands::Broker { command } => broker_command(command),
        Commands::Worktrees { command } => worktrees_command(command),
        Commands::Workspace { command } => workspace_command(command),
        Commands::Logs { command, kind } => logs(command, kind),
        Commands::Edit { project, app } => edit(project, app),
        Commands::Unlock {
            project,
            app,
            all,
            ttl,
            mode,
            verify_only,
        } => unlock_vault_for_target(project, app, all, &ttl, mode.as_deref(), verify_only),
        Commands::Modes { command } => modes_command(command),
        Commands::Lock {
            project,
            app,
            workspace,
            all,
        } => lock(project, app, workspace, all),
        Commands::Teardown {
            project,
            app,
            export_path,
            yes,
            restore_env,
        } => teardown(project, app, export_path, yes, restore_env),
        #[cfg(all(coverage, not(test)))]
        Commands::Coverage => coverage_exercise_cli_edges(),
        Commands::BrokerServe => broker::serve(),
        Commands::ShellInit { shell } => shell_init(shell.as_deref()),
        Commands::Rotate { project, app } => rotate_vault(project, app),
        Commands::Recovery {
            project,
            app,
            command,
        } => recovery_command(project, app, command),
        Commands::Dashboard { command } => dashboard_command(command),
        Commands::DashboardServer { port, token } => crate::webui::serve_standalone(port, token),
        Commands::CloudDevServer { port, token, db } => cloud::serve_standalone(port, token, db),
        Commands::Human {
            project,
            app,
            all,
            ttl,
        } => crate::human::activate_human_mode(project, app, all, &ttl),
        Commands::HumanGuardian {
            shell_pid,
            session_token,
            ttl_seconds,
            projects,
        } => crate::human::serve_guardian(shell_pid, &session_token, ttl_seconds, projects),
    }
}

#[derive(Serialize)]
struct VaultImportEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    source: &'a Path,
    vault: &'a Path,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvFileEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    env_file: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
}

#[derive(Serialize)]
struct RequestEvent<'a> {
    #[serde(rename = "correlationId")]
    correlation_id: uuid::Uuid,
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    expires_at: Option<&'a chrono::DateTime<chrono::Utc>>,
    access: &'a AccessRequest,
    policy: &'a policy::PolicyEvaluation,
    git: &'a git_context::GitContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestAuditSnapshot<'a> {
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    action: &'a Option<String>,
    command: &'a str,
    env: &'a [String],
    requested_env: &'a [String],
    matched_profile: &'a Option<String>,
    matched_preset: &'a Option<String>,
    matched_mode: &'a Option<String>,
    policy_findings: &'a [detection::Finding],
    git: &'a git_context::GitContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalEvent<'a> {
    correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    project: &'a str,
    approval_channel: ApprovalChannel,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_snapshot: Option<RequestAuditSnapshot<'a>>,
    decision: &'a ApprovalDecision,
    persisted_grant: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<&'a str>,
    critical_confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    human_proof: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionStartedEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    declared_action: &'a Option<String>,
    requested_command: &'a str,
    cwd: &'a Path,
    git: &'a git_context::GitContext,
    requested_env: &'a [String],
    injected_env: &'a [String],
    policy_findings: &'a [detection::Finding],
    approval_scope: ApprovalScope,
    approval_source: approvals::ApprovalSource,
    approval_channel: ApprovalChannel,
    grant_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_origin_request_id: Option<uuid::Uuid>,
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    correlation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<uuid::Uuid>,
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    declared_action: &'a Option<String>,
    requested_command: &'a str,
    cwd: &'a Path,
    git: &'a git_context::GitContext,
    requested_env: &'a [String],
    injected_env: &'a [String],
    policy_findings: &'a [detection::Finding],
    approval_scope: ApprovalScope,
    approval_source: approvals::ApprovalSource,
    approval_channel: ApprovalChannel,
    grant_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_origin_request_id: Option<uuid::Uuid>,
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
    outcome: &'a runner::RunCommandOutcome,
}

#[derive(Serialize)]
struct OutputRedactionEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    command: &'a str,
    count: usize,
    alerts: &'a [runner::OutputAlert],
}

#[derive(Serialize)]
struct VaultEditEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
}

#[derive(Serialize)]
struct VaultUnlockEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    status: &'a str,
    project: &'a str,
    vault: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultLockEvent {
    #[serde(rename = "type")]
    event_type: &'static str,
    revoked_session_grants: usize,
    cleared_unlock_sessions: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogsUnlockEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
    expires_at: String,
}

#[derive(Debug, Clone)]
struct SetupOptions {
    yes: bool,
    project: Option<String>,
    source: PathBuf,
    vault: PathBuf,
    commit_vault: bool,
    ignore_vault: bool,
    remove_plaintext: bool,
    keep_plaintext: bool,
    unlock_ttl: String,
    no_unlock: bool,
}

const SETUP_GUIDED_BODY: &str = "Ward will encrypt your local env, create a vault, and prepare this project for safe human and agent access.";
const WORKSPACE_SETUP_BODY: &str = "Ward detected a monorepo workspace. It will configure each app with its own encrypted vault and trust this workspace Git root for agent runs.";
const WORKSPACE_SETUP_PROMPT_HELP: &str =
    "Ward will create or refresh app-level .ward.json files, vaults, profiles, and workspace-root trust.";
const RECOVERY_EXPORT_PROMPT: &str = "Export a recovery backup now?";
const RECOVERY_EXPORT_HELP: &str =
    "Store this somewhere safe, such as a USB drive or secure cloud backup.";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceSetupResult {
    workspace: String,
    root: PathBuf,
    configured: Vec<WorkspaceSetupItem>,
    skipped: Vec<WorkspaceSetupItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceSetupItem {
    app: String,
    project: String,
    path: PathBuf,
    status: String,
    reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    source: &'a Path,
    vault: &'a Path,
    imported: bool,
    removed_plaintext: bool,
    locked_env: bool,
    committed_vault: bool,
    unlock_created: bool,
    unlock_expires_at: Option<String>,
}

struct RunOptions {
    profile: Option<String>,
    project: Option<String>,
    agent: Option<String>,
    branch: Option<String>,
    action: Option<String>,
    env_names: Vec<String>,
    command: Vec<String>,
    json: bool,
    no_prompt: bool,
    wait_for_approval: bool,
    approval_timeout: String,
}

#[derive(Debug, Clone, Default)]
struct AgentContextOptions {
    agent: Option<String>,
    agent_key_id: Option<String>,
    worktree: Option<PathBuf>,
    git_remote: Option<String>,
    commit: Option<String>,
    branch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunApprovalRequiredResponse<'a> {
    status: &'static str,
    unlock_required: bool,
    #[serde(flatten)]
    request: pending_requests::PendingRequestResponse<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunUnlockRequiredResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unlock_reason: Option<&'a str>,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    findings: &'a [detection::Finding],
    risk: String,
    unlock_command: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDeniedResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    findings: &'a [detection::Finding],
    risk: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunVaultKeyMissingResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    missing_env: Vec<String>,
    findings: &'a [detection::Finding],
    risk: String,
    message: &'static str,
    remediation: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvalidInvocationResponse {
    status: &'static str,
    reason: &'static str,
    message: &'static str,
    correct_example: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeRequiredResponse<'a> {
    status: &'static str,
    approval_required: bool,
    approval_type: &'static str,
    project: &'a str,
    worktree: &'a Path,
    git_remote: &'a str,
    branch: &'a str,
    commit: &'a str,
    reason: &'a str,
    approval_options: Vec<WorktreeApprovalOption>,
    approve_command: String,
    deny_command: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeApprovalOption {
    action: &'static str,
    label: &'static str,
    command: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeBoundResponse<'a> {
    status: &'static str,
    project: &'a str,
    worktree: &'a Path,
    match_kind: &'a str,
    continued: bool,
}

#[derive(Debug, Clone)]
struct ResolvedProfile {
    command: String,
    command_args: Vec<String>,
    env_names: Vec<String>,
    action: Option<String>,
    default_scope: ApprovalScope,
}

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
    let source_exists = options.source.exists();
    let configured_vault_path = if options.vault.is_absolute() {
        options.vault.clone()
    } else {
        cwd.join(&options.vault)
    };
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
    let source_is_locked = if source_exists {
        env_file::is_locked_env_file(&options.source)?
    } else {
        false
    };

    let env_keys = if source_exists && !source_is_locked {
        config::env_keys_from_dotenv_file(&options.source)?
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
                    options.source.display(),
                    vault_path.display()
                );
            }
            env_file::lock_env_file(&options.source, &vault_path)?;
            locked_env = true;
            term::ok_detail("locked marker", "refreshed");
        } else {
            let passphrase = vault::read_new_passphrase()?;
            term::blank();
            let sp = term::spinner("Encrypting local env");
            vault::import_env_file(&options.source, &vault_path, &passphrase)?;
            let plaintext = vault::decrypt_vault_file(&vault_path, &passphrase)?;
            verified_env_keys = Some(config::env_keys_from_dotenv_str(&plaintext)?);
            recovery_plaintext = Some(plaintext);
            setup_passphrase = Some(passphrase);
            imported = true;
            if !options.keep_plaintext && !remove_plaintext {
                env_file::lock_env_file(&options.source, &vault_path)?;
                locked_env = true;
            }
            term::done_detail(
                sp,
                "vault encrypted",
                &format!("{} -> {}", options.source.display(), vault_path.display()),
            );
        }
    } else if !vault_path.exists() {
        let passphrase = vault::read_new_passphrase()?;
        term::blank();
        let sp = term::spinner("Creating empty vault");
        let envelope = vault::encrypt_env("", &passphrase)?;
        vault::write_vault(&vault_path, &envelope)?;
        vault::decrypt_vault_file(&vault_path, &passphrase)?;
        env_file::lock_env_file(&options.source, &vault_path)?;
        verified_env_keys = Some(Vec::new());
        recovery_plaintext = Some(String::new());
        setup_passphrase = Some(passphrase);
        locked_env = true;
        term::done_detail(sp, "vault encrypted", "empty vault");
    } else {
        term::ok_detail("vault encrypted", &term::short_path(&vault_path));
    }
    if locked_env && !source_is_locked {
        term::ok_detail("locked marker", &options.source.display().to_string());
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
        fs::remove_file(&options.source)
            .context(format!("failed to remove {}", options.source.display()))?;
        removed_plaintext = true;
    }

    // Resolve passphrase at outer scope so we can reuse it for recovery creation.
    let setup_passphrase_final: Option<String> = if options.no_unlock {
        setup_passphrase
    } else {
        Some(match setup_passphrase {
            Some(p) => p,
            None => vault::read_existing_passphrase()?,
        })
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
                if error.to_string().contains("failed to decrypt vault") {
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
        source: &options.source,
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

    // Auto-create recovery key using the same PIN/passphrase — no extra prompt.
    if let Some(ref passphrase) = setup_passphrase_final {
        term::section("recovery");
        let sp = term::spinner("Creating recovery key");
        match recovery::create_recovery_files_with_material(
            &project_config.project,
            passphrase,
            passphrase,
            recovery_plaintext.as_deref(),
        ) {
            Ok(recovery_file) => {
                term::done_detail(
                    sp,
                    "recovery key created",
                    &term::short_path(&recovery_file),
                );
                project_config.recovery_created = true;
                let _ = config::write_project_config(&cwd, &project_config, true);

                // Offer to export a backup immediately.
                #[cfg(not(coverage))]
                {
                    term::blank();
                    let export = options.yes
                        || inquire::Confirm::new(RECOVERY_EXPORT_PROMPT)
                            .with_help_message(RECOVERY_EXPORT_HELP)
                            .with_default(true)
                            .prompt()
                            .unwrap_or(false);

                    if export {
                        let dest = dirs::desktop_dir()
                            .or_else(dirs::home_dir)
                            .unwrap_or_else(|| PathBuf::from("."));
                        match recovery::export_recovery_file(
                            &project_config.project,
                            passphrase,
                            &dest,
                        ) {
                            Ok(out_path) => {
                                project_config.backup_exported = true;
                                let _ = config::write_project_config(&cwd, &project_config, true);
                                term::ok_detail("backup saved", &term::short_path(&out_path));
                                #[cfg(not(test))]
                                let _ = std::process::Command::new("open")
                                    .arg("-R")
                                    .arg(&out_path)
                                    .spawn();
                            }
                            Err(e) => {
                                term::warn_detail("backup export failed", &e.to_string());
                                term::next("run: ward recovery export");
                            }
                        }
                    } else {
                        term::next("run: ward recovery export");
                    }
                }
            }
            Err(error) => {
                term::warn_step_detail(sp, "recovery key failed", &error.to_string());
                term::next("run: ward recovery create");
            }
        }
    }

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
        prompt_shell_reload(&rc);
    } else {
        term::ok_detail("shell integration", "ready");
    }
    Ok(())
}

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

fn import(source: PathBuf, explicit_vault: Option<PathBuf>) -> Result<()> {
    let cwd = env::current_dir()?;
    let mut config =
        config::read_project_config(&cwd).context("missing .ward.json; run ward init first")?;
    if env_file::is_locked_env_file(&source)? {
        anyhow::bail!(
            "{} is already an Ward locked marker; use ward env unlock to restore plaintext before importing",
            source.display()
        );
    }
    let passphrase = vault::read_new_passphrase()?;
    let vault_path = match explicit_vault {
        Some(vault) => {
            config.vault = vault.clone();
            config::write_project_config(&cwd, &config, true)?;
            if vault.is_absolute() {
                vault
            } else {
                cwd.join(vault)
            }
        }
        None => registry::resolve_project(Some(&config.project), &cwd)
            .ok()
            .map(|resolved| resolved.vault)
            .filter(|path| path.exists())
            .unwrap_or_else(|| {
                config::resolve_vault_path_with_passphrase(&cwd, &config, &passphrase)
            }),
    };

    let written = vault::import_env_file(&source, &vault_path, &passphrase)?;
    vault::decrypt_vault_file(&written, &passphrase)?;
    env_file::lock_env_file(&source, &written)?;
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
        source: &source,
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
    term::ok_detail("locked marker", &source.display().to_string());
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
                term::ok_detail(
                    &name,
                    &format!(
                        "{active} path={} vault={}",
                        term::short_path(&project.path),
                        term::short_path(&project.vault)
                    ),
                );
            }
        }
        ProjectsCommand::Show { project } => {
            let cwd = env::current_dir()?;
            let resolved = registry::resolve_project(project.as_deref(), &cwd)?;
            term::emit_header(&term::Header {
                command: Some("projects show"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            term::ok_detail("vault", &term::short_path(&resolved.vault));
        }
        ProjectsCommand::Register {
            project,
            path,
            vault,
        } => register(project, path, vault)?,
        ProjectsCommand::Use { project } => use_project(&project)?,
        ProjectsCommand::Remove { project } => {
            if registry::remove_project(&project)? {
                term::emit_header(&term::Header {
                    command: Some("projects remove"),
                    project: &project,
                    path: None,
                    mode: None,
                });
                term::ok("project removed");
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
                    members: Vec::new(),
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

fn setup_command(command: SetupCommand) -> Result<()> {
    match command {
        SetupCommand::Login {
            cloud_url,
            team,
            project,
            environment,
            json,
        } => {
            let cwd = env::current_dir()?;
            let auth = cloud::load_auth_session(&cloud_url)?;
            let pin = vault::read_existing_passphrase()?;
            let imported = cloud::import_from_cloud(cloud::SetupLoginOptions {
                db: cloud::default_db_path(),
                cloud_url,
                auth,
                pin,
                target_dir: cwd,
                team,
                project,
                environment,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&imported)?);
            } else {
                term::guided_header(
                    "setup login",
                    &imported.local_project,
                    &imported.path,
                    "Ward imported this cloud-managed project into a local encrypted vault.",
                );
                term::section("cloud");
                term::ok_detail(
                    "source",
                    &format!(
                        "{} / {} / {}",
                        imported.team, imported.project, imported.environment
                    ),
                );
                term::section("vault");
                term::ok_detail("encrypted vault", &term::short_path(&imported.vault));
                term::ok_detail("env names imported", &imported.env_names.join(", "));
                term::section("project");
                term::ok(".ward.json compiled from cloud policies");
                term::ok("project registered");
            }
        }
    }
    Ok(())
}

fn auth_command(command: AuthCommand) -> Result<()> {
    match command {
        AuthCommand::Login {
            cloud_url,
            email,
            name,
            device_name,
            json,
        } => {
            let email = match email {
                Some(email) => email,
                None => inquire::Text::new("Account email").prompt()?,
            };
            let pin =
                vault::read_new_pin("New local Ward cloud PIN", "Confirm local Ward cloud PIN")?;
            let session = cloud::login_account(cloud::AuthLoginOptions {
                cloud_url,
                email,
                name,
                device_name,
                pin,
            })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&cloud::CloudAuthSummary::from(session))?
                );
            } else {
                term::guided_header(
                    "auth login",
                    &session.account_email,
                    Path::new("."),
                    "Ward created a local cloud account session and encrypted this device key with your PIN.",
                );
                term::section("account");
                term::ok_detail("signed in", &session.account_email);
                term::section("device");
                term::ok_detail("registered", &session.device_id);
                term::next("run: ward setup login");
            }
        }
    }
    Ok(())
}

fn cloud_command(command: CloudCommand) -> Result<()> {
    match command {
        CloudCommand::Dev { command } => cloud_dev_command(command),
    }
}

fn cloud_dev_command(command: CloudDevCommand) -> Result<()> {
    match command {
        CloudDevCommand::Start {
            port,
            db,
            foreground,
            json,
        } => {
            cloud::start_dev_server(cloud::CloudDevStartOptions {
                port,
                db,
                foreground,
                json,
            })?;
        }
        CloudDevCommand::Stop { json } => {
            cloud::stop_dev_server(cloud::CloudDevStopOptions { json })?;
        }
        CloudDevCommand::Status { json } => {
            cloud::status(json)?;
        }
        CloudDevCommand::Publish {
            cloud_url,
            project,
            team,
            cloud_project,
            environment,
            env_names,
            profiles,
            agents,
            members,
            json,
        } => publish_cloud_environment(
            cloud_url,
            project,
            team,
            cloud_project,
            environment,
            env_names,
            profiles,
            agents,
            members,
            json,
        )?,
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_cloud_environment(
    cloud_url: String,
    project: Option<String>,
    team: String,
    cloud_project: Option<String>,
    environment: String,
    env_names: Vec<String>,
    profiles: Vec<String>,
    agents: Vec<String>,
    members: Vec<String>,
    json: bool,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let source = registry::resolve_project(project.as_deref(), &cwd)?;
    let auth = cloud::load_auth_session(&cloud_url)?;
    let owner_pin = vault::read_existing_passphrase()?;
    let source_passphrase = if source.vault.exists() {
        vault::read_existing_passphrase()?
    } else {
        anyhow::bail!("source vault is missing: {}", source.vault.display());
    };
    let member_inputs = parse_cloud_members(members)?;
    let published = cloud::publish_environment(cloud::PublishEnvironmentOptions {
        db: cloud::default_db_path(),
        cloud_url,
        owner: auth,
        owner_pin,
        source_project: source.name.clone(),
        source_path: source.path.clone(),
        source_vault: source.vault.clone(),
        source_passphrase,
        team_name: team,
        project_name: cloud_project.unwrap_or_else(|| source.name.clone()),
        environment_name: environment,
        env_names,
        profile_names: profiles,
        agent_names: agents,
        members: member_inputs,
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&published)?);
    } else {
        term::emit_header(&term::Header {
            command: Some("cloud dev publish"),
            project: &published.project.name,
            path: Some(&source.path),
            mode: None,
        });
        term::ok_detail(
            "published",
            &format!(
                "{} / {} / {}",
                published.team.name, published.project.name, published.environment.name
            ),
        );
        term::ok_detail("env", &published.environment.env_names.join(", "));
        term::ok_detail("wrapped devices", &published.wrapped_devices.to_string());
        if !published.rewrap_required_members.is_empty() {
            term::warn_detail(
                "rewrap required",
                &format!(
                    "after device login: {}",
                    published.rewrap_required_members.join(", ")
                ),
            );
        }
    }
    Ok(())
}

fn parse_cloud_members(values: Vec<String>) -> Result<Vec<cloud::CloudMemberInput>> {
    values
        .into_iter()
        .map(|value| {
            let mut parts = value.splitn(2, ':');
            let email = parts
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .context("member must be formatted as email:role")?
                .to_string();
            let role = match parts.next().map(str::trim).unwrap_or("developer") {
                "owner" => cloud::CloudRole::Owner,
                "admin" => cloud::CloudRole::Admin,
                "developer" => cloud::CloudRole::Developer,
                "viewer" => cloud::CloudRole::Viewer,
                other => anyhow::bail!("unsupported cloud member role: {other}"),
            };
            Ok(cloud::CloudMemberInput { email, role })
        })
        .collect()
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

fn setup_workspace(options: SetupOptions, apps: Vec<String>, all: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let discovery = workspace::discover(&cwd)?
        .context("no workspace manifest found; expected pnpm-workspace.yaml, package.json workspaces, or turbo.json")?;
    setup_workspace_with_discovery(options, apps, all, discovery)
}

fn setup_workspace_with_discovery(
    options: SetupOptions,
    apps: Vec<String>,
    all: bool,
    discovery: workspace::WorkspaceDiscovery,
) -> Result<()> {
    if options.commit_vault && options.ignore_vault {
        anyhow::bail!("choose either --commit-vault or --ignore-vault");
    }
    if options.remove_plaintext && options.keep_plaintext {
        anyhow::bail!("choose either --remove-plaintext or --keep-plaintext");
    }

    term::guided_context_header(
        "setup",
        "Workspace",
        &discovery.workspace_name,
        &discovery.root,
        WORKSPACE_SETUP_BODY,
    );
    print_workspace_setup_overview(&discovery);

    let project_prefix = options
        .project
        .as_deref()
        .unwrap_or(&discovery.workspace_name)
        .to_string();
    let selected = selected_workspace_apps(&discovery, &apps, all, options.yes)?;
    if selected.is_empty() {
        let refreshed = trust_workspace_root_for_configured_apps(&discovery, &project_prefix)?;
        if !refreshed.is_empty() {
            let result = WorkspaceSetupResult {
                workspace: discovery.workspace_name,
                root: discovery.root,
                configured: Vec::new(),
                skipped: refreshed,
            };
            print_workspace_setup_result(&result);
            return Ok(());
        }
        term::section("Next");
        term::info("No ready app env files were found.");
        term::next("add .env files to app folders, then run: ward setup --workspace --all");
        term::next("or choose one app: ward setup --workspace --app <name>");
        return Ok(());
    }

    let passphrase = vault::read_existing_passphrase()?;
    let mut configured = Vec::new();
    let mut skipped = Vec::new();

    for package in selected {
        let project_name = workspace_package_project_name(package, &project_prefix);
        if package.setup_status == workspace::WorkspaceSetupStatus::Configured {
            trust_workspace_root_for_project(&project_name, &discovery.root)?;
            workspace_target::register_workspace_metadata(&project_name, &discovery, package)?;
            skipped.push(WorkspaceSetupItem {
                app: package.slug.clone(),
                project: project_name,
                path: package.path.clone(),
                status: "configured".to_string(),
                reason: Some("app already has .ward.json".to_string()),
            });
            continue;
        }
        if !package.can_setup() {
            skipped.push(WorkspaceSetupItem {
                app: package.slug.clone(),
                project: project_name,
                path: package.path.clone(),
                status: workspace_setup_status_label(&package.setup_status).to_string(),
                reason: Some("app has no plaintext .env to import".to_string()),
            });
            continue;
        }

        match broker::setup_project_with_passphrase(&package.path, Some(&project_name), &passphrase)
        {
            Ok(status) => {
                trust_workspace_root_for_project(&status.project, &discovery.root)?;
                workspace_target::register_workspace_metadata(
                    &status.project,
                    &discovery,
                    package,
                )?;
                configured.push(WorkspaceSetupItem {
                    app: package.slug.clone(),
                    project: status.project,
                    path: status.path,
                    status: "configured".to_string(),
                    reason: None,
                });
            }
            Err(error) => {
                skipped.push(WorkspaceSetupItem {
                    app: package.slug.clone(),
                    project: project_name,
                    path: package.path.clone(),
                    status: "failed".to_string(),
                    reason: Some(error.to_string()),
                });
            }
        }
    }

    let result = WorkspaceSetupResult {
        workspace: discovery.workspace_name,
        root: discovery.root,
        configured,
        skipped,
    };
    print_workspace_setup_result(&result);
    Ok(())
}

fn print_workspace_setup_overview(discovery: &workspace::WorkspaceDiscovery) {
    let apps = discovery.app_candidates().collect::<Vec<_>>();
    let ready_apps = apps.iter().filter(|package| package.can_setup()).count();
    let configured_apps = apps
        .iter()
        .filter(|package| package.setup_status == workspace::WorkspaceSetupStatus::Configured)
        .count();
    let needs_env_apps = apps
        .iter()
        .filter(|package| package.setup_status == workspace::WorkspaceSetupStatus::NeedsEnv)
        .count();
    let library_count = discovery
        .packages
        .iter()
        .filter(|package| !package.app_candidate)
        .count();

    term::section("Workspace");
    if let Some(manager) = discovery.package_manager.as_deref() {
        term::ok(&format!("package manager {manager}"));
    }
    if discovery.turborepo {
        term::ok("turborepo detected");
    }
    term::ok(&format!("{} app project(s) detected", apps.len()));
    if ready_apps > 0 {
        term::ok(&format!("{ready_apps} app(s) ready to configure"));
    }
    if configured_apps > 0 {
        term::ok(&format!("{configured_apps} app(s) already configured"));
    }
    if needs_env_apps > 0 {
        term::warn(&format!(
            "{needs_env_apps} app(s) need a real .env before setup"
        ));
    }
    if library_count > 0 {
        term::info(&format!("{library_count} package(s) skipped by default"));
    }

    term::section("Apps");
    for package in &discovery.packages {
        print_workspace_package_line(package);
    }
}

fn print_workspace_package_line(package: &workspace::WorkspacePackage) {
    let path = term::short_path(&package.relative_path);
    if !package.app_candidate {
        term::info(&format!("{}  package skipped  {}", package.slug, path));
        return;
    }

    match package.setup_status {
        workspace::WorkspaceSetupStatus::Configured => term::ok(&format!(
            "{}  already configured  {}  {}",
            package.slug, package.project_name, path
        )),
        workspace::WorkspaceSetupStatus::NeedsEnv => term::warn(&format!(
            "{}  needs .env  {}  {}",
            package.slug, package.project_name, path
        )),
        workspace::WorkspaceSetupStatus::NotConfigured => {
            if package.env_status == workspace::WorkspaceEnvStatus::Present {
                term::ok(&format!(
                    "{}  .env ready  {}  {}",
                    package.slug, package.project_name, path
                ));
            } else {
                term::info(&format!(
                    "{}  no .env  {}  {}",
                    package.slug, package.project_name, path
                ));
            }
        }
    }
}

fn print_workspace_setup_result(result: &WorkspaceSetupResult) {
    term::section("Setup");
    if result.configured.is_empty() && result.skipped.is_empty() {
        term::info("No app projects changed.");
    }
    for item in &result.configured {
        term::ok(&format!("{} configured as {}", item.app, item.project));
        term::info(&format!("path {}", term::short_path(&item.path)));
    }
    for item in &result.skipped {
        match item.reason.as_deref() {
            Some("workspace Git root trusted") => {
                term::ok(&format!("{} refreshed as {}", item.app, item.project));
                term::info("workspace Git root trusted");
            }
            Some("app already has .ward.json") => {
                term::ok(&format!(
                    "{} already configured as {}",
                    item.app, item.project
                ));
                term::info("workspace Git root trusted");
            }
            Some(reason) => {
                term::warn(&format!("{} skipped — {reason}", item.app));
            }
            None => {
                term::info(&format!("{} skipped", item.app));
            }
        }
    }

    term::section("Next");
    if !result.configured.is_empty() {
        term::next("open the dashboard: ward dashboard start");
        term::next("activate an app terminal: cd apps/<app> && ward human");
        term::next("or from the workspace root: ward human --app <app>");
    } else {
        term::next("open the dashboard: ward dashboard start");
    }
}

fn trust_workspace_root_for_configured_apps(
    discovery: &workspace::WorkspaceDiscovery,
    project_prefix: &str,
) -> Result<Vec<WorkspaceSetupItem>> {
    let mut refreshed = Vec::new();
    for package in discovery
        .app_candidates()
        .filter(|package| package.setup_status == workspace::WorkspaceSetupStatus::Configured)
    {
        let project_name = workspace_package_project_name(package, project_prefix);
        trust_workspace_root_for_project(&project_name, &discovery.root)?;
        workspace_target::register_workspace_metadata(&project_name, discovery, package)?;
        refreshed.push(WorkspaceSetupItem {
            app: package.slug.clone(),
            project: project_name,
            path: package.path.clone(),
            status: "configured".to_string(),
            reason: Some("workspace Git root trusted".to_string()),
        });
    }
    Ok(refreshed)
}

fn workspace_package_project_name(
    package: &workspace::WorkspacePackage,
    project_prefix: &str,
) -> String {
    config::read_project_config(&package.path)
        .map(|config| config.project)
        .unwrap_or_else(|_| format!("{project_prefix}:{}", package.slug))
}

fn trust_workspace_root_for_project(project: &str, workspace_root: &Path) -> Result<()> {
    let git = git_context::collect_git_context(workspace_root);
    let git_remote = git.remote.as_deref().unwrap_or_default();
    worktrees::trust_worktree(
        project,
        workspace_root,
        git_remote,
        git.common_dir,
        "workspace-root-setup",
    )?;
    Ok(())
}

fn should_auto_route_workspace_setup(options: &SetupOptions) -> bool {
    options.source == PathBuf::from(".env")
        && options.vault == PathBuf::from(config::DEFAULT_VAULT_FILE)
        && !options.commit_vault
        && !options.ignore_vault
        && !options.remove_plaintext
        && !options.keep_plaintext
}

fn selected_workspace_apps<'a>(
    discovery: &'a workspace::WorkspaceDiscovery,
    apps: &[String],
    all: bool,
    yes: bool,
) -> Result<Vec<&'a workspace::WorkspacePackage>> {
    if all || !apps.is_empty() {
        return discovery.selected_apps(apps, all);
    }

    let setup_capable = discovery
        .app_candidates()
        .filter(|package| package.can_setup())
        .collect::<Vec<_>>();
    if setup_capable.is_empty() {
        return Ok(Vec::new());
    }
    if yes {
        return Ok(setup_capable);
    }

    #[cfg(coverage)]
    {
        return Ok(setup_capable);
    }
    #[cfg(not(coverage))]
    {
        let prompt = format!(
            "Configure {} ready workspace app(s) now?",
            setup_capable.len()
        );
        let configure = inquire::Confirm::new(&prompt)
            .with_help_message(WORKSPACE_SETUP_PROMPT_HELP)
            .with_default(true)
            .prompt()
            .unwrap_or(false);
        if configure {
            Ok(setup_capable)
        } else {
            Ok(Vec::new())
        }
    }
}

fn workspace_setup_status_label(status: &workspace::WorkspaceSetupStatus) -> &'static str {
    match status {
        workspace::WorkspaceSetupStatus::Configured => "configured",
        workspace::WorkspaceSetupStatus::NeedsEnv => "needsEnv",
        workspace::WorkspaceSetupStatus::NotConfigured => "notConfigured",
    }
}

fn broker_command(command: BrokerCommand) -> Result<()> {
    match command {
        BrokerCommand::Status => {
            let status = broker::status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        BrokerCommand::Stop => {
            broker::stop()?;
            term::emit_header(&term::Header {
                command: Some("broker stop"),
                project: "runtime",
                path: None,
                mode: None,
            });
            term::ok("broker stopped");
        }
        BrokerCommand::SocketPath => println!("{}", broker::socket_path().display()),
    }
    Ok(())
}

fn dashboard_command(command: Option<DashboardCommand>) -> Result<()> {
    match command.unwrap_or(DashboardCommand::Tui) {
        DashboardCommand::Start {
            port,
            no_open,
            foreground,
            json,
        } => crate::webui::start_dashboard(crate::webui::DashboardStartOptions {
            port,
            open_browser: !no_open,
            foreground,
            json,
        }),
        DashboardCommand::Stop {
            all,
            pid,
            port,
            json,
        } => crate::webui::stop_dashboards(crate::webui::DashboardStopOptions {
            all,
            pid,
            port,
            json,
        }),
        DashboardCommand::Status { json } => crate::webui::print_dashboard_status(json),
        DashboardCommand::Tui => crate::dashboard::run_dashboard(),
    }
}

fn worktrees_command(command: WorktreesCommand) -> Result<()> {
    match command {
        WorktreesCommand::List { project } => {
            let state = worktrees::list_project(&project)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        WorktreesCommand::AllowRoot { project, path } => {
            let root = worktrees::allow_root(&project, &path)?;
            term::emit_header(&term::Header {
                command: Some("worktrees allow-root"),
                project: &project,
                path: None,
                mode: None,
            });
            term::ok_detail("allowed root", &term::short_path(&root));
        }
        WorktreesCommand::RemoveRoot { project, path } => {
            if worktrees::remove_root(&project, &path)? {
                term::emit_header(&term::Header {
                    command: Some("worktrees remove-root"),
                    project: &project,
                    path: None,
                    mode: None,
                });
                term::ok_detail("removed root", &term::short_path(&path));
            } else {
                term::warn_detail("worktree root not found", &term::short_path(&path));
            }
        }
        WorktreesCommand::Approve { request_id, json } => {
            require_human_terminal_confirmation("APPROVE-WORKTREE", request_id)?;
            if let Some(worktree) = worktrees::approve_pending(request_id)? {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "approved",
                            "requestId": request_id,
                            "worktree": worktree.path,
                        }))?
                    );
                    return Ok(());
                }
                term::emit_header(&term::Header {
                    command: Some("worktrees approve"),
                    project: "worktree binding",
                    path: Some(&worktree.path),
                    mode: None,
                });
                term::ok_detail("request approved", &request_id.to_string());
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "not_found",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                term::warn_detail("worktree request not found", &request_id.to_string());
            }
        }
        WorktreesCommand::Deny { request_id, json } => {
            require_human_terminal_confirmation("DENY-WORKTREE", request_id)?;
            if worktrees::deny_pending(request_id)? {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "denied",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                term::emit_header(&term::Header {
                    command: Some("worktrees deny"),
                    project: "worktree binding",
                    path: None,
                    mode: None,
                });
                term::ok_detail("request denied", &request_id.to_string());
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "not_found",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                term::warn_detail("worktree request not found", &request_id.to_string());
            }
        }
    }
    Ok(())
}

fn env_command(command: EnvCommand) -> Result<()> {
    match command {
        EnvCommand::List {
            project,
            app,
            all,
            json,
            no_prompt,
        } => {
            if no_prompt {
                if !json {
                    anyhow::bail!("ward env list --no-prompt requires --json");
                }
                let targets = resolve_env_targets(project, app, all)?;
                let mut projects = Vec::new();
                for target in targets {
                    let names =
                        broker::list_vault_keys_from_active_session(&target.name, &target.vault)
                            .with_context(|| {
                                format!(
                                    "env list requires an active broker session for {}",
                                    target.name
                                )
                            })?;
                    projects.push(serde_json::json!({
                        "project": target.name,
                        "envNames": names,
                    }));
                }
                if all {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "projects": projects,
                        }))?
                    );
                } else {
                    let project = projects
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| serde_json::json!({ "project": "", "envNames": [] }));
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "project": project.get("project").cloned().unwrap_or_default(),
                            "envNames": project.get("envNames").cloned().unwrap_or_default(),
                        }))?
                    );
                }
                return Ok(());
            }
            let passphrase = vault::read_existing_passphrase()?;
            let targets = resolve_env_targets_with_passphrase(project, app, all, &passphrase)?;
            let mut json_projects = Vec::new();
            for target in targets {
                let resolved = target.resolved_project();
                let names = with_passphrase_vault_access(&resolved, &passphrase, || {
                    env_file::list_env_names(&resolved.vault, &passphrase)
                })?;
                if json {
                    json_projects.push(serde_json::json!({
                        "project": resolved.name,
                        "envNames": names,
                    }));
                } else {
                    for name in names {
                        if all {
                            println!("{}\t{name}", resolved.name);
                        } else {
                            println!("{name}");
                        }
                    }
                }
            }
            if json {
                if all {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "projects": json_projects,
                        }))?
                    );
                } else {
                    let project = json_projects
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| serde_json::json!({ "project": "", "envNames": [] }));
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "project": project.get("project").cloned().unwrap_or_default(),
                            "envNames": project.get("envNames").cloned().unwrap_or_default(),
                        }))?
                    );
                }
            }
        }
        EnvCommand::RequestSet {
            project,
            app,
            key,
            wait_for_approval,
            approval_timeout,
            json,
            no_prompt,
        } => {
            if no_prompt && !json {
                anyhow::bail!("ward env request-set --no-prompt requires --json");
            }
            let key = key.trim().to_string();
            validate_env_key(&key)?;
            let target = resolve_env_project(project, app)?;
            let fix_command = format!(
                "ward env set --project {} {}=<value> && ward env lock --project {}",
                shell_quote(&target.name),
                key,
                shell_quote(&target.name)
            );
            let notification = notifications::create_block_notification(
                notifications::NotificationKind::VaultKeyMissing,
                &target.name,
                None,
                Some("ward env request-set"),
                std::slice::from_ref(&key),
                &[],
                "warning",
                format!("Env key {key} is missing from the vault. A human must add its value."),
                Some(&fix_command),
            )?;
            if wait_for_approval {
                wait_for_env_key(&target, &key, &approval_timeout)?;
                notifications::remove_block_notification(notification.id)?;
                print_env_request_set_response(
                    json,
                    "env_available",
                    &target.name,
                    &key,
                    notification.id,
                    Some(&fix_command),
                )?;
            } else {
                print_env_request_set_response(
                    json,
                    "notification_created",
                    &target.name,
                    &key,
                    notification.id,
                    Some(&fix_command),
                )?;
            }
        }
        EnvCommand::Set {
            project,
            app,
            assignment,
        } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            let key = with_passphrase_vault_access(&resolved, &passphrase, || {
                let key = env_file::set_env_value(&resolved.vault, &passphrase, &assignment)?;
                warn_store_refresh_failure(refresh_project_store_with_passphrase(
                    &resolved,
                    &passphrase,
                ));
                Ok(key)
            })?;
            env_file::refresh_locked_env(&resolved.path, &resolved.vault)?;
            log_env_file_event("env.set", &resolved, None, Some(&key))?;
            term::emit_header(&term::Header {
                command: Some("env set"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            term::ok_detail("encrypted env set", &key);
        }
        EnvCommand::Unset { project, app, key } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            let removed = with_passphrase_vault_access(&resolved, &passphrase, || {
                let removed = env_file::unset_env_value(&resolved.vault, &passphrase, &key)?;
                warn_store_refresh_failure(refresh_project_store_with_passphrase(
                    &resolved,
                    &passphrase,
                ));
                Ok(removed)
            })?;
            env_file::refresh_locked_env(&resolved.path, &resolved.vault)?;
            log_env_file_event("env.unset", &resolved, None, Some(&key))?;
            if removed {
                term::emit_header(&term::Header {
                    command: Some("env unset"),
                    project: &resolved.name,
                    path: Some(&resolved.path),
                    mode: None,
                });
                term::ok_detail("encrypted env removed", &key);
            } else {
                term::warn_detail("encrypted env not found", &key);
            }
        }
        EnvCommand::Unlock {
            project,
            app,
            all,
            output,
            force,
        } => {
            if all && !force {
                anyhow::bail!("ward env unlock --all requires --force");
            }
            let passphrase = vault::read_existing_passphrase()?;
            let targets = resolve_env_targets_with_passphrase(project, app, all, &passphrase)?;
            for target in targets {
                let resolved = target.resolved_project();
                let output = project_relative_path(&resolved.path, output.clone());
                with_passphrase_vault_access(&resolved, &passphrase, || {
                    env_file::unlock_env_file(&output, &resolved.vault, &passphrase, force)
                })?;
                log_env_file_event("env.unlock", &resolved, Some(&output), None)?;
                term::emit_header(&term::Header {
                    command: Some("env unlock"),
                    project: &resolved.name,
                    path: Some(&resolved.path),
                    mode: None,
                });
                term::warn_detail("plaintext env written", &term::short_path(&output));
            }
            term::next("run: ward env lock");
        }
        EnvCommand::Lock {
            project,
            app,
            source,
        } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            let source = project_relative_path(&resolved.path, source);
            with_passphrase_vault_access(&resolved, &passphrase, || {
                env_file::lock_plaintext_source(&source, &resolved.vault, &passphrase)?;
                warn_store_refresh_failure(refresh_project_store_with_passphrase(
                    &resolved,
                    &passphrase,
                ));
                Ok(())
            })?;
            log_env_file_event("env.lock", &resolved, Some(&source), None)?;
            term::emit_header(&term::Header {
                command: Some("env lock"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            term::ok_detail("vault re-encrypted", &term::short_path(&resolved.vault));
            term::ok_detail("locked marker", &term::short_path(&source));
        }
        EnvCommand::Export {
            project,
            app,
            output,
            force,
            unsafe_stdout,
        } => {
            let passphrase = vault::read_existing_passphrase()?;
            let resolved = resolve_env_project_with_passphrase(project, app, &passphrase)?;
            if unsafe_stdout {
                let plaintext = with_passphrase_vault_access(&resolved, &passphrase, || {
                    let plaintext = vault::decrypt_vault_file(&resolved.vault, &passphrase)?;
                    vault::validate_dotenv(&plaintext)?;
                    Ok(plaintext)
                })?;
                print!("{plaintext}");
                log_env_file_event("env.export.stdout", &resolved, None, None)?;
            } else {
                let output_path = match output {
                    Some(path) => path,
                    None => ".env.export".into(),
                };
                let output = project_relative_path(&resolved.path, output_path);
                with_passphrase_vault_access(&resolved, &passphrase, || {
                    env_file::export_env_file(&output, &resolved.vault, &passphrase, force)
                })?;
                log_env_file_event("env.export", &resolved, Some(&output), None)?;
                term::emit_header(&term::Header {
                    command: Some("env export"),
                    project: &resolved.name,
                    path: Some(&resolved.path),
                    mode: None,
                });
                term::warn_detail("plaintext env exported", &term::short_path(&output));
            }
        }
    }
    Ok(())
}

fn resolve_env_project_with_passphrase(
    project: Option<String>,
    app: Option<String>,
    passphrase: &str,
) -> Result<registry::ResolvedProject> {
    let cwd = env::current_dir()?;
    let target = workspace_target::resolve_one_with_passphrase(
        &workspace_target::TargetSelector::one(project, app),
        &cwd,
        passphrase,
    )?;
    let resolved = target.resolved_project();
    if resolved.vault.exists() {
        registry::update_project_vault(
            &resolved.name,
            resolved.path.clone(),
            resolved.vault.clone(),
        )?;
    }
    Ok(resolved)
}

fn resolve_env_project(
    project: Option<String>,
    app: Option<String>,
) -> Result<registry::ResolvedProject> {
    let cwd = env::current_dir()?;
    let target =
        workspace_target::resolve_one(&workspace_target::TargetSelector::one(project, app), &cwd)?;
    Ok(target.resolved_project())
}

fn resolve_env_targets(
    project: Option<String>,
    app: Option<String>,
    all: bool,
) -> Result<Vec<workspace_target::WorkspaceTarget>> {
    let cwd = env::current_dir()?;
    workspace_target::resolve_many(
        &workspace_target::TargetSelector { project, app, all },
        &cwd,
    )
}

fn resolve_env_targets_with_passphrase(
    project: Option<String>,
    app: Option<String>,
    all: bool,
    passphrase: &str,
) -> Result<Vec<workspace_target::WorkspaceTarget>> {
    let cwd = env::current_dir()?;
    let selector = workspace_target::TargetSelector { project, app, all };
    let targets = workspace_target::resolve_many_with_passphrase(&selector, &cwd, passphrase)?;
    for target in &targets {
        if target.vault.exists() {
            registry::update_project_vault(
                &target.name,
                target.path.clone(),
                target.vault.clone(),
            )?;
        }
    }
    Ok(targets)
}

fn validate_env_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !key
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        anyhow::bail!("invalid env name: {key}");
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.' | '/'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn wait_for_env_key(target: &registry::ResolvedProject, key: &str, timeout: &str) -> Result<()> {
    let timeout = unlock::parse_ttl(timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    loop {
        if let Ok(names) = broker::list_vault_keys_from_active_session(&target.name, &target.vault)
        {
            if names.iter().any(|name| name == key) {
                return Ok(());
            }
        }
        if chrono::Utc::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for env key {key} to be added to {}",
                target.name
            );
        }
        thread::sleep(StdDuration::from_millis(500));
    }
}

fn print_env_request_set_response(
    json_output: bool,
    status: &str,
    project: &str,
    key: &str,
    notification_id: uuid::Uuid,
    fix_command: Option<&str>,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "project": project,
                "envName": key,
                "notificationId": notification_id,
                "fixCommand": fix_command,
            }))?
        );
    } else {
        term::emit_header(&term::Header {
            command: Some("env request-set"),
            project,
            path: None,
            mode: None,
        });
        term::ok_detail(status, key);
        if let Some(command) = fix_command {
            term::next(command);
        }
    }
    Ok(())
}

fn project_relative_path(project_path: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        project_path.join(path)
    }
}

fn log_env_file_event(
    event_type: &'static str,
    resolved: &registry::ResolvedProject,
    env_file: Option<&Path>,
    key: Option<&str>,
) -> Result<()> {
    let event = EnvFileEvent {
        event_type,
        project: &resolved.name,
        vault: &resolved.vault,
        env_file,
        key,
    };
    audit_logs::append_event(LogKind::Sessions, event)
}

fn with_passphrase_vault_access<T>(
    resolved: &registry::ResolvedProject,
    passphrase: &str,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let active_expires_at = broker::active_session_expiry(&resolved.name, &resolved.vault)?;
    let active_ttl = active_expires_at
        .and_then(|expires_at| remaining_session_ttl(expires_at, chrono::Utc::now()));
    if active_ttl.is_some() {
        if let Some(session_fingerprint) =
            broker::active_session_fingerprint(&resolved.name, &resolved.vault)?
        {
            let file_fingerprint = vault_file_fingerprint(&resolved.vault)?;
            if session_fingerprint != file_fingerprint {
                anyhow::bail!(
                    "active broker session is stale for {}; run ward unlock again before modifying the vault",
                    resolved.name
                );
            }
        }
    }

    let result = operation();
    if let Some(ttl) = active_ttl {
        let refresh_result =
            broker::unlock_project(&resolved.name, &resolved.vault, passphrase, ttl);
        match (&result, refresh_result) {
            (Ok(_), Err(error)) => {
                return Err(error).context(
                    "vault operation succeeded, but Ward could not refresh the active broker session",
                );
            }
            (Err(_), Err(error)) => {
                term::warn_detail("broker session refresh failed", &error.to_string());
            }
            _ => {}
        }
    }
    result
}

fn vault_file_fingerprint(vault: &Path) -> Result<String> {
    let bytes = fs::read(vault).with_context(|| format!("failed to read {}", vault.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn refresh_project_store_with_passphrase(
    resolved: &registry::ResolvedProject,
    passphrase: &str,
) -> Result<project_store::ProjectStoreSummary> {
    let config = config::read_project_config(&resolved.path)?;
    project_store::refresh_from_vault(
        &resolved.name,
        &resolved.path,
        &resolved.vault,
        &config,
        passphrase,
    )
}

fn warn_store_refresh_failure(result: Result<project_store::ProjectStoreSummary>) {
    if let Err(error) = result {
        term::warn_detail("project-store refresh failed", &error.to_string());
    }
}

fn remaining_session_ttl(
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::Duration> {
    let ttl = expires_at.signed_duration_since(now);
    (ttl.num_seconds() > 0).then_some(ttl)
}

fn verified_no_prompt_context(
    cwd: &Path,
    resolved: &registry::ResolvedProject,
    context_options: &AgentContextOptions,
) -> Result<Option<context::VerifiedContext>> {
    let Some(agent_name) = context_options
        .agent
        .as_deref()
        .filter(|agent| agent_identity_is_present(Some(*agent)))
    else {
        let problem = context::ContextProblem::ContextRequired {
            missing: vec!["agent"],
        };
        println!("{}", context::context_problem_json(&problem)?);
        return Ok(None);
    };
    let agent = agents::ensure_agent(&resolved.name, agent_name)?;
    if let Some(claimed_key) = context_options.agent_key_id.as_deref() {
        if claimed_key != agent.agent_key_id {
            let problem = context::ContextProblem::ContextMismatch {
                field: "agentKeyId",
                claimed: claimed_key.to_string(),
                actual: agent.agent_key_id,
            };
            println!("{}", context::context_problem_json(&problem)?);
            return Ok(None);
        }
    }
    let claimed = context::ClaimedContext {
        agent: context_options.agent.clone(),
        agent_key_id: Some(agent.agent_key_id.clone()),
        worktree: context_options.worktree.clone(),
        branch: context_options.branch.clone(),
        git_remote: context_options.git_remote.clone(),
        commit: context_options.commit.clone(),
    };
    match context::verify_no_prompt_context(&claimed, cwd, resolved, agent.agent_key_id) {
        Ok(verified) => Ok(Some(verified)),
        Err(problem) => {
            println!("{}", context::context_problem_json(&problem)?);
            Ok(None)
        }
    }
}

fn agent_identity_is_present(agent: Option<&str>) -> bool {
    agent.is_some_and(|value| !value.trim().is_empty())
}

fn require_agent_identity_for_non_human(agent: Option<&str>) -> Result<()> {
    if agent_identity_is_present(agent) {
        return Ok(());
    }
    anyhow::bail!("--agent is required outside human mode; pass --agent <name> or run ward human")
}

fn enforce_worktree_for_no_prompt(
    resolved: &registry::ResolvedProject,
    verified: &context::VerifiedContext,
    wait_for_approval: bool,
    approval_timeout: &str,
) -> Result<bool> {
    let registry = registry::load_registry()?;
    let Some(registered) = registry.projects.get(&resolved.name) else {
        return Ok(true);
    };
    match worktrees::evaluate_worktree(registered, &resolved.name, verified)? {
        worktrees::WorktreeDecision::Trusted { .. } => Ok(true),
        worktrees::WorktreeDecision::AutoBound { match_kind } => {
            let response = WorktreeBoundResponse {
                status: "worktree_bound",
                project: &resolved.name,
                worktree: &verified.worktree,
                match_kind: &match_kind,
                continued: true,
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(true)
        }
        worktrees::WorktreeDecision::ApprovalRequired { request } => {
            if wait_for_approval {
                return wait_for_worktree_approval(resolved, verified, request, approval_timeout);
            }
            let approve_command = format!("ward worktrees approve {}", request.id);
            let deny_command = format!("ward worktrees deny {}", request.id);
            let response = WorktreeRequiredResponse {
                status: "worktree_approval_required",
                approval_required: true,
                approval_type: "worktreeBinding",
                project: &resolved.name,
                worktree: &request.path,
                git_remote: &request.git_remote,
                branch: &request.branch,
                commit: &request.commit,
                reason: &request.reason,
                approval_options: vec![
                    WorktreeApprovalOption {
                        action: "approve",
                        label: "Approve this worktree",
                        command: approve_command.clone(),
                    },
                    WorktreeApprovalOption {
                        action: "deny",
                        label: "Deny this worktree",
                        command: deny_command.clone(),
                    },
                ],
                approve_command,
                deny_command,
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(false)
        }
        worktrees::WorktreeDecision::Denied { reason } => {
            let response = serde_json::json!({
                "status": "worktree_denied",
                "project": resolved.name,
                "worktree": verified.worktree,
                "reason": reason,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(false)
        }
    }
}

fn wait_for_worktree_approval(
    resolved: &registry::ResolvedProject,
    verified: &context::VerifiedContext,
    request: worktrees::PendingWorktree,
    approval_timeout: &str,
) -> Result<bool> {
    let timeout = unlock::parse_ttl(approval_timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    term::emit_block(&term::MessageBlock {
        level: term::StatusLevel::Info,
        title: "waiting for worktree approval",
        body: Some("open the dashboard notification center or approve from a human terminal"),
        command: Some(&format!("ward worktrees approve {}", request.id)),
    });
    loop {
        if worktrees::is_known_worktree(&resolved.name, &request.path)? {
            return Ok(true);
        }
        if worktrees::load_pending_worktree(request.id)?.is_none() {
            let response = serde_json::json!({
                "status": "worktree_denied",
                "project": resolved.name,
                "worktree": verified.worktree,
                "requestId": request.id,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(false);
        }
        if chrono::Utc::now() >= deadline {
            let response = serde_json::json!({
                "status": "approval_timeout",
                "approvalType": "worktreeBinding",
                "project": resolved.name,
                "worktree": verified.worktree,
                "requestId": request.id,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(false);
        }
        thread::sleep(StdDuration::from_millis(500));
    }
}

#[cfg(any(test, coverage))]
fn request(
    profile: Option<String>,
    context_options: AgentContextOptions,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
    json: bool,
    no_prompt: bool,
) -> Result<()> {
    request_for_target(
        None,
        None,
        profile,
        context_options,
        action,
        command,
        env_names,
        json,
        no_prompt,
    )
}

fn request_for_target(
    project: Option<String>,
    app: Option<String>,
    profile: Option<String>,
    context_options: AgentContextOptions,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
    json: bool,
    no_prompt: bool,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let target =
        workspace_target::resolve_one(&workspace_target::TargetSelector::one(project, app), &cwd)?;
    let resolved = target.resolved_project();
    let config = config::read_project_config(&resolved.path)?;
    let git = git_context::collect_git_context(&cwd);
    let mut context_options = context_options;
    let human_terminal = crate::human::is_human_terminal();
    if human_terminal && !agent_identity_is_present(context_options.agent.as_deref()) {
        context_options.agent = Some("human".to_string());
    }
    let branch = context_options.branch.clone().or(git.branch.clone());
    let resolved_profile =
        resolve_profile(&config, profile.as_deref(), action, command, env_names)?;
    if !human_terminal && !no_prompt {
        require_agent_identity_for_non_human(context_options.agent.as_deref())?;
    }
    let access = AccessRequest {
        project: resolved.name.clone(),
        agent: context_options.agent.clone(),
        branch,
        action: resolved_profile.action,
        command: resolved_profile.command,
        env: resolved_profile.env_names,
    };
    let evaluation = evaluate_access(&config, &access);

    if no_prompt {
        if !json {
            anyhow::bail!("--no-prompt requires --json");
        }
        let Some(verified_context) = verified_no_prompt_context(&cwd, &resolved, &context_options)?
        else {
            return Ok(());
        };
        if !enforce_worktree_for_no_prompt(&resolved, &verified_context, false, "30m")? {
            return Ok(());
        }
        let pending =
            create_run_pending_request(&access, &evaluation, &git, Some(verified_context))?;
        let request_event = RequestEvent {
            correlation_id: pending.id,
            request_id: Some(pending.id),
            expires_at: Some(&pending.expires_at),
            access: &pending.access,
            policy: &pending.policy,
            git: &pending.git,
            verified_context: pending.verified_context.as_ref(),
        };
        audit_logs::append_event(LogKind::Requests, request_event)?;
        let response = serde_json::to_string_pretty(&pending_requests::response_for(&pending))?;
        println!("{response}");
        return Ok(());
    }

    let correlation_id = uuid::Uuid::new_v4();
    let decision = decide_access(&access, &evaluation, true)?;
    let critical_confirmation = critical_confirmation_for_decision(&decision, &evaluation);
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(
        critical_confirmation,
    ));
    let persisted_grant =
        grants::persist_grant(&access, &decision, &resolved.vault, receipt_context)?;
    let receipt = persisted_grant
        .as_ref()
        .and_then(|grant| grant.receipt.as_ref());

    let request_event = RequestEvent {
        correlation_id,
        request_id: None,
        expires_at: None,
        access: &access,
        policy: &evaluation,
        git: &git,
        verified_context: None,
    };
    let request_snapshot = request_audit_snapshot(&access, &evaluation, &git, None);
    let approval_event = ApprovalEvent {
        correlation_id,
        request_id: None,
        project: &access.project,
        approval_channel: approval_channel_for_source(decision.source),
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: persisted_grant.as_ref().map(|grant| grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Requests, request_event)?;
    if should_log_approval_event(&decision) {
        audit_logs::append_event(LogKind::Approvals, &approval_event)?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&approval_event)?);
    } else if decision.approved {
        term::emit_header(&term::Header {
            command: Some("request"),
            project: &access.project,
            path: Some(&resolved.path),
            mode: None,
        });
        term::ok_detail("approved env", &decision.approved_env.join(", "));
        term::ok_detail("scope", &format!("{:?}", decision.scope));
    } else {
        term::emit_header(&term::Header {
            command: Some("request"),
            project: &access.project,
            path: Some(&resolved.path),
            mode: None,
        });
        term::warn("request denied");
    }

    Ok(())
}

#[cfg(any(test, coverage))]
fn allow(
    profile: Option<String>,
    scope: Option<ApprovalScope>,
    agent: Option<String>,
    branch: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
) -> Result<()> {
    allow_for_target(
        None, None, profile, scope, agent, branch, command, env_names,
    )
}

fn allow_for_target(
    project: Option<String>,
    app: Option<String>,
    profile: Option<String>,
    scope: Option<ApprovalScope>,
    agent: Option<String>,
    branch: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let target =
        workspace_target::resolve_one(&workspace_target::TargetSelector::one(project, app), &cwd)?;
    let resolved = target.resolved_project();
    let config = config::read_project_config(&resolved.path)?;
    let resolved_profile = resolve_profile(
        &config,
        profile.as_deref(),
        Some("Manual allow grant".to_string()),
        command,
        env_names,
    )?;
    let scope = match scope {
        Some(scope) => scope,
        None if profile.is_some() => resolved_profile.default_scope,
        None => anyhow::bail!("--scope is required unless --profile is used"),
    };
    if matches!(scope, ApprovalScope::Once | ApprovalScope::Deny) {
        anyhow::bail!("ward allow supports session, branch, and always scopes");
    }
    require_manual_allow_confirmation(scope)?;
    require_agent_identity_for_non_human(agent.as_deref())?;

    let git = git_context::collect_git_context(&cwd);
    let branch = branch.or(git.branch.clone());
    let correlation_id = uuid::Uuid::new_v4();
    let access = AccessRequest {
        project: resolved.name,
        agent,
        branch,
        action: resolved_profile.action,
        command: resolved_profile.command,
        env: resolved_profile.env_names,
    };
    let evaluation = evaluate_access(&config, &access);
    if detection::has_critical_findings(&evaluation.findings) {
        anyhow::bail!(
            "critical exploit findings cannot be stored as durable allow grants; use ward request and approve once with --confirm-critical"
        );
    }
    approvals::validate_scope_for_findings(scope, &evaluation.findings)?;
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(false));
    let source = approvals::ApprovalSource::ManualAllow;
    let grant =
        grants::persist_manual_grant(&access, scope, source, &resolved.vault, receipt_context)?;
    let receipt = grant.receipt.as_ref();
    let mut decision = grants::approval_from_grant(&access, &grant);
    decision.source = approvals::ApprovalSource::ManualAllow;
    let request_snapshot = request_audit_snapshot(&access, &evaluation, &git, None);
    let approval_event = ApprovalEvent {
        correlation_id,
        request_id: None,
        project: &access.project,
        approval_channel: ApprovalChannel::ManualAllow,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: Some(grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation: false,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    term::emit_header(&term::Header {
        command: Some("allow"),
        project: &access.project,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("grant created", &grant.id.to_string());
    term::ok_detail("scope", &scope.to_string());
    Ok(())
}

fn require_manual_allow_confirmation(scope: ApprovalScope) -> Result<()> {
    #[cfg(any(test, coverage))]
    {
        let _ = scope;
        return Ok(());
    }

    #[cfg(not(any(test, coverage)))]
    {
        use std::io::IsTerminal as _;

        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            anyhow::bail!(
                "ward allow requires an interactive local terminal; agents must use ward run --wait-for-approval"
            );
        }
        term::emit_block(&term::MessageBlock {
            level: term::StatusLevel::Warn,
            title: "durable grant confirmation required",
            body: Some("ward allow creates a reusable approval grant"),
            command: Some(&format!("type: ALLOW {}", approval_scope_cli_value(scope))),
        });
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("failed to read allow confirmation")?;
        if input.trim() != format!("ALLOW {}", approval_scope_cli_value(scope)) {
            anyhow::bail!("confirmation did not match; no grant was created");
        }
        Ok(())
    }
}

#[cfg(not(any(test, coverage)))]
fn approval_scope_cli_value(scope: ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "once",
        ApprovalScope::Session => "session",
        ApprovalScope::Branch => "branch",
        ApprovalScope::Always => "always",
        ApprovalScope::Deny => "deny",
    }
}

fn grants_command(command: GrantsCommand) -> Result<()> {
    match command {
        GrantsCommand::List => {
            term::emit_header(&term::Header {
                command: Some("grants list"),
                project: "local",
                path: None,
                mode: None,
            });
            let grants = grants::load_grants()?;
            if grants.is_empty() {
                term::info("no stored approval grants");
                return Ok(());
            }
            term::section("grants");
            for grant in grants {
                let expires = match grant.expires_at {
                    Some(value) => value.to_rfc3339(),
                    None => "-".to_string(),
                };
                let status =
                    grant_status_label(grants::grant_integrity_status(&grant, chrono::Utc::now()));
                let receipt_hash = grant
                    .receipt
                    .as_ref()
                    .map(|receipt| receipt.payload_hash.as_str())
                    .unwrap_or("-");
                term::ok_detail(
                    &grant.id.to_string(),
                    &format!(
                        "scope={:?} status={} project={} command=\"{}\" env={} agent={} branch={} expires={} receipt={}",
                        grant.scope,
                        status,
                        grant.project,
                        grant.command,
                        grant.approved_env.join(","),
                        grant.agent.as_deref().unwrap_or("-"),
                        grant.branch.as_deref().unwrap_or("-"),
                        expires,
                        receipt_hash,
                    ),
                );
            }
        }
        GrantsCommand::Revoke { grant_id } => {
            if grants::revoke_grant(grant_id)? {
                term::emit_header(&term::Header {
                    command: Some("grants revoke"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::ok_detail("grant revoked", &grant_id.to_string());
            } else {
                term::warn_detail("grant not found", &grant_id.to_string());
            }
        }
        GrantsCommand::Prune => {
            let pruned = grants::prune_expired_grants()?;
            term::emit_header(&term::Header {
                command: Some("grants prune"),
                project: "local",
                path: None,
                mode: None,
            });
            term::ok_detail("expired grants pruned", &pruned.to_string());
        }
    }
    Ok(())
}

fn approvals_command(command: ApprovalsCommand) -> Result<()> {
    match command {
        ApprovalsCommand::List { json } => {
            let notifications = notifications::list_notifications()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&notifications)?);
            } else if notifications.is_empty() {
                term::emit_header(&term::Header {
                    command: Some("approvals list"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::info("no pending approval notifications");
            } else {
                term::emit_header(&term::Header {
                    command: Some("approvals list"),
                    project: "local",
                    path: None,
                    mode: None,
                });
                term::section("pending");
                for notification in notifications {
                    term::warn_detail(
                        &notification.id.to_string(),
                        &format!(
                            "{:?} project={} risk={} {}",
                            notification.kind,
                            notification.project,
                            notification.risk,
                            notification.command.as_deref().unwrap_or("")
                        ),
                    );
                }
            }
            Ok(())
        }
        ApprovalsCommand::Wait {
            request_id,
            json,
            timeout,
        } => wait_for_approval_command(request_id, json, &timeout),
    }
}

fn wait_for_approval_command(request_id: uuid::Uuid, json: bool, timeout: &str) -> Result<()> {
    let timeout = unlock::parse_ttl(timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    loop {
        if let Some(resolution) = pending_requests::load_resolution(request_id)? {
            if json {
                println!("{}", serde_json::to_string_pretty(&resolution)?);
            } else {
                term::emit_header(&term::Header {
                    command: Some("approvals wait"),
                    project: &resolution.project,
                    path: None,
                    mode: None,
                });
                term::ok_detail(&resolution.status, &resolution.request_id.to_string());
            }
            return Ok(());
        }
        if chrono::Utc::now() >= deadline {
            let response = serde_json::json!({
                "status": "approval_timeout",
                "requestId": request_id,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                term::warn_detail("approval wait timed out", &request_id.to_string());
            }
            return Ok(());
        }
        thread::sleep(StdDuration::from_millis(500));
    }
}

fn require_human_terminal_confirmation(action: &str, request_id: uuid::Uuid) -> Result<()> {
    #[cfg(any(test, coverage))]
    {
        let _ = (action, request_id);
        return Ok(());
    }

    #[cfg(not(any(test, coverage)))]
    {
        use std::io::IsTerminal as _;

        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            anyhow::bail!(
                "Ward {action} requires an interactive local terminal; use the dashboard approval flow or ask a human to run this command"
        );
        }
        term::emit_block(&term::MessageBlock {
            level: term::StatusLevel::Warn,
            title: "human confirmation required",
            body: Some("approval state can only be changed from an interactive local terminal"),
            command: Some(&format!("type: {action} {request_id}")),
        });
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("failed to read approval confirmation")?;
        if input.trim() != format!("{action} {request_id}") {
            anyhow::bail!("confirmation did not match; no approval state was changed");
        }
        Ok(())
    }
}

fn approve(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    agent_mediated: bool,
    json: bool,
) -> Result<()> {
    if agent_mediated {
        anyhow::bail!(
            "--agent-mediated can no longer create approvals; agents must use `ward run --wait-for-approval` or `ward approvals wait <request-id> --json`"
        );
    }
    require_human_terminal_confirmation("APPROVE", request_id)?;
    match approve_inner(
        request_id,
        scope,
        confirm_critical,
        ApprovalChannel::TerminalApprove,
    ) {
        Ok(response) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                term::emit_header(&term::Header {
                    command: Some("approve"),
                    project: &response.project,
                    path: None,
                    mode: None,
                });
                term::ok_detail("request approved", &request_id.to_string());
                term::ok_detail("grant", &response.grant_id.to_string());
            }
            Ok(())
        }
        Err(error) if json && is_unlock_or_signing_error(&error) => {
            print_unlock_required_json(error.to_string())?;
            Ok(())
        }
        Err(error) if json => {
            if print_pending_request_error_json(request_id, &error)? {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApproveJsonResponse {
    status: &'static str,
    request_id: uuid::Uuid,
    project: String,
    grant_id: uuid::Uuid,
    approval_receipt_hash: Option<String>,
    signer_key_id: Option<String>,
    signature_algorithm: Option<String>,
    approval_source: approvals::ApprovalSource,
    approval_channel: ApprovalChannel,
}

fn approve_inner(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    approval_channel: ApprovalChannel,
) -> Result<ApproveJsonResponse> {
    if scope == ApprovalScope::Deny {
        anyhow::bail!("use ward deny for denied requests");
    }
    let pending = pending_requests::load_pending_request(request_id)?;
    let critical = detection::has_critical_findings(&pending.policy.findings);
    validate_pending_approval(&pending, scope, confirm_critical)?;
    let status =
        broker::approve_pending_request(request_id, scope, confirm_critical, approval_channel)?;
    let source = approvals::ApprovalSource::BrokerApproval;
    let decision = ApprovalDecision {
        approved: true,
        scope,
        approved_env: status.access.env.clone(),
        denied_env: Vec::new(),
        source,
        grant_id: Some(status.grant_id),
    };
    let request_snapshot = request_audit_snapshot(
        &pending.access,
        &pending.policy,
        &pending.git,
        pending.verified_context.as_ref(),
    );
    let approval_event = ApprovalEvent {
        correlation_id: request_id,
        request_id: Some(request_id),
        project: &pending.access.project,
        approval_channel,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: Some(status.grant_id),
        approval_receipt_hash: status.approval_receipt_hash.as_deref(),
        signer_key_id: status.signer_key_id.as_deref(),
        signature_algorithm: status.signature_algorithm.as_deref(),
        critical_confirmation: critical && confirm_critical,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    Ok(ApproveJsonResponse {
        status: "approved",
        request_id,
        project: pending.access.project,
        grant_id: status.grant_id,
        approval_receipt_hash: status.approval_receipt_hash,
        signer_key_id: status.signer_key_id,
        signature_algorithm: status.signature_algorithm,
        approval_source: source,
        approval_channel,
    })
}

pub(crate) fn approve_request_from_dashboard(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
) -> Result<Value> {
    let response = approve_inner(
        request_id,
        scope,
        confirm_critical,
        ApprovalChannel::Dashboard,
    )?;
    serde_json::to_value(response).context("failed to serialize approval response")
}

fn validate_pending_approval(
    pending: &pending_requests::PendingRequest,
    scope: ApprovalScope,
    confirm_critical: bool,
) -> Result<()> {
    let critical = detection::has_critical_findings(&pending.policy.findings);
    if critical && !confirm_critical {
        anyhow::bail!("critical request requires --confirm-critical");
    }
    approvals::validate_scope_for_findings(scope, &pending.policy.findings)
}

fn deny(request_id: uuid::Uuid, agent_mediated: bool, json: bool) -> Result<()> {
    if agent_mediated {
        anyhow::bail!(
            "--agent-mediated can no longer deny requests; agents must use `ward run --wait-for-approval` or `ward approvals wait <request-id> --json`"
        );
    }
    require_human_terminal_confirmation("DENY", request_id)?;
    let pending = match pending_requests::load_pending_request(request_id) {
        Ok(pending) => pending,
        Err(error) if json => {
            if print_pending_request_error_json(request_id, &error)? {
                return Ok(());
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let status = broker::deny_pending_request(request_id, ApprovalChannel::TerminalApprove)?;
    let source = approvals::ApprovalSource::BrokerApproval;
    let decision = ApprovalDecision {
        approved: false,
        scope: ApprovalScope::Deny,
        approved_env: Vec::new(),
        denied_env: pending.access.env.clone(),
        source,
        grant_id: None,
    };
    let approval_channel = ApprovalChannel::TerminalApprove;
    let request_snapshot = request_audit_snapshot(
        &pending.access,
        &pending.policy,
        &pending.git,
        pending.verified_context.as_ref(),
    );
    let approval_event = ApprovalEvent {
        correlation_id: request_id,
        request_id: Some(request_id),
        project: &pending.access.project,
        approval_channel,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: None,
        approval_receipt_hash: None,
        signer_key_id: None,
        signature_algorithm: None,
        critical_confirmation: false,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "denied",
                "requestId": request_id,
                "project": status.project,
                "approvalSource": source,
                "approvalChannel": approval_channel,
            }))?
        );
    } else {
        term::emit_header(&term::Header {
            command: Some("deny"),
            project: &status.project,
            path: None,
            mode: None,
        });
        term::ok_detail("request denied", &request_id.to_string());
    }
    Ok(())
}

pub(crate) fn deny_request_from_dashboard(request_id: uuid::Uuid) -> Result<Value> {
    let pending = pending_requests::load_pending_request(request_id)?;
    let status = broker::deny_pending_request(request_id, ApprovalChannel::Dashboard)?;
    let source = approvals::ApprovalSource::BrokerApproval;
    let decision = ApprovalDecision {
        approved: false,
        scope: ApprovalScope::Deny,
        approved_env: Vec::new(),
        denied_env: pending.access.env.clone(),
        source,
        grant_id: None,
    };
    let request_snapshot = request_audit_snapshot(
        &pending.access,
        &pending.policy,
        &pending.git,
        pending.verified_context.as_ref(),
    );
    let approval_event = ApprovalEvent {
        correlation_id: request_id,
        request_id: Some(request_id),
        project: &pending.access.project,
        approval_channel: ApprovalChannel::Dashboard,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: None,
        approval_receipt_hash: None,
        signer_key_id: None,
        signature_algorithm: None,
        critical_confirmation: false,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    Ok(serde_json::json!({
        "status": "denied",
        "requestId": request_id,
        "project": status.project,
        "approvalSource": source,
        "approvalChannel": ApprovalChannel::Dashboard,
    }))
}

fn is_unlock_or_signing_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("signing_key_unavailable")
        || message.contains("unlock_required")
        || message.contains("missing broker unlock session")
        || message.contains("expired broker unlock session")
        || message.contains("Ward broker is unavailable")
}

fn print_unlock_required_json(reason: String) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "unlock_required",
            "reason": reason,
            "unlockCommand": "ward unlock --ttl 8h",
        }))?
    );
    Ok(())
}

fn print_pending_request_error_json(request_id: uuid::Uuid, error: &anyhow::Error) -> Result<bool> {
    let path = pending_requests::pending_request_path(request_id);
    let (status, reason) = if !path.exists() {
        ("not_found", "pending_request_not_found")
    } else {
        let message = error.to_string();
        if message.contains("failed to parse") {
            ("invalid_request", "pending_request_malformed")
        } else if message.contains("pending request") && message.contains("expired") {
            ("invalid_request", "pending_request_expired")
        } else if message.contains("failed to read") {
            ("invalid_request", "pending_request_unreadable")
        } else {
            return Ok(false);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": status,
            "requestId": request_id,
            "reason": reason,
        }))?
    );
    Ok(true)
}

#[cfg(any(test, coverage))]
fn run(options: RunOptions) -> Result<()> {
    run_with_context(options, AgentContextOptions::default(), None)
}

fn run_with_context(
    mut options: RunOptions,
    context_options: AgentContextOptions,
    app: Option<String>,
) -> Result<()> {
    if reject_misplaced_run_flags(&options.command)? {
        return Ok(());
    }
    let invocation_cwd = env::current_dir()?;
    let selector = workspace_target::TargetSelector::one(options.project.clone(), app);
    let target = workspace_target::resolve_one(&selector, &invocation_cwd)?;
    let explicit_target = options.project.is_some() || selector.app.is_some();
    let profile_command = options.profile.is_some() && options.command.is_empty();
    let cwd = if explicit_target && profile_command {
        target.path.clone()
    } else {
        invocation_cwd
    };
    let resolved = target.resolved_project();
    let config = config::read_project_config(&resolved.path)?;
    let git = git_context::collect_git_context(&cwd);
    let branch = options.branch.or(git.branch.clone());
    let mut context_options = context_options;
    let human_terminal = crate::human::is_human_terminal();
    if context_options.agent.is_none() {
        context_options.agent = options.agent.clone();
    }
    if context_options.branch.is_none() {
        context_options.branch = branch.clone();
    }
    // In a human terminal, infer remaining context from the current git repo.
    if human_terminal {
        if !agent_identity_is_present(context_options.agent.as_deref()) {
            context_options.agent = Some("human".to_string());
        }
        if !agent_identity_is_present(options.agent.as_deref()) {
            options.agent = Some("human".to_string());
        }
        if context_options.worktree.is_none() {
            context_options.worktree = git.worktree_path.as_deref().map(PathBuf::from);
        }
        if context_options.commit.is_none() {
            context_options.commit = git.commit.clone();
        }
        if context_options.git_remote.is_none() {
            context_options.git_remote = git.remote.clone();
        }
        // Inject all vault keys automatically when no --env was specified.
        if options.env_names.is_empty() && options.profile.is_none() {
            options.env_names = broker::list_vault_keys_for_human(
                &resolved.name,
                &resolved.vault,
                crate::human::current_shell_pid(),
            )
            .context(
                    "human mode requires an active broker session; run `ward human` or `ward unlock --ttl 8h`",
                )?;
        }
    }
    let resolved_profile = resolve_run_profile(
        &config,
        options.profile.as_deref(),
        options.action,
        options.env_names,
        options.command,
        human_terminal,
    )?;
    if !human_terminal && !options.no_prompt {
        require_agent_identity_for_non_human(options.agent.as_deref())?;
    }
    let command_text = resolved_profile.command.clone();

    let access = AccessRequest {
        project: resolved.name.clone(),
        agent: options.agent,
        branch,
        action: resolved_profile.action,
        command: command_text.clone(),
        env: resolved_profile.env_names.clone(),
    };
    let evaluation = evaluate_access(&config, &access);
    let mut verified_context = None;
    let mut correlation_id = uuid::Uuid::new_v4();
    let mut linked_request_id = None;
    let decision = if human_terminal && !options.no_prompt {
        ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: resolved_profile.env_names.clone(),
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::LocalTty,
            grant_id: None,
        }
    } else if options.no_prompt {
        if !options.json {
            anyhow::bail!("--no-prompt requires --json");
        }
        let Some(context) = verified_no_prompt_context(&cwd, &resolved, &context_options)? else {
            return Ok(());
        };
        if !enforce_worktree_for_no_prompt(
            &resolved,
            &context,
            options.wait_for_approval,
            &options.approval_timeout,
        )? {
            return Ok(());
        }
        verified_context = Some(context);
        let decision = match non_interactive_decision_with_context(
            &access,
            &evaluation,
            verified_context.as_ref(),
        )? {
            Some(decision) => decision,
            None => {
                let pending = create_run_pending_request(
                    &access,
                    &evaluation,
                    &git,
                    verified_context.clone(),
                )?;
                let request_event = RequestEvent {
                    correlation_id: pending.id,
                    request_id: Some(pending.id),
                    expires_at: Some(&pending.expires_at),
                    access: &pending.access,
                    policy: &pending.policy,
                    git: &pending.git,
                    verified_context: pending.verified_context.as_ref(),
                };
                audit_logs::append_event(LogKind::Requests, request_event)?;
                if options.wait_for_approval {
                    correlation_id = pending.id;
                    linked_request_id = Some(pending.id);
                    let Some(decision) = wait_for_run_approval(
                        &pending,
                        &access,
                        &evaluation,
                        verified_context.as_ref(),
                        &options.approval_timeout,
                    )?
                    else {
                        return Ok(());
                    };
                    decision
                } else {
                    print_run_approval_required(&pending)?;
                    return Ok(());
                }
            }
        };
        if !decision.approved {
            let request_event = RequestEvent {
                correlation_id,
                request_id: linked_request_id,
                expires_at: None,
                access: &access,
                policy: &evaluation,
                git: &git,
                verified_context: verified_context.as_ref(),
            };
            let request_snapshot =
                request_audit_snapshot(&access, &evaluation, &git, verified_context.as_ref());
            let approval_event = ApprovalEvent {
                correlation_id,
                request_id: linked_request_id,
                project: &access.project,
                approval_channel: approval_channel_for_source(decision.source),
                request_snapshot: Some(request_snapshot),
                decision: &decision,
                persisted_grant: None,
                approval_receipt_hash: None,
                signer_key_id: None,
                signature_algorithm: None,
                critical_confirmation: false,
                human_proof: approval_human_proof(decision.source),
            };
            audit_logs::append_event(LogKind::Requests, request_event)?;
            audit_logs::append_event(LogKind::Approvals, approval_event)?;
            create_run_block_notification(
                notifications::NotificationKind::PolicyDenied,
                &access,
                &evaluation,
                "Ward policy denied this request.",
                None,
            )?;
            print_run_denied(&access, &evaluation)?;
            return Ok(());
        }
        decision
    } else {
        decide_access(&access, &evaluation, true)?
    };
    let critical_confirmation = critical_confirmation_for_decision(&decision, &evaluation);
    let receipt_context = Some(grants::GrantReceiptContext {
        request_id: uuid::Uuid::new_v4(),
        pending_request: false,
        critical_confirmation,
        verified_context: verified_context.clone(),
    });
    let persisted_grant =
        grants::persist_grant(&access, &decision, &resolved.vault, receipt_context)?;
    let receipt = persisted_grant
        .as_ref()
        .and_then(|grant| grant.receipt.as_ref());

    let request_event = RequestEvent {
        correlation_id,
        request_id: linked_request_id,
        expires_at: None,
        access: &access,
        policy: &evaluation,
        git: &git,
        verified_context: verified_context.as_ref(),
    };
    let request_snapshot =
        request_audit_snapshot(&access, &evaluation, &git, verified_context.as_ref());
    let approval_channel = approval_channel_for_source(decision.source);
    let approval_event = ApprovalEvent {
        correlation_id,
        request_id: linked_request_id,
        project: &access.project,
        approval_channel,
        request_snapshot: Some(request_snapshot),
        decision: &decision,
        persisted_grant: persisted_grant.as_ref().map(|grant| grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Requests, request_event)?;
    if should_log_approval_event(&decision) {
        audit_logs::append_event(LogKind::Approvals, approval_event)?;
    }

    if !decision.approved {
        anyhow::bail!("Ward access denied");
    }

    let grant_id = effective_grant_id(&decision, persisted_grant.as_ref());
    let grant_origin_request_id = grant_origin_request_id(&decision);
    let approval_receipt_hash = grant_receipt_hash(&decision, persisted_grant.as_ref())?;
    let started_event = ExecutionStartedEvent {
        event_type: "execution.started",
        correlation_id,
        request_id: linked_request_id,
        project: &resolved.name,
        agent: &access.agent,
        branch: &access.branch,
        declared_action: &access.action,
        requested_command: &command_text,
        cwd: &cwd,
        git: &git,
        requested_env: &evaluation.requested_env,
        injected_env: &decision.approved_env,
        policy_findings: &evaluation.findings,
        approval_scope: decision.scope,
        approval_source: decision.source,
        approval_channel,
        grant_id,
        grant_origin_request_id,
        approval_receipt_hash: approval_receipt_hash.as_deref(),
        agent_key_id: verified_agent_key_id(verified_context.as_ref()),
        verified_context: verified_context.as_ref(),
    };
    audit_logs::append_event(LogKind::Executions, started_event)?;

    consume_once_grant_if_reused(&decision)?;

    let command_args = resolved_profile.command_args.clone();
    let mut execute_payload = broker::ExecuteAuthorizationPayload::new(
        resolved.name.clone(),
        resolved.vault.clone(),
        cwd.clone(),
        decision.approved_env.clone(),
        command_args.clone(),
        decision.scope,
        decision.source,
    );
    execute_payload.agent = access.agent.clone();
    execute_payload.branch = access.branch.clone();
    execute_payload.action = access.action.clone();
    execute_payload.grant_id = grant_id;
    execute_payload.approval_receipt_hash = approval_receipt_hash.clone();
    if let Some(context) = verified_context.as_ref() {
        execute_payload.worktree = Some(context.worktree.clone());
        execute_payload.git_remote = Some(context.git_remote.clone());
        execute_payload.commit = Some(context.commit.clone());
    }

    let outcome = if options.no_prompt {
        let context = verified_context
            .as_ref()
            .expect("verified in no-prompt mode");
        let Some(outcome) = execute_no_prompt_with_optional_wait(
            &resolved,
            &cwd,
            &decision,
            &command_args,
            execute_payload,
            context,
            &access,
            &evaluation,
            options.wait_for_approval,
            &options.approval_timeout,
        )?
        else {
            return Ok(());
        };
        outcome
    } else {
        match broker::execute(
            &resolved.name,
            &resolved.vault,
            &cwd,
            decision.approved_env.clone(),
            command_args.clone(),
            if human_terminal {
                broker::ExecuteAuthorization::Human {
                    shell_pid: crate::human::current_shell_pid(),
                }
            } else {
                broker::ExecuteAuthorization::Internal {
                    payload: execute_payload,
                }
            },
        ) {
            Ok(outcome) => outcome,
            Err(broker_err) => {
                if broker_execution_rejection_is_authoritative(&broker_err) {
                    anyhow::bail!("broker rejected execution: {broker_err}");
                }
                // If only broker metadata exists and the broker is unavailable,
                // there is no usable secret material for no-prompt execution.
                let fallback_passphrase = match unlock::active_run_lookup(
                    &resolved.name,
                    &resolved.vault,
                )? {
                    unlock::RunUnlockLookup::Available(passphrase) => Some(passphrase),
                    unlock::RunUnlockLookup::MaterialUnavailable { .. } => {
                        anyhow::bail!(
                            "broker session metadata exists but broker is not running ({})\nRun `ward unlock` to recreate the master session.",
                            broker_err
                        );
                    }
                    unlock::RunUnlockLookup::Missing => None,
                };
                let passphrase = match fallback_passphrase {
                    Some(passphrase) => passphrase,
                    None => vault::read_existing_passphrase()?,
                };
                let plaintext = vault::decrypt_vault_file(&resolved.vault, &passphrase)?;
                let env = env_file::parse_env_map(&plaintext)?;
                runner::run_command(RunCommandRequest {
                    cwd: cwd.clone(),
                    env_names: decision.approved_env.clone(),
                    env,
                    command: command_args,
                    inherited_env: std::env::vars().collect(),
                    cancellation: None,
                    human_shell_pid: if human_terminal {
                        Some(crate::human::current_shell_pid())
                    } else {
                        None
                    },
                    child_pid: None,
                })?
            }
        }
    };

    let execution_event = ExecutionEvent {
        event_type: "execution.finished",
        correlation_id,
        request_id: linked_request_id,
        project: &resolved.name,
        agent: &access.agent,
        branch: &access.branch,
        declared_action: &access.action,
        requested_command: &command_text,
        cwd: &cwd,
        git: &git,
        requested_env: &evaluation.requested_env,
        injected_env: &decision.approved_env,
        policy_findings: &evaluation.findings,
        approval_scope: decision.scope,
        approval_source: decision.source,
        approval_channel,
        grant_id,
        grant_origin_request_id,
        approval_receipt_hash: approval_receipt_hash.as_deref(),
        agent_key_id: verified_agent_key_id(verified_context.as_ref()),
        verified_context: verified_context.as_ref(),
        outcome: &outcome,
    };
    let finish_result = audit_logs::append_event(LogKind::Executions, execution_event);
    let anomaly_result = log_anomaly_alerts(&config, grant_id);

    let alert_result = if outcome.redaction_alerts > 0 {
        let output_redaction_event = OutputRedactionEvent {
            event_type: "output.redaction",
            command: &command_text,
            count: outcome.redaction_alerts,
            alerts: &outcome.output_alerts,
        };
        audit_logs::append_event(LogKind::Alerts, output_redaction_event)
    } else {
        Ok(())
    };

    handle_post_run_logging_result(outcome.exit_code, finish_result.and(alert_result))?;
    warn_anomaly_failure(anomaly_result);

    if outcome.exit_code != 0 {
        return Err(ChildExit::new(outcome.exit_code).into());
    }

    Ok(())
}

fn reject_misplaced_run_flags(command: &[String]) -> Result<bool> {
    if !command.iter().any(|arg| arg == "--no-prompt") {
        return Ok(false);
    }
    let response = InvalidInvocationResponse {
        status: "invalid_invocation",
        reason: "ward_flags_after_separator",
        message: "Move Ward flags before --.",
        correct_example: "ward run --json --no-prompt --env DATABASE_URI -- <command>",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(true)
}

#[cfg(any(test, coverage))]
fn doctor() -> Result<()> {
    doctor_for_target(None, None, false)
}

fn doctor_for_target(project: Option<String>, app: Option<String>, all: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let selector = workspace_target::TargetSelector { project, app, all };
    if selector.all {
        return doctor_workspace(&cwd);
    }
    if selector.project.is_some() || selector.app.is_some() {
        let target = workspace_target::resolve_one(&selector, &cwd)?;
        return doctor_project_at(target.path);
    }
    if config::find_project_root(&cwd).is_none() && workspace::discover_containing(&cwd)?.is_some()
    {
        return doctor_workspace(&cwd);
    }
    doctor_project_at(cwd)
}

fn doctor_workspace(cwd: &Path) -> Result<()> {
    let discovery = workspace::discover_containing(cwd)?
        .context("no workspace manifest found; expected pnpm-workspace.yaml, package.json workspaces, or turbo.json")?;
    term::guided_context_header(
        "doctor",
        "Workspace",
        &discovery.workspace_name,
        &discovery.root,
        "Ward found a monorepo workspace. App folders are checked as separate Ward projects.",
    );
    let targets = workspace_target::configured_workspace_targets(&discovery)?;
    term::section("workspace");
    term::ok(&format!(
        "{} app package(s) detected",
        discovery.app_candidates().count()
    ));
    if let Some(manager) = discovery.package_manager.as_deref() {
        term::info(&format!("package manager {manager}"));
    }
    if discovery.turborepo {
        term::ok("turborepo detected");
    }
    term::section("apps");
    if targets.is_empty() {
        term::warn("no configured Ward app projects found");
        term::next("run: ward setup --workspace --all");
        return Ok(());
    }
    for target in targets {
        let cfg_status = if config::config_path(&target.path).is_file() {
            "config ok"
        } else {
            "config missing"
        };
        let vault_status = if target.vault.exists() {
            "vault ok"
        } else {
            "vault missing"
        };
        let session =
            broker::list_vault_keys_from_active_session(&target.name, &target.vault).is_ok();
        let session_status = if session { "session active" } else { "locked" };
        let app = target.app_slug.as_deref().unwrap_or(&target.name);
        term::info(&format!(
            "{app}  {}  {cfg_status}  {vault_status}  {session_status}",
            target.name
        ));
    }
    term::blank();
    Ok(())
}

fn doctor_project_at(cwd: PathBuf) -> Result<()> {
    let config_path = config::config_path(&cwd);
    let plaintext_env = cwd.join(".env");
    let project_name = cwd
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    term::header_cmd("doctor", &project_name);

    // ── config ────────────────────────────────────────────────────────────────
    term::section("config");

    if !config_path.exists() {
        match config::find_project_config_backup_for_path(&cwd)? {
            Some((backup_path, backup)) => {
                term::warn(&format!(
                    ".ward.json missing but recoverable for {}",
                    backup.project
                ));
                term::info(&format!("backup {}", term::short_path(&backup_path)));
                term::info("run ward config restore, or rerun ward setup to restore automatically");
            }
            None => term::fail(".ward.json missing — run ward setup"),
        }
        term::blank();
        return Ok(());
    }
    term::ok(&format!(".ward.json  {}", term::short_path(&config_path)));

    let project_config = config::read_project_config(&cwd);
    match &project_config {
        Ok(cfg) => {
            term::ok(&format!("project  {}", cfg.project));
            let vault_path = doctor_vault_path(&cwd, cfg);
            if vault_path.exists() {
                term::ok(&format!("vault  {}", term::short_path(&vault_path)));
            } else {
                term::fail(&format!(
                    "vault not found  {}",
                    term::short_path(&vault_path)
                ));
            }
            match config::find_project_config_backup_for_path(&cwd)? {
                Some((backup_path, _)) => {
                    term::ok(&format!(
                        "config backup  {}",
                        term::short_path(&backup_path)
                    ));
                }
                None => {
                    term::warn("config backup missing — rerun ward setup to refresh metadata");
                }
            }
        }
        Err(e) => {
            term::fail(&format!("config parse error — {e}"));
        }
    }

    // ── secrets ───────────────────────────────────────────────────────────────
    term::section("secrets");

    match &project_config {
        Ok(cfg) => {
            let vault_path = doctor_vault_path(&cwd, cfg);
            match env_file::inspect_env_file(&plaintext_env, &vault_path) {
                Ok(env_file::EnvFileState::Locked) => term::ok(".env  locked"),
                Ok(env_file::EnvFileState::StaleLocked) => {
                    term::warn(".env locked but stale — run ward env lock")
                }
                Ok(env_file::EnvFileState::Plaintext) => {
                    term::warn(".env is plaintext — run ward env lock")
                }
                Ok(env_file::EnvFileState::Missing) => term::warn(".env missing"),
                Err(e) => term::fail(&format!(".env check failed — {e}")),
            }
        }
        Err(_) if plaintext_env.exists() => {
            term::warn(".env is plaintext — run ward setup or ward import .env");
        }
        Err(_) => term::warn(".env missing"),
    }

    let secret_files = likely_secret_env_files(&cwd)?;
    if secret_files.is_empty() {
        term::ok("no .env.* secret variants found");
    } else {
        for path in &secret_files {
            term::warn(&format!(
                "plaintext env variant  {}",
                term::short_path(path)
            ));
        }
    }

    // ── gitignore ─────────────────────────────────────────────────────────────
    term::section("gitignore");
    check_gitignore(&cwd)?;

    let gitignore_path = cwd.join(".gitignore");
    if gitignore_path.exists() {
        match fs::read_to_string(&gitignore_path) {
            Ok(contents) if contents.contains(config::WARD_JSON_GITIGNORE_ENTRY) => {
                term::ok(".ward.json  excluded");
            }
            Ok(_) => {
                term::warn(".ward.json not in .gitignore — vault nonce may leak into git history");
            }
            Err(_) => {}
        }
    }

    // ── broker ────────────────────────────────────────────────────────────────
    term::section("broker");

    match registry::resolve_project(None, &cwd) {
        Ok(project) => {
            term::ok(&format!("project  {}", project.name));
            if !project.vault.exists() {
                term::warn(&format!(
                    "vault not found  {}",
                    term::short_path(&project.vault)
                ));
            }
            match broker::status() {
                Ok(status) if status.running => {
                    term::info(&format!("socket  {}", term::short_path(&status.socket)));
                    term::info(&format!("version  {}", status.version));
                    if broker::privileged_rpc_peer_auth_supported() {
                        term::ok(&format!(
                            "privileged RPC peer auth  {}",
                            broker::peer_auth_platform()
                        ));
                    } else {
                        term::warn("privileged RPC peer auth unsupported — privileged broker calls fail closed");
                    }
                    if let Some(pid) = status.pid {
                        match status.ppid {
                            Some(ppid) => term::info(&format!("pid={pid} ppid={ppid}")),
                            None => term::info(&format!("pid={pid}")),
                        }
                    }
                    if let Some(started_at) = status.started_at {
                        term::info(&format!("started  {}", started_at.to_rfc3339()));
                    }
                    term::info(&format!("sessions  {}", status.sessions.len()));
                    term::info(&format!("broker approvals  {}", status.approval_count));
                    match broker::list_vault_keys_from_active_session(&project.name, &project.vault)
                    {
                        Ok(names) => {
                            term::ok("active broker session can serve env names");
                            term::info(&format!("env names in memory  {}", names.len()));
                        }
                        Err(_) => warn_missing_broker_session(&project.name, &project.vault),
                    }
                }
                Ok(_) => warn_missing_broker_session(&project.name, &project.vault),
                Err(e) => term::fail(&format!("broker status failed — {e}")),
            }
        }
        Err(e) => term::fail(&format!("registry resolve failed — {e}")),
    }

    // ── project store ────────────────────────────────────────────────────────
    term::section("project store");
    match registry::resolve_project(None, &cwd) {
        Ok(project) => {
            match project_store::diagnostics(&project.name) {
                Ok(diagnostics) if diagnostics.exists => {
                    if diagnostics.stale {
                        term::warn(&format!(
                            "snapshot stale  {}",
                            term::short_path(&diagnostics.path)
                        ));
                    } else {
                        term::ok(&format!(
                            "snapshot  {}",
                            term::short_path(&diagnostics.path)
                        ));
                    }
                    term::info(&format!(
                        "env={} profiles={} agentPolicies={}",
                        diagnostics.env_count,
                        diagnostics.profile_count,
                        diagnostics.agent_policy_count
                    ));
                }
                Ok(diagnostics) => {
                    term::warn("no local project-store snapshot");
                    term::info(&format!("expected {}", term::short_path(&diagnostics.path)));
                }
                Err(error) => term::fail(&format!("project-store check failed — {error}")),
            }
            match broker::list_vault_keys_from_active_session(&project.name, &project.vault) {
                Ok(_) => term::ok("active broker session can refresh/provision"),
                Err(_) => {
                    term::warn("run ward unlock --ttl 8h to refresh/provision from this project")
                }
            }
        }
        Err(error) => term::fail(&format!("registry resolve failed — {error}")),
    }

    // ── human mode ───────────────────────────────────────────────────────────
    term::section("human mode");
    let human = crate::human::runtime_diagnostics();
    if human.shell_hooks_loaded {
        term::ok("shell hooks loaded");
    } else {
        term::warn("shell hooks not loaded — reload your shell, then run ward human");
    }
    if human.guardian_socket_exists {
        term::ok(&format!("guardian active for shell {}", human.shell_pid));
    } else {
        term::warn(&format!(
            "guardian missing for shell {} — run ward human",
            human.shell_pid
        ));
        term::info(&format!(
            "expected socket {}",
            term::short_path(&human.socket_path)
        ));
    }
    if human.stale_guardian_pids.is_empty() && human.stale_run_dirs.is_empty() {
        term::ok("no stale human runtime files");
    } else {
        if !human.stale_guardian_pids.is_empty() {
            term::warn(&format!(
                "stale guardian process(es): {}",
                human
                    .stale_guardian_pids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for dir in &human.stale_run_dirs {
            term::warn(&format!("stale runtime dir  {}", term::short_path(dir)));
        }
        term::info("run ward human to clean stale human runtime state");
    }

    // ── dashboard ───────────────────────────────────────────────────────────
    term::section("dashboard");
    match crate::webui::dashboard_diagnostics() {
        Ok(instances) if instances.is_empty() => {
            term::ok("no standalone browser dashboards running");
            term::info("run ward dashboard start to open the browser dashboard");
        }
        Ok(instances) => {
            term::ok(&format!(
                "{} standalone browser dashboard(s) running",
                instances.len()
            ));
            for instance in instances {
                term::info(&format!(
                    "pid={} port={} project={}",
                    instance.pid,
                    instance.port,
                    instance.started_project.as_deref().unwrap_or("-")
                ));
            }
        }
        Err(e) => term::fail(&format!("dashboard status failed — {e}")),
    }

    // ── grants ────────────────────────────────────────────────────────────────
    term::section("grants");

    match grants::load_grants() {
        Ok(loaded) => {
            let now = chrono::Utc::now();
            let unsigned = loaded
                .iter()
                .filter(|g| {
                    grants::grant_integrity_status(g, now)
                        == grants::GrantIntegrityStatus::LegacyUnsigned
                })
                .count();
            let invalid = loaded
                .iter()
                .filter(|g| {
                    grants::grant_integrity_status(g, now) == grants::GrantIntegrityStatus::Invalid
                })
                .count();
            if unsigned == 0 && invalid == 0 {
                term::ok("all approval grants signed and valid");
            }
            if unsigned > 0 {
                term::warn(&format!(
                    "{unsigned} legacy unsigned grant(s) — re-approve them"
                ));
            }
            if invalid > 0 {
                term::warn(&format!(
                    "{invalid} invalid grant signature(s) — revoke and re-approve"
                ));
            }
        }
        Err(e) => term::fail(&format!("grant check failed — {e}")),
    }

    // ── logs ──────────────────────────────────────────────────────────────────
    term::section("logs");

    match audit_logs::entry_count(LogKind::Alerts) {
        Ok(0) => term::ok("no alerts"),
        Ok(n) => term::warn(&format!("{n} alert(s) — run ward logs view alerts")),
        Err(e) => term::fail(&format!("alert log check failed — {e}")),
    }

    // ── recovery ──────────────────────────────────────────────────────────────
    term::section("recovery");

    if let Ok(cfg) = &project_config {
        let recovery_dir = logs::recovery_dir();
        let key_files_exist = recovery_dir.exists()
            && fs::read_dir(&recovery_dir)
                .map(|mut d| {
                    d.any(|e| {
                        e.map(|e| e.path().extension().and_then(|x| x.to_str()) == Some("key"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

        if cfg.recovery_created && !key_files_exist {
            term::fail("recovery key missing — run: ward recovery create");
            term::info(&format!("expected in {}", term::short_path(&recovery_dir)));
        } else if cfg.recovery_created {
            term::ok("recovery key present");
            if !cfg.backup_exported {
                term::warn("no backup exported — run: ward recovery export");
            } else {
                term::ok("recovery backup exported");
            }
        } else {
            term::warn("recovery key not created — run: ward recovery create");
        }

        if vault::test_passphrase().is_some() {
            let passphrase = vault::test_passphrase().unwrap();
            if !recovery::recovery_file_exists(&cfg.project, &passphrase) {
                term::fail("recovery file not found at derived path — run: ward recovery create");
            }
        }
    } else {
        term::warn("unable to check recovery — config not readable");
    }

    term::blank();
    Ok(())
}

fn doctor_vault_path(cwd: &Path, cfg: &config::ProjectConfig) -> PathBuf {
    registry::resolve_project(Some(&cfg.project), cwd)
        .map(|resolved| resolved.vault)
        .unwrap_or_else(|_| config::resolve_vault_path(cwd, cfg))
}

#[cfg(any(test, coverage))]
fn signing_lookup_message(result: Result<unlock::RunSigningLookup>) -> String {
    match result {
        Ok(unlock::RunSigningLookup::Available(_)) => {
            "[ok] Active signing key session is readable.".to_string()
        }
        Ok(unlock::RunSigningLookup::Missing) => {
            "! No active signing key session. Run ward unlock --ttl 8h.".to_string()
        }
        Ok(unlock::RunSigningLookup::MaterialUnavailable { reason }) => {
            format!(
                "! Active signing key session is unavailable ({reason}). Run ward unlock --ttl 8h."
            )
        }
        Err(error) => format!("! Signing key session check failed: {error}"),
    }
}

fn logs(command: Option<LogsCommand>, kind: Option<LogKind>) -> Result<()> {
    match command {
        Some(LogsCommand::View { kind }) => {
            ensure_logs_passphrase()?;
            warn_log_view_access();
            let output = render_log_events(&audit_logs::decrypt_events(kind)?)?;
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Some(LogsCommand::Verify { kind, full }) => {
            let reports = if full {
                ensure_logs_passphrase()?;
                audit_logs::verify_logs_full(kind)?
            } else {
                audit_logs::verify_logs(kind)?
            };
            term::emit_header(&term::Header {
                command: Some("logs verify"),
                project: "audit logs",
                path: Some(&audit_logs::logs_dir()),
                mode: None,
            });
            for report in reports {
                term::ok_detail(
                    report.kind.as_str(),
                    &format!(
                        "entries={} path={}",
                        report.entries,
                        term::short_path(&report.path)
                    ),
                );
            }
        }
        Some(LogsCommand::Export {
            kind,
            output,
            force,
        }) => {
            if output.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite",
                    output.display()
                );
            }
            ensure_logs_passphrase()?;
            warn_log_view_access();
            let output_contents = render_log_events(&audit_logs::decrypt_events(kind)?)?;
            crate::fs_util::write_private_file(&output, output_contents.as_bytes())?;
            term::emit_header(&term::Header {
                command: Some("logs export"),
                project: kind.as_str(),
                path: Some(&output),
                mode: None,
            });
            term::ok("decrypted log exported");
        }
        Some(LogsCommand::Unlock { ttl }) => unlock_logs(&ttl)?,
        None => match kind {
            Some(kind) => println!("{}", audit_logs::log_path(kind).display()),
            None => println!("{}", audit_logs::logs_dir().display()),
        },
    }
    Ok(())
}

fn render_log_events(events: &[Value]) -> Result<String> {
    let mut lines = Vec::with_capacity(events.len());
    for event in events {
        lines.push(serde_json::to_string(event)?);
    }
    Ok(lines.join("\n"))
}

fn edit(project: Option<String>, app: Option<String>) -> Result<()> {
    let cwd = env::current_dir()?;
    let passphrase = vault::read_existing_passphrase()?;
    let target = workspace_target::resolve_one_with_passphrase(
        &workspace_target::TargetSelector::one(project, app),
        &cwd,
        &passphrase,
    )?;
    let resolved = target.resolved_project();
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::edit_vault_file(&resolved.vault, &passphrase)?;
        warn_store_refresh_failure(refresh_project_store_with_passphrase(
            &resolved,
            &passphrase,
        ));
        Ok(())
    })?;
    let event = VaultEditEvent {
        event_type: "vault.edit",
        project: &resolved.name,
        vault: &resolved.vault,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    term::emit_header(&term::Header {
        command: Some("edit"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail(
        "encrypted vault updated",
        &term::short_path(&resolved.vault),
    );
    Ok(())
}

pub(crate) fn create_run_unlock_session(
    project: &str,
    vault_path: &Path,
    passphrase: &str,
    ttl: &str,
    mode: Option<&str>,
) -> Result<unlock::UnlockSession> {
    let ttl = unlock::parse_ttl(ttl)?;

    // Send unlock to the broker first. The broker decrypts the stable vault once
    // and keeps the runtime env map in memory for command injection.
    broker::unlock_project_with_mode(
        project,
        vault_path,
        passphrase,
        ttl,
        mode.map(str::to_string),
    )
    .map_err(|error| {
        let error_message = error.to_string();
        let event = VaultUnlockEvent {
            event_type: "vault.unlock",
            status: "failure",
            project,
            vault: vault_path,
            error: Some(&error_message),
            expires_at: None,
        };
        let _ = audit_logs::append_event(LogKind::Sessions, event);
        error
    })?;

    #[cfg(not(test))]
    let broker_expires_at = match broker::active_session_expiry(project, vault_path) {
        Ok(Some(expires_at)) => expires_at,
        Ok(None) => {
            let error_message =
                "broker unlock did not create an active session; run ward unlock again".to_string();
            let event = VaultUnlockEvent {
                event_type: "vault.unlock",
                status: "failure",
                project,
                vault: vault_path,
                error: Some(&error_message),
                expires_at: None,
            };
            audit_logs::append_event(LogKind::Sessions, event)?;
            anyhow::bail!("{error_message}");
        }
        Err(error) => {
            let error_message = error.to_string();
            let event = VaultUnlockEvent {
                event_type: "vault.unlock",
                status: "failure",
                project,
                vault: vault_path,
                error: Some(&error_message),
                expires_at: None,
            };
            audit_logs::append_event(LogKind::Sessions, event)?;
            anyhow::bail!("{error_message}");
        }
    };
    #[cfg(test)]
    let broker_expires_at = chrono::Utc::now() + ttl;

    let mut session = if let Some(mode_name) = mode {
        unlock::create_mode_unlock(project, vault_path, passphrase, ttl, mode_name)?
    } else {
        unlock::create_run_unlock(project, vault_path, passphrase, ttl)?
    };
    if broker_expires_at < session.expires_at {
        session.expires_at = broker_expires_at;
    }
    let event = VaultUnlockEvent {
        event_type: "vault.unlock",
        status: "success",
        project,
        vault: vault_path,
        error: None,
        expires_at: Some(session.expires_at.to_rfc3339()),
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    Ok(session)
}

#[cfg(any(test, coverage))]
fn unlock_vault(ttl: &str, mode: Option<&str>, verify_only: bool) -> Result<()> {
    unlock_vault_for_target(None, None, false, ttl, mode, verify_only)
}

fn unlock_vault_for_target(
    project: Option<String>,
    app: Option<String>,
    all: bool,
    ttl: &str,
    mode: Option<&str>,
    verify_only: bool,
) -> Result<()> {
    let cwd = env::current_dir()?;
    if verify_only {
        if mode.is_some() {
            anyhow::bail!("--verify-only cannot be combined with --mode");
        }
        let selector = workspace_target::TargetSelector { project, app, all };
        let targets = workspace_target::resolve_many(&selector, &cwd)?;
        for target in targets {
            let resolved = target.resolved_project();
            match broker::list_vault_keys_from_active_session(&resolved.name, &resolved.vault) {
                Ok(names) => {
                    let expires_at =
                        broker::active_session_expiry(&resolved.name, &resolved.vault)?
                            .context("broker session can serve env names but has no expiry")?;
                    term::emit_header(&term::Header {
                        command: Some("unlock"),
                        project: &resolved.name,
                        path: Some(&resolved.path),
                        mode: Some("verify"),
                    });
                    term::ok_detail(
                        "broker session",
                        &format!("expires {}", expires_at.to_rfc3339()),
                    );
                    term::ok_detail("env names in memory", &names.len().to_string());
                }
                Err(_) => anyhow::bail!(
                    "broker has no active session for {}; run ward unlock --ttl 8h",
                    resolved.name
                ),
            }
        }
        return Ok(());
    }
    let passphrase = vault::read_existing_passphrase()?;
    let selector = workspace_target::TargetSelector { project, app, all };
    let targets = workspace_target::resolve_many_with_passphrase(&selector, &cwd, &passphrase)?;
    for target in targets {
        let resolved = target.resolved_project();
        registry::update_project_vault(
            &resolved.name,
            resolved.path.clone(),
            resolved.vault.clone(),
        )?;
        let session =
            create_run_unlock_session(&resolved.name, &resolved.vault, &passphrase, ttl, mode)?;
        term::emit_header(&term::Header {
            command: Some("unlock"),
            project: &resolved.name,
            path: Some(&resolved.path),
            mode,
        });
        if let Some(mode_name) = mode {
            term::ok_detail("vault unlocked", &format!("mode {mode_name}"));
        } else {
            term::ok("vault unlocked");
        }
        term::ok_detail(
            "session active",
            &format!("expires {}", session.expires_at.to_rfc3339()),
        );
    }
    Ok(())
}

fn lock(
    project: Option<String>,
    app: Option<String>,
    workspace_scope: bool,
    all: bool,
) -> Result<()> {
    if project.is_some() && app.is_some() {
        anyhow::bail!("choose either --project or --app, not both");
    }
    if all && (project.is_some() || app.is_some() || workspace_scope) {
        anyhow::bail!("--all cannot be combined with --project, --app, or --workspace");
    }
    if workspace_scope && (project.is_some() || app.is_some()) {
        anyhow::bail!("--workspace cannot be combined with --project or --app");
    }

    if project.is_some() || app.is_some() || workspace_scope {
        let cwd = env::current_dir()?;
        let targets = if workspace_scope {
            let discovery = workspace::discover_containing(&cwd)?
                .context("--workspace requires running inside a Ward workspace")?;
            let targets = workspace_target::configured_workspace_targets(&discovery)?;
            if targets.is_empty() {
                anyhow::bail!("workspace has no configured Ward app projects");
            }
            targets
        } else {
            vec![workspace_target::resolve_one(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
            )?]
        };

        for target in targets {
            let status = broker::lock_project(&target.name, &target.vault)?;
            term::emit_header(&term::Header {
                command: Some("lock"),
                project: &status.project,
                path: Some(&target.path),
                mode: None,
            });
            term::ok_detail(
                "broker session removed",
                &status.broker_session_removed.to_string(),
            );
            term::ok_detail(
                "session grants revoked",
                &status.revoked_session_grants.to_string(),
            );
            term::ok_detail(
                "unlock metadata cleared",
                &status.cleared_unlock_sessions.to_string(),
            );
            term::ok_detail(
                "human commands cancelled",
                &status.cancelled_human_commands.to_string(),
            );
        }
        return Ok(());
    }

    let _ = all;
    if crate::human::is_human_terminal() {
        let _ = crate::human::send_guardian_shutdown();
    }
    let revoked = grants::revoke_session_grants()?;
    let cleared_unlocks = unlock::clear_all_unlocks()?;
    broker::stop()?;
    let event = VaultLockEvent {
        event_type: "vault.lock",
        revoked_session_grants: revoked,
        cleared_unlock_sessions: cleared_unlocks,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    term::emit_header(&term::Header {
        command: Some("lock"),
        project: "all projects",
        path: None,
        mode: None,
    });
    term::ok_detail("session grants revoked", &revoked.to_string());
    term::ok_detail("unlock metadata cleared", &cleared_unlocks.to_string());
    Ok(())
}

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

    let plaintext = vault::decrypt_vault_file(&old_vault, &passphrase)?;
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

fn prompt_shell_reload(_rc: &Path) {
    #[cfg(not(coverage))]
    {
        let reload = inquire::Confirm::new("Reload your shell now to activate Ward hooks?")
            .with_help_message("After reload, run ward human to protect this terminal.")
            .with_default(true)
            .prompt()
            .unwrap_or(false);
        if reload {
            let marker = broker::run_dir().join("shell-reload");
            crate::fs_util::ensure_private_dir(&broker::run_dir()).ok();
            fs::write(&marker, "").ok();
            // Fallback if the ward() shell function isn't installed yet.
            term::next("reload with: exec $SHELL && ward human");
        } else {
            term::next("when ready: exec $SHELL && ward human");
        }
    }
    #[cfg(coverage)]
    {
        let _ = rc;
        term::next("reload with: exec $SHELL && ward human");
    }
}

fn ensure_shell_integration() -> Option<PathBuf> {
    let shell = detect_shell()?;
    let rc_path = shell_rc_path(&shell)?;
    let contents = fs::read_to_string(&rc_path).unwrap_or_default();
    let updated = install_shell_integration_contents(&shell, &contents);
    if updated == contents {
        return None;
    }
    if fs::write(&rc_path, updated).is_ok() {
        Some(rc_path)
    } else {
        None
    }
}

fn install_shell_integration_contents(shell: &str, contents: &str) -> String {
    let mut updated = strip_ward_shell_integration(contents)
        .trim_end_matches('\n')
        .to_string();
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    if !shell_path_present(&updated, shell) {
        updated.push_str(shell_path_snippet(shell));
        updated.push('\n');
    }
    updated.push_str(shell_integration_snippet(shell));
    updated
}

fn strip_ward_shell_integration(contents: &str) -> String {
    let lines = contents.lines().collect::<Vec<_>>();
    let mut retained = Vec::with_capacity(lines.len());
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim() == "# ward shell integration" {
            index += 1;
            if index < lines.len() {
                let next = lines[index].trim();
                if next == "if command -v ward >/dev/null 2>&1; then" || next == "if type -q ward" {
                    index += 1;
                    while index < lines.len()
                        && lines[index].trim() != "fi"
                        && lines[index].trim() != "end"
                    {
                        index += 1;
                    }
                    if index < lines.len() {
                        index += 1;
                    }
                } else if next == "eval \"$(ward shell-init)\""
                    || next == "ward shell-init | source"
                {
                    index += 1;
                }
            }
            while index < lines.len() && lines[index].trim().is_empty() {
                index += 1;
            }
            continue;
        }
        retained.push(lines[index]);
        index += 1;
    }
    let mut stripped = retained.join("\n");
    if contents.ends_with('\n') && !stripped.is_empty() {
        stripped.push('\n');
    }
    stripped
}

fn shell_path_present(contents: &str, shell: &str) -> bool {
    if shell == "fish" {
        contents.contains(".cargo/bin")
    } else {
        contents.contains("export PATH=\"$HOME/.cargo/bin:$PATH\"")
            || contents.contains("export PATH=\"$HOME/.cargo/bin:${PATH}\"")
            || contents.contains("export PATH=$HOME/.cargo/bin:$PATH")
    }
}

fn shell_path_snippet(shell: &str) -> &'static str {
    if shell == "fish" {
        "# Added by ward installer\nfish_add_path \"$HOME/.cargo/bin\"\n"
    } else {
        "# Added by ward installer\nexport PATH=\"$HOME/.cargo/bin:$PATH\"\n"
    }
}

fn shell_integration_snippet(shell: &str) -> &'static str {
    if shell == "fish" {
        "# ward shell integration\nif type -q ward\n    set -gx WARD_SHELL_INTEGRATION 1\n    ward shell-init | source\nend\n"
    } else {
        "# ward shell integration\nif command -v ward >/dev/null 2>&1; then\n  export WARD_SHELL_INTEGRATION=1\n  eval \"$(ward shell-init)\"\nfi\n"
    }
}

fn shell_rc_path(shell: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let path = match shell {
        "zsh" => home.join(".zshrc"),
        "bash" => {
            let candidate = home.join(".bashrc");
            if candidate.exists() {
                candidate
            } else {
                home.join(".bash_profile")
            }
        }
        "fish" => home.join(".config").join("fish").join("config.fish"),
        _ => return None,
    };
    Some(path)
}

fn shell_init(shell_override: Option<&str>) -> Result<()> {
    let shell = shell_override
        .map(str::to_string)
        .or_else(detect_shell)
        .unwrap_or_else(|| "sh".to_string());
    print!("{}", shell_init_code(&shell));
    Ok(())
}

fn detect_shell() -> Option<String> {
    std::env::var("SHELL").ok().and_then(|s| {
        std::path::Path::new(&s)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
    })
}

fn collect_command_prefixes(cwd: &Path) -> Vec<String> {
    let mut prefixes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for prefix in default_human_wrapped_commands() {
        prefixes.insert(prefix.to_string());
    }

    if let Ok(project_config) = config::read_project_config(cwd) {
        for profile in project_config.profiles.values() {
            if let Some(prefix) = profile.command.split_whitespace().next() {
                prefixes.insert(prefix.to_string());
            }
        }
        for preset in &project_config.presets {
            for cmd in &preset.match_commands {
                if let Some(prefix) = cmd.split_whitespace().next() {
                    prefixes.insert(prefix.to_string());
                }
            }
        }
    }

    if let Ok(mode_configs) = modes::load_local_modes(cwd) {
        for mode in &mode_configs {
            for cmd in &mode.allowed_commands {
                if let Some(raw) = cmd.split_whitespace().next() {
                    let prefix = raw.trim_matches('*').trim_matches('/');
                    if !prefix.is_empty() {
                        prefixes.insert(prefix.to_string());
                    }
                }
            }
        }
    }

    prefixes
        .into_iter()
        .filter(|p| is_safe_shell_function_name(p))
        .collect()
}

fn default_human_wrapped_commands() -> &'static [&'static str] {
    &[
        "bun",
        "cargo",
        "deno",
        "dotenv",
        "drizzle-kit",
        "next",
        "node",
        "npm",
        "npx",
        "pnpm",
        "prisma",
        "tsx",
        "ts-node",
        "vite",
        "yarn",
    ]
}

fn is_safe_shell_function_name(name: &str) -> bool {
    if name == "ward" {
        return false;
    }
    const BUILTINS: &[&str] = &[
        "cd", "echo", "export", "source", ".", "exec", "exit", "set", "unset", "alias", "eval",
        "read", "printf", "test", "[", "[[", "true", "false", "return", "break", "continue",
        "shift", "trap",
    ];
    if BUILTINS.iter().any(|b| *b == name) {
        return false;
    }
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        && !name.starts_with('-')
}

fn shell_init_code(shell: &str) -> String {
    let ward_home = audit_logs::ward_home();
    let sock_path = ward_home
        .join("run")
        .join("human-$$/guardian.sock")
        .display()
        .to_string();

    let cwd = env::current_dir().unwrap_or_default();
    let cmds = collect_command_prefixes(&cwd);
    let cmds_ref: Vec<&str> = cmds.iter().map(String::as_str).collect();

    if shell == "fish" {
        fish_init_code(&ward_home, &cmds_ref)
    } else {
        posix_init_code(shell, &ward_home, &sock_path, &cmds_ref)
    }
}

fn posix_init_code(
    shell: &str,
    ward_home: &std::path::Path,
    sock_path: &str,
    cmds: &[&str],
) -> String {
    let mut out =
        String::from("# ward shell integration — only active in human mode inside ward projects\n");
    out.push_str("export WARD_SHELL_INTEGRATION=1\n");
    out.push_str("__ward_project_root() {\n");
    out.push_str("  __ward_dir=\"$PWD\"\n");
    out.push_str("  while [ -n \"$__ward_dir\" ]; do\n");
    out.push_str("    if [ -f \"$__ward_dir/.ward.json\" ]; then\n");
    out.push_str("      printf '%s\\n' \"$__ward_dir\"\n");
    out.push_str("      return 0\n");
    out.push_str("    fi\n");
    out.push_str("    if [ \"$__ward_dir\" = \"/\" ]; then\n");
    out.push_str("      break\n");
    out.push_str("    fi\n");
    out.push_str("    __ward_dir=$(dirname \"$__ward_dir\")\n");
    out.push_str("  done\n");
    out.push_str("  return 1\n");
    out.push_str("}\n");
    out.push_str("__ward_workspace_root() {\n");
    out.push_str("  __ward_dir=\"$PWD\"\n");
    out.push_str("  while [ -n \"$__ward_dir\" ]; do\n");
    out.push_str("    if [ -f \"$__ward_dir/pnpm-workspace.yaml\" ] || [ -f \"$__ward_dir/turbo.json\" ]; then\n");
    out.push_str("      printf '%s\\n' \"$__ward_dir\"\n");
    out.push_str("      return 0\n");
    out.push_str("    fi\n");
    out.push_str("    if [ \"$__ward_dir\" = \"/\" ]; then\n");
    out.push_str("      break\n");
    out.push_str("    fi\n");
    out.push_str("    __ward_dir=$(dirname \"$__ward_dir\")\n");
    out.push_str("  done\n");
    out.push_str("  return 1\n");
    out.push_str("}\n");
    out.push_str("__ward_app_from_command() {\n");
    out.push_str("  case \"$1\" in\n");
    out.push_str("    pnpm|npm|yarn|bun)\n");
    out.push_str("      shift\n");
    out.push_str("      while [ $# -gt 0 ]; do\n");
    out.push_str("        case \"$1\" in\n");
    out.push_str("          --filter|--workspace)\n");
    out.push_str("            shift\n");
    out.push_str("            [ -n \"$1\" ] && printf '%s\\n' \"$1\" && return 0\n");
    out.push_str("            ;;\n");
    out.push_str("          --filter=*|--workspace=*)\n");
    out.push_str("            printf '%s\\n' \"${1#*=}\"\n");
    out.push_str("            return 0\n");
    out.push_str("            ;;\n");
    out.push_str("        esac\n");
    out.push_str("        shift\n");
    out.push_str("      done\n");
    out.push_str("      ;;\n");
    out.push_str("  esac\n");
    out.push_str("  return 1\n");
    out.push_str("}\n");
    out.push_str("__ward_wrap() {\n");
    out.push_str("  __ward_root=\"$(__ward_project_root)\"\n");
    out.push_str("  __ward_workspace=\"$(__ward_workspace_root)\"\n");
    out.push_str("  if [ -z \"$__ward_root\" ] && [ -z \"$__ward_workspace\" ]; then\n");
    out.push_str("    command \"$@\"\n");
    out.push_str("    return $?\n");
    out.push_str("  fi\n");
    out.push_str(&format!("  if [ -S \"{sock_path}\" ]; then\n"));
    out.push_str("    if [ -n \"$__ward_root\" ]; then\n");
    out.push_str("    WARD_HUMAN_SHELL_PID=$$ command ward run -- \"$@\"\n");
    out.push_str("    return $?\n");
    out.push_str("    fi\n");
    out.push_str("    __ward_app=\"$(__ward_app_from_command \"$@\")\"\n");
    out.push_str("    if [ -n \"$__ward_app\" ]; then\n");
    out.push_str(
        "      WARD_HUMAN_SHELL_PID=$$ command ward run --app \"$__ward_app\" -- \"$@\"\n",
    );
    out.push_str("      return $?\n");
    out.push_str("    fi\n");
    out.push_str("    printf '%s\\n' 'Ward could not map this workspace-root command to one app; rerun with ward run --app <app> -- <command>' >&2\n");
    out.push_str("    return 126\n");
    out.push_str("  fi\n");
    out.push_str(
        "  printf '%s\\n' 'Ward human mode is not active for this terminal; run ward human' >&2\n",
    );
    out.push_str("  printf '%s\\n' \"shell pid: $$\" >&2\n");
    out.push_str(&format!(
        "  printf '%s\\n' \"expected guardian: {sock_path}\" >&2\n"
    ));
    out.push_str("  return 126\n");
    out.push_str("}\n");
    if shell == "zsh" {
        out.push_str(&zsh_prompt_badge_code(sock_path));
    }
    let reload_marker = ward_home
        .join("run")
        .join("shell-reload")
        .display()
        .to_string();
    out.push_str("ward() {\n");
    out.push_str("  WARD_HUMAN_SHELL_PID=$$ command ward \"$@\"\n");
    out.push_str("  __ward_exit=$?\n");
    out.push_str("  case \"$1\" in\n");
    out.push_str("    setup|init)\n");
    out.push_str(&format!("      if [ -f \"{reload_marker}\" ]; then\n"));
    out.push_str(&format!("        rm -f \"{reload_marker}\"\n"));
    out.push_str("        exec $SHELL\n");
    out.push_str("      fi\n");
    out.push_str("      ;;\n");
    out.push_str("  esac\n");
    out.push_str("  return $__ward_exit\n");
    out.push_str("}\n");
    for cmd in cmds {
        out.push_str(&format!("{cmd}() {{ __ward_wrap {cmd} \"$@\"; }}\n"));
    }
    // Catch-all fallback: routes unknown commands through ward when in human mode.
    // bash uses command_not_found_handle, zsh uses command_not_found_handler.
    out.push_str("command_not_found_handle() { __ward_wrap \"$@\"; }\n");
    out.push_str("command_not_found_handler() { __ward_wrap \"$@\"; }\n");
    out
}

fn zsh_prompt_badge_code(sock_path: &str) -> String {
    let mut out = String::new();
    out.push_str("if [ -n \"${ZSH_VERSION:-}\" ]; then\n");
    out.push_str("__WARD_HUMAN_BADGE='%F{135}◬ ward:human%f'\n");
    out.push_str("__WARD_LOCKED_BADGE='%F{244}ward:locked%f'\n");
    out.push_str("__ward_prompt_badge() {\n");
    out.push_str("  __ward_root=\"$(__ward_project_root)\"\n");
    out.push_str("  __ward_workspace=\"$(__ward_workspace_root)\"\n");
    out.push_str("  if [ -z \"$__ward_root\" ] && [ -z \"$__ward_workspace\" ]; then\n");
    out.push_str("    return 0\n");
    out.push_str("  fi\n");
    out.push_str(&format!("  if [ -S \"{sock_path}\" ]; then\n"));
    out.push_str("    printf '%s' \"$__WARD_HUMAN_BADGE\"\n");
    out.push_str("  else\n");
    out.push_str("    printf '%s' \"$__WARD_LOCKED_BADGE\"\n");
    out.push_str("  fi\n");
    out.push_str("}\n");
    out.push_str("__ward_prompt_without_badge() {\n");
    out.push_str("  __ward_prompt=\"${1:-}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// $__WARD_HUMAN_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//$__WARD_HUMAN_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// $__WARD_LOCKED_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//$__WARD_LOCKED_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// ◬ ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//◬ ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// ward:locked/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//ward:locked/}\"\n");
    out.push_str("  printf '%s' \"$__ward_prompt\"\n");
    out.push_str("}\n");
    out.push_str("__ward_precmd() {\n");
    out.push_str("  __ward_badge=\"$(__ward_prompt_badge)\"\n");
    out.push_str("  RPROMPT=\"$(__ward_prompt_without_badge \"${RPROMPT:-}\")\"\n");
    out.push_str("  if [ -n \"$__ward_badge\" ]; then\n");
    out.push_str("    if [ -n \"$RPROMPT\" ]; then\n");
    out.push_str("      RPROMPT=\"$RPROMPT $__ward_badge\"\n");
    out.push_str("    else\n");
    out.push_str("      RPROMPT=\"$__ward_badge\"\n");
    out.push_str("    fi\n");
    out.push_str("  fi\n");
    out.push_str("}\n");
    out.push_str("if ! (( ${precmd_functions[(I)__ward_precmd]} )); then\n");
    out.push_str("  precmd_functions+=(__ward_precmd)\n");
    out.push_str("fi\n");
    out.push_str("__ward_precmd\n");
    out.push_str("fi\n");
    out
}

fn fish_init_code(ward_home: &std::path::Path, cmds: &[&str]) -> String {
    let sock_dir = ward_home.join("run").display().to_string();
    let mut out =
        String::from("# ward shell integration — only active in human mode inside ward projects\n");
    out.push_str("set -gx WARD_SHELL_INTEGRATION 1\n");
    out.push_str("function __ward_project_root\n");
    out.push_str("    set dir (pwd)\n");
    out.push_str("    while test -n \"$dir\"\n");
    out.push_str("        if test -f \"$dir/.ward.json\"\n");
    out.push_str("            echo $dir\n");
    out.push_str("            return 0\n");
    out.push_str("        end\n");
    out.push_str("        if test \"$dir\" = \"/\"\n");
    out.push_str("            break\n");
    out.push_str("        end\n");
    out.push_str("        set dir (dirname \"$dir\")\n");
    out.push_str("    end\n");
    out.push_str("    return 1\n");
    out.push_str("end\n");
    out.push_str("function __ward_workspace_root\n");
    out.push_str("    set dir (pwd)\n");
    out.push_str("    while test -n \"$dir\"\n");
    out.push_str(
        "        if test -f \"$dir/pnpm-workspace.yaml\"; or test -f \"$dir/turbo.json\"\n",
    );
    out.push_str("            echo $dir\n");
    out.push_str("            return 0\n");
    out.push_str("        end\n");
    out.push_str("        if test \"$dir\" = \"/\"\n");
    out.push_str("            break\n");
    out.push_str("        end\n");
    out.push_str("        set dir (dirname \"$dir\")\n");
    out.push_str("    end\n");
    out.push_str("    return 1\n");
    out.push_str("end\n");
    out.push_str("function __ward_app_from_command\n");
    out.push_str("    switch $argv[1]\n");
    out.push_str("        case pnpm npm yarn bun\n");
    out.push_str("            set args $argv[2..-1]\n");
    out.push_str("            set i 1\n");
    out.push_str("            while test $i -le (count $args)\n");
    out.push_str("                set arg $args[$i]\n");
    out.push_str(
        "                if test \"$arg\" = \"--filter\"; or test \"$arg\" = \"--workspace\"\n",
    );
    out.push_str("                    set i (math $i + 1)\n");
    out.push_str(
        "                    test $i -le (count $args); and echo $args[$i]; and return 0\n",
    );
    out.push_str("                else if string match -q -- '--filter=*' $arg; or string match -q -- '--workspace=*' $arg\n");
    out.push_str("                    string replace -r '^[^=]+=' '' $arg\n");
    out.push_str("                    return 0\n");
    out.push_str("                end\n");
    out.push_str("                set i (math $i + 1)\n");
    out.push_str("            end\n");
    out.push_str("    end\n");
    out.push_str("    return 1\n");
    out.push_str("end\n");
    out.push_str("function __ward_wrap\n");
    // Use $fish_pid directly — it's the fish shell PID, matching getppid() in child processes.
    out.push_str(&format!(
        "    set sock \"{sock_dir}/human-$fish_pid/guardian.sock\"\n"
    ));
    out.push_str("    set project_root (__ward_project_root)\n");
    out.push_str("    set workspace_root (__ward_workspace_root)\n");
    out.push_str("    if test -z \"$project_root\"; and test -z \"$workspace_root\"\n");
    out.push_str("        command $argv\n");
    out.push_str("        return $status\n");
    out.push_str("    end\n");
    out.push_str("    if test -S $sock\n");
    out.push_str("        if test -n \"$project_root\"\n");
    out.push_str("        env WARD_HUMAN_SHELL_PID=$fish_pid command ward run -- $argv\n");
    out.push_str("        return $status\n");
    out.push_str("        end\n");
    out.push_str("        set app (__ward_app_from_command $argv)\n");
    out.push_str("        if test -n \"$app\"\n");
    out.push_str(
        "            env WARD_HUMAN_SHELL_PID=$fish_pid command ward run --app \"$app\" -- $argv\n",
    );
    out.push_str("            return $status\n");
    out.push_str("        end\n");
    out.push_str("        echo 'Ward could not map this workspace-root command to one app; rerun with ward run --app <app> -- <command>' >&2\n");
    out.push_str("        return 126\n");
    out.push_str("    else\n");
    out.push_str(
        "        echo 'Ward human mode is not active for this terminal; run ward human' >&2\n",
    );
    out.push_str("        echo \"shell pid: $fish_pid\" >&2\n");
    out.push_str("        echo \"expected guardian: $sock\" >&2\n");
    out.push_str("        return 126\n");
    out.push_str("    end\n");
    out.push_str("end\n");
    out.push_str("function ward\n");
    out.push_str("    env WARD_HUMAN_SHELL_PID=$fish_pid command ward $argv\n");
    out.push_str("    set __ward_exit $status\n");
    out.push_str("    if contains -- $argv[1] setup init\n");
    out.push_str("        source ~/.config/fish/config.fish 2>/dev/null\n");
    out.push_str("    end\n");
    out.push_str("    return $__ward_exit\n");
    out.push_str("end\n");
    for cmd in cmds {
        out.push_str(&format!("function {cmd}; __ward_wrap {cmd} $argv; end\n"));
    }
    // Catch-all fallback for any command not found in PATH while in human mode.
    out.push_str("function __ward_command_not_found --on-event fish_command_not_found\n");
    out.push_str("    __ward_wrap $argv\n");
    out.push_str("end\n");
    out
}

fn modes_command(command: ModesCommand) -> Result<()> {
    match command {
        ModesCommand::List { project, app } => {
            let cwd = env::current_dir()?;
            let target = workspace_target::resolve_one(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
            )?;
            let resolved = target.resolved_project();
            let modes = modes::load_local_modes(&resolved.path)?;
            term::emit_header(&term::Header {
                command: Some("modes list"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            if modes.is_empty() {
                term::info("no modes defined in .ward.modes.json");
            } else {
                for mode in &modes {
                    let level = serde_json::to_string(&mode.level)
                        .unwrap_or_default()
                        .trim_matches('"')
                        .to_string();
                    term::ok_detail(&mode.name, &level);
                }
            }
            Ok(())
        }
        ModesCommand::Push {
            project,
            app,
            global: _,
        } => {
            let cwd = env::current_dir()?;
            let selector = workspace_target::TargetSelector::one(project, app);
            let initial = workspace_target::resolve_one(&selector, &cwd)?.resolved_project();
            let modes_path = modes::local_modes_path(&initial.path);
            let local_modes = modes::load_local_modes(&initial.path)?;
            if local_modes.is_empty() {
                anyhow::bail!("no modes found in {}", modes_path.display());
            }
            let passphrase = vault::read_existing_passphrase()?;
            let resolved =
                workspace_target::resolve_one_with_passphrase(&selector, &cwd, &passphrase)?
                    .resolved_project();
            // Validate passphrase by decrypting the vault
            with_passphrase_vault_access(&resolved, &passphrase, || {
                vault::decrypt_vault_file(&resolved.vault, &passphrase)
                    .context("invalid passphrase — cannot push modes")
            })?;
            modes::push_modes(&local_modes, &resolved.name, &passphrase, &modes_path)?;
            term::emit_header(&term::Header {
                command: Some("modes push"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            term::ok_detail("modes pushed", &format!("{} mode(s)", local_modes.len()));
            Ok(())
        }
        ModesCommand::Status { project, app } => {
            let cwd = env::current_dir()?;
            let target = workspace_target::resolve_one(
                &workspace_target::TargetSelector::one(project, app),
                &cwd,
            )?;
            let resolved = target.resolved_project();
            term::emit_header(&term::Header {
                command: Some("modes status"),
                project: &resolved.name,
                path: Some(&resolved.path),
                mode: None,
            });
            match broker::status() {
                Ok(status) => {
                    let session = status.sessions.iter().find(|s| s.project == resolved.name);
                    match session.and_then(|s| s.active_mode.as_deref()) {
                        Some(mode_name) => term::ok_detail("active mode", mode_name),
                        None => term::info("no active mode"),
                    }
                }
                Err(_) => term::warn("broker not running; no active mode"),
            }
            Ok(())
        }
    }
}

fn teardown(
    project: Option<String>,
    app: Option<String>,
    export_path: PathBuf,
    yes: bool,
    restore_env: bool,
) -> Result<()> {
    if !yes {
        anyhow::bail!("teardown requires --yes");
    }
    let cwd = env::current_dir()?;
    let selector = workspace_target::TargetSelector::one(project, app);
    if env::var_os("WARD_UNSAFE_TEST_PASSPHRASE").is_none() && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "teardown requires the vault PIN/passphrase; --yes only skips destructive confirmation and does not bypass secret export approval"
        );
    }
    let passphrase = vault::read_existing_passphrase().context(
        "teardown requires the vault PIN/passphrase even with --yes; run from an interactive terminal or set the unsafe test passphrase only in tests",
    )?;
    let resolved = workspace_target::resolve_one_with_passphrase(&selector, &cwd, &passphrase)?
        .resolved_project();
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::decrypt_vault_file(&resolved.vault, &passphrase)
    })?;
    let outcome = crate::project_teardown::teardown_project(
        crate::project_teardown::ProjectTeardownRequest {
            project: resolved.name.clone(),
            path: resolved.path.clone(),
            vault: resolved.vault.clone(),
            export_path,
            restore_env,
            decrypt_key: passphrase,
        },
    )?;
    term::emit_header(&term::Header {
        command: Some("teardown"),
        project: &outcome.project,
        path: Some(&resolved.path),
        mode: None,
    });
    term::ok_detail("plaintext export", &term::short_path(&outcome.export_path));
    term::ok("Ward project removed");
    term::ok("encrypted audit logs preserved");
    Ok(())
}

fn unlock_logs(ttl: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let passphrase = vault::read_existing_passphrase()?;
    let resolved = registry::resolve_project_with_passphrase(None, &cwd, &passphrase)?;
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::decrypt_vault_file(&resolved.vault, &passphrase)
    })?;
    let event = LogsUnlockEvent {
        event_type: "logs.unlock",
        project: &resolved.name,
        vault: &resolved.vault,
        expires_at: "deprecated-validate-only".to_string(),
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    term::emit_header(&term::Header {
        command: Some("logs unlock"),
        project: &resolved.name,
        path: Some(&resolved.path),
        mode: None,
    });
    term::warn("logs unlock is deprecated");
    term::info("logs view/export validates the passphrase every time");
    term::info_detail("requested TTL ignored", ttl);
    Ok(())
}

fn ensure_logs_passphrase() -> Result<()> {
    let cwd = env::current_dir()?;
    let passphrase = vault::read_existing_passphrase()?;
    let resolved = registry::resolve_project_with_passphrase(None, &cwd, &passphrase)?;
    with_passphrase_vault_access(&resolved, &passphrase, || {
        vault::decrypt_vault_file(&resolved.vault, &passphrase)
    })?;
    Ok(())
}

fn warn_log_view_access() {
    term::emit_block(&term::MessageBlock {
        level: term::StatusLevel::Warn,
        title: "decrypted logs are for review only",
        body: Some(
            "edits are tamper-evident through the hash chain; deleted logs should be treated as high severity",
        ),
        command: None,
    });
}

fn resolve_profile(
    config: &config::ProjectConfig,
    profile: Option<&str>,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
) -> Result<ResolvedProfile> {
    if let Some(profile_name) = profile {
        if command.is_some() || !env_names.is_empty() {
            anyhow::bail!("--profile cannot be combined with --command or --env");
        }
        let Some(profile) = config.profiles.get(profile_name) else {
            anyhow::bail!("profile {profile_name} is not defined in .ward.json");
        };
        return Ok(ResolvedProfile {
            command: profile.command.clone(),
            command_args: split_profile_command(&profile.command),
            env_names: profile.env.clone(),
            action: action.or_else(|| Some(profile.action.clone())),
            default_scope: profile.default_scope,
        });
    }

    let command = command.context("--command is required unless --profile is used")?;
    if env_names.is_empty() {
        anyhow::bail!("at least one --env is required unless --profile is used");
    }
    Ok(ResolvedProfile {
        command: command.clone(),
        command_args: split_profile_command(&command),
        env_names,
        action,
        default_scope: ApprovalScope::Once,
    })
}

fn resolve_run_profile(
    config: &config::ProjectConfig,
    profile: Option<&str>,
    action: Option<String>,
    env_names: Vec<String>,
    command: Vec<String>,
    allow_empty_env: bool,
) -> Result<ResolvedProfile> {
    if let Some(profile_name) = profile {
        if !env_names.is_empty() {
            anyhow::bail!("--profile cannot be combined with --env");
        }
        let Some(profile) = config.profiles.get(profile_name) else {
            anyhow::bail!("profile {profile_name} is not defined in .ward.json");
        };
        let mut command_args = split_profile_command(&profile.command);
        command_args.extend(command);
        let command_text = if command_args.is_empty() {
            profile.command.clone()
        } else {
            command_args.join(" ")
        };
        return Ok(ResolvedProfile {
            command: command_text,
            command_args,
            env_names: profile.env.clone(),
            action: action.or_else(|| Some(profile.action.clone())),
            default_scope: profile.default_scope,
        });
    }

    if command.is_empty() {
        anyhow::bail!("command args are required unless --profile is used");
    }
    if env_names.is_empty() && !allow_empty_env {
        anyhow::bail!("at least one --env is required unless --profile is used");
    }
    Ok(ResolvedProfile {
        command: command.join(" "),
        command_args: command,
        env_names,
        action,
        default_scope: ApprovalScope::Once,
    })
}

fn split_profile_command(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn effective_grant_id(
    decision: &ApprovalDecision,
    persisted_grant: Option<&grants::ApprovalGrant>,
) -> Option<uuid::Uuid> {
    decision
        .grant_id
        .or_else(|| persisted_grant.map(|grant| grant.id))
}

fn grant_receipt_hash(
    decision: &ApprovalDecision,
    persisted_grant: Option<&grants::ApprovalGrant>,
) -> Result<Option<String>> {
    if let Some(grant) = persisted_grant {
        return Ok(grant
            .receipt
            .as_ref()
            .map(|receipt| receipt.payload_hash.clone()));
    }
    let Some(grant_id) = decision.grant_id else {
        return Ok(None);
    };
    Ok(grants::load_grants()?
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .and_then(|grant| grant.receipt.map(|receipt| receipt.payload_hash)))
}

fn log_anomaly_alerts(config: &config::ProjectConfig, grant_id: Option<uuid::Uuid>) -> Result<()> {
    let Some(grant_id) = grant_id else {
        return Ok(());
    };
    let events = audit_logs::decrypt_events(LogKind::Executions)?;
    for alert in anomaly::detect_grant_anomalies(
        &config.anomaly_detection,
        &events,
        grant_id,
        chrono::Utc::now(),
    ) {
        audit_logs::append_event(LogKind::Alerts, alert)?;
    }
    Ok(())
}

fn evaluate_access(
    config: &config::ProjectConfig,
    access: &AccessRequest,
) -> policy::PolicyEvaluation {
    let findings =
        detection::preflight_findings(&access.command, &access.env, access.action.as_deref());
    policy::evaluate_request(config, access, None, findings)
}

fn request_audit_snapshot<'a>(
    access: &'a AccessRequest,
    evaluation: &'a policy::PolicyEvaluation,
    git: &'a git_context::GitContext,
    verified_context: Option<&'a context::VerifiedContext>,
) -> RequestAuditSnapshot<'a> {
    RequestAuditSnapshot {
        project: &access.project,
        agent: &access.agent,
        branch: &access.branch,
        action: &access.action,
        command: &access.command,
        env: &access.env,
        requested_env: &evaluation.requested_env,
        matched_profile: &evaluation.matched_profile,
        matched_preset: &evaluation.matched_preset,
        matched_mode: &evaluation.matched_mode,
        policy_findings: &evaluation.findings,
        git,
        verified_context,
    }
}

fn approval_channel_for_source(source: approvals::ApprovalSource) -> ApprovalChannel {
    match source {
        approvals::ApprovalSource::LocalTty => ApprovalChannel::LocalPrompt,
        approvals::ApprovalSource::ManualAllow => ApprovalChannel::ManualAllow,
        approvals::ApprovalSource::AgentMediated => ApprovalChannel::AgentMediatedCli,
        approvals::ApprovalSource::BrokerApproval => ApprovalChannel::Dashboard,
        approvals::ApprovalSource::Grant => ApprovalChannel::GrantReuse,
        approvals::ApprovalSource::PolicyAuto => ApprovalChannel::PolicyAuto,
        approvals::ApprovalSource::PolicyDeny => ApprovalChannel::PolicyDeny,
    }
}

fn grant_origin_request_id(decision: &ApprovalDecision) -> Option<uuid::Uuid> {
    if decision.source != approvals::ApprovalSource::Grant {
        return None;
    }
    let grant_id = decision.grant_id?;
    grants::load_grants()
        .ok()?
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .and_then(|grant| grant.request_id)
}

fn should_log_approval_event(decision: &ApprovalDecision) -> bool {
    decision.source != approvals::ApprovalSource::Grant
}

fn approval_human_proof(source: approvals::ApprovalSource) -> Option<&'static str> {
    match source {
        approvals::ApprovalSource::AgentMediated => Some("external-agent-ui"),
        approvals::ApprovalSource::BrokerApproval => Some("broker-approval"),
        approvals::ApprovalSource::LocalTty => Some("local-tty"),
        approvals::ApprovalSource::ManualAllow => Some("local-cli"),
        _ => None,
    }
}

fn critical_confirmation_for_decision(
    decision: &ApprovalDecision,
    evaluation: &policy::PolicyEvaluation,
) -> bool {
    decision.approved
        && decision.scope == ApprovalScope::Once
        && detection::has_critical_findings(&evaluation.findings)
}

fn handle_post_run_logging_result(exit_code: i32, result: Result<()>) -> Result<()> {
    if let Err(error) = result {
        term::warn_detail("post-run audit logging failed", &error.to_string());
        if exit_code == 0 {
            anyhow::bail!("Ward post-run audit logging failed");
        }
    }
    Ok(())
}

fn warn_anomaly_failure(result: Result<()>) {
    if let Err(error) = result {
        term::warn_detail("anomaly detection failed", &error.to_string());
    }
}

fn consume_once_grant_if_reused(decision: &ApprovalDecision) -> Result<()> {
    let should_consume = decision.source == approvals::ApprovalSource::Grant
        && decision.scope == ApprovalScope::Once;
    if !should_consume {
        return Ok(());
    }

    let Some(grant_id) = decision.grant_id else {
        return Ok(());
    };

    grants::consume_once_grant(grant_id).map(|_| ())
}

fn decide_access(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    allow_grants: bool,
) -> Result<ApprovalDecision> {
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        });
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    if allow_grants {
        let grant = if critical {
            grants::find_matching_once_grant(access, true)?
        } else if suspicious_action {
            grants::find_matching_non_always_grant(access)?
        } else {
            grants::find_matching_grant(access)?
        };
        if let Some(grant) = grant {
            return Ok(grants::approval_from_grant(access, &grant));
        }
    }

    if evaluation.requires_prompt {
        approvals::prompt_for_approval(access, evaluation)
    } else {
        Ok(approvals::auto_approval(evaluation))
    }
}

fn non_interactive_decision(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
) -> Result<Option<ApprovalDecision>> {
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(Some(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        }));
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    let grant = if critical {
        grants::find_matching_once_grant(access, true)?
    } else if suspicious_action {
        grants::find_matching_non_always_grant(access)?
    } else {
        grants::find_matching_grant(access)?
    };
    if let Some(grant) = grant {
        return Ok(Some(grants::approval_from_grant(access, &grant)));
    }
    if evaluation.requires_prompt {
        return Ok(None);
    }
    Ok(Some(approvals::auto_approval(evaluation)))
}

fn non_interactive_decision_with_context(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    verified_context: Option<&context::VerifiedContext>,
) -> Result<Option<ApprovalDecision>> {
    let Some(verified_context) = verified_context else {
        return non_interactive_decision(access, evaluation);
    };
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(Some(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        }));
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    let grant = if critical {
        grants::find_matching_once_grant_with_context(access, true, verified_context)?
    } else if suspicious_action {
        grants::find_matching_non_always_grant_with_context(access, verified_context)?
    } else {
        grants::find_matching_grant_with_context(access, verified_context)?
    };
    if let Some(grant) = grant {
        return Ok(Some(grants::approval_from_grant(access, &grant)));
    }
    if evaluation.requires_prompt {
        return Ok(None);
    }
    Ok(Some(approvals::auto_approval(evaluation)))
}

fn create_run_pending_request(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    git: &git_context::GitContext,
    verified_context: Option<context::VerifiedContext>,
) -> Result<pending_requests::PendingRequest> {
    pending_requests::create_pending_request_with_context(
        access.clone(),
        evaluation.clone(),
        git.clone(),
        verified_context,
    )
}

fn print_run_approval_required(pending: &pending_requests::PendingRequest) -> Result<()> {
    let response = RunApprovalRequiredResponse {
        status: "approval_required",
        unlock_required: false,
        request: pending_requests::response_for(pending),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_unlock_required(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    unlock_reason: Option<&str>,
) -> Result<()> {
    let response = RunUnlockRequiredResponse {
        status: "unlock_required",
        approval_required: false,
        unlock_required: true,
        unlock_reason,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
        unlock_command: "ward unlock --ttl 8h",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_vault_key_missing(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    missing_env: Vec<String>,
) -> Result<()> {
    let response = RunVaultKeyMissingResponse {
        status: "vault_key_missing",
        approval_required: false,
        unlock_required: false,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        missing_env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
        message: "One or more approved env vars are not present in the vault.",
        remediation: "Add/update a profile that covers this command and env name, or run ward env request-set --key <ENV_NAME> --wait-for-approval --json --no-prompt so a human can add the missing vault key.",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_denied(access: &AccessRequest, evaluation: &policy::PolicyEvaluation) -> Result<()> {
    let response = RunDeniedResponse {
        status: "denied",
        approval_required: false,
        unlock_required: false,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn wait_for_run_approval(
    pending: &pending_requests::PendingRequest,
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    verified_context: Option<&context::VerifiedContext>,
    approval_timeout: &str,
) -> Result<Option<ApprovalDecision>> {
    let timeout = unlock::parse_ttl(approval_timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    term::emit_block(&term::MessageBlock {
        level: term::StatusLevel::Info,
        title: "waiting for approval",
        body: Some("open the dashboard notification center or approve from a human terminal"),
        command: Some(&format!("ward approve {} --scope session", pending.id)),
    });

    loop {
        if let Some(resolution) = pending_requests::load_resolution(pending.id)? {
            if resolution.status == "denied" {
                print_run_wait_denied(pending.id, access)?;
                return Ok(None);
            }
            if resolution.status == "approved" {
                if let Some(decision) =
                    non_interactive_decision_with_context(access, evaluation, verified_context)?
                {
                    return Ok(Some(decision));
                }
            }
        }

        if !pending_requests::pending_request_path(pending.id).exists() {
            if let Some(decision) =
                non_interactive_decision_with_context(access, evaluation, verified_context)?
            {
                return Ok(Some(decision));
            }
        }

        if chrono::Utc::now() >= deadline {
            print_run_wait_timeout(Some(pending.id), access, "run")?;
            return Ok(None);
        }

        thread::sleep(StdDuration::from_millis(500));
    }
}

fn execute_no_prompt_with_optional_wait(
    resolved: &registry::ResolvedProject,
    cwd: &Path,
    decision: &ApprovalDecision,
    command_args: &[String],
    mut execute_payload: broker::ExecuteAuthorizationPayload,
    context: &context::VerifiedContext,
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    wait_for_approval: bool,
    approval_timeout: &str,
) -> Result<Option<runner::RunCommandOutcome>> {
    let timeout = unlock::parse_ttl(approval_timeout)?;
    let deadline = chrono::Utc::now() + timeout;
    let mut unlock_notification = None;

    loop {
        execute_payload.expires_at = chrono::Utc::now() + chrono::Duration::seconds(60);
        execute_payload.nonce = uuid::Uuid::new_v4().to_string();
        let proof_payload =
            serde_json::to_string(&execute_payload).expect("execution payload should serialize");
        let proof = agents::sign_payload(&resolved.name, &context.agent, &proof_payload)?;

        match broker::execute(
            &resolved.name,
            &resolved.vault,
            cwd,
            decision.approved_env.clone(),
            command_args.to_vec(),
            broker::ExecuteAuthorization::Agent { proof },
        ) {
            Ok(outcome) => {
                if let Some(notification_id) = unlock_notification.take() {
                    notifications::remove_block_notification(notification_id)?;
                }
                return Ok(Some(outcome));
            }
            Err(error) => {
                if let Some(missing_env) = broker_vault_key_missing_envs(&error) {
                    create_run_block_notification(
                        notifications::NotificationKind::VaultKeyMissing,
                        access,
                        evaluation,
                        "The approved request references env names that are not present in the vault.",
                        Some(
                            "ward env request-set --key <ENV_NAME> --wait-for-approval --json --no-prompt",
                        ),
                    )?;
                    print_run_vault_key_missing(access, evaluation, missing_env)?;
                    return Ok(None);
                }
                if broker_execution_rejection_is_authoritative(&error) {
                    return Err(error).context("broker rejected no-prompt execution");
                }
                if !wait_for_approval {
                    let reason = error.to_string();
                    print_run_unlock_required(access, evaluation, Some(&reason))?;
                    return Ok(None);
                }

                if unlock_notification.is_none() {
                    let notification = create_run_block_notification(
                        notifications::NotificationKind::UnlockRequired,
                        access,
                        evaluation,
                        "This request is waiting for the vault to be unlocked before it can run.",
                        Some("ward unlock --ttl 8h"),
                    )?;
                    unlock_notification = Some(notification.id);
                    term::emit_block(&term::MessageBlock {
                        level: term::StatusLevel::Warn,
                        title: "waiting for unlock",
                        body: Some("the command will resume after the broker session is active"),
                        command: Some("ward unlock --ttl 8h"),
                    });
                }

                if chrono::Utc::now() >= deadline {
                    if let Some(notification_id) = unlock_notification.take() {
                        notifications::remove_block_notification(notification_id)?;
                    }
                    print_run_wait_timeout(None, access, "unlock")?;
                    return Ok(None);
                }

                if broker::active_session_expiry(&resolved.name, &resolved.vault)?.is_some() {
                    if let Some(notification_id) = unlock_notification.take() {
                        notifications::remove_block_notification(notification_id)?;
                    }
                    continue;
                }

                thread::sleep(StdDuration::from_millis(500));
            }
        }
    }
}

fn create_run_block_notification(
    kind: notifications::NotificationKind,
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    message: &str,
    fix_command: Option<&str>,
) -> Result<notifications::BlockNotification> {
    notifications::create_block_notification(
        kind,
        &access.project,
        access.agent.as_deref(),
        Some(&access.command),
        &access.env,
        &evaluation.findings,
        run_risk_summary(evaluation),
        message,
        fix_command,
    )
}

fn print_run_wait_denied(request_id: uuid::Uuid, access: &AccessRequest) -> Result<()> {
    let response = serde_json::json!({
        "status": "denied",
        "approvalRequired": false,
        "unlockRequired": false,
        "requestId": request_id,
        "project": access.project,
        "command": access.command,
    });
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_wait_timeout(
    request_id: Option<uuid::Uuid>,
    access: &AccessRequest,
    approval_type: &str,
) -> Result<()> {
    let mut response = serde_json::json!({
        "status": "approval_timeout",
        "approvalType": approval_type,
        "project": access.project,
        "command": access.command,
    });
    if let Some(request_id) = request_id {
        response["requestId"] = serde_json::json!(request_id);
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn broker_vault_key_missing_envs(error: &anyhow::Error) -> Option<Vec<String>> {
    let broker_error = error.downcast_ref::<broker::BrokerError>()?;
    if broker_error.reason() != "vault_key_missing" {
        return None;
    }
    Some(
        broker_error
            .message()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn broker_execution_rejection_is_authoritative(error: &anyhow::Error) -> bool {
    let Some(broker_error) = error.downcast_ref::<broker::BrokerError>() else {
        return false;
    };
    matches!(
        broker_error.reason(),
        "agent_proof_invalid"
            | "agent_self_approval_rejected"
            | "approval_required"
            | "broker_client_untrusted"
            | "execute_authorization_expired"
            | "execute_authorization_invalid"
            | "execute_authorization_mismatch"
            | "execute_authorization_replayed"
            | "execute_authorization_required"
            | "grant_lookup_failed"
            | "human_approval_required"
            | "human_session_required"
            | "mode_confirmation_required"
            | "mode_env_violation"
            | "policy_denied"
            | "security_policy_violation"
    )
}

fn run_risk_summary(evaluation: &policy::PolicyEvaluation) -> String {
    if detection::has_critical_findings(&evaluation.findings) {
        "critical".to_string()
    } else if !evaluation.findings.is_empty() || !evaluation.denied_env.is_empty() {
        "warning".to_string()
    } else {
        "low".to_string()
    }
}

#[cfg(any(test, coverage))]
fn marker(ok: bool) -> &'static str {
    if ok {
        "[ok]"
    } else {
        "!"
    }
}

#[cfg(any(test, coverage))]
fn grant_integrity_messages(unsigned: usize, invalid: usize) -> Vec<String> {
    let mut messages = Vec::new();
    if unsigned == 0 && invalid == 0 {
        messages.push("[ok] Approval grants are signed and valid.".to_string());
    }
    if unsigned > 0 {
        messages.push(format!(
            "! Legacy unsigned approval grants: {unsigned}. Re-approve them."
        ));
    }
    if invalid > 0 {
        messages.push(format!(
            "! Invalid signed approval grants: {invalid}. Revoke and re-approve them."
        ));
    }
    messages
}

fn grant_status_label(status: grants::GrantIntegrityStatus) -> &'static str {
    match status {
        grants::GrantIntegrityStatus::Valid => "valid-signed",
        grants::GrantIntegrityStatus::Expired => "expired",
        grants::GrantIntegrityStatus::LegacyUnsigned => "legacy-unsigned",
        grants::GrantIntegrityStatus::Invalid => "invalid-signature",
    }
}

fn verified_agent_key_id(context: Option<&context::VerifiedContext>) -> Option<&str> {
    match context {
        Some(context) => Some(context.agent_key_id.as_str()),
        None => None,
    }
}

#[cfg(all(coverage, not(test)))]
#[doc(hidden)]
pub fn coverage_exercise_cli_edges() -> Result<()> {
    let old_cwd = env::current_dir()?;
    let home = tempfile::tempdir()?;
    env::set_var("WARD_HOME", home.path());
    env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");

    let project = tempfile::tempdir()?;
    env::set_current_dir(project.path())?;
    fs::write(project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let project_env = project.path().join(".env");
    fs::write(&project_env, "DATABASE_URL=postgres://coverage\n")?;
    let main_setup = SetupOptions {
        yes: true,
        project: Some("coverage-main".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(main_setup)?;
    dispatch(Cli {
        command: Commands::Broker {
            command: BrokerCommand::SocketPath,
        },
    })
    .expect("coverage broker socket dispatch should succeed");
    dispatch(Cli {
        command: Commands::Worktrees {
            command: WorktreesCommand::List {
                project: "coverage-main".to_string(),
            },
        },
    })
    .expect("coverage worktree list dispatch should succeed");
    broker_command(BrokerCommand::SocketPath)?;
    broker_command(BrokerCommand::Status)?;
    broker_command(BrokerCommand::Stop)?;
    let allowed_root = tempfile::tempdir()?;
    worktrees_command(WorktreesCommand::AllowRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage allow-root should succeed");
    worktrees_command(WorktreesCommand::List {
        project: "coverage-main".to_string(),
    })
    .expect("coverage list should succeed");
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage remove-root should succeed");
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage missing remove-root should succeed");
    worktrees_command(WorktreesCommand::Approve {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .expect("coverage missing worktree approval should succeed");
    worktrees_command(WorktreesCommand::Deny {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .expect("coverage missing worktree denial should succeed");

    let absolute_export = EnvCommand::Export {
        project: None,
        app: None,
        output: Some(project.path().join(".env.absolute.export")),
        force: false,
        unsafe_stdout: false,
    };
    env_command(absolute_export)?;
    let stdout_export = EnvCommand::Export {
        project: None,
        app: None,
        output: None,
        force: false,
        unsafe_stdout: true,
    };
    env_command(stdout_export)?;

    let access = AccessRequest {
        project: "coverage-main".to_string(),
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Coverage".to_string()),
        command: "sh -c true".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let clean = policy::PolicyEvaluation {
        matched_profile: None,
        matched_preset: None,
        approval_mode: ApprovalMode::Auto,
        requested_env: access.env.clone(),
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        requires_prompt: false,
        findings: Vec::new(),
    };
    let mut critical = clean.clone();
    critical.findings.push(detection::Finding::critical(
        "critical.coverage",
        "critical coverage finding",
    ));
    critical.requires_prompt = true;
    let _ = decide_access(&access, &clean, true)?;
    let _ = non_interactive_decision(&access, &clean)?;
    let mut denied = clean.clone();
    denied.approval_mode = ApprovalMode::Deny;
    let _ = non_interactive_decision(&access, &denied)?;
    let _ = non_interactive_decision(&access, &critical)?;
    let _ = run_risk_summary(&critical);
    let mut suspicious = clean.clone();
    suspicious.findings.push(detection::Finding::warning(
        "action.prompt_injection",
        "coverage suspicious action finding",
    ));
    suspicious.requires_prompt = true;
    let _ = decide_access(&access, &suspicious, true)?;
    let _ = signing_lookup_message(Ok(unlock::RunSigningLookup::Missing));
    let _ = signing_lookup_message(Ok(unlock::RunSigningLookup::MaterialUnavailable {
        reason: "coverage".to_string(),
    }));
    let _ = signing_lookup_message(Err(anyhow::anyhow!("coverage")));
    let _ = grant_integrity_messages(1, 1);
    let _ = grant_status_label(grants::GrantIntegrityStatus::Expired);
    let _ = grant_status_label(grants::GrantIntegrityStatus::LegacyUnsigned);
    let _ = grant_status_label(grants::GrantIntegrityStatus::Invalid);
    let resolved_main = registry::resolve_project(Some("coverage-main"), project.path())?;
    let missing_context = AgentContextOptions {
        agent: None,
        agent_key_id: None,
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &missing_context)?.is_none()
    );
    request(
        None,
        missing_context.clone(),
        Some("Coverage missing context".to_string()),
        Some("sh -c true".to_string()),
        access.env.clone(),
        true,
        true,
    )
    .expect("coverage missing-context request should return structured JSON");
    let wrong_key_context = AgentContextOptions {
        agent: Some("codex".to_string()),
        agent_key_id: Some("agent:wrong".to_string()),
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &wrong_key_context)?.is_none()
    );
    let agent = agents::ensure_agent("coverage-main", "codex")?;
    let proof = agents::sign_payload("coverage-main", "codex", "coverage payload")?;
    let _ = agents::verify_proof("coverage-main", &proof)?;
    let _ = context::normalize_remote("https://example.test/demo.git/");
    let mut agent_state = agents::load_agents()?;
    let agent_record = agent_state
        .projects
        .get_mut("coverage-main")
        .and_then(|agents| agents.iter_mut().find(|agent| agent.agent_name == "codex"))
        .expect("coverage agent should exist");
    agent_record.private_seed = "AQID".to_string();
    agents::save_agents(&agent_state)?;
    assert!(agents::sign_payload("coverage-main", "codex", "coverage payload").is_err());
    let mut agent_state = agents::load_agents()?;
    let agent_record = agent_state
        .projects
        .get_mut("coverage-main")
        .and_then(|agents| agents.iter_mut().find(|agent| agent.agent_name == "codex"))
        .expect("coverage agent should exist");
    agent_record.public_key = "AQID".to_string();
    agents::save_agents(&agent_state)?;
    assert!(agents::verify_proof("coverage-main", &proof).is_err());
    let matching_key_context = AgentContextOptions {
        agent: Some("codex".to_string()),
        agent_key_id: Some(agent.agent_key_id),
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &matching_key_context)?
            .is_none()
    );
    let no_git_claim = context::ClaimedContext {
        agent: Some("codex".to_string()),
        agent_key_id: None,
        worktree: Some(project.path().to_path_buf()),
        branch: Some("main".to_string()),
        git_remote: Some("https://example.test/demo.git".to_string()),
        commit: Some("abc".to_string()),
    };
    assert!(context::verify_no_prompt_context(
        &no_git_claim,
        project.path(),
        &resolved_main,
        "agent:coverage".to_string(),
    )
    .is_err());
    let verified_worktree = |path: PathBuf, remote: &str| context::VerifiedContext {
        project: "coverage-main".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:coverage".to_string(),
        worktree: path,
        branch: "main".to_string(),
        git_remote: remote.to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    let unregistered = registry::ResolvedProject {
        name: "coverage-unregistered".to_string(),
        path: project.path().to_path_buf(),
        vault: project.path().join(".env.vault"),
    };
    let unregistered_context =
        verified_worktree(project.path().to_path_buf(), "https://example.test/demo");
    let unregistered_allowed =
        enforce_worktree_for_no_prompt(&unregistered, &unregistered_context, false, "30m")?;
    assert!(unregistered_allowed);
    let autobind_root = tempfile::tempdir()?;
    let autobind_worktree = autobind_root.path().join("agent-wt");
    fs::create_dir(&autobind_worktree)?;
    worktrees::allow_root("coverage-main", autobind_root.path())?;
    let missing_root = home.path().join("missing-root");
    let missing_worktree = missing_root.join("child");
    let _ = worktrees::allow_root("coverage-main", &missing_root)?;
    let autobind_context = verified_worktree(autobind_worktree, "https://example.test/demo");
    let autobind_allowed =
        enforce_worktree_for_no_prompt(&resolved_main, &autobind_context, false, "30m")?;
    assert!(autobind_allowed);
    let missing_autobind_context = verified_worktree(missing_worktree, "https://example.test/demo");
    let _ =
        enforce_worktree_for_no_prompt(&resolved_main, &missing_autobind_context, false, "30m")?;
    let _ = worktrees::remove_root("coverage-main", &missing_root)?;
    let approval_worktree = tempfile::tempdir()?;
    let approval_context = verified_worktree(
        approval_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let approval_allowed =
        enforce_worktree_for_no_prompt(&resolved_main, &approval_context, false, "30m")?;
    assert!(!approval_allowed);
    let registered_for_worktree = registry::load_registry()?
        .projects
        .get("coverage-main")
        .cloned()
        .context("coverage-main should be registered")?;
    let approve_pending_worktree = tempfile::tempdir()?;
    let approve_context = verified_worktree(
        approve_pending_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let decision =
        worktrees::evaluate_worktree(&registered_for_worktree, "coverage-main", &approve_context)?;
    assert!(matches!(
        decision,
        worktrees::WorktreeDecision::ApprovalRequired { .. }
    ));
    let request = worktrees::list_project("coverage-main")?
        .pending
        .last()
        .cloned()
        .context("coverage approve pending worktree missing")?;
    worktrees_command(WorktreesCommand::Approve {
        request_id: request.id,
        json: false,
    })
    .expect("coverage pending worktree approval should succeed");
    let deny_pending_worktree = tempfile::tempdir()?;
    let deny_context = verified_worktree(
        deny_pending_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let decision =
        worktrees::evaluate_worktree(&registered_for_worktree, "coverage-main", &deny_context)?;
    assert!(matches!(
        decision,
        worktrees::WorktreeDecision::ApprovalRequired { .. }
    ));
    let request = worktrees::list_project("coverage-main")?
        .pending
        .last()
        .cloned()
        .context("coverage deny pending worktree missing")?;
    worktrees_command(WorktreesCommand::Deny {
        request_id: request.id,
        json: false,
    })
    .expect("coverage pending worktree denial should succeed");
    let mut registry = registry::load_registry()?;
    registry
        .projects
        .get_mut("coverage-main")
        .expect("coverage-main should be registered")
        .git_remote = Some("https://example.test/expected.git".to_string());
    registry::save_registry(&registry)?;
    let denied_worktree = tempfile::tempdir()?;
    let denied_context = verified_worktree(
        denied_worktree.path().to_path_buf(),
        "https://example.test/other",
    );
    let denied_allowed =
        enforce_worktree_for_no_prompt(&resolved_main, &denied_context, false, "30m")?;
    assert!(!denied_allowed);
    registry
        .projects
        .get_mut("coverage-main")
        .expect("coverage-main should be registered")
        .git_remote = None;
    registry::save_registry(&registry)?;

    let missing_grant = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Once,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::Grant,
        grant_id: None,
    };
    consume_once_grant_if_reused(&missing_grant)?;
    handle_post_run_logging_result(7, Err(anyhow::anyhow!("coverage log failure")))?;

    let mut removed_files = Vec::new();
    let missing_file = project.path().join("missing");
    remove_project_file_if_exists(&missing_file, &mut removed_files)?;
    remove_locked_env_if_needed(&missing_file, &missing_file, &mut removed_files)?;
    let no_marker = project.path().join("AGENTS.no-marker.md");
    fs::write(&no_marker, "Intro\n")?;
    let _ = remove_agent_instruction_section(&no_marker)?;
    let retained = project.path().join("AGENTS.retained.md");
    let retained_contents = "Intro\n\n<!-- ward-agent-instructions -->\nGenerated\n";
    fs::write(&retained, retained_contents)?;
    let _ = remove_agent_instruction_section(&retained)?;

    let no_json = run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("No prompt without json".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: false,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    });
    assert!(no_json.is_err());
    let critical_run = RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Critical pending".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "printenv".to_string()],
        json: true,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    };
    run(critical_run)?;
    let grant_source = approvals::ApprovalSource::ManualAllow;
    unlock_vault("1h", None, false)?;
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(false));
    let scope = ApprovalScope::Always;
    let vault = &resolved_main.vault;
    let auto_context = context::VerifiedContext {
        project: "coverage-main".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:coverage".to_string(),
        worktree: project.path().to_path_buf(),
        branch: "main".to_string(),
        git_remote: "https://example.test/demo".to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    let session_grant = grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        None,
    )
    .expect("coverage default manual grant should persist");
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Always,
        approvals::ApprovalSource::Grant,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Deny,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Branch,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    let context_receipt = grants::GrantReceiptContext {
        request_id: uuid::Uuid::new_v4(),
        pending_request: false,
        critical_confirmation: false,
        verified_context: Some(auto_context.clone()),
    };
    let _ = grants::persist_manual_grant(
        &access,
        ApprovalScope::Once,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(context_receipt),
    )
    .expect("coverage context manual grant should persist");
    grants::persist_manual_grant(&access, scope, grant_source, vault, receipt_context.clone())?;
    let _ = grants::find_matching_grant(&access)?;
    let _ = grants::find_matching_grant_with_context(&access, &auto_context)?;
    let _ = grants::find_matching_non_always_grant(&access)?;
    let _ = grants::find_matching_non_always_grant_with_context(&access, &auto_context)?;
    let _ = grants::find_matching_once_grant(&access, false)?;
    let _ = grants::find_matching_once_grant_with_context(&access, false, &auto_context)?;
    let unlocked_run = RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Unlocked run".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: true,
        no_prompt: true,
        wait_for_approval: false,
        approval_timeout: "30m".to_string(),
    };
    run(unlocked_run)?;
    let suspicious_session = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Session,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::LocalTty,
        grant_id: None,
    };
    let _ = grants::persist_grant(&access, &suspicious_session, vault, receipt_context.clone())?;
    let _ = grants::persist_grant(&access, &suspicious_session, vault, None)?;
    let grants_edge_path = home.path().join("sessions").join("coverage-grants.jsonl");
    let grants_edge_parent = grants_edge_path
        .parent()
        .context("coverage grants edge path has no parent")?;
    fs::create_dir_all(grants_edge_parent)?;
    fs::write(&grants_edge_path, "\n")?;
    assert!(grants::load_grants_from_path(&grants_edge_path)?.is_empty());
    assert!(!grants::consume_once_grant(uuid::Uuid::new_v4())?);
    assert_eq!(grants::revoke_session_grants_at_path(&grants_edge_path)?, 0);
    let mut expired_grant = session_grant.clone();
    expired_grant.id = uuid::Uuid::new_v4();
    expired_grant.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    let mut future_grant = session_grant.clone();
    future_grant.id = uuid::Uuid::new_v4();
    future_grant.expires_at = Some(chrono::Utc::now() + chrono::Duration::minutes(1));
    let mut durable_grant = session_grant.clone();
    durable_grant.id = uuid::Uuid::new_v4();
    durable_grant.expires_at = None;
    grants::append_grant_to_path(&grants_edge_path, &expired_grant)?;
    grants::append_grant_to_path(&grants_edge_path, &future_grant)?;
    grants::append_grant_to_path(&grants_edge_path, &durable_grant)?;
    assert_eq!(
        grants::prune_expired_grants_at_path(&grants_edge_path, chrono::Utc::now())?,
        1
    );
    assert_eq!(
        grants::grant_integrity_status(&expired_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::Expired
    );
    let mut legacy_grant = future_grant.clone();
    legacy_grant.receipt = None;
    assert_eq!(
        grants::grant_integrity_status(&legacy_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::LegacyUnsigned
    );
    let mut invalid_grant = future_grant.clone();
    invalid_grant.project = "tampered".to_string();
    assert_eq!(
        grants::grant_integrity_status(&invalid_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::Invalid
    );
    let _ = non_interactive_decision(&access, &suspicious)?;
    let _ = non_interactive_decision_with_context(&access, &clean, None)?;
    let _ = non_interactive_decision_with_context(&access, &denied, Some(&auto_context))?;
    let fresh_access = AccessRequest {
        project: "coverage-main".to_string(),
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Fresh auto".to_string()),
        command: "sh -c echo fresh".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let _ = non_interactive_decision_with_context(&fresh_access, &clean, Some(&auto_context))?;
    let _ = non_interactive_decision_with_context(&access, &clean, Some(&auto_context))?;
    broker_command(BrokerCommand::Stop)?;
    let _ = unlock::clear_all_unlocks()?;
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    let unavailable_session = unlock::create_run_unlock(
        "coverage-main",
        vault,
        "coverage passphrase",
        chrono::Duration::hours(1),
    )
    .expect("coverage unavailable signing session should be created");
    crate::key_store::delete_secret(&unavailable_session.key_name)?;
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    unlock_vault("1h", None, false)?;
    let verify_logs = Some(LogsCommand::Verify {
        kind: Some(LogKind::Requests),
        full: true,
    });
    logs(verify_logs, None)?;
    let export_logs = Some(LogsCommand::Export {
        kind: LogKind::Requests,
        output: project.path().join("requests.export.jsonl"),
        force: false,
    });
    logs(export_logs, None)?;
    assert!(teardown(None, ".env.unused".into(), false, false).is_err());

    let remove_project = tempfile::tempdir()?;
    env::set_current_dir(remove_project.path())?;
    fs::write(remove_project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let remove_env = remove_project.path().join(".env");
    fs::write(&remove_env, "DATABASE_URL=postgres://remove\n")?;
    let remove_setup = SetupOptions {
        yes: true,
        project: Some("coverage-remove".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: true,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(remove_setup)?;

    let import_project = tempfile::tempdir()?;
    env::set_current_dir(import_project.path())?;
    init(Some("coverage-import".to_string()), false, false)?;
    let import_env = import_project.path().join(".env");
    fs::write(&import_env, "DATABASE_URL=postgres://import\n")?;
    import(".env".into(), Some("relative.vault".into()))?;

    let doctor_project = tempfile::tempdir()?;
    env::set_current_dir(doctor_project.path())?;
    fs::write(doctor_project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let doctor_env = doctor_project.path().join(".env");
    let doctor_vault = doctor_project.path().join(".env.vault");
    fs::write(&doctor_env, "DATABASE_URL=postgres://doctor\n")?;
    let doctor_setup = SetupOptions {
        yes: true,
        project: Some("coverage-doctor".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(doctor_setup)?;
    doctor()?;
    fs::write(&doctor_env, "DATABASE_URL=postgres://plaintext\n")?;
    doctor()?;
    env_file::lock_env_file(&doctor_env, &doctor_vault)?;
    fs::write(&doctor_vault, "changed")?;
    doctor()?;
    fs::remove_file(&doctor_env)?;
    doctor()?;
    fs::create_dir(&doctor_env)?;
    doctor()?;
    let grants_path = grants::grants_path();
    let grants_parent = grants_path.parent().context("grants path has no parent")?;
    fs::create_dir_all(grants_parent)?;
    fs::write(grants_path, "{bad-json}\n")?;
    doctor()?;
    crate::broker::coverage_exercise_broker_edges()?;

    env::set_current_dir(old_cwd)?;
    env::remove_var("WARD_HOME");
    env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::ProjectConfig,
        policy::{AccessRequest, ApprovalMode, PolicyEvaluation},
        project_teardown::{
            remove_agent_instruction_section, remove_locked_env_if_needed,
            remove_project_file_if_exists,
        },
    };
    use clap::CommandFactory;
    use std::{
        path::{Path, PathBuf},
        process::Command as StdCommand,
        sync::{Mutex, OnceLock},
    };

    fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
                command: None,
                yes: true,
                project: Some("kept".to_string()),
                source: ".env".into(),
                vault: ".env.vault".into(),
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
        std::env::set_current_dir(project.path()).unwrap();

        let dispatch_conflict = dispatch(Cli {
            command: Commands::Setup {
                command: None,
                yes: true,
                project: Some("demo".to_string()),
                source: "missing.env".into(),
                vault: "missing.vault".into(),
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
            yes: false,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: "missing.vault".into(),
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
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap();
        assert!(vault::decrypt_vault_file(
            &project.path().join(".env.vault"),
            "coverage passphrase"
        )
        .unwrap()
        .contains("postgres://coverage"));
        std::fs::remove_file(project.path().join(".env.vault")).unwrap();
        let missing_vault = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
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
                command: None,
                yes: true,
                project: Some("demo".to_string()),
                source: ".env".into(),
                vault: ".env.vault".into(),
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
        assert!(env_example_error.contains("failed to read"));
        assert!(instructions_error.contains("failed to read"));
        assert!(gitignore_error.contains("failed to read"));
        #[cfg(unix)]
        assert!(log_error.contains("failed to read"));
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
            },
        })
        .unwrap();
        std::fs::write(
            project.path().join(".env.alt"),
            "DATABASE_URL=postgres://coverage-alt\nPAYLOAD_SECRET=payload-alt\n",
        )
        .unwrap();
        dispatch(Cli {
            command: Commands::Import {
                source: ".env.alt".into(),
                vault: Some(".env.alt.vault".into()),
            },
        })
        .unwrap();
        let mut config_after_alt_import = config::read_project_config(project.path()).unwrap();
        config_after_alt_import.vault = ".env.vault".into();
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
        dispatch(Cli {
            command: Commands::Approve {
                request_id: pending_id,
                scope: ApprovalScope::Once,
                confirm_critical: false,
                agent_mediated: true,
                json: false,
            },
        })
        .unwrap();

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

        dispatch(Cli {
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
        .unwrap();
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
        dispatch(Cli {
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
        .unwrap();
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
        run(RunOptions {
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
        .unwrap();
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
        assert_eq!(
            child_error.downcast_ref::<ChildExit>().unwrap().exit_code(),
            7
        );
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        dispatch(Cli {
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
        .unwrap();
        dispatch(Cli {
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
        .unwrap();
        dispatch(Cli {
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
        .unwrap();

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
        import(".env".into(), None).unwrap();
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
        run(RunOptions {
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
        .unwrap();
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
        deny(pending.id, false, false).unwrap();
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
        approve(pending.id, ApprovalScope::Session, false, false, false).unwrap();
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
        approve(critical_pending.id, ApprovalScope::Once, true, true, false).unwrap();
        let once_grant = grants::load_grants()
            .unwrap()
            .into_iter()
            .find(|grant| grant.scope == ApprovalScope::Once)
            .unwrap();
        let once_reuse = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::Grant,
            grant_id: Some(once_grant.id),
        };
        consume_once_grant_if_reused(&once_reuse).unwrap();
        grants_command(GrantsCommand::List).unwrap();
        let signed_grant = grants::load_grants()
            .unwrap()
            .into_iter()
            .find(|grant| grant.receipt.is_some())
            .unwrap();
        let mut legacy_grant = signed_grant.clone();
        legacy_grant.id = uuid::Uuid::new_v4();
        legacy_grant.receipt = None;
        grants::append_grant_to_path(&grants::grants_path(), &legacy_grant).unwrap();
        let mut invalid_grant = signed_grant;
        invalid_grant.id = uuid::Uuid::new_v4();
        invalid_grant.command = "sh -c tampered".to_string();
        grants::append_grant_to_path(&grants::grants_path(), &invalid_grant).unwrap();
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
        dispatch(Cli {
            command: Commands::Deny {
                request_id: pending.id,
                agent_mediated: true,
                json: false,
            },
        })
        .unwrap();
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
        let prompted =
            decide_access(&access, &evaluation(ApprovalMode::Prompt, true), false).unwrap();
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

        let once = grants::persist_manual_grant(
            &access,
            ApprovalScope::Once,
            approvals::ApprovalSource::AgentMediated,
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
        invalid_grant.receipt = Some(crate::approval_receipts::ApprovalReceipt {
            payload: crate::approval_receipts::build_payload(
                &access(),
                invalid_grant.id,
                uuid::Uuid::new_v4(),
                &["DATABASE_URL".to_string()],
                approvals::ApprovalScope::Always,
                None,
                false,
                now,
                "missing-signer".to_string(),
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
        let config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

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
            vec![
                "ward",
                "auth",
                "login",
                "--cloud-url",
                "http://127.0.0.1:8787",
                "--email",
                "owner@example.com",
                "--json",
            ],
            vec![
                "ward",
                "setup",
                "login",
                "--cloud-url",
                "http://127.0.0.1:8787",
                "--team",
                "team",
                "--project",
                "project",
                "--environment",
                "development",
                "--json",
            ],
            vec!["ward", "cloud", "dev", "start", "--port", "8787", "--json"],
            vec!["ward", "cloud", "dev", "status", "--json"],
            vec!["ward", "cloud", "dev", "stop", "--json"],
            vec![
                "ward",
                "cloud",
                "dev",
                "publish",
                "--cloud-url",
                "http://127.0.0.1:8787",
                "--project",
                "ward",
                "--team",
                "team",
                "--cloud-project",
                "project",
                "--environment",
                "development",
                "--env",
                "DATABASE_URL",
                "--profile",
                "dev",
                "--agent",
                "codex",
                "--member",
                "dev@example.com:developer",
                "--json",
            ],
            vec!["ward", "edit"],
            vec!["ward", "unlock", "--ttl", "1h"],
            vec!["ward", "lock"],
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
                    command: None,
                    yes: true,
                    project: Some("demo".to_string()),
                    source: ".env".into(),
                    vault: ".env.vault".into(),
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
                Commands::Setup {
                    command: Some(SetupCommand::Login {
                        cloud_url: "http://127.0.0.1:8787".to_string(),
                        team: Some("team".to_string()),
                        project: Some("project".to_string()),
                        environment: Some("development".to_string()),
                        json: true,
                    }),
                    yes: false,
                    project: None,
                    source: ".env".into(),
                    vault: ".env.vault".into(),
                    commit_vault: false,
                    ignore_vault: false,
                    remove_plaintext: false,
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
                Commands::Auth {
                    command: AuthCommand::Login {
                        cloud_url: "http://127.0.0.1:8787".to_string(),
                        email: Some("owner@example.com".to_string()),
                        name: None,
                        device_name: None,
                        json: true,
                    },
                }
            ),
            format!(
                "{:?}",
                Commands::Cloud {
                    command: CloudCommand::Dev {
                        command: CloudDevCommand::Start {
                            port: Some(8787),
                            db: None,
                            foreground: false,
                            json: true,
                        },
                    },
                }
            ),
            format!(
                "{:?}",
                Commands::Cloud {
                    command: CloudCommand::Dev {
                        command: CloudDevCommand::Status { json: true },
                    },
                }
            ),
            format!(
                "{:?}",
                Commands::Cloud {
                    command: CloudCommand::Dev {
                        command: CloudDevCommand::Stop { json: true },
                    },
                }
            ),
            format!(
                "{:?}",
                Commands::Cloud {
                    command: CloudCommand::Dev {
                        command: CloudDevCommand::Publish {
                            cloud_url: "http://127.0.0.1:8787".to_string(),
                            project: Some("ward".to_string()),
                            team: "team".to_string(),
                            cloud_project: Some("project".to_string()),
                            environment: "development".to_string(),
                            env_names: vec!["DATABASE_URL".to_string()],
                            profiles: vec!["dev".to_string()],
                            agents: vec!["codex".to_string()],
                            members: vec!["dev@example.com:developer".to_string()],
                            json: true,
                        },
                    },
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

        assert_eq!(commands.len(), 35);
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
        assert_eq!(RECOVERY_EXPORT_PROMPT, "Export a recovery backup now?");
        assert!(RECOVERY_EXPORT_HELP.contains("USB drive"));
        assert!(RECOVERY_EXPORT_HELP.contains("secure cloud backup"));
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
}
