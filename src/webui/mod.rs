use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Cursor,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use tiny_http::{Header, Method, Response, Server, StatusCode};

use crate::{
    approvals, broker,
    config::{self, ProfileConfig},
    fs_util, human,
    logs::{self, LogKind},
    notifications, project_store, project_teardown,
    registry::{self, RegisteredProject},
    term, workspace, worktrees,
};

const DEFAULT_PORT: u16 = 7777;
const PORT_SCAN_WIDTH: u16 = 20;
const DASHBOARD_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct DashboardStartOptions {
    pub port: Option<u16>,
    pub open_browser: bool,
    pub foreground: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
pub struct DashboardStopOptions {
    pub all: bool,
    pub pid: Option<u32>,
    pub port: Option<u16>,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardInstance {
    pub pid: u32,
    pub port: u16,
    pub url: String,
    pub token: String,
    pub started_project: Option<String>,
    pub started_path: PathBuf,
    pub started_at: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardStartResult {
    reused: bool,
    instance: DashboardInstance,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardStopResult {
    stopped: Vec<DashboardInstance>,
    stale_removed: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardStatus {
    instances: Vec<DashboardInstance>,
    broker: broker::BrokerStatus,
    human: HumanRuntimeView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HumanRuntimeView {
    shell_pid: u32,
    shell_hooks_loaded: bool,
    guardian_socket_exists: bool,
    socket_path: PathBuf,
    stale_guardian_pids: Vec<u32>,
    stale_run_dirs: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectView {
    name: String,
    path: PathBuf,
    vault: PathBuf,
    active: bool,
    config_status: String,
    setup_status: String,
    setup_available: bool,
    workspace_root: Option<PathBuf>,
    parent_project: Option<String>,
    package_name: Option<String>,
    package_kind: Option<String>,
    profiles: Vec<ProfileView>,
    agent_policies: Vec<AgentPolicyView>,
    env_names: Vec<String>,
    vault_keys_verified: bool,
    broker_session_active: bool,
    broker_session_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    store_snapshot: Option<project_store::ProjectStoreSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileView {
    name: String,
    command: String,
    env: Vec<String>,
    default_scope: crate::approvals::ApprovalScope,
    action: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentPolicyView {
    agent: String,
    profiles: Vec<String>,
    env: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProfileEnvRequest {
    env: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfilePolicyRequest {
    name: Option<String>,
    command: Option<String>,
    action: Option<String>,
    default_scope: Option<crate::approvals::ApprovalScope>,
    #[serde(default)]
    env: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PickFolderRequest {
    path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PickFolderResponse {
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectSetupRequest {
    path: PathBuf,
    project: Option<String>,
    source_project: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectProvisionRequest {
    source_project: Option<String>,
    path: PathBuf,
    project: String,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    agents: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveProjectRequest {
    confirm: String,
    #[serde(default = "default_remove_export_path")]
    export_path: PathBuf,
    #[serde(default)]
    restore_env: bool,
}

fn default_remove_export_path() -> PathBuf {
    PathBuf::from(".env.export")
}

include!("parts/runtime.rs");
include!("parts/routing.rs");
include!("parts/actions.rs");
include!("parts/projects.rs");
include!("parts/lifecycle.rs");
include!("parts/assets.rs");
include!("parts/tests.rs");
