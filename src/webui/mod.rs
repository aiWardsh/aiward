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

pub fn start_dashboard(options: DashboardStartOptions) -> Result<()> {
    cleanup_stale_instances()?;
    let requested_port = options.port;

    if !options.foreground {
        if let Some(existing) = running_instances()?
            .into_iter()
            .find(|instance| requested_port.is_none_or(|port| port == instance.port))
        {
            let result = DashboardStartResult {
                reused: true,
                instance: existing,
            };
            if options.open_browser {
                open_browser_best_effort(&result.instance.url);
            }
            print_start_result(&result, options.json)?;
            return Ok(());
        }
    }

    let port = requested_port.unwrap_or_else(|| find_available_port(DEFAULT_PORT));
    let token = generate_token();

    if options.foreground {
        let instance = current_instance(port, token.clone())?;
        write_instance(&instance)?;
        if options.open_browser {
            open_browser_best_effort(&instance.url);
        }
        print_start_result(
            &DashboardStartResult {
                reused: false,
                instance: instance.clone(),
            },
            options.json,
        )?;
        let result = serve_blocking(port, token);
        let _ = remove_instance(instance.pid);
        return result;
    }

    let exe = std::env::current_exe().context("cannot locate ward binary")?;
    let mut command = Command::new(exe);
    command
        .arg("__dashboard-server")
        .arg("--port")
        .arg(port.to_string())
        .arg("--token")
        .arg(&token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("failed to start Ward dashboard")?;

    let mut instance = current_instance(port, token)?;
    instance.pid = child.id();
    write_instance(&instance)?;

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if port_accepts_connections(port) {
            let result = DashboardStartResult {
                reused: false,
                instance,
            };
            if options.open_browser {
                open_browser_best_effort(&result.instance.url);
            }
            print_start_result(&result, options.json)?;
            return Ok(());
        }
        if child.try_wait()?.is_some() {
            let _ = remove_instance(instance.pid);
            anyhow::bail!("Ward dashboard exited before it became ready");
        }
        thread::sleep(Duration::from_millis(50));
    }

    let _ = remove_instance(instance.pid);
    anyhow::bail!("Ward dashboard did not become ready on port {port}");
}

pub fn serve_standalone(port: u16, token: String) -> Result<()> {
    let instance = current_instance(port, token.clone())?;
    write_instance(&instance)?;
    let result = serve_blocking(port, token);
    let _ = remove_instance(instance.pid);
    result
}

pub fn stop_dashboards(options: DashboardStopOptions) -> Result<()> {
    let stale_removed = cleanup_stale_instances()?;
    let mut targets = select_stop_targets(&options)?;
    targets.sort_by_key(|instance| instance.pid);
    targets.dedup_by_key(|instance| instance.pid);

    for instance in &targets {
        terminate_dashboard_process(instance.pid);
        let _ = remove_instance(instance.pid);
    }

    let result = DashboardStopResult {
        stopped: targets,
        stale_removed,
    };
    if options.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.stopped.is_empty() {
        term::emit_header(&term::Header {
            command: Some("dashboard stop"),
            project: "local",
            path: None,
            mode: None,
        });
        term::info("no standalone dashboard instances were running");
        if result.stale_removed > 0 {
            term::ok_detail("stale metadata removed", &result.stale_removed.to_string());
        }
    } else {
        term::emit_header(&term::Header {
            command: Some("dashboard stop"),
            project: "local",
            path: None,
            mode: None,
        });
        term::ok_detail(
            "dashboard stopped",
            &format!("{} instance(s)", result.stopped.len()),
        );
        if result.stale_removed > 0 {
            term::ok_detail("stale metadata removed", &result.stale_removed.to_string());
        }
    }
    Ok(())
}

pub fn print_dashboard_status(json_output: bool) -> Result<()> {
    cleanup_stale_instances()?;
    let status = dashboard_status()?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    term::emit_header(&term::Header {
        command: Some("dashboard status"),
        project: "local",
        path: None,
        mode: None,
    });
    if status.instances.is_empty() {
        term::info("no standalone browser dashboards running");
        term::next("run: ward dashboard start");
    } else {
        term::section("instances");
        for instance in &status.instances {
            term::ok_detail(
                &format!("pid {}", instance.pid),
                &format!(
                    "port={} project={} url={}",
                    instance.port,
                    instance.started_project.as_deref().unwrap_or("-"),
                    instance.url
                ),
            );
        }
    }
    Ok(())
}

pub fn dashboard_diagnostics() -> Result<Vec<DashboardInstance>> {
    cleanup_stale_instances()?;
    running_instances()
}

fn serve_blocking(port: u16, token: String) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_for_handler.store(true, Ordering::SeqCst);
    });

    let server = Server::http(format!("127.0.0.1:{port}"))
        .map_err(|error| anyhow::anyhow!("failed to start dashboard server: {error}"))?;
    while !stop.load(Ordering::SeqCst) {
        match server.recv_timeout(Duration::from_millis(200)) {
            Ok(Some(req)) => handle(req, &token),
            Ok(None) => {}
            Err(_) => continue,
        }
    }
    Ok(())
}

fn handle(mut req: tiny_http::Request, token: &str) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = split_url(&url);

    if method == Method::Options {
        respond_empty(req, StatusCode(204));
        return;
    }

    if path.starts_with("/api/") && !authorized(&req, &query, token) {
        respond_json(
            req,
            StatusCode(403),
            &json!({ "error": "unauthorized", "message": "dashboard token required" }),
        );
        return;
    }

    if method == Method::Get && path == "/favicon.png" {
        serve_png(req, WARD_FAVICON_LIGHT_PNG);
        return;
    }

    if method == Method::Get && path == "/favicon.svg" {
        serve_svg(req, WARD_LOGO_DARK_SVG);
        return;
    }

    if method == Method::Get && path == "/assets/ward-logo-dark.png" {
        serve_png(req, WARD_LOGO_DARK_PNG);
        return;
    }

    if method == Method::Get && path == "/assets/ward-logo-transparent.svg" {
        serve_svg(req, WARD_LOGO_TRANSPARENT_SVG);
        return;
    }

    if method == Method::Get && is_dashboard_page_route(&path) {
        serve_html(req);
        return;
    }

    match (method, path.as_str()) {
        (Method::Get, "/api/projects") => respond_json_result(req, dashboard_projects()),
        (Method::Get, "/api/store/projects") => {
            respond_json_result(req, project_store::list_summaries())
        }
        (Method::Get, "/api/events") => {
            let project = query_param(&query, "project");
            respond_json_result(req, Ok(load_all_events(project.as_deref())))
        }
        (Method::Get, "/api/notifications") => {
            respond_json_result(req, notifications::list_notifications())
        }
        (Method::Get, "/api/notifications/stream") => {
            respond_notifications_stream(req);
        }
        (Method::Get, "/api/dashboard/status") => respond_json_result(req, dashboard_status()),
        (Method::Get, _) => respond_not_found(req),
        (Method::Post, "/api/projects/pick-folder") => {
            let result = pick_project_folder(&mut req);
            respond_json_result(req, result);
        }
        (Method::Post, "/api/projects/setup") => {
            let result = setup_project_from_dashboard(&mut req);
            respond_project_setup_result(req, result);
        }
        (Method::Post, "/api/projects/provision") => {
            let result = provision_project_from_dashboard(&mut req);
            respond_project_provision_result(req, result);
        }
        (Method::Post, _) => {
            if let Some((notification_id, action)) = notification_action_route(&path) {
                let result = notification_action(notification_id, &action);
                respond_json_result(req, result);
            } else if path == "/api/sessions/lock-all" {
                let result = lock_all_sessions();
                respond_json_result(req, result);
            } else if let Some((project, action)) = project_action_route(&path) {
                match action.as_str() {
                    "lock" => {
                        let result = lock_project_session(&project);
                        respond_json_result(req, result);
                    }
                    "remove" => {
                        let result = remove_project_from_dashboard(&project, &mut req);
                        respond_broker_project_result(req, result, "project_remove_failed");
                    }
                    _ => respond_not_found(req),
                }
            } else if let Some((request_id, action)) = approval_action_route(&path) {
                let result = approval_action(&mut req, request_id, &action);
                respond_approval_result(req, result);
            } else if let Some((request_id, action)) = worktree_action_route(&path) {
                let result = worktree_action(request_id, &action);
                respond_json_result(req, result);
            } else if let Some(project) = profiles_collection_route(&path) {
                let result = create_profile_policy(&project, &mut req);
                respond_json_result(req, result);
            } else if let Some(project) = store_snapshot_route(&path) {
                let result = snapshot_project_from_dashboard(&project);
                respond_project_snapshot_result(req, result);
            } else if let Some((project, profile)) = profile_env_route(&path) {
                let result = update_profile_env(&project, &profile, &mut req);
                respond_json_result(req, result);
            } else {
                respond_not_found(req);
            }
        }
        (Method::Patch, _) => {
            if let Some((project, profile)) = profile_policy_route(&path) {
                let result = update_profile_policy(&project, &profile, &mut req);
                respond_json_result(req, result);
            } else if let Some((project, profile)) = profile_env_route(&path) {
                let result = update_profile_env(&project, &profile, &mut req);
                respond_json_result(req, result);
            } else {
                respond_not_found(req);
            }
        }
        (Method::Delete, _) => {
            if let Some((project, profile)) = profile_policy_route(&path) {
                let result = delete_profile_policy(&project, &profile);
                respond_json_result(req, result);
            } else {
                respond_not_found(req);
            }
        }
        _ => respond_not_found(req),
    }
}

fn serve_html(req: tiny_http::Request) {
    let html = DASHBOARD_HTML.as_bytes();
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(html),
        Some(html.len()),
        None,
    );
    let _ = req.respond(response);
}

fn serve_svg(req: tiny_http::Request, svg: &'static str) {
    let body = svg.as_bytes();
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "image/svg+xml; charset=utf-8").unwrap(),
            Header::from_bytes("Cache-Control", "public, max-age=86400").unwrap(),
        ],
        Cursor::new(body),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn serve_png(req: tiny_http::Request, body: &'static [u8]) {
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "image/png").unwrap(),
            Header::from_bytes("Cache-Control", "public, max-age=86400").unwrap(),
        ],
        Cursor::new(body),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_json_result<T: Serialize>(req: tiny_http::Request, result: Result<T>) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => respond_json(
            req,
            StatusCode(500),
            &json!({ "error": "dashboard_error", "message": error.to_string() }),
        ),
    }
}

fn respond_project_setup_result(
    req: tiny_http::Request,
    result: Result<broker::BrokerProjectSetupStatus>,
) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => {
            if let Some(broker_error) = error.downcast_ref::<broker::BrokerError>() {
                if broker_error.reason() == "unlock_required" {
                    respond_json(
                        req,
                        StatusCode(423),
                        &json!({
                            "status": "unlock_required",
                            "unlockRequired": true,
                            "message": broker_error.message(),
                            "fixCommand": "ward unlock --ttl 8h"
                        }),
                    );
                    return;
                }
            }
            respond_json(
                req,
                StatusCode(500),
                &json!({ "error": "project_setup_failed", "message": error.to_string() }),
            );
        }
    }
}

fn respond_approval_result(req: tiny_http::Request, result: Result<Value>) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("signing_key_unavailable")
                || message.contains("unlock_required")
                || message.contains("missing broker unlock session")
                || message.contains("expired broker unlock session")
                || message.contains("Ward broker is unavailable")
            {
                StatusCode(423)
            } else {
                StatusCode(500)
            };
            respond_json(
                req,
                status,
                &json!({
                    "error": "approval_failed",
                    "message": message,
                    "unlockRequired": status.0 == 423,
                    "fixCommand": "ward unlock --ttl 8h"
                }),
            );
        }
    }
}

fn respond_project_snapshot_result(
    req: tiny_http::Request,
    result: Result<broker::BrokerProjectSnapshotStatus>,
) {
    respond_broker_project_result(req, result, "project_snapshot_failed")
}

fn respond_project_provision_result(
    req: tiny_http::Request,
    result: Result<broker::BrokerProjectProvisionStatus>,
) {
    respond_broker_project_result(req, result, "project_provision_failed")
}

fn respond_broker_project_result<T: Serialize>(
    req: tiny_http::Request,
    result: Result<T>,
    error_name: &'static str,
) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => {
            if let Some(broker_error) = error.downcast_ref::<broker::BrokerError>() {
                if broker_error.reason() == "unlock_required"
                    || broker_error
                        .message()
                        .contains("missing broker unlock session")
                    || broker_error
                        .message()
                        .contains("expired broker unlock session")
                {
                    respond_json(
                        req,
                        StatusCode(423),
                        &json!({
                            "status": "unlock_required",
                            "unlockRequired": true,
                            "message": broker_error.message(),
                            "fixCommand": "ward unlock --ttl 8h"
                        }),
                    );
                    return;
                }
            }
            respond_json(
                req,
                StatusCode(500),
                &json!({ "error": error_name, "message": error.to_string() }),
            );
        }
    }
}

fn respond_json<T: Serialize>(req: tiny_http::Request, status: StatusCode, value: &T) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let response = Response::new(
        status,
        vec![
            Header::from_bytes("Content-Type", "application/json").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(body.clone()),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_notifications_stream(req: tiny_http::Request) {
    let payload = match notifications::list_notifications() {
        Ok(notifications) => json!({ "notifications": notifications }),
        Err(error) => {
            json!({ "error": "notification_stream_failed", "message": error.to_string() })
        }
    };
    let body = format!("retry: 2000\nevent: notifications\ndata: {payload}\n\n");
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/event-stream").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(body.clone().into_bytes()),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_empty(req: tiny_http::Request, status: StatusCode) {
    let _ = req.respond(Response::new(
        status,
        Vec::new(),
        Cursor::new(Vec::new()),
        Some(0),
        None,
    ));
}

fn respond_not_found(req: tiny_http::Request) {
    let _ = req.respond(Response::new(
        StatusCode(404),
        Vec::new(),
        Cursor::new(b"not found".to_vec()),
        Some(9),
        None,
    ));
}

fn split_url(url: &str) -> (String, String) {
    match url.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (url.to_string(), String::new()),
    }
}

fn authorized(req: &tiny_http::Request, query: &str, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    if query_param(query, "token").as_deref() == Some(token) {
        return true;
    }
    req.headers().iter().any(|header| {
        let name = header
            .field
            .to_string()
            .eq_ignore_ascii_case("authorization");
        let value = header.value.as_str();
        (name && value == format!("Bearer {token}"))
            || (header
                .field
                .to_string()
                .eq_ignore_ascii_case("x-ward-dashboard-token")
                && value == token)
    })
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (url_decode(key) == name).then(|| url_decode(value))
    })
}

fn is_dashboard_page_route(path: &str) -> bool {
    path == "/" || path == "/logs" || project_logs_route(path).is_some()
}

fn project_logs_route(path: &str) -> Option<String> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["projects", project, "logs"] => Some(url_decode(project)),
        _ => None,
    }
}

fn store_snapshot_route(path: &str) -> Option<String> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "store", "projects", project, "snapshot"] => Some(url_decode(project)),
        _ => None,
    }
}

fn profiles_collection_route(path: &str) -> Option<String> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, "profiles"] => Some(url_decode(project)),
        _ => None,
    }
}

fn profile_policy_route(path: &str) -> Option<(String, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, "profiles", profile] => {
            Some((url_decode(project), url_decode(profile)))
        }
        _ => None,
    }
}

fn profile_env_route(path: &str) -> Option<(String, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, "profiles", profile, "env"] => {
            Some((url_decode(project), url_decode(profile)))
        }
        _ => None,
    }
}

fn project_action_route(path: &str) -> Option<(String, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, action] if *action == "lock" || *action == "remove" => {
            Some((url_decode(project), (*action).to_string()))
        }
        _ => None,
    }
}

fn notification_action_route(path: &str) -> Option<(uuid::Uuid, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "notifications", notification_id, action] if *action == "dismiss" => Some((
            uuid::Uuid::parse_str(notification_id).ok()?,
            (*action).to_string(),
        )),
        _ => None,
    }
}

fn approval_action_route(path: &str) -> Option<(uuid::Uuid, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "approvals", request_id, action] if *action == "approve" || *action == "deny" => {
            Some((
                uuid::Uuid::parse_str(request_id).ok()?,
                (*action).to_string(),
            ))
        }
        _ => None,
    }
}

fn worktree_action_route(path: &str) -> Option<(uuid::Uuid, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "worktrees", request_id, action] if *action == "approve" || *action == "deny" => {
            Some((
                uuid::Uuid::parse_str(request_id).ok()?,
                (*action).to_string(),
            ))
        }
        _ => None,
    }
}

fn url_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        out.push(byte);
                        index += 3;
                        continue;
                    }
                }
                out.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DashboardApprovalRequest {
    #[serde(default)]
    scope: Option<approvals::ApprovalScope>,
    #[serde(default)]
    confirm_critical: bool,
}

fn approval_action(
    req: &mut tiny_http::Request,
    request_id: uuid::Uuid,
    action: &str,
) -> Result<Value> {
    match action {
        "approve" => {
            let body = read_optional_body(req)?;
            let request = if body.trim().is_empty() {
                DashboardApprovalRequest {
                    scope: Some(approvals::ApprovalScope::Session),
                    confirm_critical: false,
                }
            } else {
                serde_json::from_str::<DashboardApprovalRequest>(&body)
                    .context("failed to parse approval JSON request")?
            };
            crate::cli::approve_request_from_dashboard(
                request_id,
                request.scope.unwrap_or(approvals::ApprovalScope::Session),
                request.confirm_critical,
            )
        }
        "deny" => crate::cli::deny_request_from_dashboard(request_id),
        _ => anyhow::bail!("unknown approval action: {action}"),
    }
}

fn worktree_action(request_id: uuid::Uuid, action: &str) -> Result<Value> {
    match action {
        "approve" => {
            let Some(known) = worktrees::approve_pending(request_id)? else {
                anyhow::bail!("pending worktree request not found: {request_id}");
            };
            Ok(json!({
                "status": "approved",
                "requestId": request_id,
                "worktree": known.path,
                "matchKind": known.match_kind,
            }))
        }
        "deny" => {
            if !worktrees::deny_pending(request_id)? {
                anyhow::bail!("pending worktree request not found: {request_id}");
            }
            Ok(json!({
                "status": "denied",
                "requestId": request_id,
            }))
        }
        _ => anyhow::bail!("unknown worktree action: {action}"),
    }
}

fn notification_action(notification_id: uuid::Uuid, action: &str) -> Result<Value> {
    match action {
        "dismiss" => Ok(serde_json::to_value(notifications::dismiss_notification(
            notification_id,
        )?)?),
        _ => anyhow::bail!("unknown notification action: {action}"),
    }
}

fn lock_project_session(project: &str) -> Result<broker::BrokerProjectLockStatus> {
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    broker::lock_project(project, &registered.vault)
}

fn lock_all_sessions() -> Result<Value> {
    let revoked_session_grants = crate::grants::revoke_session_grants()?;
    let cleared_unlock_sessions = crate::unlock::clear_all_unlocks()?;
    broker::stop()?;
    Ok(json!({
        "status": "locked",
        "revokedSessionGrants": revoked_session_grants,
        "clearedUnlockSessions": cleared_unlock_sessions,
    }))
}

fn remove_project_from_dashboard(
    project: &str,
    req: &mut tiny_http::Request,
) -> Result<project_teardown::ProjectTeardownOutcome> {
    let requested: RemoveProjectRequest = read_json_body(req)?;
    if requested.confirm != project {
        anyhow::bail!("project removal requires confirm to equal the project name");
    }
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    broker::remove_project_from_active_session(
        project,
        &registered.vault,
        requested.export_path,
        requested.restore_env,
    )
}

fn update_profile_env(
    project: &str,
    profile: &str,
    req: &mut tiny_http::Request,
) -> Result<ProjectView> {
    let mut body = String::new();
    std::io::Read::read_to_string(req.as_reader(), &mut body)
        .context("failed to read request body")?;
    let requested: UpdateProfileEnvRequest =
        serde_json::from_str(&body).context("failed to parse profile env update")?;
    let env = normalize_env_names(requested.env)?;
    update_profile_env_for_project(project, profile, env)
}

fn update_profile_env_for_project(
    project: &str,
    profile: &str,
    env: Vec<String>,
) -> Result<ProjectView> {
    let env = normalize_env_names(env)?;
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    let profile_cfg = cfg
        .profiles
        .get_mut(profile)
        .with_context(|| format!("profile {profile} not found in project {project}"))?;
    profile_cfg.env = env;
    config::write_project_config(&registered.path, &cfg, true)?;

    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn create_profile_policy(project: &str, req: &mut tiny_http::Request) -> Result<ProjectView> {
    let requested: ProfilePolicyRequest = read_json_body(req)?;
    create_profile_policy_for_project(project, requested)
}

fn create_profile_policy_for_project(
    project: &str,
    requested: ProfilePolicyRequest,
) -> Result<ProjectView> {
    let name = requested
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .context("profile name is required")?
        .to_string();
    validate_profile_name(&name)?;
    let profile = profile_from_request(None, requested)?;

    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    if cfg.profiles.contains_key(&name) {
        anyhow::bail!("profile {name} already exists in project {project}");
    }
    cfg.profiles.insert(name, profile);
    config::write_project_config(&registered.path, &cfg, true)?;
    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn update_profile_policy(
    project: &str,
    profile: &str,
    req: &mut tiny_http::Request,
) -> Result<ProjectView> {
    let requested: ProfilePolicyRequest = read_json_body(req)?;
    update_profile_policy_for_project(project, profile, requested)
}

fn update_profile_policy_for_project(
    project: &str,
    profile: &str,
    requested: ProfilePolicyRequest,
) -> Result<ProjectView> {
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    let existing = cfg
        .profiles
        .remove(profile)
        .with_context(|| format!("profile {profile} not found in project {project}"))?;
    let new_name = requested
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(profile)
        .to_string();
    validate_profile_name(&new_name)?;
    if new_name != profile && cfg.profiles.contains_key(&new_name) {
        anyhow::bail!("profile {new_name} already exists in project {project}");
    }
    let profile_config = profile_from_request(Some(existing), requested)?;
    cfg.profiles.insert(new_name, profile_config);
    config::write_project_config(&registered.path, &cfg, true)?;
    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn delete_profile_policy(project: &str, profile: &str) -> Result<ProjectView> {
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    if cfg.profiles.remove(profile).is_none() {
        anyhow::bail!("profile {profile} not found in project {project}");
    }
    config::write_project_config(&registered.path, &cfg, true)?;
    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn profile_from_request(
    existing: Option<ProfileConfig>,
    requested: ProfilePolicyRequest,
) -> Result<ProfileConfig> {
    let command = string_field(
        "command",
        requested.command,
        existing.as_ref().map(|p| &p.command),
    )?;
    let action = string_field(
        "action",
        requested.action,
        existing.as_ref().map(|p| &p.action),
    )?;
    let default_scope = requested
        .default_scope
        .or_else(|| existing.as_ref().map(|p| p.default_scope))
        .unwrap_or(crate::approvals::ApprovalScope::Session);
    let env = match requested.env {
        Some(env) => normalize_env_names(env)?,
        None => existing.map(|profile| profile.env).unwrap_or_default(),
    };
    Ok(ProfileConfig {
        command,
        env,
        default_scope,
        action,
    })
}

fn string_field(
    name: &str,
    requested: Option<String>,
    existing: Option<&String>,
) -> Result<String> {
    let value = requested
        .as_deref()
        .or(existing.map(String::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is required"))?;
    Ok(value.to_string())
}

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|ch| ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
    {
        anyhow::bail!("invalid profile name: {name}");
    }
    Ok(())
}

fn pick_project_folder(req: &mut tiny_http::Request) -> Result<PickFolderResponse> {
    let body = read_optional_body(req)?;
    if !body.trim().is_empty() {
        let requested: PickFolderRequest =
            serde_json::from_str(&body).context("failed to parse folder picker request")?;
        if requested.path.is_some() {
            return pick_folder_from_request(requested);
        }
    }
    pick_folder_with_native_dialog()
}

fn pick_folder_from_request(requested: PickFolderRequest) -> Result<PickFolderResponse> {
    requested
        .path
        .map(|path| PickFolderResponse { path })
        .context("path is required")
}

fn pick_folder_with_native_dialog() -> Result<PickFolderResponse> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("osascript")
            .args([
                "-e",
                r#"POSIX path of (choose folder with prompt "Select a project folder for Ward")"#,
            ])
            .output()
            .context("failed to open Finder folder picker")?;
        if !output.status.success() {
            anyhow::bail!("folder selection was cancelled");
        }
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            anyhow::bail!("folder selection returned no path");
        }
        Ok(PickFolderResponse {
            path: PathBuf::from(path),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("native folder picker is only available on macOS")
    }
}

fn setup_project_from_dashboard(
    req: &mut tiny_http::Request,
) -> Result<broker::BrokerProjectSetupStatus> {
    let requested: ProjectSetupRequest = read_json_body(req)?;
    let target_path = validate_dashboard_setup_target(&requested.path)?;
    let cwd = std::env::current_dir()?;
    let current = registry::resolve_project(requested.source_project.as_deref(), &cwd)?;
    broker::setup_project_with_active_passphrase(
        &current.name,
        &current.vault,
        &target_path,
        requested.project,
    )
}

fn snapshot_project_from_dashboard(project: &str) -> Result<broker::BrokerProjectSnapshotStatus> {
    let cwd = std::env::current_dir()?;
    let resolved = registry::resolve_project(Some(project), &cwd)?;
    broker::snapshot_project_from_active_session(&resolved.name, &resolved.vault)
}

fn provision_project_from_dashboard(
    req: &mut tiny_http::Request,
) -> Result<broker::BrokerProjectProvisionStatus> {
    let requested: ProjectProvisionRequest = read_json_body(req)?;
    let target_path = requested.path;
    let cwd = std::env::current_dir()?;
    let source = registry::resolve_project(requested.source_project.as_deref(), &cwd)?;
    let status = broker::provision_project_from_active_session(broker::ProjectProvisionRequest {
        source_project: source.name,
        source_vault: source.vault,
        target_path,
        project: requested.project,
        profiles: requested.profiles,
        env_names: requested.env,
        agents: requested.agents,
    })?;
    Ok(status)
}

fn validate_dashboard_setup_target(path: &Path) -> Result<PathBuf> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !path.is_dir() {
        anyhow::bail!("selected path is not a directory: {}", path.display());
    }
    if !path.join(".ward.json").exists() && !path.join(".env").exists() {
        anyhow::bail!(
            "selected folder has no .env or .ward.json; choose a project folder that already has secrets or run ward setup manually"
        );
    }
    Ok(path)
}

fn read_json_body<T: for<'de> Deserialize<'de>>(req: &mut tiny_http::Request) -> Result<T> {
    let body = read_optional_body(req)?;
    serde_json::from_str(&body).context("failed to parse JSON request")
}

fn read_optional_body(req: &mut tiny_http::Request) -> Result<String> {
    let mut body = String::new();
    std::io::Read::read_to_string(req.as_reader(), &mut body)
        .context("failed to read request body")?;
    Ok(body)
}

fn normalize_env_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let trimmed = name.trim();
        if !is_valid_env_name(trimmed) {
            anyhow::bail!("invalid env name: {trimmed}");
        }
        normalized.insert(trimmed.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
}

fn dashboard_status() -> Result<DashboardStatus> {
    Ok(DashboardStatus {
        instances: running_instances()?,
        broker: broker::status()?,
        human: human_runtime_view(),
    })
}

fn dashboard_projects() -> Result<Vec<ProjectView>> {
    let registry = registry::list_projects()?;
    let broker_status = broker::status().ok();
    let mut projects = Vec::new();
    for (name, project) in &registry.projects {
        if should_hide_invalid_workspace_root(project) {
            continue;
        }
        projects.push(project_view(
            name,
            project,
            registry.active_project.as_deref(),
            broker_status.as_ref(),
        )?);
    }
    append_discovered_workspace_apps(&mut projects, &registry, broker_status.as_ref())?;
    projects.sort_by(|left, right| {
        left.workspace_root
            .cmp(&right.workspace_root)
            .then_with(|| left.parent_project.cmp(&right.parent_project))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(projects)
}

fn should_hide_invalid_workspace_root(project: &RegisteredProject) -> bool {
    !config::config_path(&project.path).is_file()
        && workspace::discover(&project.path)
            .ok()
            .flatten()
            .is_some_and(|discovery| discovery.app_candidates().next().is_some())
}

fn project_view(
    name: &str,
    project: &RegisteredProject,
    active_project: Option<&str>,
    broker_status: Option<&broker::BrokerStatus>,
) -> Result<ProjectView> {
    let config_result = config::read_project_config(&project.path);
    let mut env_names = BTreeSet::new();
    let mut profiles = Vec::new();
    let mut agent_policies = Vec::new();
    let config_status = match config_result {
        Ok(cfg) => {
            for (profile_name, profile) in cfg.profiles {
                collect_profile_env(&profile, &mut env_names);
                profiles.push(ProfileView {
                    name: profile_name,
                    command: profile.command,
                    env: profile.env,
                    default_scope: profile.default_scope,
                    action: profile.action,
                });
            }
            for (agent, policy) in cfg.agent_policies {
                env_names.extend(policy.env.iter().cloned());
                agent_policies.push(AgentPolicyView {
                    agent,
                    profiles: policy.profiles,
                    env: policy.env,
                });
            }
            "ok".to_string()
        }
        Err(error) => format!("unavailable: {error}"),
    };

    let status_expires_at = broker_status.and_then(|status| {
        status
            .sessions
            .iter()
            .filter(|session| session.project == name && same_path(&session.vault, &project.vault))
            .map(|session| session.expires_at)
            .max()
    });

    let mut vault_keys_verified = false;
    let broker_session_expires_at = if status_expires_at.is_some() {
        match broker::list_vault_keys_from_active_session(name, &project.vault) {
            Ok(vault_keys) => {
                vault_keys_verified = true;
                env_names.extend(vault_keys);
                status_expires_at
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let broker_session_active = broker_session_expires_at.is_some();

    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    agent_policies.sort_by(|left, right| left.agent.cmp(&right.agent));
    Ok(ProjectView {
        name: name.to_string(),
        path: project.path.clone(),
        vault: project.vault.clone(),
        active: active_project == Some(name),
        config_status,
        setup_status: "configured".to_string(),
        setup_available: false,
        workspace_root: project.workspace_root.clone(),
        parent_project: project.parent_workspace.clone(),
        package_name: None,
        package_kind: None,
        profiles,
        agent_policies,
        env_names: env_names.into_iter().collect(),
        vault_keys_verified,
        broker_session_active,
        broker_session_expires_at,
        store_snapshot: project_store::show_summary(name).ok(),
    })
}

fn append_discovered_workspace_apps(
    projects: &mut Vec<ProjectView>,
    registry: &registry::Registry,
    broker_status: Option<&broker::BrokerStatus>,
) -> Result<()> {
    let mut known_paths = projects
        .iter()
        .map(|project| canonical_or_self(&project.path))
        .collect::<BTreeSet<_>>();
    let known_names = projects
        .iter()
        .map(|project| project.name.clone())
        .collect::<BTreeSet<_>>();

    for (root_project_name, registered) in &registry.projects {
        let Some(discovery) = workspace::discover(&registered.path)? else {
            continue;
        };
        for package in discovery.app_candidates() {
            let canonical_path = canonical_or_self(&package.path);
            if known_paths.contains(&canonical_path) || known_names.contains(&package.project_name)
            {
                continue;
            }
            known_paths.insert(canonical_path);
            projects.push(discovered_project_view(
                root_project_name,
                package,
                registry.active_project.as_deref(),
                broker_status,
            )?);
        }
    }
    Ok(())
}

fn discovered_project_view(
    parent_project: &str,
    package: &workspace::WorkspacePackage,
    active_project: Option<&str>,
    broker_status: Option<&broker::BrokerStatus>,
) -> Result<ProjectView> {
    let mut env_names = BTreeSet::new();
    env_names.extend(package.env_example_keys.iter().cloned());
    let config_status = match package.setup_status {
        workspace::WorkspaceSetupStatus::Configured => "ok".to_string(),
        workspace::WorkspaceSetupStatus::NeedsEnv => "needs env".to_string(),
        workspace::WorkspaceSetupStatus::NotConfigured => "not configured".to_string(),
    };
    let package_vault = package.path.join(config::DEFAULT_VAULT_FILE);
    let status_expires_at = broker_status.and_then(|status| {
        status
            .sessions
            .iter()
            .filter(|session| {
                session.project == package.project_name && same_path(&session.vault, &package_vault)
            })
            .map(|session| session.expires_at)
            .max()
    });
    let broker_session_expires_at = if status_expires_at.is_some() {
        match broker::list_vault_keys_from_active_session(&package.project_name, &package_vault) {
            Ok(_) => status_expires_at,
            Err(_) => None,
        }
    } else {
        None
    };
    let broker_session_active = broker_session_expires_at.is_some();

    Ok(ProjectView {
        name: package.project_name.clone(),
        path: package.path.clone(),
        vault: package_vault,
        active: active_project == Some(package.project_name.as_str()),
        config_status,
        setup_status: workspace_setup_status_label(&package.setup_status).to_string(),
        setup_available: package.can_setup(),
        workspace_root: Some(
            package
                .path
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
                .unwrap_or_else(|| package.path.clone()),
        ),
        parent_project: Some(parent_project.to_string()),
        package_name: package.name.clone(),
        package_kind: Some(workspace_package_kind_label(&package.package_kind).to_string()),
        profiles: Vec::new(),
        agent_policies: Vec::new(),
        env_names: env_names.into_iter().collect(),
        vault_keys_verified: false,
        broker_session_active,
        broker_session_expires_at,
        store_snapshot: None,
    })
}

fn workspace_setup_status_label(status: &workspace::WorkspaceSetupStatus) -> &'static str {
    match status {
        workspace::WorkspaceSetupStatus::Configured => "configured",
        workspace::WorkspaceSetupStatus::NeedsEnv => "needsEnv",
        workspace::WorkspaceSetupStatus::NotConfigured => "notConfigured",
    }
}

fn workspace_package_kind_label(kind: &workspace::WorkspacePackageKind) -> &'static str {
    match kind {
        workspace::WorkspacePackageKind::App => "app",
        workspace::WorkspacePackageKind::Package => "package",
    }
}

fn canonical_or_self(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn collect_profile_env(profile: &ProfileConfig, names: &mut BTreeSet<String>) {
    names.extend(profile.env.iter().cloned());
}

fn load_all_events(project_filter: Option<&str>) -> Vec<Value> {
    let registry = registry::list_projects().unwrap_or_default();
    let mut all = Vec::new();
    for &kind in LogKind::all() {
        if let Ok(events) = logs::decrypt_events(kind) {
            for mut event in events {
                scrub_sensitive_fields(&mut event);
                let project = infer_event_project(&event, &registry.projects);
                if let Some(filter) = project_filter {
                    if project.as_deref() != Some(filter) {
                        continue;
                    }
                }
                if let Some(obj) = event.as_object_mut() {
                    obj.insert(
                        "_kind".to_string(),
                        Value::String(event_kind_str(kind).to_string()),
                    );
                    if let Some(project) = project {
                        obj.insert("_project".to_string(), Value::String(project));
                    }
                }
                all.push(event);
            }
        }
    }
    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(Value::as_str).unwrap_or("");
        let tb = b.get("timestamp").and_then(Value::as_str).unwrap_or("");
        tb.cmp(ta)
    });
    all
}

fn event_kind_str(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Executions => "execution",
        LogKind::Requests => "request",
        LogKind::Approvals => "approval",
        LogKind::Alerts => "alert",
        LogKind::Sessions => "session",
    }
}

fn infer_event_project(
    event: &Value,
    projects: &BTreeMap<String, RegisteredProject>,
) -> Option<String> {
    let payload = event.get("payload").unwrap_or(event);
    for path in [
        vec!["project"],
        vec!["access", "project"],
        vec!["verifiedContext", "project"],
        vec!["payload", "project"],
    ] {
        if let Some(project) = nested_str(payload, &path) {
            return Some(project.to_string());
        }
    }

    for path in [
        vec!["cwd"],
        vec!["worktree"],
        vec!["git", "worktreePath"],
        vec!["access", "worktree"],
    ] {
        if let Some(candidate) = nested_str(payload, &path) {
            if let Some(project) = project_for_path(candidate, projects) {
                return Some(project);
            }
        }
    }
    None
}

fn nested_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_str)
}

fn project_for_path(path: &str, projects: &BTreeMap<String, RegisteredProject>) -> Option<String> {
    let candidate = Path::new(path);
    projects
        .iter()
        .filter(|(_, project)| candidate.starts_with(&project.path))
        .max_by_key(|(_, project)| project.path.components().count())
        .map(|(name, _)| name.clone())
}

fn scrub_sensitive_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                if should_redact_key(key) {
                    *nested = Value::String("[redacted]".to_string());
                } else {
                    scrub_sensitive_fields(nested);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_sensitive_fields(item);
            }
        }
        _ => {}
    }
}

fn should_redact_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("passphrase")
        || lower.contains("sessiontoken")
        || lower == "token"
        || lower.contains("plaintext")
        || lower == "secret"
}

fn current_instance(port: u16, token: String) -> Result<DashboardInstance> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let started_project = registry::resolve_project(None, &cwd)
        .ok()
        .map(|project| project.name);
    let url = dashboard_url(port, &token);
    Ok(DashboardInstance {
        pid: std::process::id(),
        port,
        url,
        token,
        started_project,
        started_path: cwd,
        started_at: chrono::Utc::now().to_rfc3339(),
        version: DASHBOARD_VERSION.to_string(),
    })
}

fn print_start_result(result: &DashboardStartResult, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else if result.reused {
        term::emit_header(&term::Header {
            command: Some("dashboard start"),
            project: result
                .instance
                .started_project
                .as_deref()
                .unwrap_or("local"),
            path: Some(&result.instance.started_path),
            mode: Some("reused"),
        });
        term::ok_detail(
            "dashboard already running",
            &format!("pid {}", result.instance.pid),
        );
        term::ok_detail("url", &result.instance.url);
    } else {
        term::emit_header(&term::Header {
            command: Some("dashboard start"),
            project: result
                .instance
                .started_project
                .as_deref()
                .unwrap_or("local"),
            path: Some(&result.instance.started_path),
            mode: None,
        });
        term::ok_detail("dashboard running", &format!("pid {}", result.instance.pid));
        term::ok_detail("url", &result.instance.url);
    }
    Ok(())
}

fn select_stop_targets(options: &DashboardStopOptions) -> Result<Vec<DashboardInstance>> {
    let target_all = options.all || (options.pid.is_none() && options.port.is_none());
    let mut targets = running_instances()?
        .into_iter()
        .filter(|instance| {
            target_all || options.pid == Some(instance.pid) || options.port == Some(instance.port)
        })
        .collect::<Vec<_>>();

    if let Some(pid) = options.pid {
        if targets.is_empty() && is_dashboard_process(pid) {
            targets.push(transient_instance(pid));
        }
    }

    Ok(targets)
}

fn transient_instance(pid: u32) -> DashboardInstance {
    DashboardInstance {
        pid,
        port: 0,
        url: String::new(),
        token: String::new(),
        started_project: None,
        started_path: PathBuf::new(),
        started_at: String::new(),
        version: DASHBOARD_VERSION.to_string(),
    }
}

fn dashboard_url(port: u16, token: &str) -> String {
    format!("http://127.0.0.1:{port}/?token={token}")
}

fn generate_token() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn find_available_port(start: u16) -> u16 {
    for port in start..start + PORT_SCAN_WIDTH {
        if std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok() {
            return port;
        }
    }
    start
}

fn port_accepts_connections(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

fn metadata_dir() -> PathBuf {
    logs::ward_home().join("run").join("dashboard")
}

fn metadata_path(pid: u32) -> PathBuf {
    metadata_dir().join(format!("{pid}.json"))
}

fn write_instance(instance: &DashboardInstance) -> Result<()> {
    fs_util::ensure_private_dir(&metadata_dir())?;
    let body = serde_json::to_vec_pretty(instance)?;
    fs_util::write_private_file(&metadata_path(instance.pid), &body)
}

fn remove_instance(pid: u32) -> Result<()> {
    let path = metadata_path(pid);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn running_instances() -> Result<Vec<DashboardInstance>> {
    Ok(load_instances()?
        .into_iter()
        .filter(|instance| {
            human::process_exists(instance.pid) && is_dashboard_process(instance.pid)
        })
        .collect())
}

fn load_instances() -> Result<Vec<DashboardInstance>> {
    let dir = metadata_dir();
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut instances = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(instance) = serde_json::from_str::<DashboardInstance>(&contents) {
            instances.push(instance);
        }
    }
    instances.sort_by_key(|instance| instance.pid);
    Ok(instances)
}

fn cleanup_stale_instances() -> Result<usize> {
    let mut removed = 0;
    for instance in load_instances()? {
        let version_mismatch = instance.version != DASHBOARD_VERSION;
        if version_mismatch {
            terminate_dashboard_process(instance.pid);
            let _ = remove_instance(instance.pid);
            removed += 1;
            continue;
        }
        if !human::process_exists(instance.pid) || !is_dashboard_process(instance.pid) {
            let _ = remove_instance(instance.pid);
            removed += 1;
        }
    }
    Ok(removed)
}

fn human_runtime_view() -> HumanRuntimeView {
    let diagnostics = human::runtime_diagnostics();
    HumanRuntimeView {
        shell_pid: diagnostics.shell_pid,
        shell_hooks_loaded: diagnostics.shell_hooks_loaded,
        guardian_socket_exists: diagnostics.guardian_socket_exists,
        socket_path: diagnostics.socket_path,
        stale_guardian_pids: diagnostics.stale_guardian_pids,
        stale_run_dirs: diagnostics.stale_run_dirs,
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

fn open_browser_best_effort(url: &str) {
    #[cfg(target_os = "macos")]
    let command = ("open", vec![url]);
    #[cfg(target_os = "linux")]
    let command = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let command = ("cmd", vec!["/C", "start", "", url]);

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let _ = Command::new(command.0)
            .args(command.1)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

fn terminate_dashboard_process(pid: u32) {
    #[cfg(unix)]
    {
        if !is_dashboard_process(pid) {
            return;
        }
        // SAFETY: target pid is selected by dashboard command-line inspection.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if !human::process_exists(pid) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        // SAFETY: best-effort stop for the same dashboard process if SIGTERM was ignored.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn is_dashboard_process(pid: u32) -> bool {
    command_line(pid)
        .map(|line| {
            line.contains("__dashboard-server")
                || (line.contains("dashboard")
                    && line.contains("--foreground")
                    && line.contains("ward"))
        })
        .unwrap_or(false)
}

fn command_line(pid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

const DASHBOARD_HTML: &str = include_str!("../dashboard.html");
const WARD_LOGO_DARK_SVG: &str = include_str!("../assets/ward-logo-dark.svg");
const WARD_LOGO_TRANSPARENT_SVG: &str = include_str!("../assets/ward-logo-transparent.svg");
const WARD_LOGO_DARK_PNG: &[u8] = include_bytes!("../assets/ward-logo-dark.png");
const WARD_FAVICON_LIGHT_PNG: &[u8] = include_bytes!("../assets/ward-favicon-light.png");

#[allow(dead_code)]
const LEGACY_OVERVIEW_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ward Dashboard</title>
<style>
  * { box-sizing: border-box; }
  :root {
    --bg: #0f1115;
    --panel: #171a20;
    --panel-2: #1d222a;
    --line: #2b323c;
    --text: #e7ecf2;
    --muted: #91a0ae;
    --faint: #64717f;
    --accent: #34d399;
    --blue: #60a5fa;
    --warn: #f59e0b;
    --danger: #fb7185;
    --radius: 8px;
    --font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    --mono: "SF Mono", "Cascadia Code", "Roboto Mono", monospace;
  }
  body {
    margin: 0;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
    font: 13px/1.4 var(--font);
    overflow: hidden;
  }
  button, input { font: inherit; }
  .shell { display: grid; grid-template-columns: 260px 1fr; height: 100vh; }
  aside {
    border-right: 1px solid var(--line);
    background: #12151a;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .brand {
    height: 52px;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 16px;
    border-bottom: 1px solid var(--line);
    font-weight: 700;
    letter-spacing: 0;
  }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); }
  .project-list { overflow: auto; padding: 8px; }
  .project {
    width: 100%;
    text-align: left;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text);
    padding: 9px 10px;
    border-radius: var(--radius);
    cursor: pointer;
  }
  .project:hover { background: var(--panel); }
  .project.active { background: var(--panel-2); border-color: var(--line); }
  .project-name { font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .project-path { color: var(--faint); font: 11px var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 2px; }
  main { display: grid; grid-template-rows: 52px 1fr; min-width: 0; }
  header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 0 18px;
    border-bottom: 1px solid var(--line);
    background: var(--panel);
  }
  .title { font-weight: 700; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .header-meta { margin-left: auto; color: var(--muted); font-size: 12px; display: flex; align-items: center; gap: 12px; }
  .btn {
    border: 1px solid var(--line);
    border-radius: 6px;
    background: #20252d;
    color: var(--text);
    padding: 5px 10px;
    cursor: pointer;
  }
  .btn:hover { border-color: var(--muted); }
  .content {
    display: grid;
    grid-template-columns: minmax(460px, 1fr) minmax(360px, 0.8fr);
    gap: 0;
    min-height: 0;
  }
  .left, .right { overflow: auto; padding: 16px 18px; }
  .right { border-left: 1px solid var(--line); background: #111419; }
  section { margin-bottom: 18px; }
  .section-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  h2 { margin: 0; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }
  .subtle { color: var(--faint); font-size: 12px; }
  .panel {
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--panel);
    overflow: hidden;
  }
  .kv { display: grid; grid-template-columns: 140px 1fr; border-bottom: 1px solid var(--line); }
  .kv:last-child { border-bottom: 0; }
  .kv div { padding: 8px 10px; min-width: 0; }
  .kv div:first-child { color: var(--muted); }
  .mono { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; background: #15191f; position: sticky; top: 0; }
  tr:last-child td { border-bottom: 0; }
  .check { display: flex; align-items: center; gap: 6px; margin: 2px 0; color: var(--text); font-family: var(--mono); font-size: 12px; }
  .env-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 3px 10px; }
  .input-row { display: flex; gap: 8px; padding: 10px; border-top: 1px solid var(--line); }
  .input-row input { flex: 1; min-width: 0; background: #101318; color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 6px 8px; }
  .pill { display: inline-flex; align-items: center; min-height: 22px; padding: 2px 8px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: 12px; }
  .pill.ok { color: var(--accent); border-color: rgba(52,211,153,.35); }
  .pill.warn { color: var(--warn); border-color: rgba(245,158,11,.35); }
  .events { max-height: 460px; overflow: auto; }
  .event-row { cursor: pointer; }
  .event-row:hover { background: #1b2027; }
  .kind { color: var(--blue); font-family: var(--mono); font-size: 11px; }
  pre { margin: 0; white-space: pre-wrap; word-break: break-word; font: 11px/1.45 var(--mono); color: var(--muted); }
  @media (max-width: 900px) {
    body { overflow: auto; }
    .shell, main, .content { display: block; height: auto; }
    aside { border-right: 0; border-bottom: 1px solid var(--line); }
    .project-list { display: flex; overflow-x: auto; }
    .project { min-width: 220px; }
    .right { border-left: 0; border-top: 1px solid var(--line); }
  }
</style>
</head>
<body>
<div class="shell">
  <aside>
    <div class="brand"><span class="status-dot"></span><span>Ward Dashboard</span></div>
    <div class="project-list" id="projects"></div>
  </aside>
  <main>
    <header>
      <div class="title" id="title">Projects</div>
      <div class="header-meta">
        <span id="lastRefresh"></span>
        <button class="btn" id="refresh">Refresh</button>
      </div>
    </header>
    <div class="content">
      <div class="left">
        <section>
          <div class="section-head"><h2>Project</h2><span class="pill" id="configState">-</span></div>
          <div class="panel" id="projectMeta"></div>
        </section>
        <section>
          <div class="section-head"><h2>Profile Env Policy</h2><span class="subtle" id="vaultState"></span></div>
          <div class="panel" id="profiles"></div>
        </section>
      </div>
      <div class="right">
        <section>
          <div class="section-head"><h2>Runtime</h2><span class="pill" id="brokerState">-</span></div>
          <div class="panel" id="runtime"></div>
        </section>
        <section>
          <div class="section-head"><h2>Logs</h2><span class="subtle" id="eventCount"></span></div>
          <div class="panel events"><table><thead><tr><th>Time</th><th>Kind</th><th>Event</th></tr></thead><tbody id="events"></tbody></table></div>
        </section>
        <section>
          <div class="section-head"><h2>Event Detail</h2></div>
          <div class="panel" style="padding:10px"><pre id="eventDetail">Select an event</pre></div>
        </section>
      </div>
    </div>
  </main>
</div>
<script>
const token = new URLSearchParams(location.search).get('token') || '';
let projects = [];
let status = null;
let events = [];
let selectedProject = null;

function withToken(path) {
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}token=${encodeURIComponent(token)}`;
}

async function api(path, options = {}) {
  const response = await fetch(withToken(path), {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function load() {
  [projects, status] = await Promise.all([
    api('/api/projects'),
    api('/api/dashboard/status')
  ]);
  if (!selectedProject && projects.length) {
    selectedProject = (projects.find(p => p.active) || projects[0]).name;
  }
  await loadEvents();
  render();
}

async function loadEvents() {
  const suffix = selectedProject ? `?project=${encodeURIComponent(selectedProject)}` : '';
  events = await api(`/api/events${suffix}`);
}

function render() {
  renderProjects();
  renderProject();
  renderRuntime();
  renderEvents();
  document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();
}

function currentProject() {
  return projects.find(p => p.name === selectedProject) || projects[0] || null;
}

function renderProjects() {
  const host = document.getElementById('projects');
  host.innerHTML = '';
  projects.forEach(project => {
    const btn = document.createElement('button');
    btn.className = `project ${project.name === selectedProject ? 'active' : ''}`;
    btn.innerHTML = `<div class="project-name">${esc(project.name)}</div><div class="project-path">${esc(project.path)}</div>`;
    btn.addEventListener('click', async () => {
      selectedProject = project.name;
      await loadEvents();
      render();
    });
    host.appendChild(btn);
  });
}

function renderProject() {
  const project = currentProject();
  document.getElementById('title').textContent = project ? project.name : 'Projects';
  if (!project) {
    document.getElementById('projectMeta').innerHTML = '<div class="kv"><div>Status</div><div>No projects registered</div></div>';
    document.getElementById('profiles').innerHTML = '';
    return;
  }
  document.getElementById('configState').textContent = project.configStatus;
  document.getElementById('configState').className = `pill ${project.configStatus === 'ok' ? 'ok' : 'warn'}`;
  document.getElementById('vaultState').textContent = project.vaultKeysVerified ? 'vault keys verified' : 'vault keys unavailable';
  document.getElementById('projectMeta').innerHTML = [
    kv('path', project.path),
    kv('vault', project.vault),
    kv('broker session', project.brokerSessionActive ? 'active' : 'inactive'),
    kv('env names', String(project.envNames.length))
  ].join('');
  renderProfiles(project);
}

function renderProfiles(project) {
  const host = document.getElementById('profiles');
  if (!project.profiles.length) {
    host.innerHTML = '<div class="kv"><div>Profiles</div><div>None</div></div>';
    return;
  }
  host.innerHTML = project.profiles.map(profile => `
    <div style="border-bottom:1px solid var(--line)">
      <div class="kv"><div>${esc(profile.name)}</div><div class="mono">${esc(profile.command)}</div></div>
      <div style="padding:10px">
        <div class="env-grid">
          ${project.envNames.map(name => checkbox(project.name, profile.name, name, profile.env.includes(name))).join('')}
        </div>
      </div>
      <div class="input-row">
        <input data-add-env="${esc(project.name)}:${esc(profile.name)}" placeholder="ENV_NAME">
        <button class="btn" data-add-btn="${esc(project.name)}:${esc(profile.name)}">Add</button>
      </div>
    </div>
  `).join('');
  host.querySelectorAll('input[type="checkbox"]').forEach(input => {
    input.addEventListener('change', () => toggleEnv(project.name, input.dataset.profile, input.dataset.env, input.checked));
  });
  host.querySelectorAll('[data-add-btn]').forEach(btn => {
    btn.addEventListener('click', () => {
      const [projectName, profileName] = btn.dataset.addBtn.split(':');
      const input = host.querySelector(`[data-add-env="${cssEsc(projectName)}:${cssEsc(profileName)}"]`);
      addEnv(projectName, profileName, input.value);
      input.value = '';
    });
  });
}

function checkbox(project, profile, env, checked) {
  return `<label class="check"><input type="checkbox" data-project="${esc(project)}" data-profile="${esc(profile)}" data-env="${esc(env)}" ${checked ? 'checked' : ''}>${esc(env)}</label>`;
}

async function toggleEnv(projectName, profileName, envName, enabled) {
  const project = projects.find(p => p.name === projectName);
  const profile = project.profiles.find(p => p.name === profileName);
  const env = new Set(profile.env);
  enabled ? env.add(envName) : env.delete(envName);
  await saveProfileEnv(projectName, profileName, [...env]);
}

async function addEnv(projectName, profileName, envName) {
  envName = envName.trim();
  if (!envName) return;
  const project = projects.find(p => p.name === projectName);
  const profile = project.profiles.find(p => p.name === profileName);
  const env = new Set([...profile.env, envName]);
  await saveProfileEnv(projectName, profileName, [...env]);
}

async function saveProfileEnv(projectName, profileName, env) {
  const updated = await api(`/api/projects/${encodeURIComponent(projectName)}/profiles/${encodeURIComponent(profileName)}/env`, {
    method: 'PATCH',
    body: JSON.stringify({ env })
  });
  projects = projects.map(project => project.name === projectName ? updated : project);
  renderProject();
}

function renderRuntime() {
  const broker = status && status.broker;
  document.getElementById('brokerState').textContent = broker && broker.running ? 'broker active' : 'broker inactive';
  document.getElementById('brokerState').className = `pill ${broker && broker.running ? 'ok' : 'warn'}`;
  const rows = [];
  rows.push(kv('dashboards', String((status && status.instances || []).length)));
  rows.push(kv('guardian', status && status.human.guardianSocketExists ? 'active' : 'inactive'));
  rows.push(kv('shell pid', status ? String(status.human.shellPid) : '-'));
  rows.push(kv('sessions', broker ? String(broker.sessions.length) : '0'));
  document.getElementById('runtime').innerHTML = rows.join('');
}

function renderEvents() {
  document.getElementById('eventCount').textContent = `${events.length} events`;
  const body = document.getElementById('events');
  body.innerHTML = events.slice(0, 250).map((event, index) => {
    const payload = event.payload || event;
    const label = payload.eventType || payload.requestedCommand || payload.declaredAction || payload.status || '-';
    return `<tr class="event-row" data-event-index="${index}">
      <td class="mono">${esc((event.timestamp || '').slice(11, 19))}</td>
      <td class="kind">${esc(event._kind || '-')}</td>
      <td>${esc(String(label))}</td>
    </tr>`;
  }).join('');
  body.querySelectorAll('.event-row').forEach(row => {
    row.addEventListener('click', () => {
      const event = events[Number(row.dataset.eventIndex)];
      document.getElementById('eventDetail').textContent = JSON.stringify(event, null, 2);
    });
  });
}

function kv(label, value) {
  return `<div class="kv"><div>${esc(label)}</div><div class="mono">${esc(value)}</div></div>`;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function cssEsc(value) {
  return String(value).replace(/["\\]/g, '\\$&');
}

document.getElementById('refresh').addEventListener('click', load);
load().catch(error => {
  document.getElementById('title').textContent = 'Dashboard error';
  document.getElementById('projectMeta').innerHTML = `<div class="kv"><div>Error</div><div>${esc(error.message)}</div></div>`;
});
</script>
</body>
</html>"##;

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
