pub mod display;

use std::{
    io::{BufRead, BufReader, IsTerminal, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{broker, config, fs_util, global_disable, term, workspace_target};
use base64::Engine as _;

const HUMAN_ACTIVATION_BODY: &str =
    "Enter your vault passphrase to activate human mode for this terminal.";
const HUMAN_ACTIVE_BODY: &str =
    "This terminal is now protected. Normal project commands receive vault envs through Ward while this session is active.";

// ── Path helpers ─────────────────────────────────────────────────────────────

pub fn human_run_dir(shell_pid: u32) -> PathBuf {
    let relative = PathBuf::from("run").join(format!("human-{shell_pid}"));
    fs_util::resolve_ward_home_path(&relative, "human run directory")
        .expect("human run directory should stay inside Ward home")
}

pub fn guardian_socket_path(shell_pid: u32) -> PathBuf {
    human_run_dir(shell_pid).join("guardian.sock")
}

fn ready_marker_path(shell_pid: u32) -> PathBuf {
    human_run_dir(shell_pid).join("ready")
}

// ── Terminal identity ─────────────────────────────────────────────────────────

pub fn parent_pid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getppid() is always safe; reads a process attribute only.
        unsafe { libc::getppid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub fn current_shell_pid() -> u32 {
    std::env::var("WARD_HUMAN_SHELL_PID")
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|pid| *pid != 0)
        .unwrap_or_else(parent_pid)
}

pub fn is_human_terminal() -> bool {
    guardian_socket_path(current_shell_pid()).exists()
}

#[derive(Debug, Clone)]
pub struct RuntimeDiagnostics {
    pub shell_pid: u32,
    pub socket_path: PathBuf,
    pub shell_hooks_loaded: bool,
    pub guardian_socket_exists: bool,
    pub stale_guardian_pids: Vec<u32>,
    pub stale_run_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct GuardianProcess {
    pid: u32,
    shell_pid: u32,
}

pub fn runtime_diagnostics() -> RuntimeDiagnostics {
    let shell_pid = current_shell_pid();
    let socket_path = guardian_socket_path(shell_pid);
    RuntimeDiagnostics {
        shell_pid,
        guardian_socket_exists: socket_path.exists(),
        socket_path,
        shell_hooks_loaded: std::env::var_os("WARD_SHELL_INTEGRATION").is_some(),
        stale_guardian_pids: stale_guardian_processes()
            .into_iter()
            .map(|guardian| guardian.pid)
            .collect(),
        stale_run_dirs: stale_human_run_dirs(),
    }
}

pub fn cleanup_stale_runtime() -> RuntimeDiagnostics {
    let diagnostics = runtime_diagnostics();
    for pid in &diagnostics.stale_guardian_pids {
        terminate_process(*pid);
    }
    for dir in &diagnostics.stale_run_dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
    diagnostics
}

// ── Guardian protocol ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GuardianRequest {
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GuardianResponse {
    Ok,
    Error { reason: String, message: String },
}

fn write_guardian_response(stream: &mut UnixStream, resp: &GuardianResponse) -> Result<()> {
    let mut line = serde_json::to_string(resp)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    Ok(())
}

// ── Guardian subprocess ───────────────────────────────────────────────────────

pub fn serve_guardian(
    shell_pid: u32,
    session_token: &str,
    ttl_seconds: i64,
    projects: Vec<String>,
) -> Result<()> {
    let dir = human_run_dir(shell_pid);
    let socket_path = guardian_socket_path(shell_pid);
    let ready_path = ready_marker_path(shell_pid);

    // Clean up any stale socket from a previous crashed guardian.
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    fs_util::ensure_private_dir(&dir)?;
    let listener = UnixListener::bind(&socket_path).with_context(|| {
        format!(
            "failed to bind guardian socket at {}",
            socket_path.display()
        )
    })?;
    listener.set_nonblocking(true)?;

    broker::ensure_running()?;
    broker::register_human_session(shell_pid, session_token, ttl_seconds, &projects)?;

    // Write the ready marker — `activate_human_mode` polls for this.
    fs_util::write_private_file(&ready_path, b"")?;

    let deadline = Instant::now() + Duration::from_secs(ttl_seconds.max(0) as u64);

    'accept: loop {
        if Instant::now() >= deadline {
            break;
        }
        if !process_exists(shell_pid) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut reader = BufReader::new(stream.try_clone()?);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    match serde_json::from_str::<GuardianRequest>(line.trim()) {
                        Ok(GuardianRequest::Shutdown) => {
                            let _ = write_guardian_response(&mut stream, &GuardianResponse::Ok);
                            break 'accept;
                        }
                        Err(_) => {
                            let _ = write_guardian_response(
                                &mut stream,
                                &GuardianResponse::Error {
                                    reason: "unknown_request".into(),
                                    message: "unrecognised guardian request".into(),
                                },
                            );
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    // Cleanup — deregister session and remove files.
    let _ = broker::deregister_human_session(shell_pid, session_token);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&ready_path);
    let _ = std::fs::remove_dir(&dir);

    Ok(())
}

pub fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) does not send a signal; it only checks process visibility.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

// ── Shutdown from lock() ──────────────────────────────────────────────────────

pub fn send_guardian_shutdown() -> Result<()> {
    let socket_path = guardian_socket_path(current_shell_pid());
    if !socket_path.exists() {
        return Ok(());
    }
    let mut stream =
        UnixStream::connect(&socket_path).context("failed to connect to human guardian socket")?;
    let mut msg = serde_json::to_string(&GuardianRequest::Shutdown)?;
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;
    // Best-effort read response; ignore errors.
    let mut reader = BufReader::new(stream);
    let mut _line = String::new();
    let _ = reader.read_line(&mut _line);
    Ok(())
}

// ── Activation (ward human command handler) ───────────────────────────────────

pub fn activate_human_mode(
    project: Option<String>,
    app: Option<String>,
    all: bool,
    ttl: &str,
) -> Result<()> {
    use crate::{logs::LogKind, registry, unlock, vault};

    if global_disable::is_disabled() {
        term::warn("Ward is globally disabled — run: ward on");
        return Ok(());
    }

    let cwd = std::env::current_dir()?;
    let selector = workspace_target::TargetSelector { project, app, all };
    let selector = resolve_human_selector(selector, &cwd)?;
    let (header_project, header_path) = human_header_context(&selector, &cwd);
    term::guided_header(
        "human",
        &header_project,
        &header_path,
        HUMAN_ACTIVATION_BODY,
    );

    let passphrase = vault::read_existing_passphrase()?;
    let targets = workspace_target::resolve_many_with_passphrase(&selector, &cwd, &passphrase)?;
    let duration = unlock::parse_ttl(ttl)?;
    let ttl_seconds = duration.num_seconds();

    // Unlock each target in the broker master-session map.
    for target in &targets {
        let resolved = target.resolved_project();
        registry::update_project_vault(
            &resolved.name,
            resolved.path.clone(),
            resolved.vault.clone(),
        )?;
        if let Err(error) = crate::cli::create_run_unlock_session(
            &resolved.name,
            &resolved.vault,
            &passphrase,
            ttl,
            None,
        ) {
            term::emit_block(&term::MessageBlock {
                level: term::StatusLevel::Warn,
                title: "human mode not activated",
                body: Some("the vault passphrase did not unlock this project"),
                command: Some("ward human"),
            });
            return Err(error).context("human mode was not activated");
        }
    }

    // Generate a random session token.
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let session_token = base64::engine::general_purpose::STANDARD.encode(bytes);

    let shell_pid = parent_pid();
    let shell_hooks_loaded = shell_hooks_loaded();
    let _ = cleanup_stale_runtime();

    // Clean up any stale previous session for this terminal.
    terminate_existing_guardians(shell_pid);
    let stale_socket = guardian_socket_path(shell_pid);
    if stale_socket.exists() {
        let _ = std::fs::remove_file(&stale_socket);
    }
    let _ = std::fs::remove_dir_all(human_run_dir(shell_pid));

    // Spawn guardian subprocess.
    let exe = std::env::current_exe().context("cannot locate ward binary")?;
    let project_names = targets
        .iter()
        .map(|target| target.name.clone())
        .collect::<Vec<_>>();
    let mut command = std::process::Command::new(&exe);
    command
        .arg("__human-guardian")
        .arg("--shell-pid")
        .arg(shell_pid.to_string())
        .arg("--session-token")
        .arg(&session_token)
        .arg("--ttl-seconds")
        .arg(ttl_seconds.to_string());
    for project_name in &project_names {
        command.arg("--project").arg(project_name);
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("failed to spawn human guardian")?;

    // Allow detached broker and guardian startup to settle on slower machines.
    let ready = ready_marker_path(shell_pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        if Instant::now() >= deadline {
            term::emit_block(&term::MessageBlock {
                level: term::StatusLevel::Warn,
                title: "human mode not activated",
                body: Some("the terminal guardian did not become ready in time"),
                command: Some("ward human"),
            });
            anyhow::bail!("human guardian did not become ready in time");
        }
        thread::sleep(Duration::from_millis(25));
    }

    let expires_at = (chrono::Utc::now() + duration).to_rfc3339();
    let ttl_label = format_ttl_label(ttl_seconds);

    term::section("session");
    term::ok("human mode active");
    term::info(HUMAN_ACTIVE_BODY);
    if targets.len() > 1 {
        term::ok_detail(
            "workspace apps unlocked",
            &format!("{} project sessions", targets.len()),
        );
    }
    term::ok_detail("expires", &ttl_label);
    term::ok_detail("guardian attached", &format!("shell {shell_pid}"));

    term::section("commands");
    if shell_hooks_loaded {
        term::ok_detail("commands wrapped", "route through ward run");
        term::next("try: pnpm dev");
    } else {
        print_missing_shell_hooks_warning();
    }

    if let Ok(instances) = crate::webui::dashboard_diagnostics() {
        if let Some(instance) = instances.first() {
            term::section("dashboard");
            term::next(&format!("open: {}", instance.url));
        }
    }

    #[derive(serde::Serialize)]
    struct HumanModeEvent {
        event_type: &'static str,
        shell_pid: u32,
        expires_at: String,
    }
    crate::logs::append_event(
        LogKind::Sessions,
        HumanModeEvent {
            event_type: "human_mode.activated",
            shell_pid,
            expires_at,
        },
    )?;

    Ok(())
}

fn human_header_context(
    selector: &workspace_target::TargetSelector,
    cwd: &std::path::Path,
) -> (String, PathBuf) {
    if let Ok(targets) = workspace_target::resolve_many(selector, cwd) {
        if targets.len() == 1 {
            let target = &targets[0];
            return (target.name.clone(), target.path.clone());
        }
        if let Some(target) = targets.first() {
            if let (Some(name), Some(root)) = (&target.workspace_name, &target.workspace_root) {
                return (format!("{name} workspace"), root.clone());
            }
        }
    }

    if let Some(root) = config::find_project_root(cwd) {
        if let Ok(cfg) = config::read_project_config(&root) {
            return (cfg.project, root);
        }
    }

    let project = cwd
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project")
        .to_string();
    (project, cwd.to_path_buf())
}

fn resolve_human_selector(
    selector: workspace_target::TargetSelector,
    cwd: &std::path::Path,
) -> Result<workspace_target::TargetSelector> {
    if selector.project.is_some() || selector.app.is_some() || selector.all {
        return Ok(selector);
    }
    if crate::config::find_project_root(cwd).is_some() {
        return Ok(selector);
    }
    let Some(discovery) = crate::workspace::discover_containing(cwd)? else {
        return Ok(selector);
    };
    let targets = workspace_target::configured_workspace_targets(&discovery)?;
    match targets.len() {
        0 => anyhow::bail!("workspace has no configured Ward app projects; run ward setup --workspace"),
        1 => {
            let target = targets.into_iter().next().expect("one target exists");
            Ok(workspace_target::TargetSelector {
                project: None,
                app: target.app_slug.or(Some(target.name)),
                all: false,
            })
        }
        _ if std::io::stdin().is_terminal() => {
            let labels = targets
                .iter()
                .map(|target| {
                    let app = target.app_slug.as_deref().unwrap_or(&target.name);
                    format!("{app} ({})", target.name)
                })
                .collect::<Vec<_>>();
            term::section("Project");
            term::info("This workspace has multiple Ward app projects.");
            let selected = inquire::Select::new("Activate human mode for which app?", labels.clone())
                .prompt()
                .context("app selection cancelled")?;
            let index = labels
                .iter()
                .position(|label| label == &selected)
                .context("selected app was not found")?;
            let target = targets[index].clone();
            Ok(workspace_target::TargetSelector {
                project: None,
                app: target.app_slug.or(Some(target.name)),
                all: false,
            })
        }
        _ => anyhow::bail!(
            "workspace root has multiple Ward app projects; human mode is per app, so choose one with --app <app> or --project <project>, or run ward human inside each app folder: {}",
            workspace_target::target_suggestions(&targets)
        ),
    }
}

fn shell_hooks_loaded() -> bool {
    std::env::var_os("WARD_SHELL_INTEGRATION").is_some()
}

fn missing_shell_hooks_warning_lines() -> [&'static str; 4] {
    [
        "shell hooks are not loaded for this terminal",
        "Ward can unlock the vault, but normal commands may not be wrapped yet.",
        "Reload your shell, then run:",
        "exec $SHELL && ward human",
    ]
}

fn print_missing_shell_hooks_warning() {
    let [title, body, lead, command] = missing_shell_hooks_warning_lines();
    term::warn(title);
    term::info(body);
    term::info(lead);
    term::command_hint(command);
}

fn terminate_existing_guardians(shell_pid: u32) {
    #[cfg(unix)]
    {
        let current_pid = std::process::id();
        for guardian in guardian_processes() {
            if guardian.shell_pid != shell_pid || guardian.pid == current_pid {
                continue;
            }
            terminate_process(guardian.pid);
        }
    }
}

#[cfg(unix)]
fn guardian_processes() -> Vec<GuardianProcess> {
    let Ok(output) = std::process::Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
    else {
        return Vec::new();
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter(|line| line.contains("__human-guardian"))
        .filter_map(parse_guardian_process)
        .collect()
}

#[cfg(not(unix))]
fn guardian_processes() -> Vec<GuardianProcess> {
    Vec::new()
}

fn parse_guardian_process(line: &str) -> Option<GuardianProcess> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    let pid = parts.first()?.parse::<u32>().ok()?;
    let shell_pid = parts
        .windows(2)
        .find_map(|window| (window[0] == "--shell-pid").then(|| window[1]))
        .and_then(|raw| raw.parse::<u32>().ok())?;
    Some(GuardianProcess { pid, shell_pid })
}

fn stale_guardian_processes() -> Vec<GuardianProcess> {
    guardian_processes()
        .into_iter()
        .filter(|guardian| !process_exists(guardian.shell_pid))
        .collect()
}

fn stale_human_run_dirs() -> Vec<PathBuf> {
    let run_dir = broker::run_dir();
    let Ok(entries) = std::fs::read_dir(run_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter_map(|path| {
            let shell_pid = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("human-"))
                .and_then(|raw| raw.parse::<u32>().ok())?;
            if !process_exists(shell_pid) || !path.join("guardian.sock").exists() {
                Some(path)
            } else {
                None
            }
        })
        .collect()
}

fn terminate_process(pid: u32) {
    #[cfg(unix)]
    {
        // SAFETY: sends SIGTERM to a Ward guardian process selected by command line.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn format_ttl_label(ttl_seconds: i64) -> String {
    let h = ttl_seconds / 3600;
    let m = (ttl_seconds % 3600) / 60;
    if m == 0 {
        format!("{h}h")
    } else if h == 0 {
        format!("{m}m")
    } else {
        format!("{h}h {m}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_helpers_use_shell_pid() {
        let dir = human_run_dir(4821);
        assert!(dir.to_string_lossy().contains("human-4821"));
        let sock = guardian_socket_path(4821);
        assert!(sock.to_string_lossy().ends_with("human-4821/guardian.sock"));
    }

    #[test]
    fn is_human_terminal_false_when_no_socket() {
        // With a random PID that certainly has no socket file.
        assert!(!guardian_socket_path(9999999).exists());
    }

    #[test]
    fn ttl_label_formatting() {
        assert_eq!(format_ttl_label(28800), "8h");
        assert_eq!(format_ttl_label(3600), "1h");
        assert_eq!(format_ttl_label(5400), "1h 30m");
        assert_eq!(format_ttl_label(1800), "30m");
    }

    #[test]
    fn missing_shell_hooks_copy_includes_exact_reload_command() {
        let lines = missing_shell_hooks_warning_lines();
        assert_eq!(lines[0], "shell hooks are not loaded for this terminal");
        assert_eq!(lines[3], "exec $SHELL && ward human");
    }

    #[test]
    fn activation_copy_distinguishes_prompt_from_success() {
        assert!(HUMAN_ACTIVATION_BODY.contains("activate human mode"));
        assert!(HUMAN_ACTIVE_BODY.contains("This terminal is now protected"));
    }
}
