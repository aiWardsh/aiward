pub mod display;

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{broker, fs_util, logs, process_util, term};
use base64::Engine as _;

const HUMAN_ACTIVATION_BODY: &str =
    "Enter your vault passphrase to activate human mode for this terminal.";
const HUMAN_ACTIVE_BODY: &str = "This terminal is now protected. Normal commands in this Ward project will receive vault envs through Ward while this session is active.";

// ── Path helpers ─────────────────────────────────────────────────────────────

pub fn human_run_dir(shell_pid: u32) -> PathBuf {
    logs::ward_home()
        .join("run")
        .join(format!("human-{shell_pid}"))
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

pub fn serve_guardian(shell_pid: u32, session_token: &str, ttl_seconds: i64) -> Result<()> {
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
    broker::register_human_session(shell_pid, session_token, ttl_seconds)?;

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
    process_util::process_exists(pid)
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
    use crate::{config, logs::LogKind, registry, unlock, vault, workspace, workspace_target};

    let cwd = std::env::current_dir()?;
    let workspace_root_mode = project.is_none()
        && app.is_none()
        && config::find_project_root(&cwd).is_none()
        && workspace::discover_containing(&cwd)?.is_some();
    let (header_project, header_path) = config::find_project_root(&cwd)
        .and_then(|root| {
            config::read_project_config(&root)
                .ok()
                .map(|cfg| (cfg.project, root))
        })
        .unwrap_or_else(|| {
            let project = cwd
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("project")
                .to_string();
            (project, cwd.clone())
        });
    term::guided_header(
        "human",
        &header_project,
        &header_path,
        HUMAN_ACTIVATION_BODY,
    );

    let passphrase = vault::read_existing_passphrase()?;
    let selector = workspace_target::TargetSelector {
        project,
        app,
        all: all || workspace_root_mode,
    };
    let targets = workspace_target::resolve_many_with_passphrase(&selector, &cwd, &passphrase)?;
    let duration = unlock::parse_ttl(ttl)?;
    let ttl_seconds = duration.num_seconds();

    // Unlock vault in broker (handles both passphrase-encrypted and session-encrypted vaults).
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
            term::section("Session");
            term::warn("human mode was not activated");
            term::info(&format!(
                "The vault passphrase did not unlock {}.",
                resolved.name
            ));
            term::next("try again with: ward human");
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
    std::process::Command::new(&exe)
        .arg("__human-guardian")
        .arg("--shell-pid")
        .arg(shell_pid.to_string())
        .arg("--session-token")
        .arg(&session_token)
        .arg("--ttl-seconds")
        .arg(ttl_seconds.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("failed to spawn human guardian")?;

    // Wait up to 3 seconds for ready-marker.
    let ready = ready_marker_path(shell_pid);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready.exists() {
        if Instant::now() >= deadline {
            term::section("Session");
            term::warn("human mode was not activated");
            term::info("The terminal guardian did not become ready in time.");
            term::next("try again with: ward human");
            anyhow::bail!("human guardian did not become ready in time");
        }
        thread::sleep(Duration::from_millis(25));
    }

    let expires_at = (chrono::Utc::now() + duration).to_rfc3339();
    let ttl_label = format_ttl_label(ttl_seconds);

    term::info(HUMAN_ACTIVE_BODY);
    term::blank();
    term::section("Session");
    term::ok("human mode active");
    if targets.len() > 1 {
        term::ok(&format!(
            "{} workspace app sessions unlocked",
            targets.len()
        ));
    }
    term::ok(&format!("expires in {ttl_label}"));
    term::ok(&format!("guardian attached to shell {shell_pid}"));

    term::section("Commands");
    if shell_hooks_loaded {
        term::ok("wrapped project commands route through ward run");
        term::next("try: pnpm dev");
    } else {
        print_missing_shell_hooks_warning();
    }

    if let Ok(instances) = crate::webui::dashboard_diagnostics() {
        if let Some(instance) = instances.first() {
            term::section("Dashboard");
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
    let run_dir = logs::ward_home().join("run");
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
    process_util::terminate_if_matches(pid, Duration::from_secs(1), |target| {
        guardian_processes()
            .into_iter()
            .any(|guardian| guardian.pid == target)
    });
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
