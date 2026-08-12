#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct MissingVaultEnvError {
    missing: Vec<String>,
}

impl MissingVaultEnvError {
    pub fn missing(&self) -> &[String] {
        &self.missing
    }
}

impl std::fmt::Display for MissingVaultEnvError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "approved env vars missing from vault: {}",
            self.missing.join(", ")
        )
    }
}

impl std::error::Error for MissingVaultEnvError {}

pub fn missing_vault_envs(error: &anyhow::Error) -> Option<&[String]> {
    error
        .downcast_ref::<MissingVaultEnvError>()
        .map(MissingVaultEnvError::missing)
}

#[derive(Debug, Clone)]
pub struct RunCommandRequest {
    pub cwd: PathBuf,
    pub env_names: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub command: Vec<String>,
    pub inherited_env: BTreeMap<String, String>,
    pub cancellation: Option<Arc<AtomicBool>>,
    pub human_shell_pid: Option<u32>,
    pub child_pid: Option<Arc<AtomicU32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunCommandOutcome {
    pub exit_code: i32,
    pub duration_ms: u64,
    pub redaction_alerts: usize,
    pub output_alerts: Vec<OutputAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputAlert {
    pub stream: String,
    pub code: String,
    pub message: String,
    pub redacted_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedactionCandidate {
    pub(crate) env_name: String,
    pub(crate) value: String,
}

pub fn run_command(request: RunCommandRequest) -> Result<RunCommandOutcome> {
    run_command_with_emitter(
        request,
        Arc::new(|stream, line| {
            if stream == "stderr" {
                eprintln!("{line}");
            } else {
                println!("{line}");
            }
        }),
    )
}

type OutputEmitter = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub fn run_command_with_emitter(
    request: RunCommandRequest,
    emitter: OutputEmitter,
) -> Result<RunCommandOutcome> {
    if request.command.is_empty() {
        anyhow::bail!("no command was provided");
    }

    let started = Instant::now();
    let scoped_env = select_env(&request.env, &request.env_names)?;
    let redaction_candidates = scoped_env
        .iter()
        .filter(|(_, value)| value.len() >= 4)
        .map(|(env_name, value)| RedactionCandidate {
            env_name: env_name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();

    let mut command = Command::new(&request.command[0]);
    command
        .args(&request.command[1..])
        .current_dir(&request.cwd)
        .envs(&request.inherited_env)
        .envs(&scoped_env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    if request.cancellation.is_some() {
        // SAFETY: pre_exec runs in the child immediately before exec; setpgid only
        // moves the child into its own process group so Ward can cleanly stop it.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = command
        .spawn()
        .context(format!("failed to spawn {}", request.command.join(" ")))?;
    if let Some(child_pid) = &request.child_pid {
        child_pid.store(child.id(), Ordering::SeqCst);
    }

    let stdout_alerts = child.stdout.take().map(|stdout| {
        let secrets = redaction_candidates.clone();
        let emitter = Arc::clone(&emitter);
        thread::spawn(move || {
            let mut alerts = Vec::new();
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(std::result::Result::ok) {
                let (redacted, mut line_alerts) = inspect_output_line("stdout", &line, &secrets);
                alerts.append(&mut line_alerts);
                emitter("stdout", &redacted);
            }
            alerts
        })
    });

    let stderr_alerts = child.stderr.take().map(|stderr| {
        let secrets = redaction_candidates.clone();
        let emitter = Arc::clone(&emitter);
        thread::spawn(move || {
            let mut alerts = Vec::new();
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(std::result::Result::ok) {
                let (redacted, mut line_alerts) = inspect_output_line("stderr", &line, &secrets);
                alerts.append(&mut line_alerts);
                emitter("stderr", &redacted);
            }
            alerts
        })
    });

    let status = loop {
        if cancellation_requested(&request) {
            terminate_child_group(child.id());
            break child
                .wait()
                .context("failed to wait for cancelled child process")?;
        }
        if let Some(status) = child.try_wait().context("failed to poll child process")? {
            break status;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut output_alerts = Vec::new();

    if let Some(handle) = stdout_alerts {
        output_alerts.extend(handle.join().unwrap_or_default());
    }
    if let Some(handle) = stderr_alerts {
        output_alerts.extend(handle.join().unwrap_or_default());
    }

    Ok(RunCommandOutcome {
        exit_code: status.code().unwrap_or(1),
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        redaction_alerts: output_alerts.len(),
        output_alerts,
    })
}

fn cancellation_requested(request: &RunCommandRequest) -> bool {
    if request
        .cancellation
        .as_ref()
        .is_some_and(|cancelled| cancelled.load(Ordering::SeqCst))
    {
        return true;
    }
    if let Some(shell_pid) = request.human_shell_pid {
        return !process_exists(shell_pid);
    }
    false
}

fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) checks process visibility without sending a signal.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

fn terminate_child_group(pid: u32) {
    #[cfg(unix)]
    {
        let pgid = pid as libc::pid_t;
        // SAFETY: sends SIGTERM to the child process group created by setpgid.
        let _ = unsafe { libc::kill(-pgid, libc::SIGTERM) };
        thread::sleep(Duration::from_millis(100));
        // SAFETY: best-effort hard stop if the child ignored SIGTERM.
        let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn select_env(
    env_map: &BTreeMap<String, String>,
    env_names: &[String],
) -> Result<BTreeMap<String, String>> {
    let missing = env_names
        .iter()
        .filter(|name| !env_map.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(MissingVaultEnvError { missing }.into());
    }

    let mut scoped = BTreeMap::new();
    for name in env_names {
        let value = env_map
            .get(name)
            .expect("missing env vars were checked above");
        scoped.insert(name.clone(), value.clone());
    }
    Ok(scoped)
}

pub(crate) fn inspect_output_line(
    stream: &str,
    line: &str,
    redaction_candidates: &[RedactionCandidate],
) -> (String, Vec<OutputAlert>) {
    let (mut redacted, exact_secret_hit) = redact_exact_secret_values(line, redaction_candidates);
    let mut alerts = Vec::new();

    if exact_secret_hit {
        alerts.push(OutputAlert {
            stream: stream.to_string(),
            code: "output.secret_redacted".to_string(),
            message: "output contained an injected secret value".to_string(),
            redacted_line: redacted.clone(),
        });
    }

    let (assignment_redacted, assignment_hit) = redact_secret_assignments(&redacted);
    redacted = assignment_redacted;
    if assignment_hit {
        alerts.push(OutputAlert {
            stream: stream.to_string(),
            code: "output.secret_assignment".to_string(),
            message: "output looked like a secret-bearing KEY=value assignment".to_string(),
            redacted_line: redacted.clone(),
        });
    }

    if contains_high_risk_key_name(&redacted) {
        alerts.push(OutputAlert {
            stream: stream.to_string(),
            code: "output.high_risk_key_name".to_string(),
            message: "output referenced a high-risk secret key name".to_string(),
            redacted_line: redacted.clone(),
        });
    }

    if looks_like_env_dump_line(&redacted) {
        alerts.push(OutputAlert {
            stream: stream.to_string(),
            code: "output.env_dump_shape".to_string(),
            message: "output looked like an environment dump".to_string(),
            redacted_line: redacted.clone(),
        });
    }

    (redacted, alerts)
}

fn redact_exact_secret_values(line: &str, candidates: &[RedactionCandidate]) -> (String, bool) {
    let mut redacted = line.to_string();
    let mut hit = false;

    for candidate in candidates {
        if should_exact_redact(candidate) && redacted.contains(&candidate.value) {
            redacted = redacted.replace(&candidate.value, "[WARD_REDACTED]");
            hit = true;
        }
    }

    (redacted, hit)
}

fn should_exact_redact(candidate: &RedactionCandidate) -> bool {
    if candidate.value.len() < 4 {
        return false;
    }
    !(candidate.env_name.starts_with("NEXT_PUBLIC_")
        && is_low_risk_public_local_url(&candidate.value))
}

fn is_low_risk_public_local_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://[::1]",
        "https://[::1]",
    ]
    .iter()
    .any(|prefix| {
        lower == *prefix
            || lower.starts_with(&format!("{prefix}:"))
            || lower.starts_with(&format!("{prefix}/"))
    })
}

fn redact_secret_assignments(line: &str) -> (String, bool) {
    let mut hit = false;
    let redacted = line
        .split_whitespace()
        .map(|token| {
            if let Some((key, _value)) = token.split_once('=') {
                if is_secret_like_key(key) {
                    hit = true;
                    return format!("{key}=[WARD_REDACTED]");
                }
            }
            token.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ");

    if hit {
        (redacted, true)
    } else {
        (line.to_string(), false)
    }
}

fn contains_high_risk_key_name(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    [
        "OPENAI_API_KEY",
        "STRIPE_SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "PAYLOAD_SECRET",
        "DATABASE_URL",
    ]
    .iter()
    .any(|key| upper.contains(key))
}

fn looks_like_env_dump_line(line: &str) -> bool {
    let assignments = line
        .split_whitespace()
        .filter(|token| {
            token
                .split_once('=')
                .is_some_and(|(key, value)| is_env_key_shape(key) && !value.is_empty())
        })
        .count();

    assignments >= 3
        || line
            .split_once('=')
            .is_some_and(|(key, value)| is_secret_like_key(key) && !value.is_empty())
}

fn is_env_key_shape(key: &str) -> bool {
    !key.is_empty()
        && key.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
        && key.contains('_')
}

fn is_secret_like_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper == "DATABASE_URL"
        || upper.ends_with("_SECRET")
        || upper.ends_with("_TOKEN")
        || upper.ends_with("_PASSWORD")
        || upper.ends_with("_PRIVATE_KEY")
        || upper.ends_with("_API_KEY")
        || upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("PASSWORD")
}

#[cfg(test)]
mod tests {
    use super::{inspect_output_line, run_command, RedactionCandidate, RunCommandRequest};

    fn redaction_candidate(env_name: &str, value: &str) -> RedactionCandidate {
        RedactionCandidate {
            env_name: env_name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn redacts_exact_injected_secret_values() {
        let (redacted, alerts) = inspect_output_line(
            "stdout",
            "db=postgres://secret",
            &[redaction_candidate("DATABASE_URL", "postgres://secret")],
        );

        assert_eq!(redacted, "db=[WARD_REDACTED]");
        assert!(alerts
            .iter()
            .any(|alert| alert.code == "output.secret_redacted"));
    }

    #[test]
    fn redacts_secret_shaped_assignments() {
        let (redacted, alerts) = inspect_output_line("stdout", "OPENAI_API_KEY=sk-local", &[]);

        assert_eq!(redacted, "OPENAI_API_KEY=[WARD_REDACTED]");
        assert!(alerts
            .iter()
            .any(|alert| alert.code == "output.secret_assignment"));
    }

    #[test]
    fn skips_exact_redaction_for_low_risk_public_local_urls() {
        let (redacted, alerts) = inspect_output_line(
            "stdout",
            "ready at http://localhost:3000",
            &[redaction_candidate(
                "NEXT_PUBLIC_SERVER_URL",
                "http://localhost:3000",
            )],
        );

        assert_eq!(redacted, "ready at http://localhost:3000");
        assert!(!alerts
            .iter()
            .any(|alert| alert.code == "output.secret_redacted"));

        let (redacted, alerts) = inspect_output_line(
            "stdout",
            "public token sk-live-public",
            &[redaction_candidate("NEXT_PUBLIC_API_KEY", "sk-live-public")],
        );
        assert_eq!(redacted, "public token [WARD_REDACTED]");
        assert!(alerts
            .iter()
            .any(|alert| alert.code == "output.secret_redacted"));
    }

    #[test]
    fn detects_clean_high_risk_and_env_dump_lines() {
        let (clean, clean_alerts) = inspect_output_line("stdout", "hello world", &[]);
        let (_high_risk, high_risk_alerts) =
            inspect_output_line("stdout", "using DATABASE_URL", &[]);
        let (_dump, dump_alerts) =
            inspect_output_line("stdout", "A_KEY=one B_KEY=two C_KEY=three", &[]);

        assert_eq!(clean, "hello world");
        assert!(clean_alerts.is_empty());
        assert!(high_risk_alerts
            .iter()
            .any(|alert| alert.code == "output.high_risk_key_name"));
        assert!(dump_alerts
            .iter()
            .any(|alert| alert.code == "output.env_dump_shape"));
    }

    #[test]
    fn run_command_rejects_empty_command() {
        let tempdir = tempfile::tempdir().unwrap();
        let result = run_command(RunCommandRequest {
            cwd: tempdir.path().to_path_buf(),
            env_names: Vec::new(),
            env: std::collections::BTreeMap::new(),
            command: Vec::new(),
            inherited_env: std::collections::BTreeMap::new(),
            cancellation: None,
            human_shell_pid: None,
            child_pid: None,
        });

        assert!(result.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn run_command_reports_missing_approved_env() {
        let tempdir = tempfile::tempdir().unwrap();
        let env = std::collections::BTreeMap::from([(
            "DATABASE_URL".to_string(),
            "postgres://local".to_string(),
        )]);

        let result = run_command(RunCommandRequest {
            cwd: tempdir.path().to_path_buf(),
            env_names: vec!["PAYLOAD_SECRET".to_string()],
            env,
            command: vec!["true".to_string()],
            inherited_env: std::collections::BTreeMap::new(),
            cancellation: None,
            human_shell_pid: None,
            child_pid: None,
        });

        assert!(result.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn run_command_captures_stderr_alerts_and_exit_code() {
        let tempdir = tempfile::tempdir().unwrap();
        let env = std::collections::BTreeMap::from([(
            "PAYLOAD_SECRET".to_string(),
            "payload-secret".to_string(),
        )]);

        let outcome = run_command(RunCommandRequest {
            cwd: tempdir.path().to_path_buf(),
            env_names: vec!["PAYLOAD_SECRET".to_string()],
            env,
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf 'PAYLOAD_SECRET=%s\\n' \"$PAYLOAD_SECRET\" >&2; exit 7".to_string(),
            ],
            inherited_env: std::collections::BTreeMap::new(),
            cancellation: None,
            human_shell_pid: None,
            child_pid: None,
        })
        .unwrap();

        assert_eq!(outcome.exit_code, 7);
        assert!(outcome.redaction_alerts > 0);
        assert!(outcome
            .output_alerts
            .iter()
            .any(|alert| alert.stream == "stderr"));
    }
}
