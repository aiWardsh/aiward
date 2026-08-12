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
    let relative = PathBuf::from("run").join("dashboard");
    fs_util::resolve_ward_home_path(&relative, "dashboard metadata directory")
        .expect("dashboard metadata directory should stay inside Ward home")
}

fn metadata_path(pid: u32) -> PathBuf {
    let relative = PathBuf::from("run")
        .join("dashboard")
        .join(format!("{pid}.json"));
    fs_util::resolve_ward_home_path(&relative, "dashboard metadata path")
        .expect("dashboard metadata path should stay inside Ward home")
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
