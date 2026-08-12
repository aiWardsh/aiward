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
