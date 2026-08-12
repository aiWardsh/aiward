fn send_simple(request: BrokerRequest) -> Result<BrokerResponse> {
    let mut stream = connect()?;
    write_request(&mut stream, &request)?;
    let mut reader = BufReader::new(stream);
    read_response(&mut reader)
}

fn broker_error(reason: impl Into<BrokerReason>, message: impl Into<String>) -> BrokerResponse {
    BrokerResponse::Error {
        reason: reason.into(),
        message: message.into(),
    }
}

#[cfg(not(test))]
fn ping() -> Result<()> {
    ping_status().map(|_| ())
}

fn connect() -> Result<UnixStream> {
    UnixStream::connect(socket_path()).context("failed to connect to Ward broker")
}

fn read_request(reader: &mut BufReader<UnixStream>) -> Result<BrokerRequest> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read broker request")?;
    serde_json::from_str(line.trim()).context("failed to parse broker request")
}

fn read_response(reader: &mut BufReader<UnixStream>) -> Result<BrokerResponse> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read broker response")?;
    if line.is_empty() {
        anyhow::bail!("broker closed the connection");
    }
    serde_json::from_str(line.trim()).context("failed to parse broker response")
}

fn write_request(stream: &mut UnixStream, request: &BrokerRequest) -> Result<()> {
    let line = serde_json::to_string(request).expect("broker request should serialize");
    writeln!(stream, "{line}").context("failed to write broker request")
}

fn write_response(stream: &mut UnixStream, response: &BrokerResponse) -> Result<()> {
    let line = serde_json::to_string(response).expect("broker response should serialize");
    writeln!(stream, "{line}").context("failed to write broker response")
}

fn cleanup_stale_files() -> Result<()> {
    let socket = socket_path();
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }
    let pid = pid_path();
    if pid.exists() {
        let _ = std::fs::remove_file(pid);
    }
    Ok(())
}

fn read_pid() -> Result<u32> {
    let contents = std::fs::read_to_string(pid_path()).context("failed to read broker pid")?;
    contents
        .trim()
        .parse::<u32>()
        .context("failed to parse broker pid")
}
