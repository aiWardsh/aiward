use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

pub fn process_exists(pid: u32) -> bool {
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

pub fn command_line(pid: u32) -> Option<String> {
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

pub fn terminate_if_matches(pid: u32, timeout: Duration, matches_process: impl Fn(u32) -> bool) {
    #[cfg(unix)]
    {
        if !matches_process(pid) {
            return;
        }
        // SAFETY: caller supplied a process-kind predicate and this function rechecks it before signaling.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !process_exists(pid) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if matches_process(pid) {
            // SAFETY: best-effort hard stop after the same process-kind predicate still matches.
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, timeout, matches_process);
    }
}

pub fn terminate_process_group(pid: u32) {
    #[cfg(unix)]
    {
        let pgid = pid as libc::pid_t;
        // SAFETY: sends SIGTERM to a process group created for a Ward-managed child.
        let _ = unsafe { libc::kill(-pgid, libc::SIGTERM) };
        thread::sleep(Duration::from_millis(100));
        // SAFETY: best-effort hard stop if the process group ignored SIGTERM.
        let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}
