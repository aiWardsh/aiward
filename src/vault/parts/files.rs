pub fn read_vault(vault_path: &Path) -> Result<VaultEnvelope> {
    let contents = fs_util::read_file_to_string(vault_path, "vault file")?;
    serde_json::from_str(&contents).context(format!("failed to parse {}", vault_path.display()))
}

pub fn write_vault(vault_path: &Path, envelope: &VaultEnvelope) -> Result<()> {
    fs_util::ensure_parent_dir(vault_path)?;

    let contents = serde_json::to_string_pretty(envelope).expect("vault envelope should serialize");
    fs::write(vault_path, format!("{contents}\n"))
        .context(format!("failed to write {}", vault_path.display()))
}

pub fn read_new_passphrase() -> Result<String> {
    if let Some(passphrase) = test_passphrase() {
        return Ok(passphrase);
    }

    let (first, second) = prompt_new_passphrase_pair()?;
    validate_new_passphrase(&first, &second)?;
    Ok(first)
}

pub(crate) fn validate_new_passphrase(first: &str, second: &str) -> Result<()> {
    if first != second {
        anyhow::bail!("PIN/passphrase values did not match");
    }
    if first.len() < MIN_PIN_PASSPHRASE_LEN {
        anyhow::bail!("PIN/passphrase must be at least {MIN_PIN_PASSPHRASE_LEN} characters");
    }
    Ok(())
}

pub(crate) fn pin_strength(value: &str) -> PinStrength {
    match value.chars().count() {
        0..=5 => PinStrength::Weak,
        6..=7 => PinStrength::Better,
        8..=11 => PinStrength::Stronger,
        _ => PinStrength::Strong,
    }
}

pub(crate) fn pin_strength_message(value: &str) -> String {
    let strength = pin_strength(value);
    let chars = value.chars().count();
    let note = match strength {
        PinStrength::Weak => "quick to type, but weak if the encrypted vault leaks",
        PinStrength::Better => "still convenient, with a little more resistance",
        PinStrength::Stronger => "good for daily use",
        PinStrength::Strong => "best protection for this unlock method",
    };
    format!(
        "  PIN strength: {}{}\x1b[0m ({} chars; {})",
        strength.color(),
        strength.label(),
        chars,
        note
    )
}

#[cfg(not(coverage))]
fn print_pin_strength(value: &str) {
    eprintln!("{}", pin_strength_message(value));
}

#[cfg(coverage)]
fn print_pin_strength(_value: &str) {}

/// Prompt for a new PIN with custom labels (used for recovery PIN during setup).
pub fn read_new_pin(prompt: &str, confirm_prompt: &str) -> Result<String> {
    if let Some(passphrase) = test_passphrase() {
        return Ok(passphrase);
    }
    let first = rpassword::prompt_password(format!("{prompt}: "))?;
    print_pin_strength(&first);
    let second = rpassword::prompt_password(format!("{confirm_prompt}: "))?;
    validate_new_passphrase(&first, &second)?;
    Ok(first)
}

pub fn read_existing_passphrase() -> Result<String> {
    read_existing_passphrase_with_prompt("  Vault PIN/passphrase: ")
}

pub fn read_existing_passphrase_for_project(project: &str) -> Result<String> {
    read_existing_passphrase_with_prompt(&format!("  Vault PIN/passphrase for {project}: "))
}

fn read_existing_passphrase_with_prompt(prompt: &str) -> Result<String> {
    if let Some(passphrase) = test_passphrase_sequence_next() {
        return Ok(passphrase);
    }
    if let Some(passphrase) = test_passphrase() {
        return Ok(passphrase);
    }

    prompt_existing_passphrase(prompt)
}

pub fn validate_dotenv(contents: &str) -> Result<()> {
    let iter = dotenvy::from_read_iter(Cursor::new(contents.as_bytes()));
    for item in iter {
        item?;
    }
    Ok(())
}

pub(crate) fn selected_editor() -> String {
    env::var("EDITOR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            env::var("VISUAL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "nano".to_string())
}

pub(crate) fn test_passphrase() -> Option<String> {
    std::env::var("WARD_UNSAFE_TEST_PASSPHRASE")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn test_passphrase_sequence_next() -> Option<String> {
    let raw = std::env::var("WARD_UNSAFE_TEST_PASSPHRASE_SEQUENCE")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let mut state = test_passphrase_sequence_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.raw.as_deref() != Some(raw.as_str()) {
        state.raw = Some(raw.clone());
        state.values = raw
            .split(['\n', ','])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect();
        state.index = 0;
    }
    let value = state.values.get(state.index).cloned();
    if value.is_some() {
        state.index += 1;
    }
    value
}

fn test_passphrase_sequence_state() -> &'static Mutex<TestPassphraseSequenceState> {
    static STATE: OnceLock<Mutex<TestPassphraseSequenceState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(TestPassphraseSequenceState::default()))
}

#[derive(Default)]
struct TestPassphraseSequenceState {
    raw: Option<String>,
    values: Vec<String>,
    index: usize,
}

#[cfg(not(coverage))]
fn prompt_new_passphrase_pair() -> Result<(String, String)> {
    let first = rpassword::prompt_password("  New vault PIN/passphrase: ")?;
    print_pin_strength(&first);
    let second = rpassword::prompt_password("  Confirm vault PIN/passphrase: ")?;
    Ok((first, second))
}

#[cfg(coverage)]
fn prompt_new_passphrase_pair() -> Result<(String, String)> {
    Ok((
        "coverage passphrase".to_string(),
        "coverage passphrase".to_string(),
    ))
}

#[cfg(not(coverage))]
fn prompt_existing_passphrase(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

#[cfg(coverage)]
fn prompt_existing_passphrase(_prompt: &str) -> Result<String> {
    Ok("coverage passphrase".to_string())
}

fn run_editor(editor: &str, path: &Path) -> Result<()> {
    let mut parts = editor.split_whitespace();
    let binary = parts
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("nano");
    let status = Command::new(binary)
        .args(parts)
        .arg(path)
        .status()
        .context(format!("failed to launch editor {binary}"))?;

    if !status.success() {
        anyhow::bail!("editor exited with status {status}");
    }

    Ok(())
}

#[cfg(unix)]
fn set_restrictive_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).context(format!(
        "failed to restrict permissions for {}",
        path.display()
    ))
}

#[cfg(not(unix))]
fn set_restrictive_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
