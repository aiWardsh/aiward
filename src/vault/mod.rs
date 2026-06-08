use std::{
    env, fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::Command,
};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fs_util;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub(crate) const MIN_PIN_PASSPHRASE_LEN: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEnvelope {
    pub version: u32,
    pub kdf: KdfEnvelope,
    pub cipher: CipherEnvelope,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfEnvelope {
    pub name: String,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherEnvelope {
    pub name: String,
    pub iv: String,
    pub auth_tag: String,
    pub ciphertext: String,
}

/// Derives a hidden vault filename from passphrase + project + nonce.
/// Same inputs always produce the same filename; changing the nonce rotates it.
pub fn derive_vault_filename(passphrase: &str, project: &str, nonce: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(b"\x00");
    hasher.update(project.as_bytes());
    hasher.update(b"\x00");
    hasher.update(nonce.as_bytes());
    let hash = hasher.finalize();
    format!(".{}", hex::encode(&hash[..8]))
}

/// Generates a random 16-byte hex nonce for vault filename derivation.
pub fn generate_vault_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Encrypts with custom Argon2 parameters (used for recovery blobs).
pub fn encrypt_env_with_params(
    plaintext: &str,
    passphrase: &str,
    memory_cost: u32,
    time_cost: u32,
) -> Result<VaultEnvelope> {
    let mut salt = [0_u8; SALT_LEN];
    let mut iv = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);

    let kdf = KdfEnvelope {
        name: "argon2id".to_string(),
        memory_cost,
        time_cost,
        parallelism: 1,
        salt: STANDARD.encode(salt),
    };

    let key = derive_key(passphrase, &salt, &kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("derived AES-256 key has valid length");
    let mut encrypted = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .expect("AES-GCM encryption should not fail for a valid nonce");

    let auth_tag = encrypted.split_off(encrypted.len() - TAG_LEN);
    let now = chrono::Utc::now().to_rfc3339();

    Ok(VaultEnvelope {
        version: 1,
        kdf,
        cipher: CipherEnvelope {
            name: "aes-256-gcm".to_string(),
            iv: STANDARD.encode(iv),
            auth_tag: STANDARD.encode(auth_tag),
            ciphertext: STANDARD.encode(encrypted),
        },
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Encrypts raw bytes (not dotenv text) with a raw 32-byte key.
/// Used to generate size-identical decoy recovery files.
pub fn encrypt_raw_bytes(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<VaultEnvelope> {
    let mut iv = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut iv);

    let kdf = KdfEnvelope {
        name: "argon2id".to_string(),
        memory_cost: 65_536,
        time_cost: 3,
        parallelism: 1,
        salt: STANDARD.encode({
            let mut s = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut s);
            s
        }),
    };

    let cipher = Aes256Gcm::new_from_slice(key).expect("raw key has valid length");
    let mut encrypted = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .expect("AES-GCM encryption should not fail for a valid nonce");

    let auth_tag = encrypted.split_off(encrypted.len() - TAG_LEN);
    let now = chrono::Utc::now().to_rfc3339();

    Ok(VaultEnvelope {
        version: 1,
        kdf,
        cipher: CipherEnvelope {
            name: "aes-256-gcm".to_string(),
            iv: STANDARD.encode(iv),
            auth_tag: STANDARD.encode(auth_tag),
            ciphertext: STANDARD.encode(encrypted),
        },
        created_at: now.clone(),
        updated_at: now,
    })
}

pub fn import_env_file(source: &Path, vault_path: &Path, passphrase: &str) -> Result<PathBuf> {
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if source
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        anyhow::bail!("Invalid input: {}", source.display());
    }
    let plaintext =
        fs::read_to_string(source).context(format!("failed to read {}", source.display()))?;
    validate_dotenv(&plaintext)?;

    let envelope = encrypt_env(&plaintext, passphrase)?;
    write_vault(vault_path, &envelope)?;
    Ok(vault_path.to_path_buf())
}

pub fn encrypt_env(plaintext: &str, passphrase: &str) -> Result<VaultEnvelope> {
    let mut salt = [0_u8; SALT_LEN];
    let mut iv = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);

    let kdf = KdfEnvelope {
        name: "argon2id".to_string(),
        memory_cost: 65_536,
        time_cost: 3,
        parallelism: 1,
        salt: STANDARD.encode(salt),
    };

    let key = derive_key(passphrase, &salt, &kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("derived AES-256 key has valid length");
    let mut encrypted = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .expect("AES-GCM encryption should not fail for a valid nonce");

    let auth_tag = encrypted.split_off(encrypted.len() - TAG_LEN);
    let now = chrono::Utc::now().to_rfc3339();

    Ok(VaultEnvelope {
        version: 1,
        kdf,
        cipher: CipherEnvelope {
            name: "aes-256-gcm".to_string(),
            iv: STANDARD.encode(iv),
            auth_tag: STANDARD.encode(auth_tag),
            ciphertext: STANDARD.encode(encrypted),
        },
        created_at: now.clone(),
        updated_at: now,
    })
}

pub fn decrypt_vault_file(vault_path: &Path, passphrase: &str) -> Result<String> {
    let envelope = read_vault(vault_path)?;
    decrypt_env(&envelope, passphrase)
}

pub fn edit_vault_file(vault_path: &Path, passphrase: &str) -> Result<()> {
    let existing_envelope = read_vault(vault_path)?;
    let plaintext = decrypt_env(&existing_envelope, passphrase)?;
    let mut temp_file =
        tempfile::NamedTempFile::new().context("failed to create temporary env edit buffer")?;

    set_restrictive_permissions(temp_file.path())?;
    temp_file
        .write_all(plaintext.as_bytes())
        .context("failed to write temporary env edit buffer")?;
    temp_file
        .flush()
        .context("failed to flush temporary env edit buffer")?;

    let editor = selected_editor();
    run_editor(&editor, temp_file.path())?;

    let edited = fs::read_to_string(temp_file.path())
        .context("failed to read edited temporary env buffer")?;
    validate_dotenv(&edited).context("edited env content is not valid dotenv syntax")?;

    let mut updated = encrypt_env(&edited, passphrase)?;
    updated.created_at = existing_envelope.created_at;
    write_vault(vault_path, &updated)?;
    temp_file
        .close()
        .context("failed to remove temporary env edit buffer")?;
    Ok(())
}

pub fn decrypt_env(envelope: &VaultEnvelope, passphrase: &str) -> Result<String> {
    if envelope.version != 1 {
        anyhow::bail!("unsupported vault version {}", envelope.version);
    }
    if envelope.kdf.name != "argon2id" {
        anyhow::bail!("unsupported KDF {}", envelope.kdf.name);
    }
    if envelope.cipher.name != "aes-256-gcm" {
        anyhow::bail!("unsupported cipher {}", envelope.cipher.name);
    }

    let salt = STANDARD.decode(&envelope.kdf.salt)?;
    let iv = STANDARD.decode(&envelope.cipher.iv)?;
    let mut ciphertext = STANDARD.decode(&envelope.cipher.ciphertext)?;
    let auth_tag = STANDARD.decode(&envelope.cipher.auth_tag)?;
    if iv.len() != NONCE_LEN {
        anyhow::bail!("vault IV has invalid length");
    }
    if auth_tag.len() != TAG_LEN {
        anyhow::bail!("vault auth tag has invalid length");
    }
    ciphertext.extend(auth_tag);

    let key = derive_key(passphrase, &salt, &envelope.kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("derived AES-256 key has valid length");
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed to decrypt vault; passphrase may be incorrect"))?;

    String::from_utf8(plaintext).context("vault plaintext is not valid UTF-8")
}

pub fn read_vault(vault_path: &Path) -> Result<VaultEnvelope> {
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if vault_path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        anyhow::bail!("Invalid input: {}", vault_path.display());
    }
    let contents = fs::read_to_string(vault_path)
        .context(format!("failed to read {}", vault_path.display()))?;
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

/// Prompt for a new PIN with custom labels (used for recovery PIN during setup).
pub fn read_new_pin(prompt: &str, confirm_prompt: &str) -> Result<String> {
    if let Some(passphrase) = test_passphrase() {
        return Ok(passphrase);
    }
    let first = rpassword::prompt_password(format!("{prompt}: "))?;
    let second = rpassword::prompt_password(format!("{confirm_prompt}: "))?;
    validate_new_passphrase(&first, &second)?;
    Ok(first)
}

pub fn read_existing_passphrase() -> Result<String> {
    if let Some(passphrase) = test_passphrase() {
        return Ok(passphrase);
    }

    prompt_existing_passphrase()
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

#[cfg(not(coverage))]
fn prompt_new_passphrase_pair() -> Result<(String, String)> {
    let first = rpassword::prompt_password("  New vault PIN/passphrase: ")?;
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
fn prompt_existing_passphrase() -> Result<String> {
    Ok(rpassword::prompt_password("  Vault PIN/passphrase: ")?)
}

#[cfg(coverage)]
fn prompt_existing_passphrase() -> Result<String> {
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

fn derive_key(passphrase: &str, salt: &[u8], kdf: &KdfEnvelope) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(
        kdf.memory_cost,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| anyhow!("invalid Argon2 parameters: {error}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| anyhow!("failed to derive vault key: {error}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn encrypts_and_decrypts_env_contents() {
        let plaintext = "DATABASE_URL=postgres://local\nNEXT_PUBLIC_API_URL=http://localhost\n";
        let envelope = encrypt_env(plaintext, "correct horse battery staple").unwrap();
        let decrypted = decrypt_env(&envelope, "correct horse battery staple").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let envelope =
            encrypt_env("DATABASE_URL=postgres://local\n", "correct passphrase").unwrap();

        assert!(decrypt_env(&envelope, "wrong passphrase").is_err());
    }

    #[test]
    fn dotenv_validation_rejects_invalid_contents() {
        assert!(super::validate_dotenv("DATABASE_URL='unterminated\n").is_err());
    }

    #[test]
    fn validates_new_passphrase_confirmation_and_length() {
        assert!(validate_new_passphrase("1234", "1234").is_ok());
        assert!(validate_new_passphrase("long enough", "long enough").is_ok());
        let mismatch = validate_new_passphrase("long enough", "different enough")
            .expect_err("mismatched PIN/passphrase should be rejected")
            .to_string();
        assert!(mismatch.contains("PIN/passphrase values did not match"));
        let short = validate_new_passphrase("123", "123")
            .expect_err("three character PIN should be rejected")
            .to_string();
        assert!(short.contains("PIN/passphrase must be at least 4 characters"));
        assert!(validate_new_passphrase("1234", "4321").is_err());
    }

    #[test]
    fn import_env_file_reports_missing_source() {
        let tempdir = tempfile::tempdir().unwrap();

        assert!(import_env_file(
            &tempdir.path().join("missing.env"),
            &tempdir.path().join(".env.vault"),
            "correct horse battery staple",
        )
        .is_err());
    }

    #[test]
    fn import_env_file_rejects_invalid_dotenv_contents() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join(".env");
        std::fs::write(&source, "DATABASE_URL='unterminated\n").unwrap();

        assert!(
            import_env_file(&source, &tempdir.path().join(".env.vault"), "passphrase").is_err()
        );
    }

    #[test]
    fn import_env_file_encrypts_valid_dotenv_contents() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join(".env");
        let vault_path = tempdir.path().join(".env.vault");
        std::fs::write(&source, "DATABASE_URL=postgres://local\n").unwrap();

        assert_eq!(
            import_env_file(&source, &vault_path, "passphrase").unwrap(),
            vault_path
        );
        assert_eq!(
            decrypt_vault_file(&vault_path, "passphrase").unwrap(),
            "DATABASE_URL=postgres://local\n"
        );
    }

    #[test]
    fn import_env_file_reports_vault_write_failures() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join(".env");
        let vault_directory = tempdir.path().join(".env.vault");
        std::fs::write(&source, "DATABASE_URL=postgres://local\n").unwrap();
        std::fs::create_dir(&vault_directory).unwrap();

        assert!(import_env_file(&source, &vault_directory, "passphrase").is_err());
    }

    #[test]
    fn decrypt_rejects_invalid_envelope_metadata_and_lengths() {
        let mut envelope = encrypt_env("DATABASE_URL=postgres://local\n", "passphrase").unwrap();

        envelope.version = 2;
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.version = 1;

        envelope.kdf.name = "scrypt".to_string();
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.kdf.name = "argon2id".to_string();

        envelope.cipher.name = "xchacha20-poly1305".to_string();
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.cipher.name = "aes-256-gcm".to_string();

        let valid_iv = envelope.cipher.iv.clone();
        envelope.cipher.iv = STANDARD.encode([1_u8, 2_u8]);
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.cipher.iv = valid_iv;

        envelope.cipher.auth_tag = STANDARD.encode([1_u8, 2_u8]);
        assert!(decrypt_env(&envelope, "passphrase").is_err());
    }

    #[test]
    fn decrypt_rejects_invalid_base64_and_argon_parameters() {
        let mut envelope = encrypt_env("DATABASE_URL=postgres://local\n", "passphrase").unwrap();

        let valid_salt = envelope.kdf.salt.clone();
        envelope.kdf.salt = "@@@not-base64@@@".to_string();
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.kdf.salt = valid_salt;

        let valid_ciphertext = envelope.cipher.ciphertext.clone();
        envelope.cipher.ciphertext = "@@@not-base64@@@".to_string();
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.cipher.ciphertext = valid_ciphertext;

        let valid_iv = envelope.cipher.iv.clone();
        envelope.cipher.iv = "@@@not-base64@@@".to_string();
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.cipher.iv = valid_iv;

        let valid_auth_tag = envelope.cipher.auth_tag.clone();
        envelope.cipher.auth_tag = "@@@not-base64@@@".to_string();
        assert!(decrypt_env(&envelope, "passphrase").is_err());
        envelope.cipher.auth_tag = valid_auth_tag;

        envelope.kdf.memory_cost = 0;
        assert!(decrypt_env(&envelope, "passphrase").is_err());
    }

    #[test]
    fn read_and_write_vault_report_io_and_parse_errors() {
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("missing.vault");
        let malformed = tempdir.path().join("malformed.vault");
        let directory = tempdir.path().join("directory.vault");
        let envelope = encrypt_env("DATABASE_URL=postgres://local\n", "passphrase").unwrap();

        std::fs::write(&malformed, "{bad-json}").unwrap();
        std::fs::create_dir(&directory).unwrap();

        assert!(read_vault(&missing).is_err());
        assert!(read_vault(&malformed).is_err());
        assert!(write_vault(&directory, &envelope).is_err());
    }

    #[test]
    fn derive_key_reports_invalid_hash_inputs() {
        let kdf = KdfEnvelope {
            name: "argon2id".to_string(),
            memory_cost: 65_536,
            time_cost: 3,
            parallelism: 1,
            salt: STANDARD.encode([]),
        };
        let mut invalid_params = kdf.clone();
        invalid_params.memory_cost = 0;

        assert!(derive_key("passphrase", b"salt", &invalid_params).is_err());
        assert!(derive_key("passphrase", b"", &kdf).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn selected_editor_prefers_editor_then_visual_then_nano() {
        let _guard = env_lock();

        std::env::set_var("EDITOR", "code --wait");
        std::env::set_var("VISUAL", "vim");
        assert_eq!(selected_editor(), "code --wait");

        std::env::set_var("EDITOR", "");
        assert_eq!(selected_editor(), "vim");

        std::env::remove_var("EDITOR");
        std::env::remove_var("VISUAL");
        assert_eq!(selected_editor(), "nano");
    }

    #[test]
    #[serial_test::serial]
    fn test_passphrase_ignores_empty_values() {
        let _guard = env_lock();

        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "");
        assert!(test_passphrase().is_none());
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "secret");
        assert_eq!(test_passphrase(), Some("secret".to_string()));
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn passphrase_readers_use_test_passphrase_when_present() {
        let _guard = env_lock();

        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "secret passphrase");

        assert_eq!(read_new_passphrase().unwrap(), "secret passphrase");
        assert_eq!(read_existing_passphrase().unwrap(), "secret passphrase");

        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn edit_vault_reports_editor_failure_and_invalid_contents_without_corrupting_vault() {
        let tempdir = tempfile::tempdir().unwrap();
        let vault_path = tempdir.path().join(".env.vault");
        let envelope = encrypt_env("DATABASE_URL=postgres://original\n", "passphrase").unwrap();
        write_vault(&vault_path, &envelope).unwrap();

        let failing_editor = tempdir.path().join("fail.sh");
        std::fs::write(&failing_editor, "#!/bin/sh\nexit 3\n").unwrap();
        make_executable(&failing_editor);
        assert!(run_editor(failing_editor.to_str().unwrap(), &vault_path).is_err());

        let invalid_editor = tempdir.path().join("invalid.sh");
        std::fs::write(
            &invalid_editor,
            "#!/bin/sh\nprintf \"DATABASE_URL='unterminated\\n\" > \"$1\"\n",
        )
        .unwrap();
        make_executable(&invalid_editor);

        let _guard = env_lock();
        std::env::set_var("EDITOR", &invalid_editor);
        assert!(edit_vault_file(&vault_path, "passphrase").is_err());
        std::env::remove_var("EDITOR");

        assert_eq!(
            decrypt_vault_file(&vault_path, "passphrase").unwrap(),
            "DATABASE_URL=postgres://original\n"
        );
    }

    #[test]
    #[serial_test::serial]
    fn edit_vault_file_reencrypts_valid_editor_output() {
        let tempdir = tempfile::tempdir().unwrap();
        let vault_path = tempdir.path().join(".env.vault");
        let envelope = encrypt_env("DATABASE_URL=postgres://original\n", "passphrase").unwrap();
        write_vault(&vault_path, &envelope).unwrap();

        let editor = tempdir.path().join("edit.sh");
        std::fs::write(
            &editor,
            "#!/bin/sh\nprintf 'DATABASE_URL=postgres://edited\\n' > \"$1\"\n",
        )
        .unwrap();
        make_executable(&editor);

        let _guard = env_lock();
        std::env::set_var("EDITOR", &editor);
        edit_vault_file(&vault_path, "passphrase").unwrap();
        std::env::remove_var("EDITOR");

        assert_eq!(
            decrypt_vault_file(&vault_path, "passphrase").unwrap(),
            "DATABASE_URL=postgres://edited\n"
        );
    }

    #[cfg(coverage)]
    #[test]
    #[serial_test::serial]
    fn coverage_prompt_password_stubs_are_available_without_env() {
        let _guard = env_lock();
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");

        assert_eq!(read_new_passphrase().unwrap(), "coverage passphrase");
        assert_eq!(read_existing_passphrase().unwrap(), "coverage passphrase");
    }

    #[cfg(unix)]
    fn make_executable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &std::path::Path) {}
}
