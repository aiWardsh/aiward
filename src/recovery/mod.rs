use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{fs_util, logs, vault};

const RECOVERY_MEMORY_COST: u32 = 262_144; // 256 MiB — ~2s per attempt
const RECOVERY_TIME_COST: u32 = 8;

#[derive(Debug, Clone)]
pub struct RecoveryMaterial {
    pub passphrase: String,
    pub vault_plaintext: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryBlob {
    version: u32,
    project: String,
    passphrase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault_plaintext: Option<String>,
}

/// Creates the real recovery file and 39-59 same-size decoys in ~/.ward/recovery/.
/// Returns the path to the real recovery file.
pub fn create_recovery_files(
    project: &str,
    passphrase: &str,
    recovery_passphrase: &str,
) -> Result<PathBuf> {
    create_recovery_files_with_material(project, passphrase, recovery_passphrase, None)
}

/// Creates a recovery file that can restore both the vault passphrase and,
/// when provided, the vault plaintext after a lost broker session key.
pub fn create_recovery_files_with_material(
    project: &str,
    passphrase: &str,
    recovery_passphrase: &str,
    vault_plaintext: Option<&str>,
) -> Result<PathBuf> {
    let dir = logs::recovery_dir();
    fs_util::ensure_private_dir(&dir)?;

    let blob = RecoveryBlob {
        version: if vault_plaintext.is_some() { 2 } else { 1 },
        project: project.to_string(),
        passphrase: passphrase.to_string(),
        vault_plaintext: vault_plaintext.map(str::to_string),
    };
    let plaintext = serde_json::to_string(&blob)?;
    let envelope = vault::encrypt_env_with_params(
        &plaintext,
        recovery_passphrase,
        RECOVERY_MEMORY_COST,
        RECOVERY_TIME_COST,
    )?;
    let real_bytes = serde_json::to_vec_pretty(&envelope)?;

    let real_filename = derive_recovery_filename(passphrase, project);
    let real_path = dir.join(&real_filename);
    fs_util::write_private_file(&real_path, &real_bytes)?;

    // Generate 39-59 decoys of identical serialized size.
    let decoy_count = (OsRng.next_u32() % 21 + 39) as usize;
    for _ in 0..decoy_count {
        let mut key = [0u8; 32];
        let mut random_plain = vec![0u8; plaintext.len()];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut random_plain);
        let mut decoy_envelope = vault::encrypt_raw_bytes(&random_plain, &key)?;
        decoy_envelope.kdf.memory_cost = RECOVERY_MEMORY_COST;
        decoy_envelope.kdf.time_cost = RECOVERY_TIME_COST;
        decoy_envelope.created_at = envelope.created_at.clone();
        decoy_envelope.updated_at = envelope.updated_at.clone();
        let decoy_bytes = serde_json::to_vec_pretty(&decoy_envelope)?;
        anyhow::ensure!(
            decoy_bytes.len() == real_bytes.len(),
            "recovery decoy size mismatch"
        );
        fs_util::write_private_file(&dir.join(generate_decoy_filename()), &decoy_bytes)?;
    }

    Ok(real_path)
}

/// Restores the vault passphrase from a recovery file using the recovery passphrase.
/// If passphrase is known it derives the filename directly; otherwise tries all .key files.
pub fn restore_from_recovery(
    project: &str,
    known_passphrase: Option<&str>,
    recovery_passphrase: &str,
) -> Result<String> {
    Ok(restore_material_from_recovery(project, known_passphrase, recovery_passphrase)?.passphrase)
}

/// Restores the vault passphrase and optional vault material from a recovery file.
pub fn restore_material_from_recovery(
    project: &str,
    known_passphrase: Option<&str>,
    recovery_passphrase: &str,
) -> Result<RecoveryMaterial> {
    let dir = logs::recovery_dir();

    if let Some(passphrase) = known_passphrase {
        let filename = derive_recovery_filename(passphrase, project);
        let path = dir.join(filename);
        return material_from_recovery_file(project, &path, recovery_passphrase);
    }

    // Try all .key files — only the real one will decrypt successfully.
    let entries = std::fs::read_dir(&dir).context(format!(
        "failed to read recovery directory {}",
        dir.display()
    ))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("key") {
            if let Ok(material) = material_from_recovery_file(project, &path, recovery_passphrase) {
                return Ok(material);
            }
        }
    }

    anyhow::bail!(
        "no valid recovery file found in {} for project '{}'",
        dir.display(),
        project
    )
}

/// Restores recovery material from a specific recovery file path.
pub fn restore_material_from_file(
    project: &str,
    path: &Path,
    recovery_passphrase: &str,
) -> Result<RecoveryMaterial> {
    let path = fs_util::resolve_existing_external_file(path, "recovery file")?;
    material_from_recovery_file(project, &path, recovery_passphrase)
}

/// Rewrites the vault from recovery material, returning it to passphrase encryption.
pub fn restore_vault_from_recovery(
    project: &str,
    vault_path: &Path,
    known_passphrase: Option<&str>,
    recovery_passphrase: &str,
) -> Result<()> {
    let material = restore_material_from_recovery(project, known_passphrase, recovery_passphrase)?;
    write_recovered_vault(vault_path, &material)
}

/// Rewrites the vault from a specific recovery file path.
pub fn restore_vault_from_recovery_file(
    project: &str,
    vault_path: &Path,
    recovery_file: &Path,
    recovery_passphrase: &str,
) -> Result<()> {
    let material = restore_material_from_file(project, recovery_file, recovery_passphrase)?;
    write_recovered_vault(vault_path, &material)
}

/// Imports a recovery file backup from an external path into ~/.ward/recovery/.
pub fn import_recovery_file(source: &std::path::Path) -> Result<PathBuf> {
    let dir = logs::recovery_dir();
    fs_util::ensure_private_dir(&dir)?;
    let source = fs_util::resolve_existing_external_file(source, "recovery source")?;

    let filename = source
        .file_name()
        .context("source path has no filename")?
        .to_string_lossy()
        .into_owned();

    let dest = dir.join(&filename);
    let contents =
        std::fs::read(&source).context(format!("failed to read {}", source.display()))?;
    fs_util::write_private_file(&dest, &contents)?;
    Ok(dest)
}

/// Exports the real recovery file to a destination path.
pub fn export_recovery_file(
    project: &str,
    passphrase: &str,
    dest: &std::path::Path,
) -> Result<PathBuf> {
    let dir = logs::recovery_dir();
    let filename = derive_recovery_filename(passphrase, project);
    let source = dir.join(&filename);

    anyhow::ensure!(
        source.exists(),
        "recovery file not found at {} — run ward setup to create one",
        source.display()
    );

    let contents =
        std::fs::read(&source).context(format!("failed to read {}", source.display()))?;

    let requested_out = if dest.is_dir() {
        dest.join(&filename)
    } else {
        dest.to_path_buf()
    };
    let out_path = fs_util::resolve_external_output(&requested_out, "recovery export path")?;

    std::fs::write(&out_path, contents)
        .context(format!("failed to write {}", out_path.display()))?;
    Ok(out_path)
}

/// Returns true if the real recovery file exists for this project.
pub fn recovery_file_exists(project: &str, passphrase: &str) -> bool {
    let dir = logs::recovery_dir();
    dir.join(derive_recovery_filename(passphrase, project))
        .exists()
}

fn decrypt_recovery_file(path: &std::path::Path, pin: &str) -> Result<String> {
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        anyhow::bail!("Invalid input: {}", path.display());
    }
    let contents =
        std::fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
    let envelope: vault::VaultEnvelope =
        serde_json::from_str(&contents).context(format!("failed to parse {}", path.display()))?;
    vault::decrypt_env(&envelope, pin)
}

fn decrypt_recovery_blob(
    path: &std::path::Path,
    recovery_passphrase: &str,
) -> Result<RecoveryBlob> {
    let plaintext = decrypt_recovery_file(path, recovery_passphrase)?;
    let blob: RecoveryBlob = serde_json::from_str(&plaintext).context("invalid recovery blob")?;
    anyhow::ensure!(
        blob.version == 1 || blob.version == 2,
        "unsupported recovery blob version {}",
        blob.version
    );
    Ok(blob)
}

fn material_from_recovery_file(
    project: &str,
    path: &Path,
    recovery_passphrase: &str,
) -> Result<RecoveryMaterial> {
    let blob = decrypt_recovery_blob(path, recovery_passphrase)?;
    anyhow::ensure!(
        blob.project == project,
        "recovery file belongs to another project"
    );
    Ok(RecoveryMaterial {
        passphrase: blob.passphrase,
        vault_plaintext: blob.vault_plaintext,
    })
}

fn write_recovered_vault(vault_path: &Path, material: &RecoveryMaterial) -> Result<()> {
    let plaintext = material.vault_plaintext.as_deref().context(
        "this recovery file only contains the vault passphrase and cannot restore vault contents; create a new recovery key after unlocking a healthy vault",
    )?;
    let envelope = vault::encrypt_env(plaintext, &material.passphrase)?;
    vault::write_vault(vault_path, &envelope)
}

fn derive_recovery_filename(passphrase: &str, project: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ward-recovery\x00");
    hasher.update(passphrase.as_bytes());
    hasher.update(b"\x00");
    hasher.update(project.as_bytes());
    let hash = hasher.finalize();
    format!("{}.key", hex::encode(&hash[..6]))
}

fn generate_decoy_filename() -> String {
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    format!("{}.key", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn derive_recovery_filename_is_deterministic_and_distinct() {
        let f1 = derive_recovery_filename("passphrase", "project");
        let f2 = derive_recovery_filename("passphrase", "project");
        let f3 = derive_recovery_filename("other", "project");

        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
        assert!(f1.ends_with(".key"));
    }

    #[test]
    #[serial_test::serial]
    fn create_and_restore_recovery_files() {
        let _guard = env_lock();
        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tmpdir.path());

        create_recovery_files("myproject", "vault-passphrase", "1234").unwrap();

        let dir = logs::recovery_dir();
        let key_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("key"))
            .collect();

        // At least 40 files (real + minimum 39 decoys)
        assert!(
            key_files.len() >= 40,
            "expected >= 40 .key files, got {}",
            key_files.len()
        );

        // All .key files have identical size
        let sizes: std::collections::HashSet<u64> = key_files
            .iter()
            .map(|e| e.metadata().unwrap().len())
            .collect();
        assert_eq!(sizes.len(), 1, "all .key files should be same size");

        let recovered = restore_from_recovery("myproject", None, "1234").unwrap();
        assert_eq!(recovered, "vault-passphrase");

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn restore_with_wrong_pin_fails() {
        let _guard = env_lock();
        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tmpdir.path());

        create_recovery_files("myproject", "vault-passphrase", "1234").unwrap();
        assert!(restore_from_recovery("myproject", None, "wrong").is_err());

        std::env::remove_var("WARD_HOME");
    }
}
