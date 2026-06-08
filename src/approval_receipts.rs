use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    approvals::ApprovalScope,
    context, fs_util,
    policy::AccessRequest,
    vault::{self, VaultEnvelope},
};

const RECEIPT_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_ALGORITHM: &str = "ed25519";
const SIGNING_SEED_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalReceiptPayload {
    pub schema_version: u32,
    pub grant_id: uuid::Uuid,
    pub request_id: uuid::Uuid,
    pub project: String,
    pub agent: Option<String>,
    pub branch: Option<String>,
    pub command_hash: String,
    pub requested_env: Vec<String>,
    pub approved_env: Vec<String>,
    pub scope: ApprovalScope,
    pub expires_at: Option<DateTime<Utc>>,
    pub critical_confirmation: bool,
    pub created_at: DateTime<Utc>,
    pub signer_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_worktree: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_git_remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalReceipt {
    pub payload: ApprovalReceiptPayload,
    pub payload_hash: String,
    pub signer_key_id: String,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyCiphertext {
    pub signer_key_id: String,
    pub encrypted_private_key: VaultEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalKeyFile {
    pub version: u32,
    pub project: String,
    pub key_id: String,
    pub public_key: String,
    pub encrypted_private_key: VaultEnvelope,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SessionSigningKey {
    pub signer_key_id: String,
    seed: [u8; SIGNING_SEED_LEN],
}

impl Drop for SessionSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

pub fn keys_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(std::path::Path::new("keys"), "approval keys directory")
        .expect("approval keys directory should stay inside Ward home")
}

pub fn project_key_path(project: &str) -> PathBuf {
    let relative = PathBuf::from("keys").join(format!("{}.json", project_path_id(project)));
    fs_util::resolve_ward_home_path(&relative, "approval key path")
        .expect("approval key path should stay inside Ward home")
}

pub fn ensure_project_key(project: &str, passphrase: &str) -> Result<ApprovalKeyFile> {
    let path = project_key_path(project);
    if path.exists() {
        let key_file = read_project_key(project)?;
        let mut seed = decrypt_seed(&key_file.encrypted_private_key, passphrase)
            .with_context(|| format!("failed to decrypt approval key for project {project}"))?;
        seed.zeroize();
        return Ok(key_file);
    }

    let mut seed = [0_u8; SIGNING_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let key_id = key_id_for_public_key(&public_key);
    let encrypted_private_key = encrypt_seed(&seed, passphrase)?;
    seed.zeroize();

    let key_file = ApprovalKeyFile {
        version: 1,
        project: project.to_string(),
        key_id,
        public_key: STANDARD.encode(public_key),
        encrypted_private_key,
        created_at: Utc::now(),
    };
    write_project_key(&key_file)?;
    Ok(key_file)
}

pub fn session_signing_key_ciphertext(
    project: &str,
    project_passphrase: &str,
    session_secret: &str,
) -> Result<SigningKeyCiphertext> {
    let key_file = ensure_project_key(project, project_passphrase)?;
    let mut seed = decrypt_seed(&key_file.encrypted_private_key, project_passphrase)?;
    let encrypted_private_key = encrypt_seed(&seed, session_secret)?;
    seed.zeroize();
    Ok(SigningKeyCiphertext {
        signer_key_id: key_file.key_id,
        encrypted_private_key,
    })
}

pub fn decrypt_session_signing_key(
    ciphertext: &SigningKeyCiphertext,
    session_secret: &str,
) -> Result<SessionSigningKey> {
    let seed = decrypt_seed(&ciphertext.encrypted_private_key, session_secret)
        .context("failed to decrypt session signing key")?;
    Ok(SessionSigningKey {
        signer_key_id: ciphertext.signer_key_id.clone(),
        seed,
    })
}

pub fn build_payload(
    access: &AccessRequest,
    grant_id: uuid::Uuid,
    request_id: uuid::Uuid,
    approved_env: &[String],
    scope: ApprovalScope,
    expires_at: Option<DateTime<Utc>>,
    critical_confirmation: bool,
    created_at: DateTime<Utc>,
    signer_key_id: String,
) -> ApprovalReceiptPayload {
    build_payload_with_context(
        access,
        grant_id,
        request_id,
        approved_env,
        scope,
        expires_at,
        critical_confirmation,
        created_at,
        signer_key_id,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_payload_with_context(
    access: &AccessRequest,
    grant_id: uuid::Uuid,
    request_id: uuid::Uuid,
    approved_env: &[String],
    scope: ApprovalScope,
    expires_at: Option<DateTime<Utc>>,
    critical_confirmation: bool,
    created_at: DateTime<Utc>,
    signer_key_id: String,
    verified_context: Option<&context::VerifiedContext>,
) -> ApprovalReceiptPayload {
    ApprovalReceiptPayload {
        schema_version: RECEIPT_SCHEMA_VERSION,
        grant_id,
        request_id,
        project: access.project.clone(),
        agent: access.agent.clone(),
        branch: access.branch.clone(),
        command_hash: command_hash(&access.command),
        requested_env: sorted_strings(&access.env),
        approved_env: sorted_strings(approved_env),
        scope,
        expires_at,
        critical_confirmation,
        created_at,
        signer_key_id,
        agent_key_id: verified_context.map(|context| context.agent_key_id.clone()),
        verified_worktree: verified_context.map(|context| context.worktree.clone()),
        verified_git_remote: verified_context.map(|context| context.git_remote.clone()),
        verified_commit: verified_context.map(|context| context.commit.clone()),
    }
}

pub fn sign_payload(
    payload: ApprovalReceiptPayload,
    session_key: &SessionSigningKey,
) -> Result<ApprovalReceipt> {
    if payload.signer_key_id != session_key.signer_key_id {
        anyhow::bail!("approval receipt signer key id does not match active signing key");
    }
    let canonical = canonical_payload_bytes(&payload);
    let payload_hash = hash_bytes(&canonical);
    let signing_key = SigningKey::from_bytes(&session_key.seed);
    let signature = signing_key.sign(&canonical);
    Ok(ApprovalReceipt {
        payload,
        payload_hash,
        signer_key_id: session_key.signer_key_id.clone(),
        signature_algorithm: SIGNATURE_ALGORITHM.to_string(),
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

pub fn verify_receipt_signature(project: &str, receipt: &ApprovalReceipt) -> bool {
    let Ok(key_file) = read_project_key(project) else {
        return false;
    };
    if key_file.key_id != receipt.signer_key_id
        || key_file.key_id != receipt.payload.signer_key_id
        || receipt.signature_algorithm != SIGNATURE_ALGORITHM
    {
        return false;
    }
    let canonical = canonical_payload_bytes(&receipt.payload);
    if hash_bytes(&canonical) != receipt.payload_hash {
        return false;
    }
    let Ok(public_key_bytes) = STANDARD.decode(&key_file.public_key) else {
        return false;
    };
    let Ok(public_key_bytes) = <[u8; 32]>::try_from(public_key_bytes.as_slice()) else {
        return false;
    };
    let Ok(signature_bytes) = STANDARD.decode(&receipt.signature) else {
        return false;
    };
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).ok();
    let signature = Signature::try_from(signature_bytes.as_slice()).ok();
    verifying_key
        .zip(signature)
        .is_some_and(|(verifying_key, signature)| {
            verifying_key.verify(&canonical, &signature).is_ok()
        })
}

pub fn command_hash(command: &str) -> String {
    hash_bytes(command.as_bytes())
}

pub fn canonical_payload_bytes(payload: &ApprovalReceiptPayload) -> Vec<u8> {
    serde_json::to_vec(payload).expect("approval receipt payload serialization is infallible")
}

fn read_project_key(project: &str) -> Result<ApprovalKeyFile> {
    let path = project_key_path(project);
    let contents = fs_util::read_file_to_string(&path, "approval key")?;
    let key_file = serde_json::from_str::<ApprovalKeyFile>(&contents)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if key_file.version != 1 {
        anyhow::bail!("unsupported approval key version {}", key_file.version);
    }
    if key_file.project != project {
        anyhow::bail!("approval key project mismatch");
    }
    Ok(key_file)
}

fn write_project_key(key_file: &ApprovalKeyFile) -> Result<()> {
    fs_util::ensure_private_dir(&keys_dir())?;
    let path = project_key_path(&key_file.project);
    let contents =
        serde_json::to_string_pretty(key_file).expect("approval key serialization is infallible");
    fs_util::write_private_file(&path, format!("{contents}\n").as_bytes())
}

fn encrypt_seed(seed: &[u8; SIGNING_SEED_LEN], passphrase: &str) -> Result<VaultEnvelope> {
    vault::encrypt_env(&STANDARD.encode(seed), passphrase)
}

fn decrypt_seed(envelope: &VaultEnvelope, passphrase: &str) -> Result<[u8; SIGNING_SEED_LEN]> {
    let encoded = vault::decrypt_env(envelope, passphrase)?;
    let mut bytes = STANDARD
        .decode(encoded.trim())
        .context("approval signing key is not valid base64")?;
    let seed = <[u8; SIGNING_SEED_LEN]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("approval signing key has invalid length"))?;
    bytes.zeroize();
    Ok(seed)
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn key_id_for_public_key(public_key: &[u8; 32]) -> String {
    format!("{SIGNATURE_ALGORITHM}:{}", hash_bytes(public_key))
}

fn project_path_id(project: &str) -> String {
    hash_bytes(project.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::ApprovalScope;
    use serial_test::serial;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn access(env: Vec<&str>) -> AccessRequest {
        AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("main".to_string()),
            action: Some("Run dev server".to_string()),
            command: "pnpm dev".to_string(),
            env: env.into_iter().map(str::to_string).collect(),
        }
    }

    #[test]
    #[serial]
    fn approval_key_generation_round_trips_and_rejects_wrong_passphrase() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let key_file = ensure_project_key("demo", "1234").unwrap();
        assert_eq!(key_file.project, "demo");
        assert!(ensure_project_key("demo", "wrong").is_err());
        assert_eq!(
            ensure_project_key("demo", "1234").unwrap().key_id,
            key_file.key_id
        );

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn session_signing_ciphertext_round_trips_and_rejects_wrong_secret() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let ciphertext = session_signing_key_ciphertext("demo", "1234", "session").unwrap();
        let session_key = decrypt_session_signing_key(&ciphertext, "session").unwrap();
        assert_eq!(session_key.signer_key_id, ciphertext.signer_key_id);
        assert!(decrypt_session_signing_key(&ciphertext, "wrong").is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn canonical_receipt_is_deterministic_for_reordered_envs() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let ciphertext = session_signing_key_ciphertext("demo", "1234", "session").unwrap();
        let session_key = decrypt_session_signing_key(&ciphertext, "session").unwrap();
        let now = Utc::now();
        let first = build_payload(
            &access(vec!["B_KEY", "A_KEY"]),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            &["B_KEY".to_string(), "A_KEY".to_string()],
            ApprovalScope::Always,
            None,
            false,
            now,
            session_key.signer_key_id.clone(),
        );
        let second = build_payload(
            &access(vec!["A_KEY", "B_KEY"]),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            &["A_KEY".to_string(), "B_KEY".to_string()],
            ApprovalScope::Always,
            None,
            false,
            now,
            session_key.signer_key_id.clone(),
        );

        assert_eq!(
            canonical_payload_bytes(&first),
            canonical_payload_bytes(&second)
        );

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn signature_verifies_and_fails_after_payload_change() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let ciphertext = session_signing_key_ciphertext("demo", "1234", "session").unwrap();
        let session_key = decrypt_session_signing_key(&ciphertext, "session").unwrap();
        let payload = build_payload(
            &access(vec!["DATABASE_URL"]),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &["DATABASE_URL".to_string()],
            ApprovalScope::Always,
            None,
            false,
            Utc::now(),
            session_key.signer_key_id.clone(),
        );
        let mut receipt = sign_payload(payload, &session_key).unwrap();

        assert!(verify_receipt_signature("demo", &receipt));
        receipt.payload.scope = ApprovalScope::Session;
        assert!(!verify_receipt_signature("demo", &receipt));

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn signing_and_verification_reject_bad_metadata_and_key_files() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let ciphertext = session_signing_key_ciphertext("demo", "1234", "session").unwrap();
        let session_key = decrypt_session_signing_key(&ciphertext, "session").unwrap();
        let payload = build_payload(
            &access(vec!["DATABASE_URL"]),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &["DATABASE_URL".to_string()],
            ApprovalScope::Always,
            None,
            false,
            Utc::now(),
            session_key.signer_key_id.clone(),
        );
        let receipt = sign_payload(payload.clone(), &session_key).unwrap();

        let mut mismatched_payload = payload;
        mismatched_payload.signer_key_id = "wrong".to_string();
        assert!(sign_payload(mismatched_payload, &session_key).is_err());
        assert!(!verify_receipt_signature("missing", &receipt));

        let mut bad_receipt = receipt.clone();
        bad_receipt.signer_key_id = "wrong".to_string();
        assert!(!verify_receipt_signature("demo", &bad_receipt));
        let mut bad_receipt = receipt.clone();
        bad_receipt.signature_algorithm = "not-ed25519".to_string();
        assert!(!verify_receipt_signature("demo", &bad_receipt));
        let mut bad_receipt = receipt.clone();
        bad_receipt.payload_hash = "wrong".to_string();
        assert!(!verify_receipt_signature("demo", &bad_receipt));
        let mut bad_receipt = receipt.clone();
        bad_receipt.signature = "not-base64".to_string();
        assert!(!verify_receipt_signature("demo", &bad_receipt));
        let mut bad_receipt = receipt.clone();
        bad_receipt.signature = STANDARD.encode([1_u8, 2, 3]);
        assert!(!verify_receipt_signature("demo", &bad_receipt));

        let mut key_file = read_project_key("demo").unwrap();
        key_file.public_key = "not-base64".to_string();
        write_project_key(&key_file).unwrap();
        assert!(!verify_receipt_signature("demo", &receipt));
        key_file.public_key = STANDARD.encode([1_u8, 2, 3]);
        write_project_key(&key_file).unwrap();
        assert!(!verify_receipt_signature("demo", &receipt));
        key_file.public_key = STANDARD.encode([0xff_u8; 32]);
        write_project_key(&key_file).unwrap();
        assert!(!verify_receipt_signature("demo", &receipt));

        key_file.version = 2;
        write_project_key(&key_file).unwrap();
        assert!(read_project_key("demo").is_err());
        key_file.version = 1;
        key_file.project = "other".to_string();
        let contents = serde_json::to_string_pretty(&key_file).unwrap();
        std::fs::write(project_key_path("demo"), contents).unwrap();
        assert!(read_project_key("demo").is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn approval_key_storage_reports_parse_write_and_seed_errors() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        std::fs::create_dir_all(keys_dir()).unwrap();
        std::fs::write(project_key_path("bad-json"), "{bad-json").unwrap();
        assert!(ensure_project_key("bad-json", "1234").is_err());

        let mut bad_base64 = ensure_project_key("bad-base64", "1234").unwrap();
        bad_base64.encrypted_private_key = vault::encrypt_env("not-base64!", "1234").unwrap();
        write_project_key(&bad_base64).unwrap();
        assert!(ensure_project_key("bad-base64", "1234").is_err());

        let mut bad_length = ensure_project_key("bad-length", "1234").unwrap();
        bad_length.encrypted_private_key =
            vault::encrypt_env(&STANDARD.encode([1_u8, 2, 3]), "1234").unwrap();
        write_project_key(&bad_length).unwrap();
        assert!(ensure_project_key("bad-length", "1234").is_err());

        let blocked_home = home.path().join("blocked-home");
        std::fs::write(&blocked_home, "not a directory").unwrap();
        std::env::set_var("WARD_HOME", blocked_home);
        assert!(ensure_project_key("blocked", "1234").is_err());

        std::env::remove_var("WARD_HOME");
    }
}
