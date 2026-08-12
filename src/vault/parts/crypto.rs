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

pub fn generate_key_derivation_nonce() -> String {
    let mut bytes = [0u8; KEY_DERIVATION_NONCE_LEN];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

pub fn generate_vault_id() -> String {
    uuid::Uuid::new_v4().to_string()
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
        key_derivation: VaultKeyDerivation::LocalDerivedV1,
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
        key_derivation: VaultKeyDerivation::LocalDerivedV1,
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
    import_env_file_with_key_mode(source, vault_path, passphrase, VaultKeyMode::LocalDerivedV1)
}

pub fn import_env_file_with_key_mode(
    source: &Path,
    vault_path: &Path,
    passphrase: &str,
    key_mode: VaultKeyMode,
) -> Result<PathBuf> {
    let plaintext = fs_util::read_file_to_string(source, "dotenv source")?;
    validate_dotenv(&plaintext)?;

    let envelope = encrypt_env_with_key_mode(&plaintext, passphrase, key_mode)?;
    write_vault(vault_path, &envelope)?;
    Ok(vault_path.to_path_buf())
}

pub fn encrypt_env(plaintext: &str, passphrase: &str) -> Result<VaultEnvelope> {
    encrypt_env_with_key_mode(plaintext, passphrase, VaultKeyMode::LocalDerivedV1)
}

pub fn encrypt_env_with_key_mode(
    plaintext: &str,
    passphrase: &str,
    key_mode: VaultKeyMode,
) -> Result<VaultEnvelope> {
    match key_mode {
        VaultKeyMode::LocalDerivedV1 => encrypt_env_local(plaintext, passphrase),
        VaultKeyMode::ApiDerivedV1 => encrypt_env_api_derived(plaintext, passphrase),
    }
}

fn encrypt_env_local(plaintext: &str, passphrase: &str) -> Result<VaultEnvelope> {
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
        key_derivation: VaultKeyDerivation::LocalDerivedV1,
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

pub fn encrypt_env_like(
    existing: &VaultEnvelope,
    plaintext: &str,
    passphrase: &str,
) -> Result<VaultEnvelope> {
    match existing.key_mode() {
        VaultKeyMode::LocalDerivedV1 => {
            let mut envelope = encrypt_env_local(plaintext, passphrase)?;
            envelope.created_at = existing.created_at.clone();
            Ok(envelope)
        }
        VaultKeyMode::ApiDerivedV1 => {
            let mut envelope = encrypt_env_api_derived_with_metadata(
                plaintext,
                passphrase,
                existing
                    .api_metadata()
                    .cloned()
                    .context("api-derived vault is missing API metadata")?,
            )?;
            envelope.created_at = existing.created_at.clone();
            Ok(envelope)
        }
    }
}

fn encrypt_env_api_derived(plaintext: &str, passphrase: &str) -> Result<VaultEnvelope> {
    let api = ApiDerivedEnvelope {
        vault_id: generate_vault_id(),
        key_derivation_nonce: generate_key_derivation_nonce(),
        server_key_id: DEFAULT_SERVER_KEY_ID.to_string(),
    };
    encrypt_env_api_derived_with_metadata(plaintext, passphrase, api)
}

fn encrypt_env_api_derived_with_metadata(
    plaintext: &str,
    passphrase: &str,
    api: ApiDerivedEnvelope,
) -> Result<VaultEnvelope> {
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

    let mut key = derive_api_vault_key(passphrase, &salt, &kdf, &api)?;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("derived AES-256 key has valid length");
    let mut encrypted = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .expect("AES-GCM encryption should not fail for a valid nonce");
    key.zeroize();

    let auth_tag = encrypted.split_off(encrypted.len() - TAG_LEN);
    let now = chrono::Utc::now().to_rfc3339();

    Ok(VaultEnvelope {
        version: 2,
        key_derivation: VaultKeyDerivation::ApiDerivedV1(api),
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

    let updated = encrypt_env_like(&existing_envelope, &edited, passphrase)?;
    write_vault(vault_path, &updated)?;
    temp_file
        .close()
        .context("failed to remove temporary env edit buffer")?;
    Ok(())
}

pub fn decrypt_env(envelope: &VaultEnvelope, passphrase: &str) -> Result<String> {
    match envelope.key_mode() {
        VaultKeyMode::LocalDerivedV1 if envelope.version != 1 => {
            anyhow::bail!("unsupported local vault version {}", envelope.version);
        }
        VaultKeyMode::ApiDerivedV1 if envelope.version != 2 => {
            anyhow::bail!("unsupported api-derived vault version {}", envelope.version);
        }
        _ => {}
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

    let mut key = match &envelope.key_derivation {
        VaultKeyDerivation::LocalDerivedV1 => derive_key(passphrase, &salt, &envelope.kdf)?,
        VaultKeyDerivation::ApiDerivedV1(api) => {
            derive_api_vault_key(passphrase, &salt, &envelope.kdf, api)?
        }
    };
    let cipher = Aes256Gcm::new_from_slice(&key).expect("derived AES-256 key has valid length");
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
        .map_err(|_| anyhow::Error::new(IncorrectPassphrase))?;
    key.zeroize();

    String::from_utf8(plaintext).context("vault plaintext is not valid UTF-8")
}
