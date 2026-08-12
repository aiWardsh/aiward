use super::*;
use base64::engine::general_purpose::STANDARD;

fn env_lock() -> crate::test_support::TestEnvironment {
    crate::test_support::TestEnvironment::lock()
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
    let envelope = encrypt_env("DATABASE_URL=postgres://local\n", "correct passphrase").unwrap();

    assert!(decrypt_env(&envelope, "wrong passphrase").is_err());
}

#[test]
fn api_derived_vault_round_trips_without_raw_pin_api_in_tests() {
    let plaintext = "DATABASE_URL=postgres://api-derived\n";
    let envelope =
        encrypt_env_with_key_mode(plaintext, "1234", VaultKeyMode::ApiDerivedV1).unwrap();

    assert_eq!(envelope.version, 2);
    assert_eq!(envelope.key_mode(), VaultKeyMode::ApiDerivedV1);
    assert!(envelope.api_metadata().is_some());
    assert_eq!(decrypt_env(&envelope, "1234").unwrap(), plaintext);
    assert!(decrypt_env(&envelope, "4321").is_err());
}

#[test]
fn api_derived_nonce_separates_same_pin_vaults() {
    let first = encrypt_env_with_key_mode(
        "DATABASE_URL=postgres://one\n",
        "1234",
        VaultKeyMode::ApiDerivedV1,
    )
    .unwrap();
    let second = encrypt_env_with_key_mode(
        "DATABASE_URL=postgres://one\n",
        "1234",
        VaultKeyMode::ApiDerivedV1,
    )
    .unwrap();

    assert_ne!(
        first.api_metadata().unwrap().key_derivation_nonce,
        second.api_metadata().unwrap().key_derivation_nonce
    );
    assert_ne!(first.cipher.ciphertext, second.cipher.ciphertext);
}

#[test]
fn legacy_v1_wire_fixture_round_trips_without_migration() {
    let fixture = serde_json::json!({
        "version": 1,
        "kdf": {
            "name": "argon2id",
            "memoryCost": 65536,
            "timeCost": 3,
            "parallelism": 1,
            "salt": "c2FsdA=="
        },
        "cipher": {
            "name": "aes-256-gcm",
            "iv": "aXY=",
            "authTag": "dGFn",
            "ciphertext": "Y2lwaGVydGV4dA=="
        },
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z"
    });
    let envelope: VaultEnvelope = serde_json::from_value(fixture.clone()).unwrap();

    assert_eq!(envelope.key_mode(), VaultKeyMode::LocalDerivedV1);
    assert_eq!(serde_json::to_value(envelope).unwrap(), fixture);
}

#[test]
fn api_v2_wire_fixture_round_trips_without_migration() {
    let fixture = serde_json::json!({
        "version": 2,
        "keyMode": "api-derived-v1",
        "api": {
            "vaultId": "fixture-vault",
            "keyDerivationNonce": "fixture-nonce",
            "serverKeyId": "ward-api-derived-v1"
        },
        "kdf": {
            "name": "argon2id",
            "memoryCost": 65536,
            "timeCost": 3,
            "parallelism": 1,
            "salt": "c2FsdA=="
        },
        "cipher": {
            "name": "aes-256-gcm",
            "iv": "aXY=",
            "authTag": "dGFn",
            "ciphertext": "Y2lwaGVydGV4dA=="
        },
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z"
    });
    let envelope: VaultEnvelope = serde_json::from_value(fixture.clone()).unwrap();

    assert_eq!(envelope.key_mode(), VaultKeyMode::ApiDerivedV1);
    assert_eq!(serde_json::to_value(envelope).unwrap(), fixture);
}

#[test]
fn invalid_wire_key_mode_and_api_metadata_combinations_are_rejected() {
    let local_with_api = serde_json::json!({
        "version": 1,
        "keyMode": "local-derived-v1",
        "api": {"vaultId":"v", "keyDerivationNonce":"n", "serverKeyId":"k"},
        "kdf": {"name":"argon2id", "memoryCost":1, "timeCost":1, "parallelism":1, "salt":""},
        "cipher": {"name":"aes-256-gcm", "iv":"", "authTag":"", "ciphertext":""},
        "createdAt":"now", "updatedAt":"now"
    });
    let api_without_metadata = serde_json::json!({
        "version": 2,
        "keyMode": "api-derived-v1",
        "kdf": {"name":"argon2id", "memoryCost":1, "timeCost":1, "parallelism":1, "salt":""},
        "cipher": {"name":"aes-256-gcm", "iv":"", "authTag":"", "ciphertext":""},
        "createdAt":"now", "updatedAt":"now"
    });

    assert!(serde_json::from_value::<VaultEnvelope>(local_with_api).is_err());
    assert!(serde_json::from_value::<VaultEnvelope>(api_without_metadata).is_err());
}

#[test]
fn api_response_key_material_must_be_exactly_32_bytes() {
    for material in [Vec::new(), vec![7; KEY_LEN - 1], vec![7; KEY_LEN + 1]] {
        let body = ApiDeriveResponse {
            version: 1,
            server_key_id: DEFAULT_SERVER_KEY_ID.to_string(),
            key_material: STANDARD.encode(material),
        };
        assert!(validate_api_response(body, DEFAULT_SERVER_KEY_ID).is_err());
    }

    let malformed = ApiDeriveResponse {
        version: 1,
        server_key_id: DEFAULT_SERVER_KEY_ID.to_string(),
        key_material: "not-base64".to_string(),
    };
    assert!(validate_api_response(malformed, DEFAULT_SERVER_KEY_ID).is_err());

    let valid = ApiDeriveResponse {
        version: 1,
        server_key_id: DEFAULT_SERVER_KEY_ID.to_string(),
        key_material: STANDARD.encode([7_u8; KEY_LEN]),
    };
    assert_eq!(
        validate_api_response(valid, DEFAULT_SERVER_KEY_ID).unwrap(),
        [7_u8; KEY_LEN]
    );
}

#[test]
fn api_response_version_and_server_key_id_must_match() {
    let wrong_version = ApiDeriveResponse {
        version: 2,
        server_key_id: DEFAULT_SERVER_KEY_ID.to_string(),
        key_material: STANDARD.encode([7_u8; KEY_LEN]),
    };
    let wrong_key_id = ApiDeriveResponse {
        version: 1,
        server_key_id: "other-key".to_string(),
        key_material: STANDARD.encode([7_u8; KEY_LEN]),
    };

    assert!(validate_api_response(wrong_version, DEFAULT_SERVER_KEY_ID).is_err());
    assert!(validate_api_response(wrong_key_id, DEFAULT_SERVER_KEY_ID).is_err());
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
fn reports_pin_strength_without_blocking_longer_values() {
    assert_eq!(pin_strength("1234"), PinStrength::Weak);
    assert_eq!(pin_strength("123456"), PinStrength::Better);
    assert_eq!(pin_strength("12345678"), PinStrength::Stronger);
    assert_eq!(pin_strength("correct horse"), PinStrength::Strong);

    let weak = pin_strength_message("1234");
    assert!(weak.contains("\x1b[31mweak\x1b[0m"));
    assert!(weak.contains("4 chars"));
    assert!(validate_new_passphrase("123456789012", "123456789012").is_ok());
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

    assert!(import_env_file(&source, &tempdir.path().join(".env.vault"), "passphrase").is_err());
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
