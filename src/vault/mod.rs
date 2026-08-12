use std::{
    env, fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, OnceLock},
};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::fs_util;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_DERIVATION_NONCE_LEN: usize = 32;
#[cfg(not(test))]
const DEFAULT_KEY_API_URL: &str = "https://api.aiward.dev/v1/vault-key/derive";
const DEFAULT_SERVER_KEY_ID: &str = "ward-api-derived-v1";
const API_HKDF_SALT: &[u8] = b"ward-api-derived-v1/hkdf";
const API_HKDF_INFO: &[u8] = b"ward-vault-aes-256-gcm";
pub(crate) const MIN_PIN_PASSPHRASE_LEN: usize = 4;

#[derive(Debug)]
struct IncorrectPassphrase;

impl std::fmt::Display for IncorrectPassphrase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("failed to decrypt vault; passphrase may be incorrect")
    }
}

impl std::error::Error for IncorrectPassphrase {}

pub fn is_incorrect_passphrase(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<IncorrectPassphrase>().is_some())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinStrength {
    Weak,
    Better,
    Stronger,
    Strong,
}

impl PinStrength {
    fn label(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Better => "better",
            Self::Stronger => "stronger",
            Self::Strong => "strong",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Self::Weak => "\x1b[31m",
            Self::Better => "\x1b[33m",
            Self::Stronger => "\x1b[36m",
            Self::Strong => "\x1b[32m",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VaultEnvelope {
    pub version: u32,
    key_derivation: VaultKeyDerivation,
    pub kdf: KdfEnvelope,
    pub cipher: CipherEnvelope,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
enum VaultKeyDerivation {
    LocalDerivedV1,
    ApiDerivedV1(ApiDerivedEnvelope),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultEnvelopeWire {
    version: u32,
    #[serde(default, skip_serializing_if = "VaultKeyMode::is_local_derived_v1")]
    key_mode: VaultKeyMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api: Option<ApiDerivedEnvelope>,
    kdf: KdfEnvelope,
    cipher: CipherEnvelope,
    created_at: String,
    updated_at: String,
}

impl VaultEnvelope {
    pub fn key_mode(&self) -> VaultKeyMode {
        match self.key_derivation {
            VaultKeyDerivation::LocalDerivedV1 => VaultKeyMode::LocalDerivedV1,
            VaultKeyDerivation::ApiDerivedV1(_) => VaultKeyMode::ApiDerivedV1,
        }
    }

    pub fn api_metadata(&self) -> Option<&ApiDerivedEnvelope> {
        match &self.key_derivation {
            VaultKeyDerivation::LocalDerivedV1 => None,
            VaultKeyDerivation::ApiDerivedV1(api) => Some(api),
        }
    }
}

impl TryFrom<VaultEnvelopeWire> for VaultEnvelope {
    type Error = anyhow::Error;

    fn try_from(wire: VaultEnvelopeWire) -> Result<Self> {
        let key_derivation = match (wire.key_mode, wire.api) {
            (VaultKeyMode::LocalDerivedV1, None) => VaultKeyDerivation::LocalDerivedV1,
            (VaultKeyMode::ApiDerivedV1, Some(api)) => VaultKeyDerivation::ApiDerivedV1(api),
            (VaultKeyMode::LocalDerivedV1, Some(_)) => {
                anyhow::bail!("local-derived vault must not contain API metadata")
            }
            (VaultKeyMode::ApiDerivedV1, None) => {
                anyhow::bail!("api-derived vault is missing API metadata")
            }
        };
        Ok(Self {
            version: wire.version,
            key_derivation,
            kdf: wire.kdf,
            cipher: wire.cipher,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        })
    }
}

impl From<&VaultEnvelope> for VaultEnvelopeWire {
    fn from(envelope: &VaultEnvelope) -> Self {
        Self {
            version: envelope.version,
            key_mode: envelope.key_mode(),
            api: envelope.api_metadata().cloned(),
            kdf: envelope.kdf.clone(),
            cipher: envelope.cipher.clone(),
            created_at: envelope.created_at.clone(),
            updated_at: envelope.updated_at.clone(),
        }
    }
}

impl Serialize for VaultEnvelope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        VaultEnvelopeWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VaultEnvelope {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        VaultEnvelopeWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultKeyMode {
    #[default]
    LocalDerivedV1,
    ApiDerivedV1,
}

impl VaultKeyMode {
    pub fn is_local_derived_v1(&self) -> bool {
        matches!(self, Self::LocalDerivedV1)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::LocalDerivedV1 => "local-derived-v1",
            Self::ApiDerivedV1 => "api-derived-v1",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiDerivedEnvelope {
    pub vault_id: String,
    pub key_derivation_nonce: String,
    pub server_key_id: String,
}

trait VaultKeyProvider {
    fn derive_server_material(
        &self,
        api: &ApiDerivedEnvelope,
        client_factor: &[u8; KEY_LEN],
        kdf: &KdfEnvelope,
    ) -> Result<[u8; KEY_LEN]>;
}

#[cfg(not(test))]
struct HttpKeyProvider;

#[cfg(not(test))]
impl VaultKeyProvider for HttpKeyProvider {
    fn derive_server_material(
        &self,
        api: &ApiDerivedEnvelope,
        client_factor: &[u8; KEY_LEN],
        kdf: &KdfEnvelope,
    ) -> Result<[u8; KEY_LEN]> {
        derive_api_server_material_http(api, client_factor, kdf)
    }
}

#[cfg(test)]
struct MockKeyProvider;

#[cfg(test)]
impl VaultKeyProvider for MockKeyProvider {
    fn derive_server_material(
        &self,
        api: &ApiDerivedEnvelope,
        client_factor: &[u8; KEY_LEN],
        _kdf: &KdfEnvelope,
    ) -> Result<[u8; KEY_LEN]> {
        let mut hasher = Sha256::new();
        hasher.update(b"ward-test-key-provider-v1");
        hasher.update(api.server_key_id.as_bytes());
        hasher.update(api.vault_id.as_bytes());
        hasher.update(api.key_derivation_nonce.as_bytes());
        hasher.update(client_factor);
        Ok(hasher.finalize().into())
    }
}

#[cfg(not(test))]
fn default_key_provider() -> impl VaultKeyProvider {
    HttpKeyProvider
}

#[cfg(test)]
fn default_key_provider() -> impl VaultKeyProvider {
    MockKeyProvider
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

include!("parts/crypto.rs");
include!("parts/files.rs");
include!("parts/provider.rs");

#[cfg(test)]
#[path = "../vault_tests.rs"]
mod tests;
