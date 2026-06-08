use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{fs_util, logs};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentState {
    #[serde(default)]
    pub projects: BTreeMap<String, Vec<AgentIdentity>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentity {
    pub agent_name: String,
    pub agent_key_id: String,
    pub public_key: String,
    pub private_seed: String,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProof {
    pub agent_name: String,
    pub agent_key_id: String,
    pub payload: String,
    pub signature: String,
}

pub fn agents_path() -> PathBuf {
    fs_util::resolve_ward_home_path(std::path::Path::new("agents.json"), "agents path")
        .expect("agents path should stay inside Ward home")
}

pub fn ensure_agent(project: &str, agent_name: &str) -> Result<AgentIdentity> {
    let mut state = load_agents()?;
    let agents = state.projects.entry(project.to_string()).or_default();
    if let Some(agent) = agents
        .iter_mut()
        .find(|agent| agent.agent_name == agent_name)
    {
        agent.last_used = Utc::now();
        let agent = agent.clone();
        save_agents(&state)?;
        return Ok(agent);
    }

    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let agent = AgentIdentity {
        agent_name: agent_name.to_string(),
        agent_key_id: key_id(&public_key),
        public_key: STANDARD.encode(public_key),
        private_seed: STANDARD.encode(seed),
        created_at: Utc::now(),
        last_used: Utc::now(),
    };
    seed.zeroize();
    agents.push(agent.clone());
    save_agents(&state)?;
    Ok(agent)
}

pub fn sign_payload(project: &str, agent_name: &str, payload: &str) -> Result<AgentProof> {
    let agent = ensure_agent(project, agent_name)?;
    let mut seed = STANDARD
        .decode(&agent.private_seed)
        .context("agent private seed is not valid base64")?;
    let seed_array = <[u8; 32]>::try_from(seed.as_slice())
        .map_err(|_| anyhow::anyhow!("agent private seed has invalid length"))?;
    let signing_key = SigningKey::from_bytes(&seed_array);
    let signature = signing_key.sign(payload.as_bytes());
    seed.zeroize();
    Ok(AgentProof {
        agent_name: agent.agent_name,
        agent_key_id: agent.agent_key_id,
        payload: payload.to_string(),
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

pub fn verify_proof(project: &str, proof: &AgentProof) -> Result<bool> {
    let state = load_agents()?;
    let Some(agent) = state.projects.get(project).and_then(|agents| {
        agents.iter().find(|agent| {
            agent.agent_name == proof.agent_name && agent.agent_key_id == proof.agent_key_id
        })
    }) else {
        return Ok(false);
    };
    let public_key = STANDARD
        .decode(&agent.public_key)
        .context("agent public key is not valid base64")?;
    let public_key = <[u8; 32]>::try_from(public_key.as_slice())
        .map_err(|_| anyhow::anyhow!("agent public key has invalid length"))?;
    let signature = STANDARD
        .decode(&proof.signature)
        .context("agent signature is not valid base64")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)?;
    let signature = Signature::try_from(signature.as_slice())?;
    Ok(verifying_key
        .verify(proof.payload.as_bytes(), &signature)
        .is_ok())
}

pub fn load_agents() -> Result<AgentState> {
    let path = agents_path();
    if !path.exists() {
        return Ok(AgentState::default());
    }
    let contents =
        std::fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).context(format!("failed to parse {}", path.display()))
}

pub fn save_agents(state: &AgentState) -> Result<()> {
    fs_util::ensure_private_dir(&logs::ward_home())?;
    let contents = serde_json::to_string_pretty(state).expect("agent state should serialize");
    fs_util::write_private_file(&agents_path(), format!("{contents}\n").as_bytes())
}

fn key_id(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    format!("agent:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    #[serial]
    fn agent_identity_signs_and_verifies_payloads() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let first = ensure_agent("demo", "codex").unwrap();
        let second = ensure_agent("demo", "codex").unwrap();
        assert_eq!(first.agent_key_id, second.agent_key_id);

        let proof = sign_payload("demo", "codex", "payload").unwrap();
        assert!(verify_proof("demo", &proof).unwrap());
        let mut bad = proof.clone();
        bad.payload = "changed".to_string();
        assert!(!verify_proof("demo", &bad).unwrap());
        assert!(!verify_proof("other", &proof).unwrap());
        let mut missing_agent = proof.clone();
        missing_agent.agent_name = "claude".to_string();
        assert!(!verify_proof("demo", &missing_agent).unwrap());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn agent_state_reports_invalid_files() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::fs::create_dir_all(home.path()).unwrap();
        std::fs::write(agents_path(), "{bad-json}").unwrap();
        assert!(load_agents().is_err());
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn agent_signing_reports_invalid_key_lengths() {
        let _guard = env_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let proof = sign_payload("demo", "codex", "payload").unwrap();
        let mut state = load_agents().unwrap();
        let agent = state
            .projects
            .get_mut("demo")
            .unwrap()
            .iter_mut()
            .find(|agent| agent.agent_name == "codex")
            .unwrap();
        agent.private_seed = STANDARD.encode([1_u8, 2, 3]);
        save_agents(&state).unwrap();
        assert!(sign_payload("demo", "codex", "payload").is_err());

        let mut state = load_agents().unwrap();
        let agent = state
            .projects
            .get_mut("demo")
            .unwrap()
            .iter_mut()
            .find(|agent| agent.agent_name == "codex")
            .unwrap();
        agent.private_seed = STANDARD.encode([7_u8; 32]);
        agent.public_key = STANDARD.encode([1_u8, 2, 3]);
        save_agents(&state).unwrap();
        assert!(verify_proof("demo", &proof).is_err());

        std::env::remove_var("WARD_HOME");
    }
}
