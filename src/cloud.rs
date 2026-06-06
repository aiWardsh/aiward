use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Response, Server, StatusCode};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    config::{self, AgentPolicyConfig, ProfileConfig, ProjectConfig},
    env_file, fs_util, logs, project_store, registry, term, vault,
};

const CLOUD_DB_VERSION: u32 = 1;
const DEFAULT_CLOUD_PORT: u16 = 8787;
const CLOUD_RUN_VERSION: &str = env!("CARGO_PKG_VERSION");
const LOCAL_AUTH_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CloudRole {
    Owner,
    Admin,
    Developer,
    Viewer,
}

impl std::fmt::Display for CloudRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Developer => "developer",
            Self::Viewer => "viewer",
        };
        write!(formatter, "{value}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDevInstance {
    pub pid: u32,
    pub port: u16,
    pub url: String,
    pub token: String,
    pub db: PathBuf,
    pub started_at: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDevInstanceSummary {
    pub pid: u32,
    pub port: u16,
    pub url: String,
    pub db: PathBuf,
    pub started_at: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudAuthSummary {
    pub cloud_url: String,
    pub account_email: String,
    pub account_name: String,
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDashboardStatus {
    pub db: PathBuf,
    pub db_exists: bool,
    pub running: bool,
    pub instance: Option<CloudDevInstanceSummary>,
    pub auth: Option<CloudAuthSummary>,
}

#[derive(Debug, Clone)]
pub struct CloudDevStartOptions {
    pub port: Option<u16>,
    pub db: Option<PathBuf>,
    pub foreground: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
pub struct CloudDevStopOptions {
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudAuthSession {
    pub cloud_url: String,
    pub account_email: String,
    pub account_name: String,
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub encrypted_private_key: vault::VaultEnvelope,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalCloudAuth {
    pub version: u32,
    pub sessions: Vec<CloudAuthSession>,
}

#[derive(Debug, Clone)]
pub struct AuthLoginOptions {
    pub cloud_url: String,
    pub email: String,
    pub name: Option<String>,
    pub device_name: Option<String>,
    pub pin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub email: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: String,
    pub account_email: String,
    pub name: String,
    pub public_key: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamView {
    pub id: String,
    pub name: String,
    pub owner_email: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub id: String,
    pub team_id: String,
    pub account_email: String,
    pub role: CloudRole,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudProjectView {
    pub id: String,
    pub team_id: String,
    pub name: String,
    pub source_project: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudEnvironmentView {
    pub id: String,
    pub team_id: String,
    pub team_name: String,
    pub project_id: String,
    pub project_name: String,
    pub name: String,
    pub env_names: Vec<String>,
    pub profile_names: Vec<String>,
    pub agent_names: Vec<String>,
    pub key_wrap_available: bool,
    pub rewrap_required: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudCatalog {
    pub account_email: String,
    pub device_id: String,
    pub teams: Vec<TeamView>,
    pub environments: Vec<CloudEnvironmentView>,
}

#[derive(Debug, Clone)]
pub struct CloudMemberInput {
    pub email: String,
    pub role: CloudRole,
}

#[derive(Debug, Clone)]
pub struct PublishEnvironmentOptions {
    pub db: PathBuf,
    pub cloud_url: String,
    pub owner: CloudAuthSession,
    pub owner_pin: String,
    pub source_project: String,
    pub source_path: PathBuf,
    pub source_vault: PathBuf,
    pub source_passphrase: String,
    pub team_name: String,
    pub project_name: String,
    pub environment_name: String,
    pub env_names: Vec<String>,
    pub profile_names: Vec<String>,
    pub agent_names: Vec<String>,
    pub members: Vec<CloudMemberInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedEnvironment {
    pub team: TeamView,
    pub project: CloudProjectView,
    pub environment: CloudEnvironmentView,
    pub wrapped_devices: usize,
    pub rewrap_required_members: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SetupLoginOptions {
    pub db: PathBuf,
    pub cloud_url: String,
    pub auth: CloudAuthSession,
    pub pin: String,
    pub target_dir: PathBuf,
    pub team: Option<String>,
    pub project: Option<String>,
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedCloudProject {
    pub local_project: String,
    pub team: String,
    pub project: String,
    pub environment: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub env_names: Vec<String>,
    pub profile_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudEnvironmentRecord {
    id: String,
    team_id: String,
    team_name: String,
    project_id: String,
    project_name: String,
    name: String,
    env_names: Vec<String>,
    profiles: BTreeMap<String, ProfileConfig>,
    agent_policies: BTreeMap<String, AgentPolicyConfig>,
    encrypted_payload: vault::VaultEnvelope,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudKeyWrap {
    id: String,
    environment_id: String,
    device_id: String,
    ephemeral_public_key: String,
    wrapped_data_key: vault::VaultEnvelope,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudAuditEvent {
    pub id: String,
    pub team_id: Option<String>,
    pub project_id: Option<String>,
    pub environment_id: Option<String>,
    pub actor_email: Option<String>,
    pub payload: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudDbMeta {
    version: u32,
}

pub fn default_cloud_url() -> String {
    format!("http://127.0.0.1:{DEFAULT_CLOUD_PORT}")
}

pub fn default_db_path() -> PathBuf {
    logs::ward_home()
        .join("cloud-dev")
        .join("ward-cloud.sqlite")
}

pub fn auth_path() -> PathBuf {
    logs::ward_home().join("cloud-dev").join("auth.json")
}

pub fn run_dir() -> PathBuf {
    logs::ward_home().join("run").join("cloud-dev")
}

fn instance_path() -> PathBuf {
    run_dir().join("instance.json")
}

pub fn cloud_url(port: u16, token: &str) -> String {
    format!("http://127.0.0.1:{port}/?token={token}")
}

pub fn init_db(path: &Path) -> Result<()> {
    fs_util::ensure_private_parent_dir(path)?;
    let conn =
        Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS accounts (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            account_email TEXT NOT NULL,
            name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(account_email) REFERENCES accounts(email)
        );
        CREATE TABLE IF NOT EXISTS teams (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            owner_email TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(owner_email) REFERENCES accounts(email)
        );
        CREATE TABLE IF NOT EXISTS members (
            id TEXT PRIMARY KEY,
            team_id TEXT NOT NULL,
            account_email TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(team_id, account_email),
            FOREIGN KEY(team_id) REFERENCES teams(id),
            FOREIGN KEY(account_email) REFERENCES accounts(email)
        );
        CREATE TABLE IF NOT EXISTS invites (
            id TEXT PRIMARY KEY,
            team_id TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            code TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(team_id) REFERENCES teams(id)
        );
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            team_id TEXT NOT NULL,
            name TEXT NOT NULL,
            source_project TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(team_id, name),
            FOREIGN KEY(team_id) REFERENCES teams(id)
        );
        CREATE TABLE IF NOT EXISTS environments (
            id TEXT PRIMARY KEY,
            team_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            name TEXT NOT NULL,
            env_names_json TEXT NOT NULL,
            profiles_json TEXT NOT NULL,
            agent_policies_json TEXT NOT NULL,
            encrypted_payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(project_id, name),
            FOREIGN KEY(team_id) REFERENCES teams(id),
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );
        CREATE TABLE IF NOT EXISTS key_wraps (
            id TEXT PRIMARY KEY,
            environment_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            ephemeral_public_key TEXT NOT NULL,
            wrapped_data_key_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(environment_id, device_id),
            FOREIGN KEY(environment_id) REFERENCES environments(id),
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            team_id TEXT,
            project_id TEXT,
            environment_id TEXT,
            actor_email TEXT,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        "#,
    )?;
    let meta = CloudDbMeta {
        version: CLOUD_DB_VERSION,
    };
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema', ?1)",
        [serde_json::to_string(&meta)?],
    )?;
    fs_util::set_private_file_permissions(path)?;
    Ok(())
}

fn connect(path: &Path) -> Result<Connection> {
    init_db(path)?;
    let conn =
        Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(conn)
}

pub fn login_account(options: AuthLoginOptions) -> Result<CloudAuthSession> {
    validate_email(&options.email)?;
    let db = cloud_db_for_url(&options.cloud_url);
    let conn = connect(&db)?;
    let now = now();
    let name = options
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&options.email)
        .to_string();
    conn.execute(
        "INSERT INTO accounts (email, name, created_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(email) DO UPDATE SET name=excluded.name",
        params![options.email, name, now],
    )?;

    let (private_key, public_key) = generate_device_keypair();
    let device_id = format!("device_{}", short_hash(&public_key));
    let device_name = options
        .device_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-device")
        .to_string();
    let public_key_b64 = STANDARD.encode(public_key);
    conn.execute(
        "INSERT INTO devices (id, account_email, name, public_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, public_key=excluded.public_key",
        params![device_id, options.email, device_name, public_key_b64, now],
    )?;

    let encrypted_private_key = vault::encrypt_env(&STANDARD.encode(private_key), &options.pin)?;
    let session = CloudAuthSession {
        cloud_url: options.cloud_url,
        account_email: options.email,
        account_name: name,
        device_id,
        device_name,
        public_key: public_key_b64,
        encrypted_private_key,
        created_at: now.clone(),
        updated_at: now,
    };
    save_auth_session(session.clone())?;
    Ok(session)
}

pub fn load_auth_session(cloud_url: &str) -> Result<CloudAuthSession> {
    let state = load_auth_state()?;
    state
        .sessions
        .into_iter()
        .find(|session| normalize_cloud_url(&session.cloud_url) == normalize_cloud_url(cloud_url))
        .with_context(|| {
            format!("not signed in to {cloud_url}; run ward auth login --cloud-url {cloud_url}")
        })
}

pub fn load_any_auth_session() -> Result<CloudAuthSession> {
    let state = load_auth_state()?;
    state
        .sessions
        .into_iter()
        .next()
        .context("not signed in; run ward auth login")
}

pub fn load_auth_state() -> Result<LocalCloudAuth> {
    let path = auth_path();
    if !path.exists() {
        return Ok(LocalCloudAuth {
            version: LOCAL_AUTH_VERSION,
            sessions: Vec::new(),
        });
    }
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn save_auth_session(session: CloudAuthSession) -> Result<()> {
    let mut state = load_auth_state()?;
    state.version = LOCAL_AUTH_VERSION;
    state.sessions.retain(|existing| {
        normalize_cloud_url(&existing.cloud_url) != normalize_cloud_url(&session.cloud_url)
    });
    state.sessions.push(session);
    let contents = serde_json::to_string_pretty(&state)?;
    fs_util::write_private_file(&auth_path(), format!("{contents}\n").as_bytes())
}

pub fn decrypt_device_private_key(session: &CloudAuthSession, pin: &str) -> Result<[u8; 32]> {
    let encoded = vault::decrypt_env(&session.encrypted_private_key, pin)
        .context("failed to unlock local device key with this PIN")?;
    let bytes = STANDARD
        .decode(encoded)
        .context("local device private key is not valid base64")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("local device private key has invalid length"))
}

pub fn publish_environment(options: PublishEnvironmentOptions) -> Result<PublishedEnvironment> {
    let owner_private_key = decrypt_device_private_key(&options.owner, &options.owner_pin)?;
    let owner_public_key = public_key_from_private(owner_private_key);
    if STANDARD.encode(owner_public_key) != options.owner.public_key {
        anyhow::bail!("local device key does not match signed-in device");
    }
    let selected_env = normalize_env_names(options.env_names)?;
    if selected_env.is_empty() {
        anyhow::bail!("at least one env name must be selected");
    }
    let selected_agents = normalize_identities(options.agent_names, "agent")?;
    let conn = connect(&options.db)?;
    ensure_account(
        &conn,
        &options.owner.account_email,
        &options.owner.account_name,
    )?;
    ensure_device(&conn, &options.owner)?;

    let team = ensure_team(&conn, &options.team_name, &options.owner.account_email)?;
    ensure_member(
        &conn,
        &team.id,
        &options.owner.account_email,
        CloudRole::Owner,
        "active",
    )?;
    for member in &options.members {
        validate_email(&member.email)?;
        ensure_account(&conn, &member.email, &member.email)?;
        ensure_member(
            &conn,
            &team.id,
            &member.email,
            member.role.clone(),
            "invited",
        )?;
        ensure_invite(&conn, &team.id, &member.email, member.role.clone())?;
    }
    let project = ensure_project(
        &conn,
        &team.id,
        &options.project_name,
        Some(&options.source_project),
    )?;

    let source_config = config::read_project_config(&options.source_path)?;
    let source_plaintext =
        vault::decrypt_vault_file(&options.source_vault, &options.source_passphrase)
            .context("failed to decrypt source project vault")?;
    let source_env = env_file::parse_env_map(&source_plaintext)?;
    let missing = selected_env
        .iter()
        .filter(|name| !source_env.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "source vault is missing selected env(s): {}",
            missing.join(", ")
        );
    }

    let selected_env_set = selected_env.iter().cloned().collect::<BTreeSet<_>>();
    let profile_names = normalize_profile_names(if options.profile_names.is_empty() {
        source_config.profiles.keys().cloned().collect()
    } else {
        options.profile_names
    })?;
    let mut profiles = BTreeMap::new();
    for profile_name in &profile_names {
        let mut profile = source_config
            .profiles
            .get(profile_name)
            .with_context(|| format!("profile {profile_name} does not exist"))?
            .clone();
        profile
            .env
            .retain(|env_name| selected_env_set.contains(env_name));
        profiles.insert(profile_name.clone(), profile);
    }
    let agent_policies = selected_agents
        .iter()
        .map(|agent| {
            (
                agent.clone(),
                AgentPolicyConfig {
                    profiles: profile_names.clone(),
                    env: selected_env.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let selected_plaintext = selected_env
        .iter()
        .filter_map(|name| {
            source_env
                .get(name)
                .map(|value| (name.clone(), value.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let selected_plaintext = env_file::serialize_env_map(&selected_plaintext);
    vault::validate_dotenv(&selected_plaintext)?;

    let data_key = random_secret();
    let encrypted_payload = vault::encrypt_env(&selected_plaintext, &data_key)?;
    let environment = upsert_environment(
        &conn,
        &team,
        &project,
        &options.environment_name,
        &selected_env,
        &profiles,
        &agent_policies,
        &encrypted_payload,
    )?;

    let mut wrapped_devices = 0usize;
    let mut rewrap_required_members = Vec::new();
    let member_emails = members_for_environment(&conn, &team.id)?;
    for email in member_emails {
        let devices = devices_for_account(&conn, &email)?;
        if devices.is_empty() {
            rewrap_required_members.push(email);
            continue;
        }
        for device in devices {
            let key_wrap = wrap_data_key(&data_key, &device.public_key)?;
            write_key_wrap(&conn, &environment.id, &device.id, &key_wrap)?;
            wrapped_devices += 1;
        }
    }

    let view = environment_view_for(
        &conn,
        &options.owner.account_email,
        &options.owner.device_id,
        &environment,
    )?;
    Ok(PublishedEnvironment {
        team,
        project,
        environment: view,
        wrapped_devices,
        rewrap_required_members,
    })
}

pub fn catalog(db: &Path, account_email: &str, device_id: &str) -> Result<CloudCatalog> {
    let conn = connect(db)?;
    let mut teams_stmt = conn.prepare(
        "SELECT t.id, t.name, t.owner_email, t.created_at
         FROM teams t
         JOIN members m ON m.team_id = t.id
         WHERE m.account_email = ?1
         ORDER BY t.name",
    )?;
    let teams = teams_stmt
        .query_map([account_email], team_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut env_stmt = conn.prepare(
        "SELECT e.id, e.team_id, t.name, e.project_id, p.name, e.name,
                e.env_names_json, e.profiles_json, e.agent_policies_json,
                e.encrypted_payload_json, e.updated_at
         FROM environments e
         JOIN teams t ON t.id = e.team_id
         JOIN projects p ON p.id = e.project_id
         JOIN members m ON m.team_id = e.team_id
         WHERE m.account_email = ?1
         ORDER BY t.name, p.name, e.name",
    )?;
    let records = env_stmt
        .query_map([account_email], environment_record_summary_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut environments = Vec::new();
    for record in records {
        environments.push(environment_view_for(
            &conn,
            account_email,
            device_id,
            &record,
        )?);
    }
    Ok(CloudCatalog {
        account_email: account_email.to_string(),
        device_id: device_id.to_string(),
        teams,
        environments,
    })
}

pub fn import_from_cloud(options: SetupLoginOptions) -> Result<ImportedCloudProject> {
    let conn = connect(&options.db)?;
    let catalog = catalog(
        &options.db,
        &options.auth.account_email,
        &options.auth.device_id,
    )?;
    let selected = select_environment(
        &catalog.environments,
        options.team.as_deref(),
        options.project.as_deref(),
        options.environment.as_deref(),
    )?;
    if !selected.key_wrap_available {
        anyhow::bail!(
            "owner/admin rewrap required before this device can import {} / {} / {}",
            selected.team_name,
            selected.project_name,
            selected.name
        );
    }

    let record = read_environment(&conn, &selected.id)?;
    let key_wrap = read_key_wrap(&conn, &record.id, &options.auth.device_id)?;
    let private_key = decrypt_device_private_key(&options.auth, &options.pin)?;
    let data_key = unwrap_data_key(private_key, &key_wrap)?;
    let plaintext = vault::decrypt_env(&record.encrypted_payload, &data_key)
        .context("failed to decrypt cloud environment bundle")?;
    vault::validate_dotenv(&plaintext)?;

    let local_project = local_project_name(&record.team_name, &record.project_name, &record.name);
    let vault_path = options.target_dir.join(config::DEFAULT_VAULT_FILE);
    let mut cfg = ProjectConfig::default_for_dir(&options.target_dir, Some(local_project.clone()))?;
    cfg.vault = PathBuf::from(config::DEFAULT_VAULT_FILE);
    cfg.profiles = record.profiles.clone();
    cfg.agent_policies = record.agent_policies.clone();
    config::write_project_config(&options.target_dir, &cfg, true)?;
    config::ensure_env_example(&options.target_dir)?;
    config::ensure_agent_instructions(&options.target_dir, &local_project)?;
    config::ensure_gitignore(&options.target_dir, true)?;
    let envelope = vault::encrypt_env(&plaintext, &options.pin)?;
    vault::write_vault(&vault_path, &envelope)?;
    env_file::lock_env_file(&options.target_dir.join(".env"), &vault_path)?;
    registry::update_project_vault(
        &local_project,
        options.target_dir.clone(),
        vault_path.clone(),
    )?;
    project_store::refresh_from_plaintext(
        &local_project,
        &options.target_dir,
        &vault_path,
        &cfg,
        &plaintext,
        &options.pin,
    )?;
    append_audit_event(
        &options.db,
        CloudAuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            team_id: Some(record.team_id.clone()),
            project_id: Some(record.project_id.clone()),
            environment_id: Some(record.id.clone()),
            actor_email: Some(options.auth.account_email.clone()),
            payload: json!({
                "type": "setup_login.imported",
                "project": local_project,
                "envNames": record.env_names,
                "profileNames": record.profiles.keys().cloned().collect::<Vec<_>>(),
            }),
            created_at: now(),
        },
    )?;

    Ok(ImportedCloudProject {
        local_project,
        team: record.team_name,
        project: record.project_name,
        environment: record.name,
        path: options.target_dir,
        vault: vault_path,
        env_names: record.env_names,
        profile_names: record.profiles.keys().cloned().collect(),
    })
}

pub fn append_audit_event(db: &Path, event: CloudAuditEvent) -> Result<()> {
    let conn = connect(db)?;
    let mut payload = event.payload;
    scrub_sensitive_json(&mut payload);
    conn.execute(
        "INSERT INTO audit_events
            (id, team_id, project_id, environment_id, actor_email, payload_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event.id,
            event.team_id,
            event.project_id,
            event.environment_id,
            event.actor_email,
            serde_json::to_string(&payload)?,
            event.created_at
        ],
    )?;
    Ok(())
}

pub fn sync_local_audit_event(kind: logs::LogKind, event: &Value) -> Result<()> {
    let db = default_db_path();
    if !db.is_file() {
        return Ok(());
    }
    let auth = load_any_auth_session().ok();
    let payload = json!({
        "type": "local.audit",
        "kind": kind.as_str(),
        "event": event,
    });
    append_audit_event(
        &db,
        CloudAuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            team_id: None,
            project_id: None,
            environment_id: None,
            actor_email: auth.as_ref().map(|session| session.account_email.clone()),
            payload,
            created_at: now(),
        },
    )
}

pub fn list_audit_events(db: &Path, team_id: Option<&str>) -> Result<Vec<CloudAuditEvent>> {
    let conn = connect(db)?;
    let mut events = Vec::new();
    if let Some(team_id) = team_id {
        let mut stmt = conn.prepare(
            "SELECT id, team_id, project_id, environment_id, actor_email, payload_json, created_at
             FROM audit_events WHERE team_id = ?1 ORDER BY created_at DESC LIMIT 500",
        )?;
        for row in stmt.query_map([team_id], audit_event_from_row)? {
            events.push(row?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, team_id, project_id, environment_id, actor_email, payload_json, created_at
             FROM audit_events ORDER BY created_at DESC LIMIT 500",
        )?;
        for row in stmt.query_map([], audit_event_from_row)? {
            events.push(row?);
        }
    }
    Ok(events)
}

pub fn list_teams(db: &Path) -> Result<Vec<TeamView>> {
    let conn = connect(db)?;
    let mut stmt =
        conn.prepare("SELECT id, name, owner_email, created_at FROM teams ORDER BY name")?;
    let teams = stmt
        .query_map([], team_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(teams)
}

pub fn dashboard_status() -> Result<CloudDashboardStatus> {
    cleanup_stale_instance()?;
    let db = default_db_path();
    let instance = read_instance().ok().map(CloudDevInstanceSummary::from);
    Ok(CloudDashboardStatus {
        db: db.clone(),
        db_exists: db.is_file(),
        running: instance.is_some(),
        instance,
        auth: load_any_auth_session().ok().map(CloudAuthSummary::from),
    })
}

pub fn start_dev_server(options: CloudDevStartOptions) -> Result<CloudDevInstance> {
    cleanup_stale_instance()?;
    let db = options.db.unwrap_or_else(default_db_path);
    init_db(&db)?;
    let port = options.port.unwrap_or(DEFAULT_CLOUD_PORT);
    let token = generate_token();
    let instance = CloudDevInstance {
        pid: std::process::id(),
        port,
        url: cloud_url(port, &token),
        token,
        db: db.clone(),
        started_at: now(),
        version: CLOUD_RUN_VERSION.to_string(),
    };
    if options.foreground {
        write_instance(&instance)?;
        print_instance(&instance, options.json, false)?;
        serve_blocking(port, instance.token.clone(), db)
    } else {
        let exe = std::env::current_exe().context("failed to resolve ward executable")?;
        let mut child = Command::new(exe)
            .arg("__cloud-dev-server")
            .arg("--port")
            .arg(port.to_string())
            .arg("--token")
            .arg(&instance.token)
            .arg("--db")
            .arg(&db)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to start Ward local cloud")?;
        let mut child_instance = instance;
        child_instance.pid = child.id();
        child_instance.url = cloud_url(port, &child_instance.token);
        for _ in 0..40 {
            if ping(port, &child_instance.token) {
                write_instance(&child_instance)?;
                print_instance(&child_instance, options.json, false)?;
                return Ok(child_instance);
            }
            if let Some(status) = child.try_wait()? {
                anyhow::bail!("Ward local cloud exited before ready: {status}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        anyhow::bail!("Ward local cloud did not become ready on port {port}");
    }?;
    Ok(instance)
}

impl From<CloudDevInstance> for CloudDevInstanceSummary {
    fn from(instance: CloudDevInstance) -> Self {
        Self {
            pid: instance.pid,
            port: instance.port,
            url: format!("http://127.0.0.1:{}", instance.port),
            db: instance.db,
            started_at: instance.started_at,
            version: instance.version,
        }
    }
}

impl From<CloudAuthSession> for CloudAuthSummary {
    fn from(session: CloudAuthSession) -> Self {
        Self {
            cloud_url: session.cloud_url,
            account_email: session.account_email,
            account_name: session.account_name,
            device_id: session.device_id,
            device_name: session.device_name,
            public_key: session.public_key,
            updated_at: session.updated_at,
        }
    }
}

pub fn serve_standalone(port: u16, token: String, db: PathBuf) -> Result<()> {
    init_db(&db)?;
    let instance = CloudDevInstance {
        pid: std::process::id(),
        port,
        url: cloud_url(port, &token),
        token: token.clone(),
        db: db.clone(),
        started_at: now(),
        version: CLOUD_RUN_VERSION.to_string(),
    };
    write_instance(&instance)?;
    serve_blocking(port, token, db)
}

pub fn stop_dev_server(options: CloudDevStopOptions) -> Result<()> {
    let Some(instance) = read_instance().ok() else {
        if options.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "stopped": 0 }))?
            );
        } else {
            term::emit_header(&term::Header {
                command: Some("cloud dev stop"),
                project: "local cloud",
                path: None,
                mode: None,
            });
            term::info("no local cloud instance running");
        }
        return Ok(());
    };
    terminate_process(instance.pid);
    let _ = fs::remove_file(instance_path());
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "stopped": 1, "pid": instance.pid }))?
        );
    } else {
        term::emit_header(&term::Header {
            command: Some("cloud dev stop"),
            project: "local cloud",
            path: Some(&instance.db),
            mode: None,
        });
        term::ok_detail("instance stopped", &format!("pid {}", instance.pid));
    }
    Ok(())
}

pub fn status(json_output: bool) -> Result<()> {
    cleanup_stale_instance()?;
    let instance = read_instance().ok();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&instance)?);
    } else if let Some(instance) = instance {
        term::emit_header(&term::Header {
            command: Some("cloud dev status"),
            project: "local cloud",
            path: Some(&instance.db),
            mode: None,
        });
        term::ok_detail("running", &instance.url);
        term::info_detail("pid", &instance.pid.to_string());
        term::info_detail("version", &instance.version);
    } else {
        term::emit_header(&term::Header {
            command: Some("cloud dev status"),
            project: "local cloud",
            path: None,
            mode: None,
        });
        term::info("no local cloud instance running");
        term::next("run: ward cloud dev start");
    }
    Ok(())
}

pub fn serve_blocking(port: u16, token: String, db: PathBuf) -> Result<()> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|error| anyhow::anyhow!("failed to bind local cloud server: {error}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = stop.clone();
    ctrlc::set_handler(move || {
        stop_for_handler.store(true, Ordering::SeqCst);
    })
    .ok();
    while !stop.load(Ordering::SeqCst) {
        match server.recv_timeout(Duration::from_millis(250)) {
            Ok(Some(req)) => handle_request(req, &token, &db),
            Ok(None) => {}
            Err(error) => return Err(anyhow::anyhow!("local cloud server failed: {error}")),
        }
    }
    Ok(())
}

fn handle_request(mut req: tiny_http::Request, token: &str, db: &Path) {
    let url = req.url().to_string();
    let (path, query) = split_path_query(&url);
    if path != "/health" && !authorized(&req, &query, token) {
        respond_json(
            req,
            StatusCode(401),
            &json!({ "error": "unauthorized", "message": "local cloud token required" }),
        );
        return;
    }
    match (req.method(), path.as_str()) {
        (Method::Get, "/health") => respond_json(req, StatusCode(200), &json!({ "ok": true })),
        (Method::Get, "/api/teams") => respond_json_result(req, list_teams(db)),
        (Method::Get, "/api/catalog") => {
            let account = query_param(&query, "accountEmail");
            let device = query_param(&query, "deviceId");
            let result = account
                .zip(device)
                .context("accountEmail and deviceId are required")
                .and_then(|(account, device)| catalog(db, &account, &device));
            respond_json_result(req, result);
        }
        (Method::Get, "/api/audit/events") => {
            let team = query_param(&query, "teamId");
            respond_json_result(req, list_audit_events(db, team.as_deref()));
        }
        (Method::Post, "/api/audit/events") => {
            let result: Result<()> = read_json_body::<CloudAuditEvent>(&mut req)
                .and_then(|event| append_audit_event(db, event));
            respond_json_result(req, result.map(|_| json!({ "ok": true })));
        }
        _ => respond_json(
            req,
            StatusCode(404),
            &json!({ "error": "not_found", "message": "unknown local cloud route" }),
        ),
    }
}

fn read_json_body<T: for<'de> Deserialize<'de>>(req: &mut tiny_http::Request) -> Result<T> {
    let mut body = String::new();
    req.as_reader()
        .read_to_string(&mut body)
        .context("failed to read request body")?;
    serde_json::from_str(&body).context("failed to parse request JSON")
}

fn respond_json_result<T: Serialize>(req: tiny_http::Request, result: Result<T>) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => respond_json(
            req,
            StatusCode(400),
            &json!({ "error": "cloud_error", "message": error.to_string() }),
        ),
    }
}

fn respond_json<T: Serialize>(req: tiny_http::Request, status: StatusCode, value: &T) {
    let body = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string());
    let response = Response::from_string(body)
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
    let _ = req.respond(response);
}

fn authorized(req: &tiny_http::Request, query: &str, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    if query_param(query, "token").as_deref() == Some(token) {
        return true;
    }
    req.headers().iter().any(|header| {
        let name = header.field.to_string();
        let value = header.value.as_str();
        (name.eq_ignore_ascii_case("authorization") && value == format!("Bearer {token}"))
            || (name.eq_ignore_ascii_case("x-ward-cloud-token") && value == token)
    })
}

fn ping(port: u16, token: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let request = format!(
        "GET /health?token={token} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok() && response.contains("200 OK")
}

fn print_instance(instance: &CloudDevInstance, json_output: bool, reused: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(instance)?);
    } else if reused {
        term::emit_header(&term::Header {
            command: Some("cloud dev start"),
            project: "local cloud",
            path: Some(&instance.db),
            mode: None,
        });
        term::ok_detail("already running", &instance.url);
        term::info_detail("pid", &instance.pid.to_string());
    } else {
        term::emit_header(&term::Header {
            command: Some("cloud dev start"),
            project: "local cloud",
            path: Some(&instance.db),
            mode: None,
        });
        term::ok_detail("running", &instance.url);
        term::info_detail("pid", &instance.pid.to_string());
    }
    Ok(())
}

fn write_instance(instance: &CloudDevInstance) -> Result<()> {
    fs_util::ensure_private_dir(&run_dir())?;
    let body = serde_json::to_string_pretty(instance)?;
    fs_util::write_private_file(&instance_path(), format!("{body}\n").as_bytes())
}

fn read_instance() -> Result<CloudDevInstance> {
    let contents = fs::read_to_string(instance_path())?;
    serde_json::from_str(&contents).context("failed to parse local cloud instance metadata")
}

fn cleanup_stale_instance() -> Result<()> {
    let Ok(instance) = read_instance() else {
        return Ok(());
    };
    if !process_exists(instance.pid) {
        let _ = fs::remove_file(instance_path());
    }
    Ok(())
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    // SAFETY: kill with signal 0 only checks process existence/permission.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_exists(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn terminate_process(pid: u32) {
    // SAFETY: best-effort termination of a process recorded in Ward run metadata.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

#[cfg(not(unix))]
fn terminate_process(_pid: u32) {}

fn ensure_account(conn: &Connection, email: &str, name: &str) -> Result<AccountView> {
    validate_email(email)?;
    let now = now();
    conn.execute(
        "INSERT INTO accounts (email, name, created_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(email) DO UPDATE SET name=excluded.name",
        params![email, name, now],
    )?;
    Ok(AccountView {
        email: email.to_string(),
        name: name.to_string(),
        created_at: now,
    })
}

fn ensure_device(conn: &Connection, session: &CloudAuthSession) -> Result<()> {
    conn.execute(
        "INSERT INTO devices (id, account_email, name, public_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, public_key=excluded.public_key",
        params![
            session.device_id,
            session.account_email,
            session.device_name,
            session.public_key,
            session.created_at
        ],
    )?;
    Ok(())
}

fn ensure_team(conn: &Connection, name: &str, owner_email: &str) -> Result<TeamView> {
    validate_cloud_name(name, "team")?;
    let existing = conn
        .query_row(
            "SELECT id, name, owner_email, created_at FROM teams WHERE name = ?1",
            [name],
            team_from_row,
        )
        .optional()?;
    if let Some(existing) = existing {
        return Ok(existing);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = now();
    conn.execute(
        "INSERT INTO teams (id, name, owner_email, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, name, owner_email, now],
    )?;
    Ok(TeamView {
        id,
        name: name.to_string(),
        owner_email: owner_email.to_string(),
        created_at: now,
    })
}

fn ensure_member(
    conn: &Connection,
    team_id: &str,
    email: &str,
    role: CloudRole,
    status: &str,
) -> Result<MemberView> {
    let id = format!(
        "member_{}",
        short_hash(format!("{team_id}:{email}").as_bytes())
    );
    let now = now();
    conn.execute(
        "INSERT INTO members (id, team_id, account_email, role, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(team_id, account_email) DO UPDATE SET role=excluded.role, status=excluded.status",
        params![id, team_id, email, role.to_string(), status, now],
    )?;
    Ok(MemberView {
        id,
        team_id: team_id.to_string(),
        account_email: email.to_string(),
        role,
        status: status.to_string(),
        created_at: now,
    })
}

fn ensure_invite(conn: &Connection, team_id: &str, email: &str, role: CloudRole) -> Result<()> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT id FROM invites WHERE team_id = ?1 AND email = ?2 AND status = 'pending'",
            params![team_id, email],
            |row| row.get(0),
        )
        .optional()?;
    if existing.is_some() {
        return Ok(());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let code = format!("invite_{}", random_token(12));
    conn.execute(
        "INSERT INTO invites (id, team_id, email, role, code, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
        params![id, team_id, email, role.to_string(), code, now()],
    )?;
    Ok(())
}

fn ensure_project(
    conn: &Connection,
    team_id: &str,
    name: &str,
    source_project: Option<&str>,
) -> Result<CloudProjectView> {
    validate_cloud_name(name, "project")?;
    let existing = conn
        .query_row(
            "SELECT id, team_id, name, source_project, created_at
             FROM projects WHERE team_id = ?1 AND name = ?2",
            params![team_id, name],
            project_from_row,
        )
        .optional()?;
    if let Some(existing) = existing {
        return Ok(existing);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = now();
    conn.execute(
        "INSERT INTO projects (id, team_id, name, source_project, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, team_id, name, source_project, now],
    )?;
    Ok(CloudProjectView {
        id,
        team_id: team_id.to_string(),
        name: name.to_string(),
        source_project: source_project.map(str::to_string),
        created_at: now,
    })
}

fn upsert_environment(
    conn: &Connection,
    team: &TeamView,
    project: &CloudProjectView,
    name: &str,
    env_names: &[String],
    profiles: &BTreeMap<String, ProfileConfig>,
    agent_policies: &BTreeMap<String, AgentPolicyConfig>,
    encrypted_payload: &vault::VaultEnvelope,
) -> Result<CloudEnvironmentRecord> {
    validate_cloud_name(name, "environment")?;
    let id = conn
        .query_row(
            "SELECT id FROM environments WHERE project_id = ?1 AND name = ?2",
            params![project.id, name],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let now = now();
    conn.execute(
        "INSERT INTO environments
            (id, team_id, project_id, name, env_names_json, profiles_json,
             agent_policies_json, encrypted_payload_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
         ON CONFLICT(project_id, name) DO UPDATE SET
            env_names_json=excluded.env_names_json,
            profiles_json=excluded.profiles_json,
            agent_policies_json=excluded.agent_policies_json,
            encrypted_payload_json=excluded.encrypted_payload_json,
            updated_at=excluded.updated_at",
        params![
            id,
            team.id,
            project.id,
            name,
            serde_json::to_string(env_names)?,
            serde_json::to_string(profiles)?,
            serde_json::to_string(agent_policies)?,
            serde_json::to_string(encrypted_payload)?,
            now,
        ],
    )?;
    Ok(CloudEnvironmentRecord {
        id,
        team_id: team.id.clone(),
        team_name: team.name.clone(),
        project_id: project.id.clone(),
        project_name: project.name.clone(),
        name: name.to_string(),
        env_names: env_names.to_vec(),
        profiles: profiles.clone(),
        agent_policies: agent_policies.clone(),
        encrypted_payload: encrypted_payload.clone(),
        updated_at: now,
    })
}

fn members_for_environment(conn: &Connection, team_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT account_email FROM members WHERE team_id = ?1 ORDER BY account_email")?;
    let members = stmt
        .query_map([team_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(members)
}

fn devices_for_account(conn: &Connection, email: &str) -> Result<Vec<DeviceView>> {
    let mut stmt = conn.prepare(
        "SELECT id, account_email, name, public_key, created_at
         FROM devices WHERE account_email = ?1 ORDER BY created_at",
    )?;
    let devices = stmt
        .query_map([email], device_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(devices)
}

fn write_key_wrap(
    conn: &Connection,
    environment_id: &str,
    device_id: &str,
    wrap: &CloudKeyWrap,
) -> Result<()> {
    conn.execute(
        "INSERT INTO key_wraps
            (id, environment_id, device_id, ephemeral_public_key, wrapped_data_key_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(environment_id, device_id) DO UPDATE SET
            ephemeral_public_key=excluded.ephemeral_public_key,
            wrapped_data_key_json=excluded.wrapped_data_key_json,
            created_at=excluded.created_at",
        params![
            wrap.id,
            environment_id,
            device_id,
            wrap.ephemeral_public_key,
            serde_json::to_string(&wrap.wrapped_data_key)?,
            wrap.created_at
        ],
    )?;
    Ok(())
}

fn read_key_wrap(conn: &Connection, environment_id: &str, device_id: &str) -> Result<CloudKeyWrap> {
    conn.query_row(
        "SELECT id, environment_id, device_id, ephemeral_public_key, wrapped_data_key_json, created_at
         FROM key_wraps WHERE environment_id = ?1 AND device_id = ?2",
        params![environment_id, device_id],
        key_wrap_from_row,
    )
    .optional()?
    .context("owner/admin rewrap required for this device")
}

fn read_environment(conn: &Connection, environment_id: &str) -> Result<CloudEnvironmentRecord> {
    conn.query_row(
        "SELECT e.id, e.team_id, t.name, e.project_id, p.name, e.name, e.env_names_json,
                e.profiles_json, e.agent_policies_json, e.encrypted_payload_json, e.updated_at
         FROM environments e
         JOIN teams t ON t.id = e.team_id
         JOIN projects p ON p.id = e.project_id
         WHERE e.id = ?1",
        [environment_id],
        full_environment_from_row,
    )
    .optional()?
    .context("cloud environment not found")
}

fn environment_view_for(
    conn: &Connection,
    _account_email: &str,
    device_id: &str,
    record: &CloudEnvironmentRecord,
) -> Result<CloudEnvironmentView> {
    let key_wrap_available: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM key_wraps WHERE environment_id = ?1 AND device_id = ?2)",
        params![record.id, device_id],
        |row| row.get(0),
    )?;
    let member_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM members WHERE team_id = ?1",
        [record.team_id.as_str()],
        |row| row.get(0),
    )?;
    let wrap_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM key_wraps WHERE environment_id = ?1",
        [record.id.as_str()],
        |row| row.get(0),
    )?;
    Ok(CloudEnvironmentView {
        id: record.id.clone(),
        team_id: record.team_id.clone(),
        team_name: record.team_name.clone(),
        project_id: record.project_id.clone(),
        project_name: record.project_name.clone(),
        name: record.name.clone(),
        env_names: record.env_names.clone(),
        profile_names: record.profiles.keys().cloned().collect(),
        agent_names: record.agent_policies.keys().cloned().collect(),
        key_wrap_available,
        rewrap_required: wrap_count < member_count,
        updated_at: record.updated_at.clone(),
    })
}

fn select_environment(
    environments: &[CloudEnvironmentView],
    team: Option<&str>,
    project: Option<&str>,
    environment: Option<&str>,
) -> Result<CloudEnvironmentView> {
    let matches = environments
        .iter()
        .filter(|candidate| {
            team.is_none_or(|value| candidate.team_name == value || candidate.team_id == value)
                && project.is_none_or(|value| {
                    candidate.project_name == value || candidate.project_id == value
                })
                && environment.is_none_or(|value| candidate.name == value || candidate.id == value)
        })
        .cloned()
        .collect::<Vec<_>>();
    match matches.len() {
        0 => anyhow::bail!("no accessible cloud environment matched the selection"),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => anyhow::bail!(
            "multiple cloud environments matched; pass --team, --project, and --environment"
        ),
    }
}

fn team_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamView> {
    Ok(TeamView {
        id: row.get(0)?,
        name: row.get(1)?,
        owner_email: row.get(2)?,
        created_at: row.get(3)?,
    })
}

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceView> {
    Ok(DeviceView {
        id: row.get(0)?,
        account_email: row.get(1)?,
        name: row.get(2)?,
        public_key: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn project_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CloudProjectView> {
    Ok(CloudProjectView {
        id: row.get(0)?,
        team_id: row.get(1)?,
        name: row.get(2)?,
        source_project: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn environment_record_summary_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CloudEnvironmentRecord> {
    let env_names: Vec<String> =
        serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_default();
    let profiles: BTreeMap<String, ProfileConfig> =
        serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default();
    let agent_policies: BTreeMap<String, AgentPolicyConfig> =
        serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or_default();
    let encrypted_payload: vault::VaultEnvelope = json_from_row(row, 9)?;
    Ok(CloudEnvironmentRecord {
        id: row.get(0)?,
        team_id: row.get(1)?,
        team_name: row.get(2)?,
        project_id: row.get(3)?,
        project_name: row.get(4)?,
        name: row.get(5)?,
        env_names,
        profiles,
        agent_policies,
        encrypted_payload,
        updated_at: row.get(10)?,
    })
}

fn full_environment_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CloudEnvironmentRecord> {
    let env_names: Vec<String> = json_from_row(row, 6)?;
    let profiles: BTreeMap<String, ProfileConfig> = json_from_row(row, 7)?;
    let agent_policies: BTreeMap<String, AgentPolicyConfig> = json_from_row(row, 8)?;
    let encrypted_payload: vault::VaultEnvelope = json_from_row(row, 9)?;
    Ok(CloudEnvironmentRecord {
        id: row.get(0)?,
        team_id: row.get(1)?,
        team_name: row.get(2)?,
        project_id: row.get(3)?,
        project_name: row.get(4)?,
        name: row.get(5)?,
        env_names,
        profiles,
        agent_policies,
        encrypted_payload,
        updated_at: row.get(10)?,
    })
}

fn key_wrap_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CloudKeyWrap> {
    Ok(CloudKeyWrap {
        id: row.get(0)?,
        environment_id: row.get(1)?,
        device_id: row.get(2)?,
        ephemeral_public_key: row.get(3)?,
        wrapped_data_key: json_from_row(row, 4)?,
        created_at: row.get(5)?,
    })
}

fn audit_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CloudAuditEvent> {
    let payload: Value = json_from_row(row, 5)?;
    Ok(CloudAuditEvent {
        id: row.get(0)?,
        team_id: row.get(1)?,
        project_id: row.get(2)?,
        environment_id: row.get(3)?,
        actor_email: row.get(4)?,
        payload,
        created_at: row.get(6)?,
    })
}

fn json_from_row<T: for<'de> Deserialize<'de>>(
    row: &rusqlite::Row<'_>,
    idx: usize,
) -> rusqlite::Result<T> {
    let text = row.get::<_, String>(idx)?;
    serde_json::from_str(&text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn wrap_data_key(data_key: &str, public_key_b64: &str) -> Result<CloudKeyWrap> {
    let public_key = decode_public_key(public_key_b64)?;
    let mut ephemeral_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut ephemeral_bytes);
    let ephemeral = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(public_key));
    let passphrase = shared_passphrase(shared.as_bytes());
    Ok(CloudKeyWrap {
        id: uuid::Uuid::new_v4().to_string(),
        environment_id: String::new(),
        device_id: String::new(),
        ephemeral_public_key: STANDARD.encode(ephemeral_public.as_bytes()),
        wrapped_data_key: vault::encrypt_env(data_key, &passphrase)?,
        created_at: now(),
    })
}

fn unwrap_data_key(private_key: [u8; 32], wrap: &CloudKeyWrap) -> Result<String> {
    let ephemeral_public = decode_public_key(&wrap.ephemeral_public_key)?;
    let private = StaticSecret::from(private_key);
    let shared = private.diffie_hellman(&PublicKey::from(ephemeral_public));
    let passphrase = shared_passphrase(shared.as_bytes());
    vault::decrypt_env(&wrap.wrapped_data_key, &passphrase)
        .context("failed to unwrap environment data key")
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(value)
        .context("public key is not valid base64")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key has invalid length"))
}

fn generate_device_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private = [0_u8; 32];
    OsRng.fill_bytes(&mut private);
    let public = public_key_from_private(private);
    (private, public)
}

fn public_key_from_private(private: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(private);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}

fn shared_passphrase(shared: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ward-cloud-key-wrap-v1");
    hasher.update(shared);
    hex::encode(hasher.finalize())
}

fn random_secret() -> String {
    STANDARD.encode(random_bytes_32())
}

fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn generate_token() -> String {
    random_token(24)
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    STANDARD
        .encode(value)
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(bytes)
        .collect()
}

fn normalize_env_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let name = name.trim();
        if !is_valid_env_name(name) {
            anyhow::bail!("invalid env name: {name}");
        }
        normalized.insert(name.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_profile_names(names: Vec<String>) -> Result<Vec<String>> {
    normalize_identities(names, "profile")
}

fn normalize_identities(values: Vec<String>, label: &str) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty()
            || value.len() > 128
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@' | ':'))
        {
            anyhow::bail!("invalid {label}: {value}");
        }
        normalized.insert(value.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn validate_email(email: &str) -> Result<()> {
    if email.len() > 254 || !email.contains('@') || email.contains(char::is_whitespace) {
        anyhow::bail!("invalid account email: {email}");
    }
    Ok(())
}

fn validate_cloud_name(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 96
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.' | ' '))
    {
        anyhow::bail!("invalid {label} name: {value}");
    }
    Ok(())
}

fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
}

fn local_project_name(team: &str, project: &str, environment: &str) -> String {
    format!(
        "{}:{}:{}",
        slug_segment(team),
        slug_segment(project),
        slug_segment(environment)
    )
}

fn slug_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn cloud_db_for_url(_cloud_url: &str) -> PathBuf {
    default_db_path()
}

fn normalize_cloud_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn scrub_sensitive_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if lower.contains("secret")
                    || lower.contains("passphrase")
                    || lower.contains("token")
                    || lower.contains("password")
                    || lower.contains("private")
                    || lower.contains("stdout")
                    || lower.contains("stderr")
                {
                    *value = Value::String("[redacted]".to_string());
                } else {
                    scrub_sensitive_json(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_sensitive_json(item);
            }
        }
        _ => {}
    }
}

fn split_path_query(url: &str) -> (String, String) {
    let mut parts = url.splitn(2, '?');
    (
        parts.next().unwrap_or("/").to_string(),
        parts.next().unwrap_or("").to_string(),
    )
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let key = url_decode(parts.next().unwrap_or(""));
        let value = url_decode(parts.next().unwrap_or(""));
        (key == name).then_some(value)
    })
}

fn url_decode(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.as_bytes().iter().copied();
    while let Some(ch) = chars.next() {
        match ch {
            b'+' => out.push(' '),
            b'%' => {
                let hi = chars.next();
                let lo = chars.next();
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    let hex = [hi, lo];
                    if let Ok(hex) = std::str::from_utf8(&hex) {
                        if let Ok(byte) = u8::from_str_radix(hex, 16) {
                            out.push(byte as char);
                            continue;
                        }
                    }
                }
                out.push('%');
            }
            _ => out.push(ch as char),
        }
    }
    out
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn short_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(&hasher.finalize()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct WardHomeGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl WardHomeGuard {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var_os("WARD_HOME");
            std::env::set_var("WARD_HOME", path);
            Self { previous }
        }
    }

    impl Drop for WardHomeGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("WARD_HOME", value),
                None => std::env::remove_var("WARD_HOME"),
            }
        }
    }

    #[test]
    #[serial]
    fn device_key_wrap_round_trips_and_rejects_other_device() {
        let (private, public) = generate_device_keypair();
        let wrap = wrap_data_key("data-key", &STANDARD.encode(public)).unwrap();
        assert_eq!(unwrap_data_key(private, &wrap).unwrap(), "data-key");

        let (other_private, _) = generate_device_keypair();
        assert!(unwrap_data_key(other_private, &wrap).is_err());
    }

    #[test]
    #[serial]
    fn cloud_db_stores_secret_bundle_without_plaintext_values() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let source = tempfile::tempdir().unwrap();
        let db = home.path().join("cloud.sqlite");
        let plaintext =
            "DATABASE_URL=postgres://secret\nPAYLOAD_SECRET=not-included-secret-value\n";
        let vault_path = source.path().join(".env.vault");
        let envelope = vault::encrypt_env(plaintext, "1234").unwrap();
        vault::write_vault(&vault_path, &envelope).unwrap();
        let mut cfg =
            config::ProjectConfig::default_for_dir(source.path(), Some("source".to_string()))
                .unwrap();
        cfg.profiles.get_mut("dev").unwrap().env = vec!["DATABASE_URL".to_string()];
        config::write_project_config(source.path(), &cfg, true).unwrap();

        let owner = login_account(AuthLoginOptions {
            cloud_url: default_cloud_url(),
            email: "owner@example.com".to_string(),
            name: None,
            device_name: None,
            pin: "1234".to_string(),
        })
        .unwrap();
        let published = publish_environment(PublishEnvironmentOptions {
            db: db.clone(),
            cloud_url: default_cloud_url(),
            owner,
            owner_pin: "1234".to_string(),
            source_project: "source".to_string(),
            source_path: source.path().to_path_buf(),
            source_vault: vault_path,
            source_passphrase: "1234".to_string(),
            team_name: "team".to_string(),
            project_name: "project".to_string(),
            environment_name: "development".to_string(),
            env_names: vec!["DATABASE_URL".to_string()],
            profile_names: vec!["dev".to_string()],
            agent_names: vec!["codex".to_string()],
            members: Vec::new(),
        })
        .unwrap();
        assert_eq!(published.wrapped_devices, 1);
        let db_contents = fs::read(&db).unwrap();
        let lossy = String::from_utf8_lossy(&db_contents);
        assert!(!lossy.contains("postgres://secret"));
        assert!(!lossy.contains("not-included-secret-value"));
    }

    #[test]
    #[serial]
    fn setup_login_imports_only_assigned_environment() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let db = home.path().join("cloud.sqlite");
        let plaintext = "DATABASE_URL=postgres://secret\nPAYLOAD_SECRET=payload\n";
        let vault_path = source.path().join(".env.vault");
        vault::write_vault(&vault_path, &vault::encrypt_env(plaintext, "1234").unwrap()).unwrap();
        let mut cfg =
            config::ProjectConfig::default_for_dir(source.path(), Some("source".to_string()))
                .unwrap();
        cfg.profiles.get_mut("dev").unwrap().env = vec!["DATABASE_URL".to_string()];
        config::write_project_config(source.path(), &cfg, true).unwrap();

        let owner = login_account(AuthLoginOptions {
            cloud_url: default_cloud_url(),
            email: "owner@example.com".to_string(),
            name: None,
            device_name: None,
            pin: "1234".to_string(),
        })
        .unwrap();
        publish_environment(PublishEnvironmentOptions {
            db: db.clone(),
            cloud_url: default_cloud_url(),
            owner: owner.clone(),
            owner_pin: "1234".to_string(),
            source_project: "source".to_string(),
            source_path: source.path().to_path_buf(),
            source_vault: vault_path,
            source_passphrase: "1234".to_string(),
            team_name: "team".to_string(),
            project_name: "project".to_string(),
            environment_name: "development".to_string(),
            env_names: vec!["DATABASE_URL".to_string()],
            profile_names: vec!["dev".to_string()],
            agent_names: vec!["codex".to_string()],
            members: Vec::new(),
        })
        .unwrap();

        let imported = import_from_cloud(SetupLoginOptions {
            db: db.clone(),
            cloud_url: default_cloud_url(),
            auth: owner,
            pin: "1234".to_string(),
            target_dir: target.path().to_path_buf(),
            team: Some("team".to_string()),
            project: Some("project".to_string()),
            environment: Some("development".to_string()),
        })
        .unwrap();
        assert_eq!(imported.env_names, vec!["DATABASE_URL"]);
        let decrypted = vault::decrypt_vault_file(&imported.vault, "1234").unwrap();
        assert!(decrypted.contains("DATABASE_URL=postgres://secret"));
        assert!(!decrypted.contains("PAYLOAD_SECRET"));
        let cfg = config::read_project_config(target.path()).unwrap();
        assert!(cfg.agent_policies.contains_key("codex"));
    }

    #[test]
    #[serial]
    fn audit_events_redact_sensitive_fields() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let db = home.path().join("cloud.sqlite");
        append_audit_event(
            &db,
            CloudAuditEvent {
                id: "event".to_string(),
                team_id: Some("team".to_string()),
                project_id: None,
                environment_id: None,
                actor_email: Some("dev@example.com".to_string()),
                payload: json!({
                    "command": "pnpm dev",
                    "stdout": "DATABASE_URL=postgres://secret",
                    "envNames": ["DATABASE_URL"]
                }),
                created_at: now(),
            },
        )
        .unwrap();
        let events = list_audit_events(&db, Some("team")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload["stdout"], "[redacted]");
        assert_eq!(events[0].payload["envNames"][0], "DATABASE_URL");
    }
}
