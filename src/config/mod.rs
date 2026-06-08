use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{approvals::ApprovalScope, fs_util, policy::ApprovalMode, vault};

pub const PROJECT_CONFIG_FILE: &str = ".ward.json";
pub const WARD_JSON_GITIGNORE_ENTRY: &str = ".ward.json";
pub const DEFAULT_VAULT_FILE: &str = ".env.vault";
pub const AGENT_INSTRUCTIONS_FILE: &str = "AGENTS.md";
pub const CLAUDE_INSTRUCTIONS_FILE: &str = "CLAUDE.md";
pub const CONFIG_BACKUP_DIR: &str = "config-backups";
const CONFIG_BACKUP_VERSION: u32 = 1;

const ENV_EXAMPLE_HEADER: &str = "# Ward managed environment.\n# Plaintext .env files should not be committed or shared with AI agents.\n# Agents should request scoped access with ward request, then run approved commands with ward run.\n\n";
pub const AGENT_INSTRUCTIONS_MARKER: &str = "<!-- ward-agent-instructions -->";

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum StorageMode {
    #[default]
    VaultFile,
    Keychain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfig {
    pub version: u32,
    pub project: String,
    pub vault: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<PresetConfig>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agent_policies: BTreeMap<String, AgentPolicyConfig>,
    #[serde(default = "default_anomaly_detection")]
    pub anomaly_detection: AnomalyDetectionConfig,
    #[serde(default)]
    pub storage_mode: StorageMode,
    /// Random hex nonce used to derive the vault filename. Regenerated on each rotation.
    #[serde(default)]
    pub vault_nonce: String,
    /// Whether the user has exported a recovery backup.
    #[serde(default)]
    pub backup_exported: bool,
    /// Whether a recovery key has been created for this project.
    #[serde(default)]
    pub recovery_created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetConfig {
    pub name: String,
    #[serde(rename = "match")]
    pub match_commands: Vec<String>,
    pub allowed_env: Vec<String>,
    pub approval: ApprovalMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConfig {
    pub command: String,
    pub env: Vec<String>,
    pub default_scope: ApprovalScope,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentPolicyConfig {
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyDetectionConfig {
    pub enabled: bool,
    pub working_hours_start: u8,
    pub working_hours_end: u8,
    pub max_runs_per_hour_per_grant: usize,
    pub max_branches_per_grant: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfigBackup {
    pub version: u32,
    pub project: String,
    pub project_path: PathBuf,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub updated_at: String,
    pub config: ProjectConfig,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfigRestore {
    pub project: String,
    pub project_path: PathBuf,
    pub config_path: PathBuf,
    pub backup_path: PathBuf,
    pub updated_at: String,
}

impl ProjectConfig {
    pub fn default_for_dir(cwd: &Path, project: Option<String>) -> Result<Self> {
        let project = match project {
            Some(project) => project,
            None => cwd
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
                .context("could not infer project name from current directory")?,
        };

        let profiles = default_profiles(&default_env_keys(), cwd);

        Ok(Self {
            version: 1,
            project,
            vault: PathBuf::from(DEFAULT_VAULT_FILE),
            presets: Vec::new(),
            profiles,
            agent_policies: BTreeMap::new(),
            anomaly_detection: default_anomaly_detection(),
            storage_mode: StorageMode::VaultFile,
            vault_nonce: vault::generate_vault_nonce(),
            backup_exported: false,
            recovery_created: false,
        })
    }
}

pub fn config_path(cwd: &Path) -> PathBuf {
    cwd.join(PROJECT_CONFIG_FILE)
}

pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    for dir in cwd.ancestors() {
        if config_path(dir).is_file() {
            return Some(dir.to_path_buf());
        }
        if is_project_search_boundary(dir) {
            return None;
        }
    }
    None
}

fn is_project_search_boundary(dir: &Path) -> bool {
    dir.join(".git").exists()
        || dir.join("pnpm-workspace.yaml").is_file()
        || dir.join("turbo.json").is_file()
        || package_json_has_workspaces(dir)
}

pub fn read_project_config(cwd: &Path) -> Result<ProjectConfig> {
    let path = config_path(cwd);
    let contents = fs_util::read_file_to_string(&path, "project config")?;
    let mut config: ProjectConfig =
        serde_json::from_str(&contents).context(format!("failed to parse {}", path.display()))?;
    // Backward compat: populate nonce for legacy configs that have none.
    if config.vault_nonce.is_empty() {
        config.vault_nonce = vault::generate_vault_nonce();
    }
    validate_project_config_paths(cwd, &config)?;
    Ok(config)
}

pub fn write_project_config(cwd: &Path, config: &ProjectConfig, force: bool) -> Result<PathBuf> {
    let path = config_path(cwd);
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }

    validate_project_config_paths(cwd, config)?;
    let contents = serde_json::to_string_pretty(config)?;
    fs::write(&path, format!("{contents}\n"))
        .context(format!("failed to write {}", path.display()))?;
    maybe_write_project_config_backup(cwd, config, &contents);
    Ok(path)
}

pub fn config_backups_dir() -> PathBuf {
    fs_util::resolve_ward_home_path(Path::new(CONFIG_BACKUP_DIR), "config backup directory")
        .expect("config backup directory should stay inside Ward home")
}

pub fn config_backup_path(project: &str) -> PathBuf {
    let relative = PathBuf::from(CONFIG_BACKUP_DIR).join(format!("{}.json", slugify(project)));
    fs_util::resolve_ward_home_path(&relative, "config backup path")
        .expect("config backup path should stay inside Ward home")
}

pub fn read_project_config_backup(project: &str) -> Result<ProjectConfigBackup> {
    let path = config_backup_path(project);
    let contents = fs_util::read_file_to_string(&path, "project config backup")?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn find_project_config_backup_for_path(
    cwd: &Path,
) -> Result<Option<(PathBuf, ProjectConfigBackup)>> {
    let dir = config_backups_dir();
    if !dir.exists() {
        return Ok(None);
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(contents) = fs_util::read_file_to_string(&path, "project config backup") else {
            continue;
        };
        let Ok(backup) = serde_json::from_str::<ProjectConfigBackup>(&contents) else {
            continue;
        };
        if same_path(&backup.project_path, cwd) {
            matches.push((path, backup));
        }
    }

    matches.sort_by(|(_, left), (_, right)| right.updated_at.cmp(&left.updated_at));
    Ok(matches.into_iter().next())
}

pub fn restore_project_config_from_backup(
    cwd: &Path,
    force: bool,
) -> Result<Option<ProjectConfigRestore>> {
    let config_path = config_path(cwd);
    if config_path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            config_path.display()
        );
    }

    let Some((backup_path, backup)) = find_project_config_backup_for_path(cwd)? else {
        return Ok(None);
    };

    let contents = serde_json::to_string_pretty(&backup.config)?;
    let hash = sha256_hex(contents.as_bytes());
    if hash != backup.config_sha256 {
        anyhow::bail!(
            "config backup checksum mismatch for {}; refusing to restore",
            backup.project
        );
    }

    fs::write(&config_path, format!("{contents}\n"))
        .context(format!("failed to write {}", config_path.display()))?;
    maybe_write_project_config_backup(cwd, &backup.config, &contents);
    Ok(Some(ProjectConfigRestore {
        project: backup.project,
        project_path: cwd.to_path_buf(),
        config_path,
        backup_path,
        updated_at: backup.updated_at,
    }))
}

fn maybe_write_project_config_backup(cwd: &Path, config: &ProjectConfig, contents: &str) {
    if cfg!(test) && std::env::var_os("WARD_HOME").is_none() {
        return;
    }
    let _ = write_project_config_backup(cwd, config, contents);
}

fn write_project_config_backup(
    cwd: &Path,
    config: &ProjectConfig,
    contents: &str,
) -> Result<PathBuf> {
    let project_path = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let backup = ProjectConfigBackup {
        version: CONFIG_BACKUP_VERSION,
        project: config.project.clone(),
        project_path: project_path.clone(),
        config_path: project_path.join(PROJECT_CONFIG_FILE),
        config_sha256: sha256_hex(contents.as_bytes()),
        updated_at: chrono::Utc::now().to_rfc3339(),
        config: config.clone(),
    };
    let backup_path = config_backup_path(&backup.project);
    let backup_contents = serde_json::to_string_pretty(&backup)?;
    fs_util::write_private_file(&backup_path, format!("{backup_contents}\n").as_bytes())?;
    Ok(backup_path)
}

pub fn env_keys_from_dotenv_file(path: &Path) -> Result<Vec<String>> {
    let iter =
        dotenvy::from_path_iter(path).context(format!("failed to parse {}", path.display()))?;
    env_keys_from_dotenv_iter(iter, &path.display().to_string())
}

pub fn env_keys_from_dotenv_str(contents: &str) -> Result<Vec<String>> {
    let iter = dotenvy::from_read_iter(std::io::Cursor::new(contents.as_bytes()));
    env_keys_from_dotenv_iter(iter, "dotenv contents")
}

fn env_keys_from_dotenv_iter<I, E>(iter: I, label: &str) -> Result<Vec<String>>
where
    I: IntoIterator<Item = Result<(String, String), E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut keys = BTreeSet::new();
    for item in iter {
        let (key, _) = item.context(format!("failed to parse {label}"))?;
        keys.insert(key);
    }
    Ok(keys.into_iter().collect())
}

pub fn default_profiles(env_keys: &[String], cwd: &Path) -> BTreeMap<String, ProfileConfig> {
    let commands = detected_commands(cwd);
    let env = env_keys.iter().cloned().collect::<BTreeSet<_>>();
    let known = |name: &str| env.contains(name);

    let mut dev_env = Vec::new();
    for name in ["DATABASE_URL", "DATABASE_URI", "PAYLOAD_SECRET"] {
        if known(name) {
            dev_env.push(name.to_string());
        }
    }
    dev_env.extend(
        env.iter()
            .filter(|name| name.starts_with("NEXT_PUBLIC_"))
            .cloned(),
    );
    let mut migrate_env = Vec::new();
    for name in ["DATABASE_URL", "DATABASE_URI", "PAYLOAD_SECRET"] {
        if known(name) {
            migrate_env.push(name.to_string());
        }
    }

    BTreeMap::from([
        (
            "dev".to_string(),
            ProfileConfig {
                command: commands.dev,
                env: dev_env,
                default_scope: ApprovalScope::Always,
                action: "Run development server".to_string(),
            },
        ),
        (
            "migrate".to_string(),
            ProfileConfig {
                command: commands.migrate,
                env: migrate_env,
                default_scope: ApprovalScope::Branch,
                action: "Run Payload migration".to_string(),
            },
        ),
    ])
}

pub fn merge_default_profiles(config: &mut ProjectConfig, env_keys: &[String], cwd: &Path) {
    for (name, profile) in default_profiles(env_keys, cwd) {
        config.profiles.entry(name).or_insert(profile);
    }
}

pub fn replace_default_profiles(config: &mut ProjectConfig, env_keys: &[String], cwd: &Path) {
    for (name, profile) in default_profiles(env_keys, cwd) {
        config.profiles.insert(name, profile);
    }
}

pub fn ensure_gitignore(cwd: &Path, commit_vault: bool) -> Result<PathBuf> {
    let path = fs_util::resolve_project_path(cwd, Path::new(".gitignore"), ".gitignore path")?;
    let existing = if path.exists() {
        fs_util::read_file_to_string(&path, ".gitignore")?
    } else {
        String::new()
    };

    let vault_exception = format!("!{DEFAULT_VAULT_FILE}");
    let mut lines = existing
        .lines()
        .filter(|line| commit_vault || line.trim() != vault_exception)
        .map(str::to_string)
        .collect::<Vec<_>>();

    append_gitignore_line(&mut lines, ".env");
    append_gitignore_line(&mut lines, ".env.*");
    append_gitignore_line(&mut lines, WARD_JSON_GITIGNORE_ENTRY);
    if commit_vault {
        append_gitignore_line(&mut lines, &format!("!{DEFAULT_VAULT_FILE}"));
    }

    let mut contents = lines.join("\n");
    if !contents.is_empty() {
        contents.push('\n');
    }
    fs::write(&path, contents).context(format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn ensure_env_example(cwd: &Path) -> Result<Option<PathBuf>> {
    let path = fs_util::resolve_project_path(cwd, Path::new(".env.example"), ".env.example path")?;
    if path.exists() {
        let contents = fs_util::read_file_to_string(&path, ".env.example")?;
        if contents.contains("Ward managed environment") {
            return Ok(None);
        }

        fs::write(&path, format!("{ENV_EXAMPLE_HEADER}{contents}"))
            .context(format!("failed to write {}", path.display()))?;
        return Ok(Some(path));
    }

    fs::write(
        &path,
        format!("{ENV_EXAMPLE_HEADER}# Add non-secret env names here.\n"),
    )
    .context(format!("failed to write {}", path.display()))?;
    Ok(Some(path))
}

pub fn ensure_agent_instructions(cwd: &Path, project: &str) -> Result<Option<PathBuf>> {
    let claude_path = fs_util::resolve_project_path(
        cwd,
        Path::new(CLAUDE_INSTRUCTIONS_FILE),
        "Claude instructions path",
    )?;
    let path = if claude_path.exists() {
        claude_path
    } else {
        fs_util::resolve_project_path(
            cwd,
            Path::new(AGENT_INSTRUCTIONS_FILE),
            "agent instructions path",
        )?
    };
    let section = agent_instructions_section(project);

    if path.exists() {
        let contents = fs_util::read_file_to_string(&path, "agent instructions")?;
        if contents.contains(AGENT_INSTRUCTIONS_MARKER) {
            return Ok(None);
        }

        let separator = if contents.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        fs::write(&path, format!("{contents}{separator}{section}"))
            .context(format!("failed to write {}", path.display()))?;
        return Ok(Some(path));
    }

    fs::write(&path, section).context(format!("failed to write {}", path.display()))?;
    Ok(Some(path))
}

fn agent_instructions_section(project: &str) -> String {
    format!(
        r#"{AGENT_INSTRUCTIONS_MARKER}
# Ward Secret Access

This repository uses Ward for local secret access. Do not read, print, copy,
or modify plaintext `.env` files. Request only the env vars needed for the
declared command.

Project: {project}

Use profiles where available:

```bash
ward request --app <app-name> --profile dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward run --app <app-name> --profile dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --wait-for-approval --approval-timeout 30m --json --no-prompt
ward dev --app <app-name> --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward migrate --app <app-name> --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
```

Profiles are the user-facing command layer. They map a short name such as
`dev` or `migrate` to one command and exact env names. Presets may be added to
`.ward.json` as lower-level policy rules for raw command matching and
approval behavior; prefer profiles unless a profile does not exist.
Profile commands run from the resolved Ward project/app directory. In a
monorepo app, do not prefix profile command paths with the workspace root or
the app folder name.

Agent runs outside human mode must identify themselves with `--agent
<agent-name>`. Ward rejects anonymous `run`, `request`, and `allow` calls so
logs and grants stay tied to an agent identity.

No-prompt agent calls must always send full context up front: `--agent`,
`--worktree`, `--branch`, `--git-remote`, `--commit`, and either `--profile`
or an exact `--command` plus exact `--env` names. Use `--action` with raw
commands; profile action/env scope is inherited from `.ward.json` unless Ward
explicitly asks for an override. Do not wait for Ward to ask follow-up
questions. Ward verifies the claimed branch, remote, commit, and worktree path
locally before creating or reusing approvals.
For repositories with no `origin` remote, pass `--git-remote ""` explicitly.
In monorepos, `--worktree` must be the Git top-level path from
`git rev-parse --show-toplevel`, not the child app folder, even when the Ward
project lives inside `apps/<name>`.
If the workspace root has multiple Ward projects, pass `--app <app-name>` or
`--project <project-name>` on every agent request/run.
Human mode is per app in monorepos. Tell the user to run `ward human` from the
app folder they are working in, or `ward human --app <app-name>` from the
workspace root. If they need multiple app terminals, they should activate human
mode separately in each one.

`--profile` is mutually exclusive with `--command` and `--env`. For `ward run`,
you may append extra child args after `--`, for example
`ward run --profile seed -- --dry-run`; Ward audits and approves the expanded
profile command. All Ward flags must still appear before `--`.

For commands that should continue after a human approval, prefer
`ward run --wait-for-approval --approval-timeout 30m --json --no-prompt`.
Ward will create a dashboard notification and keep the original process alive
until the request is approved, denied, unlocked, or timed out. Do not end the
task just because Ward is waiting.
Lower-level request/wait flows can use `ward approvals wait <request-id>
--json --timeout 30m` after surfacing the approval choice to the user. This is
a passive wait primitive only; it cannot approve, deny, sign, or mutate grants.

Manual request template:

```bash
ward request \
  --agent <agent-name> \
  --worktree <absolute-path> \
  --branch <branch-name> \
  --git-remote <remote-url-or-empty> \
  --commit <sha> \
  --action "<why this command needs secrets>" \
  --command "<exact command to run>" \
  --env <ENV_NAME> \
  --json \
  --no-prompt
```

If a no-prompt command returns `"approvalRequired": true`, show
`approvalOptions`, `approveCommands`, `denyCommand`, and all `findings` to the
user as explicit choices. Use native structured choice UI when your agent
interface supports it; do not present approval choices as loose prose when
buttons, selectors, or typed choice prompts are available. If your structured
choice UI has a 4-option limit, present the approval scopes in the picker and
show `denyCommand` as a separate explicit denial action. Do not run
`approveCommands` or `denyCommand` yourself; they are human-terminal fallback
commands and Ward requires local confirmation before they mutate trust state.

If a no-prompt command returns `"status": "worktree_approval_required"` or
`"approvalType": "worktreeBinding"`, show the worktree binding as a structured
approve/deny choice. This approval trusts the exact checkout path, branch,
commit, and remote for this Ward project; it is not a normal secret grant.
Display `project`, `worktree`, `gitRemote`, `branch`, `commit`, and `reason`,
then present `approvalOptions` when available. If your interface cannot render
those options directly, present two explicit choices using `approveCommand` and
`denyCommand`. Do not run either command until the user chooses approve or deny.

Surface `action.*` findings before asking for approval. They mean the declared
action text may include prompt-injection, approval-coercion, or secret-exposure
language.

Agents must never run `ward approve`, `ward deny`, `ward allow`, or
`ward worktrees approve`. Those commands mutate trust state and are human-only
fallbacks. After surfacing the request, wait for dashboard or human-terminal
approval instead:

```bash
ward approvals wait <request-id> --json
```

Approvals are signed by the broker after dashboard approval or a local human
terminal fallback. If approval reports `"status": "unlock_required"` or
`signing_key_unavailable`, ask the user to run `ward unlock --ttl 8h` and then
approve from the dashboard or terminal. Never ask the user for the PIN/passphrase
directly.
Agents cannot create approval authority by running another Ward command. The
broker rechecks the final execution against broker-held approval records or a
valid durable broker-signed grant before decrypting envs.

If a no-prompt command returns `"unlockRequired": true`, ask the user to run:

```bash
ward unlock --ttl 8h
```

This usually means the init/setup-created unlock expired, setup was run with
`--no-unlock`, or the user explicitly ran `ward lock`.

If a no-prompt command returns `"status": "vault_key_missing"`, do not ask the
user to unlock again. The broker is already reachable, but the approved profile
or command requested an env var that is not present in `.env.vault`. Surface
`missingEnv`. If the command should use a profile, ask the user to add or update
a profile that includes the command and env name. If the key is truly missing
from the vault, ask the user to run `ward env unlock`, add the key, then run
`ward env lock`; agents may run `ward env request-set --key <ENV_NAME>
--wait-for-approval --json --no-prompt` to create a dashboard notification.

If the JSON response contains `"confirmationRequired": true`, show the
`confirmation.title`, `confirmation.body`, and recommended action to the user.
Do not rewrite, summarize away, or hide the critical confirmation text. Do not
auto-approve it and do not create a durable grant. Critical requests can only be
denied or approved once:

```bash
ward approvals wait <request-id> --json
```

Run template:

```bash
ward run \
  --app <app-name> \
  --agent <agent-name> \
  --worktree <absolute-path> \
  --branch <branch-name> \
  --git-remote <remote-url-or-empty> \
  --commit <sha> \
  --action "<why this command needs secrets>" \
  --env <ENV_NAME> \
  --wait-for-approval \
  --approval-timeout 30m \
  --json \
  --no-prompt \
  -- <command> <args>
```

All Ward flags must appear before `--`. Everything after `--` is the child
command and its arguments, so do not put `--json`, `--no-prompt`, `--agent`, or
other Ward flags after `--`.

Ward is passive: commands that need secrets must be run through
`ward run`. Automatic worktree delivery means Ward injects scoped
environment variables into the approved child process. It does not write
plaintext `.env` files for agents.

Never ask for, echo, store, or pipe the Ward vault PIN/passphrase.
`ward init` and `ward setup` create the initial run unlock by default; the
user may run `ward unlock --ttl 8h` locally later to refresh it. Viewing
decrypted logs always requires the user's PIN/passphrase. Agents can request
and wait, but approval authority belongs to the broker and human approval paths.
"#
    )
}

pub fn resolve_vault_path(cwd: &Path, config: &ProjectConfig) -> PathBuf {
    resolve_vault_path_checked(cwd, config)
        .expect("project config vault path should be validated before resolving")
}

pub fn resolve_vault_path_checked(cwd: &Path, config: &ProjectConfig) -> Result<PathBuf> {
    fs_util::resolve_project_path(cwd, &config.vault, "vault path")
}

/// Derives the vault path from passphrase + project + nonce when dynamic naming is active.
/// Falls back to the static path for keychain mode or legacy configs.
pub fn resolve_vault_path_dynamic(cwd: &Path, config: &ProjectConfig, passphrase: &str) -> PathBuf {
    if config.storage_mode == StorageMode::Keychain || config.vault_nonce.is_empty() {
        return resolve_vault_path(cwd, config);
    }
    let filename = vault::derive_vault_filename(passphrase, &config.project, &config.vault_nonce);
    fs_util::resolve_project_path(cwd, Path::new(&filename), "derived vault path")
        .expect("derived vault filename should stay inside the project")
}

/// Resolves the current vault path when a passphrase is available.
///
/// Legacy projects may still have a static `.env.vault` even after a nonce was
/// added to `.ward.json`. Prefer the derived path only once it exists, or when
/// the configured static path is absent.
pub fn resolve_vault_path_with_passphrase(
    cwd: &Path,
    config: &ProjectConfig,
    passphrase: &str,
) -> PathBuf {
    let configured = resolve_vault_path(cwd, config);
    let derived = resolve_vault_path_dynamic(cwd, config, passphrase);
    if derived.exists() || !configured.exists() {
        derived
    } else {
        configured
    }
}

fn default_anomaly_detection() -> AnomalyDetectionConfig {
    AnomalyDetectionConfig {
        enabled: true,
        working_hours_start: 8,
        working_hours_end: 20,
        max_runs_per_hour_per_grant: 20,
        max_branches_per_grant: 3,
    }
}

fn validate_project_config_paths(cwd: &Path, config: &ProjectConfig) -> Result<()> {
    resolve_vault_path_checked(cwd, config)?;
    Ok(())
}

fn default_env_keys() -> Vec<String> {
    vec![
        "DATABASE_URL".to_string(),
        "DATABASE_URI".to_string(),
        "PAYLOAD_SECRET".to_string(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectedCommands {
    dev: String,
    migrate: String,
}

fn detected_commands(cwd: &Path) -> DetectedCommands {
    match detected_package_manager(cwd).as_deref() {
        Some("npm") => DetectedCommands {
            dev: "npm run dev".to_string(),
            migrate: "npm run payload -- migrate".to_string(),
        },
        Some("yarn") => DetectedCommands {
            dev: "yarn dev".to_string(),
            migrate: "yarn payload migrate".to_string(),
        },
        Some("bun") => DetectedCommands {
            dev: "bun run dev".to_string(),
            migrate: "bun run payload migrate".to_string(),
        },
        _ => DetectedCommands {
            dev: "pnpm dev".to_string(),
            migrate: "pnpm payload migrate".to_string(),
        },
    }
}

fn detected_package_manager(cwd: &Path) -> Option<String> {
    if let Some(manager) = package_manager_from_package_json(cwd) {
        return Some(manager);
    }
    for (file, manager) in [
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
        ("bun.lockb", "bun"),
        ("bun.lock", "bun"),
    ] {
        if cwd.join(file).exists() {
            return Some(manager.to_string());
        }
    }
    None
}

fn package_manager_from_package_json(cwd: &Path) -> Option<String> {
    let path =
        fs_util::resolve_project_path(cwd, Path::new("package.json"), "package metadata").ok()?;
    let contents = fs_util::read_file_to_string(&path, "package metadata").ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&contents).ok()?;
    let manager = value.get("packageManager")?.as_str()?;
    ["pnpm", "npm", "yarn", "bun"]
        .iter()
        .find(|candidate| manager.starts_with(&format!("{candidate}@")))
        .map(|candidate| (*candidate).to_string())
}

fn package_json_has_workspaces(cwd: &Path) -> bool {
    let Ok(path) =
        fs_util::resolve_project_path(cwd, Path::new("package.json"), "package metadata")
    else {
        return false;
    };
    let Ok(contents) = fs_util::read_file_to_string(&path, "package metadata") else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };
    match value.get("workspaces") {
        Some(serde_json::Value::Array(values)) => !values.is_empty(),
        Some(serde_json::Value::Object(map)) => map
            .get("packages")
            .and_then(|packages| packages.as_array())
            .is_some_and(|values| !values.is_empty()),
        _ => false,
    }
}

fn append_gitignore_line(lines: &mut Vec<String>, expected: &str) {
    if !lines.iter().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed == expected
    }) {
        lines.push(expected.to_string());
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn slugify(project: &str) -> String {
    let slug = project
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if slug.is_empty() {
        "project".to_string()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_infers_project_and_profiles() {
        let tempdir = tempfile::tempdir().unwrap();
        let config = ProjectConfig::default_for_dir(tempdir.path(), None).unwrap();

        assert_eq!(
            config.project,
            tempdir.path().file_name().unwrap().to_string_lossy()
        );
        assert_eq!(config.vault, PathBuf::from(DEFAULT_VAULT_FILE));
        assert!(config.presets.is_empty());
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("\"presets\""));
        assert!(config.profiles.contains_key("dev"));
        assert!(config.anomaly_detection.enabled);
    }

    #[test]
    fn legacy_config_with_presets_still_parses() {
        let json = r#"{
          "version": 1,
          "project": "demo",
          "vault": ".env.vault",
          "presets": [
            {
              "name": "Raw dev",
              "match": ["pnpm dev"],
              "allowedEnv": ["DATABASE_URI"],
              "approval": "prompt"
            }
          ],
          "profiles": {}
        }"#;
        let config = serde_json::from_str::<ProjectConfig>(json).unwrap();
        assert_eq!(config.presets.len(), 1);
        assert_eq!(config.presets[0].allowed_env, vec!["DATABASE_URI"]);
    }

    #[test]
    fn write_project_config_refuses_overwrite_without_force() {
        let tempdir = tempfile::tempdir().unwrap();
        let config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

        write_project_config(tempdir.path(), &config, false).unwrap();
        assert!(write_project_config(tempdir.path(), &config, false).is_err());
        assert!(write_project_config(tempdir.path(), &config, true).is_ok());
        assert_eq!(read_project_config(tempdir.path()).unwrap().project, "demo");
    }

    #[test]
    #[serial_test::serial]
    fn config_backup_restores_missing_project_config() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let previous_home = std::env::var_os("WARD_HOME");
        std::env::set_var("WARD_HOME", home.path());

        let mut config =
            ProjectConfig::default_for_dir(project.path(), Some("demo".to_string())).unwrap();
        config.profiles.get_mut("dev").unwrap().env = vec!["DATABASE_URI".to_string()];
        write_project_config(project.path(), &config, false).unwrap();

        let backup_path = config_backup_path("demo");
        assert!(backup_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(backup_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }

        std::fs::remove_file(config_path(project.path())).unwrap();
        let restored = restore_project_config_from_backup(project.path(), false)
            .unwrap()
            .expect("backup should match project path");
        assert_eq!(restored.project, "demo");
        assert_eq!(read_project_config(project.path()).unwrap().project, "demo");
        assert_eq!(
            read_project_config(project.path()).unwrap().profiles["dev"].env,
            vec!["DATABASE_URI".to_string()]
        );

        match previous_home {
            Some(value) => std::env::set_var("WARD_HOME", value),
            None => std::env::remove_var("WARD_HOME"),
        }
    }

    #[test]
    fn ensure_env_example_is_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();

        let path = ensure_env_example(tempdir.path()).unwrap().unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("Ward managed environment"));
        assert!(ensure_env_example(tempdir.path()).unwrap().is_none());
    }

    #[test]
    fn ensure_env_example_prepends_existing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join(".env.example");
        std::fs::write(&path, "DATABASE_URL=\n").unwrap();

        assert_eq!(
            ensure_env_example(tempdir.path()).unwrap(),
            Some(path.clone())
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("# Ward managed environment."));
        assert!(contents.contains("DATABASE_URL="));
    }

    #[test]
    fn ensure_agent_instructions_creates_appends_and_is_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();
        let agents_path = tempdir.path().join(AGENT_INSTRUCTIONS_FILE);

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "demo").unwrap(),
            Some(agents_path.clone())
        );
        assert!(std::fs::read_to_string(&agents_path)
            .unwrap()
            .contains("Project: demo"));
        assert!(ensure_agent_instructions(tempdir.path(), "demo")
            .unwrap()
            .is_none());

        let tempdir = tempfile::tempdir().unwrap();
        let claude_path = tempdir.path().join(CLAUDE_INSTRUCTIONS_FILE);
        std::fs::write(&claude_path, "# Existing instructions\n").unwrap();

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "claude-demo").unwrap(),
            Some(claude_path.clone())
        );
        let contents = std::fs::read_to_string(&claude_path).unwrap();
        assert!(contents.contains("# Existing instructions"));
        assert!(contents.contains("Project: claude-demo"));
        assert!(contents.contains("Profiles are the user-facing command layer"));
        assert!(contents.contains("Presets may be added"));
        assert!(contents.contains("All Ward flags must appear before `--`"));
        assert!(contents.contains("worktree_approval_required"));
        assert!(contents.contains("approve/deny choice"));
        assert!(contents.contains("git rev-parse --show-toplevel"));
        assert!(contents.contains("ward approvals wait <request-id>"));
        assert!(contents.contains("passive wait primitive only"));
        assert!(contents.contains("approval authority belongs to the broker"));
        assert!(!contents.contains("--agent-mediated"));
        assert!(contents.contains("--app <app-name>"));
        assert!(
            contents.contains("Profile commands run from the resolved Ward project/app directory")
        );
        assert!(contents.contains("`--profile` is mutually exclusive with `--command` and `--env`"));
        assert!(contents.contains("ward env request-set --key <ENV_NAME>"));

        let tempdir = tempfile::tempdir().unwrap();
        let claude_path = tempdir.path().join(CLAUDE_INSTRUCTIONS_FILE);
        std::fs::write(&claude_path, "# Existing instructions").unwrap();

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "no-newline-demo").unwrap(),
            Some(claude_path.clone())
        );
        let contents = std::fs::read_to_string(&claude_path).unwrap();
        assert!(contents.contains("# Existing instructions\n\n<!-- ward-agent-instructions -->"));
    }

    #[test]
    fn resolves_absolute_and_relative_vault_paths() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

        assert_eq!(
            resolve_vault_path(tempdir.path(), &config),
            tempdir.path().join(DEFAULT_VAULT_FILE)
        );

        config.vault = tempdir.path().join("custom.vault");
        assert_eq!(resolve_vault_path(tempdir.path(), &config), config.vault);
    }

    #[test]
    fn project_config_rejects_vault_path_traversal() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.vault = PathBuf::from("../outside.vault");

        let error = write_project_config(tempdir.path(), &config, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("parent directory traversal"));

        std::fs::write(
            config_path(tempdir.path()),
            r#"{"version":1,"project":"demo","vault":"../outside.vault","profiles":{}}"#,
        )
        .unwrap();
        let error = read_project_config(tempdir.path()).unwrap_err().to_string();
        assert!(error.contains("parent directory traversal"));
    }

    #[test]
    fn project_config_rejects_absolute_vault_path_outside_project() {
        let tempdir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.vault = outside.path().join("outside.vault");

        let error = write_project_config(tempdir.path(), &config, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must stay inside"));
    }

    #[test]
    fn dotenv_keys_and_default_profiles_use_exact_env_names() {
        let tempdir = tempfile::tempdir().unwrap();
        let env_path = tempdir.path().join(".env");
        std::fs::write(
            &env_path,
            "DATABASE_URL=postgres://local\nPAYLOAD_SECRET=payload\nNEXT_PUBLIC_API_URL=http://localhost\nOPENAI_API_KEY=test\n",
        )
        .unwrap();

        let keys = env_keys_from_dotenv_file(&env_path).unwrap();
        let profiles = default_profiles(&keys, tempdir.path());

        assert_eq!(
            profiles["dev"].env,
            vec![
                "DATABASE_URL".to_string(),
                "PAYLOAD_SECRET".to_string(),
                "NEXT_PUBLIC_API_URL".to_string(),
            ]
        );
        assert_eq!(
            profiles["migrate"].env,
            vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()]
        );
        assert!(!profiles["dev"].env.iter().any(|name| name.contains('*')));

        let keys = env_keys_from_dotenv_str("DATABASE_URI=mongodb://local\n").unwrap();
        let profiles = default_profiles(&keys, tempdir.path());
        assert_eq!(profiles["dev"].env, vec!["DATABASE_URI".to_string()]);
        assert_eq!(profiles["migrate"].env, vec!["DATABASE_URI".to_string()]);
        assert!(!profiles["dev"].env.contains(&"DATABASE_URL".to_string()));
    }

    #[test]
    fn profile_generation_and_detection_use_package_metadata_and_lockfiles() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(
            tempdir.path().join("package.json"),
            r#"{"packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        assert_eq!(
            package_manager_from_package_json(tempdir.path()),
            Some("npm".to_string())
        );
        assert_eq!(detected_commands(tempdir.path()).dev, "npm run dev");

        std::fs::write(tempdir.path().join("package.json"), "{bad-json}").unwrap();
        std::fs::write(tempdir.path().join("yarn.lock"), "").unwrap();
        assert_eq!(
            detected_package_manager(tempdir.path()),
            Some("yarn".to_string())
        );
        assert_eq!(
            detected_commands(tempdir.path()).migrate,
            "yarn payload migrate"
        );

        let bun = tempfile::tempdir().unwrap();
        std::fs::write(bun.path().join("bun.lock"), "").unwrap();
        assert_eq!(detected_commands(bun.path()).dev, "bun run dev");

        let fallback = tempfile::tempdir().unwrap();
        assert_eq!(detected_commands(fallback.path()).dev, "pnpm dev");
    }

    #[test]
    fn project_root_lookup_stops_at_workspace_and_git_boundaries() {
        let home = tempfile::tempdir().unwrap();
        let home_config =
            ProjectConfig::default_for_dir(home.path(), Some("home-project".to_string())).unwrap();
        write_project_config(home.path(), &home_config, true).unwrap();

        let workspace = home.path().join("workspace");
        let app = workspace.join("apps").join("site");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            workspace.join("pnpm-workspace.yaml"),
            "packages:\n  - apps/*\n",
        )
        .unwrap();
        assert_eq!(find_project_root(&workspace), None);
        assert_eq!(find_project_root(&app), None);

        let app_config =
            ProjectConfig::default_for_dir(&app, Some("workspace:site".to_string())).unwrap();
        write_project_config(&app, &app_config, true).unwrap();
        assert_eq!(find_project_root(&app), Some(app.clone()));
        assert_eq!(find_project_root(&app.join("src")), Some(app.clone()));

        let git_repo = home.path().join("repo");
        std::fs::create_dir_all(git_repo.join("src")).unwrap();
        std::fs::create_dir(git_repo.join(".git")).unwrap();
        assert_eq!(find_project_root(&git_repo.join("src")), None);

        let package_workspace = home.path().join("package-workspace");
        std::fs::create_dir_all(package_workspace.join("apps").join("api")).unwrap();
        std::fs::write(
            package_workspace.join("package.json"),
            r#"{"workspaces":["apps/*"]}"#,
        )
        .unwrap();
        assert_eq!(
            find_project_root(&package_workspace.join("apps").join("api")),
            None
        );
    }

    #[test]
    fn merge_profiles_and_gitignore_updates_are_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.profiles.clear();

        merge_default_profiles(
            &mut config,
            &["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()],
            tempdir.path(),
        );
        assert!(config.profiles.contains_key("dev"));
        let original = config.profiles["dev"].clone();
        config.profiles.get_mut("dev").unwrap().command = "custom dev".to_string();
        merge_default_profiles(&mut config, &[], tempdir.path());
        assert_eq!(config.profiles["dev"].command, "custom dev");
        assert_ne!(config.profiles["dev"], original);

        let empty = tempfile::tempdir().unwrap();
        ensure_gitignore(empty.path(), true).unwrap();
        let contents = std::fs::read_to_string(empty.path().join(".gitignore")).unwrap();
        assert!(contents.contains(".env\n"));
        assert!(contents.contains(".env.*\n"));
        assert!(contents.contains("!.env.vault\n"));

        std::fs::write(tempdir.path().join(".gitignore"), "# existing\n.env\n").unwrap();
        ensure_gitignore(tempdir.path(), true).unwrap();
        let contents = std::fs::read_to_string(tempdir.path().join(".gitignore")).unwrap();
        assert!(contents.contains(".env\n"));
        assert!(contents.contains(".env.*\n"));
        assert!(contents.contains("!.env.vault\n"));

        ensure_gitignore(tempdir.path(), false).unwrap();
        let contents = std::fs::read_to_string(tempdir.path().join(".gitignore")).unwrap();
        assert!(!contents.contains("!.env.vault"));
    }

    #[test]
    fn env_key_parsing_reports_invalid_dotenv() {
        let tempdir = tempfile::tempdir().unwrap();
        let env_path = tempdir.path().join(".env");
        std::fs::write(&env_path, "DATABASE_URL='unterminated\n").unwrap();

        assert!(env_keys_from_dotenv_file(&env_path).is_err());
    }
}
