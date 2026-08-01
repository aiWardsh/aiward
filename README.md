# Ward

Ward is a local-first secret firewall for development environments. It keeps
project envs encrypted in `.env.vault`, lets normal terminal workflows keep
working, and gives AI agents scoped, auditable access to only the env names they
were approved to use.

Ward's current vault model is API-derived:

- the encrypted `.env.vault` file is safe to store with the project;
- the user's PIN/passphrase is never sent to Ward's key API;
- Ward derives a local client factor, calls the key API, and combines both
  parts locally into the AES-256-GCM vault key;
- the key API returns temporary key material only;
- encryption and decryption happen on the user's machine;
- the API server secret is deployed as infrastructure secret
  `WARD_KEY_API_SERVER_SECRETS`, not committed to Git.

The recovery rule is:

```text
Ward installed + .env.vault + correct PIN/passphrase + reachable Ward key API
= decryptable after reinstall
```

## Install

```bash
cargo install aiward --locked --force
```

Make sure `~/.cargo/bin` is on your PATH:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
ward --version
```

## Setup

Run setup inside a project that has a plaintext `.env`:

```bash
cd your-project
ward setup
```

Ward will:

- create an encrypted `.env.vault`;
- ask for a PIN/passphrase;
- replace `.env` with a locked marker;
- register the project in `~/.ward/registry.json`;
- back up `.ward.json` metadata under `~/.ward/config-backups/`;
- generate agent instructions for Codex, Claude Code, and similar tools;
- show the shell integration command when needed.

The `.ward.json` backup contains local project metadata only. It does not
contain plaintext secret values.

## Clone-Anywhere Env Vaults

Commit or copy `.env.vault` with the project. On another machine:

```bash
git clone <repo>
cd <repo>
ward env unlock
```

Enter the same PIN/passphrase. Ward reads the metadata inside `.env.vault`,
calls the Ward key API, derives the decrypt key locally, and writes a plaintext
`.env` for manual local development.

When you are done editing plaintext envs:

```bash
ward env lock
```

For command execution, prefer `ward run`, `ward dev`, or human mode instead of
leaving plaintext `.env` files around.

## Key API Infrastructure

Ward uses this API endpoint by default:

```text
https://api.aiward.dev/v1/vault-key/derive
```

Override it for local testing or failover:

```bash
export WARD_KEY_API_URL="https://your-api.example.com/v1/vault-key/derive"
```

The API deployment must provide:

```text
WARD_KEY_API_SERVER_SECRETS="ward-api-derived-v1=<base64-secret>"
```

`ward-api-derived-v1` is a public server key identifier. The value after `=` is
the private server secret. Store it as deployment secret/env state and keep an
offline backup outside Git. If this secret is lost, vaults that depend on that
server key cannot use the normal API-derived unlock path.

Use an offline key export when API availability is a concern:

```bash
ward key export --output ward-recovery-key.json
ward key import ward-recovery-key.json
```

Treat exported key files like master recovery material.

## Human Terminal Workflow

Human mode protects the current terminal session. Once active, commands that
need secrets are routed through Ward automatically.

```bash
ward human
```

Add shell integration to `~/.zshrc`:

```bash
eval "$(ward shell-init)"
```

Check active session state:

```bash
ward modes status
```

Lock when done:

```bash
ward lock
```

Inside a Ward project, shell-wrapped commands fail closed when human mode is not
active for that terminal. This prevents a dev server from silently starting
without secrets.

## Agent Workflow

Ward writes `AGENTS.md` or appends instructions to supported agent files during
setup. Agents use those instructions to request or run commands with explicit
context:

```bash
ward request \
  --agent codex \
  --worktree /absolute/git/root \
  --git-remote "" \
  --commit <sha> \
  --branch <branch> \
  --action "Run local dev server" \
  --profile dev \
  --json \
  --no-prompt
```

For commands that should continue after human approval:

```bash
ward run \
  --agent codex \
  --worktree /absolute/git/root \
  --git-remote "" \
  --commit <sha> \
  --branch <branch> \
  --action "Run local dev server" \
  --profile dev \
  --wait-for-approval \
  --approval-timeout 30m \
  --json \
  --no-prompt
```

Agents can request access and wait. They cannot create their own approvals,
approve worktree bindings, or turn a grant into broader access.

## Profiles And Presets

Profiles are the preferred command layer. A profile maps a short name to one
command, exact env names, and a default approval/action policy.

Example `.ward.json` profile:

```json
{
  "profiles": {
    "dev": {
      "command": "pnpm dev",
      "env": ["DATABASE_URI", "PAYLOAD_SECRET"],
      "defaultScope": "always",
      "action": "Run local development server"
    }
  }
}
```

Run a profile:

```bash
ward run --profile dev
ward dev
```

Allow a trusted local agent workflow:

```bash
ward allow --profile dev --agent codex --scope always
```

Presets are lower-level rules for raw command matching when a profile is not the
right fit.

## Monorepos

Run setup from the workspace root:

```bash
ward workspace discover --json
ward setup --workspace --all
```

Or configure one app:

```bash
ward setup --workspace --app web
```

Ward detects app folders from `pnpm-workspace.yaml`, `package.json` workspaces,
and `turbo.json`. Apps with their own `.env` become child Ward projects with
their own vault, profiles, registry entry, and logs.

At runtime, Ward resolves a workspace execution plan before `request`, `allow`,
`run`, profile shortcuts, and human shell routing. From inside `apps/web` or a
nested folder under it, Ward infers the app, executes from the workspace root,
and mounts package-manager commands for that app.

Examples:

```bash
ward run --app web --profile dev
ward dev --app web
ward human --app web
```

Shell-routed `pnpm dev` inside an app folder is mounted from the workspace root
as a package-manager workspace command when Ward can identify the app package.

## Global Off And On

Use `ward off` when you need a normal terminal without Ward interception:

```bash
ward off
```

Ward will:

- stop active runtime for the current terminal;
- revoke session grants;
- clear unlock sessions;
- stop the broker;
- write `~/.ward/disabled.json`;
- restore plaintext env files for known projects it can decrypt.

Known projects come from `~/.ward/registry.json` plus
`~/.ward/config-backups/`. Refresh tracking with:

```bash
ward projects discover ~/Documents
ward projects list
ward projects remove <stale-project>
```

By default, `ward off` asks once and tries the same PIN/passphrase for every
known project. Use project-by-project prompts when projects use different
PINs/passphrases:

```bash
ward off --each
ward off --discover ~/Documents
```

Ward never deletes `.ward.json`, `.env.vault`, registry entries, grants, logs,
recovery exports, config backups, or generated agent instructions. If a project
already has a non-Ward plaintext `.env`, Ward writes the restored plaintext copy
under `~/.ward/ward-off-envs/` instead of cluttering or overwriting the project.

Turn Ward back on:

```bash
ward on
```

`ward on` removes `~/.ward/disabled.json` and re-encrypts Ward-created plaintext
env files back into their vaults. Use project-by-project prompts when needed:

```bash
ward on --each
```

Ward leaves pre-existing non-Ward `.env` files alone and locks any Ward-home
sidecar files created during `ward off`.

## Env Operations

```bash
ward env list
ward env set KEY=value
ward env unset KEY
ward edit
ward env unlock
ward env lock
ward env export --output .env.plain
```

`ward env unlock`, `ward env export`, and `ward off` intentionally write
plaintext env files. Normal `ward run` and human-mode execution inject secrets
into child processes without writing plaintext `.env` files.

## Dashboard

The dashboard is a localhost service for local Ward state:

```bash
ward dashboard start
ward dashboard status
ward dashboard stop --all
ward dashboard tui
```

The dashboard shows projects, profiles, pending approvals, runtime state, and
encrypted audit logs. It does not display or edit secret values.

For approvable requests, the dashboard asks the broker to approve or deny the
exact pending request. Waiting agents unblock only when the command, env names,
agent identity, branch, commit, and worktree still match the approved request.

## Audit Logs

Every secret-bearing execution is logged locally, encrypted, and hash-chained:

```bash
ward logs view executions
ward logs view approvals
ward logs verify
```

Logs record commands, scopes, identities, decisions, and integrity metadata.
They never record plaintext secret values.

## Doctor

```bash
ward doctor
```

Doctor checks vault state, API-derived key metadata, global off/on state,
registry/config backups, broker status, gitignore, grants, recovery exports,
and log integrity.

## Security Model

Ward protects development env secrets from accidental exposure, over-broad AI
agent access, prompt-injection attempts, and casual local leaks.

Within that boundary:

- `.env.vault` stores ciphertext and public derivation metadata, not plaintext
  secrets;
- Ward does not store the PIN/passphrase;
- Ward does not store the derived AES vault key;
- the key API returns temporary key material only;
- encryption and decryption happen locally;
- profile and command access is scoped by env name;
- agent requests must include identity, command/profile, branch, commit,
  remote, and worktree context;
- approval grants are signed and scoped;
- audit logs are encrypted and hash-chained;
- `ward off` is the explicit escape hatch for plaintext local development, and
  `ward on` re-locks Ward-created plaintext outputs.

Ward is a workflow-layer firewall, not a same-user malware sandbox. If malware
or a malicious process can fully control your user account, it can observe what
you can observe. Ward's value is controlling normal development workflows,
making agent access explicit, and keeping encrypted envs recoverable across
machines.

## Future Direction

Future storage work is tracked in `FUTURE_FEATURES.md`. The current product
flow remains API-derived `.env.vault` storage plus PIN/passphrase unlock.

## License

AGPL-3.0-only. Ward is free to use, modify, and distribute. If you run a
modified version as a network service, you must make the corresponding source
available under the GNU Affero General Public License v3.
