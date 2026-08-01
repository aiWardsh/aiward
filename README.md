# Ward

Ward is a local-first AI secret firewall. It keeps your environment secrets encrypted at rest and controls when AI agents can access them — without changing how you work.

---

## How it works

Your `.env` file stays encrypted. When you or an AI agent needs to run a command that requires secrets, ward injects only the approved variables into that process — nothing else sees them.

There are two modes:

**Human mode** — you activate ward for your terminal session. Any command you run that needs secrets goes through ward automatically. No flags, no syntax changes.

**Agent mode** — AI agents (Claude, Codex, etc.) request scoped access through ward's approval flow. You see what they're asking for and approve or deny it. Ward generates the agent instructions automatically — you don't configure this manually.

Ward lets you tune how much friction each project requires. You can define
profiles and presets for trusted commands, grant approvals for a session,
branch, or long-lived project workflow, and use session modes to limit which
envs are available while the vault is unlocked. For more casual environments,
create broader profiles or auto-approved presets. Agent mode still stays
explicit, scoped, broker-authorized, and audited.

---

## Install

```bash
cargo install aiward
```

Then add `~/.cargo/bin` to your PATH if it isn't already:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

---

## Setup

Run this once inside your project directory:

```bash
cd your-project
ward setup
```

Ward will walk you through:
- Encrypting your `.env`
- Creating a vault PIN/passphrase
- Detecting workspace apps when the project is a monorepo
- Wiring up your shell

The setup wizard groups progress by project, vault, session, recovery, and shell
status, and prints exact next-step commands when action is needed.

Your plaintext `.env` is replaced with a locked marker file — secrets live in the encrypted vault from this point on.

Ward also keeps a private local metadata backup of `.ward.json` under
`~/.ward/config-backups/`. The backup is unencrypted, permissioned as local
private metadata, and never contains plaintext secret values. If `.ward.json` is
deleted, rerun `ward setup` in the project; setup tries to restore the config
from that backup before creating anything new. You can also restore explicitly:

```bash
ward config restore
```

For monorepos and Turborepos, run setup from the workspace root. Ward detects
workspace apps from `pnpm-workspace.yaml`, `package.json` workspaces, and
`turbo.json`, then configures each app that has its own `.env` as a child
project. Apps with only `.env.example` are shown as `needsEnv` until a real
`.env` is available. Workspace setup also records the workspace Git root as a
trusted worktree for each configured child app project, so agents should claim
the Git root as `--worktree` even when running commands from an app folder.

```bash
ward workspace discover --json
ward setup --workspace --app core-workbench
ward setup --workspace --all
```

---

## Human mode

Human mode turns your current terminal into a ward-protected session. Once active, secret-bearing commands run through ward automatically — no extra flags required.

**Start a session:**

```bash
ward human
```

In monorepos, human mode is activated per app. From an app folder, run
`ward human` normally. From the workspace root, choose a target app:

```bash
ward human --app core-workbench
```

Run `ward human` once for each app terminal you want protected. Ward does not
implicitly unlock every app from the workspace root.

Ward spawns a guardian tied to your terminal. When you run `pnpm dev`, `node`, or any other command that needs secrets, ward intercepts it, injects the approved env vars, and lets the process run. Inside a Ward project, wrapped commands fail closed if human mode is not active for that terminal, so a dev server does not silently start without secrets.

`ward human` prints a guided activation summary with the active project, session
TTL, guardian shell, command routing status, and dashboard link when a dashboard
is already running.

**Shell integration** (add to `~/.zshrc` for automatic loading):

```bash
eval "$(ward shell-init)"
```

**Check what's active:**

```bash
ward modes status
```

**Lock your session when done:**

```bash
ward lock
```

## Clone-anywhere encrypted envs

New projects use API-derived vaults by default. The encrypted `.env.vault`
contains public key-derivation metadata, while Ward derives the decrypt key from
your PIN/passphrase plus the Ward key API. The raw PIN is not sent to the API.

```bash
ward setup                         # creates api-derived .env.vault by default
ward import .env                   # imports with api-derived mode by default
ward setup --key-mode local-derived
ward import .env --key-mode local-derived
```

This lets a team commit `.env.vault`, clone the repo on another machine, and
unlock with Ward plus the same PIN/passphrase:

```bash
git clone <repo>
cd <repo>
ward env unlock
```

Use `ward key status` to inspect the current key mode. Existing local-derived
vaults keep working; migrate explicitly when ready:

```bash
ward key migrate --to api-derived
ward key migrate --to local-derived
```

API-derived vaults require the Ward key API. Export an offline safety file if
you need disaster recovery without the API:

```bash
ward key export --output ward-recovery-key.json
ward key import ward-recovery-key.json
```

## Global off/on

Use `ward off` when you want Ward to stop intercepting normal terminal commands
across your machine:

```bash
ward off
ward off --discover ~/Documents
```

Ward writes `~/.ward/disabled.json`, stops the local runtime, clears unlock
sessions and session grants, then restores plaintext `.env` files for every
known project it can decrypt. Known projects come from `~/.ward/registry.json`
and `~/.ward/config-backups/`; `--discover` adds projects found under the given
root to the registry first. Ward prompts project by project, so projects may use
different PINs/passphrases. If one project cannot be decrypted after retries,
Ward reports that failure and continues with the others.

Ward never deletes `.ward.json`, `.env.vault`, registry entries, grants, logs,
recovery files, config backups, or generated agent instructions. If `.env`
already contains non-Ward plaintext, Ward writes a sidecar file named
`.env.ward-off.<timestamp>` instead of overwriting it.

To refresh the global project registry without turning Ward off:

```bash
ward projects discover ~/Documents
ward projects list
```

Turn Ward back on with:

```bash
ward on
```

`ward on` only removes `~/.ward/disabled.json`. It does not relock plaintext
`.env` files; run `ward env lock` in each project when you are ready to return
to normal encrypted operation.

---

## Session modes

Modes let you define permission envelopes: which env names are available during
an unlock session and, in supervised mode, which command patterns are allowed.

Create a `.ward.modes.json` in your project:

```json
[
  {
    "name": "dev",
    "level": "read",
    "allowedEnv": ["DATABASE_URI", "NEXT_PUBLIC_SERVER_URL"],
    "allowedCommands": ["pnpm dev*"],
    "maxTtl": "8h"
  },
  {
    "name": "database",
    "level": "write",
    "allowedEnv": ["DATABASE_URI", "PAYLOAD_SECRET"],
    "allowedCommands": ["node scripts/*.mjs", "pnpm payload migrate*"],
    "maxTtl": "2h"
  }
]
```

Push modes to your local vault (passphrase required):

```bash
ward modes push
```

Unlock with a specific mode:

```bash
ward unlock --ttl 2h --mode dev
```

Now commands that request env names outside that mode's `allowedEnv` are blocked
automatically, even if you run them manually through Ward.

---

## Reducing approval prompts

Ward gives you several levels of freedom without turning agent access into an
unscoped free-for-all.

**Profiles** are the preferred command layer. A profile maps a short name to one
command, exact env names, a default approval scope, and an action description:

```json
{
  "profiles": {
    "dev": {
      "command": "pnpm dev",
      "env": ["DATABASE_URI", "PAYLOAD_SECRET", "NEXT_PUBLIC_SERVER_URL"],
      "defaultScope": "always",
      "action": "Run local development server"
    }
  }
}
```

Allow a trusted agent to reuse that profile:

```bash
ward allow --profile dev --agent codex --scope always
ward dev --agent codex
```

`ward allow` is a human terminal command. It creates a durable scoped grant and
requires local confirmation; agents should not run it. For agent workflows, use
`ward run --wait-for-approval` and approve from the dashboard or a local human
terminal fallback.

**Presets** are lower-level policy rules for raw command matching. Use them when
you want a known command pattern to be approved automatically if it asks only
for the allowed env names and no critical findings are detected:

```json
{
  "presets": [
    {
      "name": "safe-dev",
      "match": ["pnpm dev", "pnpm dev *"],
      "allowedEnv": ["DATABASE_URI", "PAYLOAD_SECRET", "NEXT_PUBLIC_*"],
      "approval": "auto"
    }
  ]
}
```

**Approval scopes** control how long a grant can be reused:

```bash
ward allow --profile dev --agent codex --scope session
ward allow --profile dev --agent codex --scope branch --branch main
ward allow --profile dev --agent codex --scope always
```

`always` is durable for the same project workflow, but it is still scoped to the
agent, command/profile, and env names. It does not decrypt the vault by itself
and it is not a generic "give this agent everything forever" switch.

---

## Vault operations

```bash
ward env list                        # see what's stored
ward env set KEY=value               # add or update a secret
ward env unset KEY                   # remove a secret
ward edit                            # open vault in $EDITOR
ward env export --output .env.plain  # write plaintext for manual use
```

---

## Dashboard

The browser dashboard is a standalone localhost service for inspecting local
Ward projects, profile env-name policies, runtime state, and encrypted logs.

```bash
ward dashboard start
ward dashboard status
ward dashboard stop --all
ward dashboard tui
```

The dashboard never displays or edits secret values. It can add/register
projects and edit profile policies by env name only. Monorepo app projects
appear alongside regular projects once detected or configured.

The header notification center shows anything currently blocking an agent:
run approvals, critical confirmations, worktree bindings, unlock-required
states, missing vault keys, and policy denials. For approvable requests, the
dashboard asks the broker to approve or deny the exact pending request. The
broker signs the grant, stores active once/session approval state, and unblocks
waiting agents only when the execution still matches the approved command, env
names, agent identity, and git context. The dashboard also shows copyable CLI
commands as a human-terminal fallback.

---

## Audit logs

Every secret-bearing execution is logged locally, encrypted, and hash-chained:

```bash
ward logs view executions   # see what ran
ward logs view approvals    # see what was approved
ward logs verify            # verify log integrity
```

---

## Doctor

```bash
ward doctor
```

Checks your setup: vault, global off/on state, broker, gitignore, grants,
PIN-based recovery, and log integrity. Run this if something feels off.

---

## Agent mode

When you run `ward setup`, ward writes an `AGENTS.md` (or appends to `CLAUDE.md`) in your project directory. This file contains everything an AI agent needs to know to work with ward — how to request access, how to run commands, what scope to declare.

You don't need to configure agent mode manually. The file is auto-generated from your profiles and vault contents, and agents pick it up from their context window automatically.

Agent runs outside human mode must identify themselves with `--agent <name>`. Ward rejects anonymous `run`, `request`, and `allow` calls so dashboard logs and approval grants stay tied to an agent identity.

If an agent reaches a new checkout, Ward may return a
`worktree_approval_required` response before any secret grant is considered.
Generated agent instructions tell Codex, Claude Code, and other agents to show
that as a structured approve/deny choice with the exact path, branch, commit,
remote, and reason. Agents must not approve that trust binding themselves.

For commands that should continue after approval, agents should use:

```bash
ward run --wait-for-approval --approval-timeout 30m --json --no-prompt -- <command>
```

When Ward blocks, this creates a dashboard notification and keeps the original
process alive until the human approves, denies, unlocks, or the timeout expires.
The lower-level tools are `ward approvals list --json` and
`ward approvals wait <request-id> --json`. These are passive inspection and wait
tools; they cannot approve, deny, sign, or mutate grants.

Agents must not run approval-mutating commands:

```bash
ward approve <request-id>
ward deny <request-id>
ward allow ...
ward worktrees approve <request-id>
```

Those commands are human fallback tools and require an interactive local
terminal confirmation. Dashboard approval is the preferred path because it goes
directly through the broker approval RPC.

The agent flow at a glance:

```
agent runs with wait  →  ward evaluates scope  →  you approve or deny
            ↓
 broker verifies the exact approval before decrypting envs
            ↓
  ward injects only the approved env vars into the command
            ↓
  execution is logged with the agent identity, command, and scope
```

Ward detects and blocks suspicious agent behavior before it reaches the approval prompt: full env dumps, secret echoing, network exfiltration patterns, clipboard access, and prompt injection attempts in declared action text.

---

## Security model

Ward is designed for a specific threat: AI agents accessing secrets through commands — accidentally, through prompt injection, or by requesting broader scope than a task needs.

Within that boundary, ward gives you hard guarantees:

- **API-derived vaults by default.** New `.env.vault` files can be committed and later unlocked from another machine with the PIN/passphrase plus Ward key API. The API returns key material only; encryption and decryption remain local.
- **Local-derived vault compatibility.** Existing PIN-derived vaults still decrypt locally. Use `ward setup --key-mode local-derived` for offline-only projects.
- **Authenticated broker operations.** Session-backed broker calls that execute commands, enumerate vault keys, sign approvals, or set up new projects require a trusted Ward client process and request authorization bound to the exact operation. Raw socket clients cannot bypass Ward policy just because a session is unlocked.
- **Broker-owned approval authority.** Agents can request access and wait, but
  they cannot create approvals, claim `agent-mediated` approval, or decide that
  a grant matches. Pending request approvals are created by the broker through
  dashboard approval or a confirmed local human terminal fallback. `once` and
  `session` approvals must match active broker state before envs decrypt;
  `branch` and `always` grants remain durable but are still broker-signed and
  matched to the exact command, env names, agent identity, and git context.
- **Simple recovery.** For API-derived vaults, keep `.env.vault` and remember the PIN/passphrase; export an offline recovery key if API availability is a concern. Four digits are convenient for daily testing, but weak without API rate limits; longer PINs/passphrases improve resistance without changing the workflow.
- **Secrets are never written to disk in plaintext** during normal operation;
  `ward off` is the explicit reversible escape hatch that restores plaintext
  `.env` files for convenience.
- **Every secret injection is logged** with the requesting identity and scope.
- **Approval grants are signed by Ward** — editing them invalidates them.
- **Audit logs are hash-chained** — tampering is detectable.

Ward operates at the workflow layer, not the OS level. The protection is effective as long as secret-bearing commands run through ward — agents cannot access secrets outside their approved scope, and every injection is logged and attributable. Ward is not a sandbox for arbitrary same-user malware, and agents should not be run inside human-mode terminals if you want agent-mode scoping guarantees.

---

## Vault rotation and recovery

```bash
ward key status                     # inspect api-derived vs local-derived mode
ward key migrate --to api-derived   # explicit clone-anywhere migration
ward key export                     # optional offline recovery key
ward rotate                         # local-derived: rotate vault to a new derived filename
ward recovery create                # optional legacy passphrase-protected recovery key
ward recovery export                # save a backup to a safe location
ward recovery import /path/to/file  # restore a recovery key from backup
ward recovery restore               # rewrite the vault from recovery material
```

The primary recovery path is `.env.vault` plus the PIN/passphrase. If `.env.vault`
is ignored by git, back it up separately before deleting or reinstalling Ward.

---

## License

AGPL-3.0-only. Ward is free to use, modify, and distribute. If you run a
modified version as a network service, you must make the corresponding source
available under the GNU Affero General Public License v3.
