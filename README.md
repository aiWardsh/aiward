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
explicit, scoped, and audited.

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
- Creating a vault passphrase
- Creating a recovery key with the same passphrase
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
dashboard uses the same signed grant logic as `ward approve`; it also shows
copyable CLI commands as a fallback.

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

Checks your setup: vault, broker, gitignore, grants, recovery key, and log integrity. Run this if something feels off.

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
`ward approvals wait <request-id> --json`.

The agent flow at a glance:

```
agent runs with wait  →  ward evaluates scope  →  you approve or deny
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

- **Vault rotation can move the vault to a derived filename.** The default vault file is `.env.vault`; `ward rotate` moves it to a passphrase-derived hidden filename and updates the registry and locked `.env` marker.
- **Session encryption.** While an unlock session is active, the vault on disk is re-encrypted with a random ephemeral key held only in broker memory. Your passphrase-encrypted form does not exist on disk during an active session.
- **Authenticated broker operations.** Session-backed broker calls that execute commands, enumerate vault keys, sign approvals, or set up new projects require a trusted Ward client process and request authorization bound to the exact operation. Raw socket clients cannot bypass Ward policy just because a session is unlocked.
- **Recovery key.** A recovery key is stored locally and encrypted with the same vault passphrase. If a session is interrupted and the broker can't restore the vault automatically, ward can use the recovery file plus your passphrase to restore access. The recovery directory contains decoys — files that are indistinguishable from the real key without the correct passphrase.
- **Secrets are never written to disk in plaintext** during normal operation.
- **Every secret injection is logged** with the requesting identity and scope.
- **Approval grants are signed** — editing them invalidates them.
- **Audit logs are hash-chained** — tampering is detectable.

Ward operates at the workflow layer, not the OS level. The protection is effective as long as secret-bearing commands run through ward — agents cannot access secrets outside their approved scope, and every injection is logged and attributable. Ward is not a sandbox for arbitrary same-user malware, and agents should not be run inside human-mode terminals if you want agent-mode scoping guarantees.

---

## Vault rotation and recovery

```bash
ward rotate                         # rotate vault to a new derived filename
ward recovery create                # create a passphrase-protected recovery key
ward recovery export                # save a backup to a safe location
ward recovery import /path/to/file  # restore a recovery key from backup
ward recovery restore               # rewrite the vault from recovery material
```

Ward doctor will warn you if the recovery key is missing or if no backup has been exported.

---

## License

AGPL-3.0-only. Ward is free to use, modify, and distribute. If you run a
modified version as a network service, you must make the corresponding source
available under the GNU Affero General Public License v3.
