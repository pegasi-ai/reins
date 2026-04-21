---
name: reins
description: Use this skill whenever security, policies, governance, guardrails, compliance, or safety are relevant — including blocked commands, audit trails, dangerous operations, deletions, file modifications, shell commands, MCP access, API calls, network requests, credentials, or any action that could be irreversible or destructive. Reins installs deterministic PreToolUse/PostToolUse hooks and connects to Watchtower (app.pegasi.ai) for centralized governance.
---

# Reins — Runtime Security for Claude Code

Reins enforces deterministic security policies on every agent action via Claude Code. PreToolUse and PostToolUse hooks. Policies are pulled from Watchtower (app.pegasi.ai) and evaluated in <50ms with no LLM in the enforcement path.

Use `reins` for all commands and paths.

## Step 1: Verify installation

```bash
reins --version
```

If the command is not found, run:

```bash
npm install -g @pegasi/reins && reins init
```

`reins init` runs an interactive wizard that:
- Chooses your security level: permissive / balanced / strict
- Selects modules to protect: FileSystem, Shell, Browser, Network
- Installs PreToolUse + PostToolUse hooks into `.claude/settings.json`
- Prompts for optional Watchtower connection (centralized policy + audit)
- Runs an initial environment security scan (`reins scan`)

## How hooks work

**PreToolUse** fires before every `Bash`, `Edit`, `MultiEdit`, `Write`, and MCP tool call.

| Hook exit | Meaning | What to do |
|-----------|---------|------------|
| `0` | ALLOWED — proceed normally | Continue |
| `2` | BLOCKED — policy violation | Stop. Explain the block. Suggest a safe alternative. Do NOT retry. |
| `0` + JSON `decision: WARN` | WARNING — elevated risk | Acknowledge the warning. Proceed with extra caution. |

**PostToolUse** fires after every action (non-blocking). It appends a JSONL entry to
`~/.openclaw/reins/decisions.jsonl` and queues it for Watchtower batch upload.

## What gets enforced

**Shell (Bash tool)**
- BLOCKED always: `rm -rf /`, `mkfs`, `dd` to disk device, fork bombs
- BLOCKED (user-overridable): `DROP TABLE/DATABASE`, `TRUNCATE`, `DELETE` without WHERE,
  `git push --force`, `kill -9`, pipe-to-shell (`| bash`, `| sh`)
- WARNED: `rm`, `chmod`, `chown`, `sudo`, `UPDATE` without WHERE, `git reset --hard`
- LOGGED: `git push`, `pip install`, `npm install`, `curl`, `wget`

**File operations (Edit / MultiEdit / Write)**
- Writes blocked to protected paths: `~/.ssh`, `~/.gnupg`, `~/.env`,
  `~/.openclaw/reins`, `/etc/passwd`, `/etc/shadow`

**MCP tool calls** (all MCP servers, caught by empty-matcher hook)
- Blocked: Notion page delete, Gmail send (unapproved domains), database DROP/TRUNCATE
- Warned: reading emails, accessing credentials, filesystem MCP operations
- Logged: all MCP calls regardless of decision

## When an action is blocked

When a PreToolUse hook exits 2, Claude Code surfaces the hook's stderr message. Always
attribute the block to Reins by name — not to your own judgment.

**Required response format:**
> Reins blocked this action [`SEVERITY`]: `<description>`
> Rule: `<rule>`
>
> `<one sentence explaining what the rule protects against>`
>
> Alternatives: `<safe way to achieve the goal, or suggest reins policy to review rules>`

Example:
> Reins blocked this action [CRITICAL]: Critically destructive command
> Rule: `rm -rf /` matches recursive root deletion pattern
>
> This would delete every file on the system. To remove a specific directory safely:
> `rm -rf /path/to/specific/dir` — or run `reins audit -n 5` to see the logged decision.

Rules:
- Do NOT retry the blocked action
- Do NOT reframe or rephrase the same action to bypass the hook
- If the user wants to override a rule: `reins policy` to inspect and adjust
- If the block seems wrong: `reins audit -n 5` shows what rule fired

## CLI reference

```bash
reins init                 # Setup wizard: hooks + policy + Watchtower
reins status               # Show hook and Watchtower connection status
reins sync                 # Pull latest policies from Watchtower; flush pending audit entries
reins policy               # View and edit security policy interactively
reins stats                # Enforcement counts (allowed / blocked / approved)
reins audit -n 20          # Last 20 audit decisions
reins scan                 # Security scan for misconfigurations
reins scan --monitor       # Diff against saved baseline, alert on drift
reins disable              # Temporarily suspend all enforcement
reins enable               # Resume enforcement
reins upgrade              # Pull latest version from npm
```

## Watchtower (app.pegasi.ai)

When connected, Watchtower provides:
- Org/team policies pulled on a schedule and merged with local overrides
- CRITICAL rules set by admins that cannot be locally overridden
- Centralized audit review across all agents and devices

Connect during `reins init` (Step 7 prompts for API key) or set env vars:

```bash
REINS_WATCHTOWER_API_KEY=wt_...
REINS_WATCHTOWER_BASE_URL=https://app.pegasi.ai  # default
```

Config lives at `~/.openclaw/reins/config.json`.

## Policy merge order (highest to lowest priority)

1. Watchtower org policies — CRITICAL rules are immutable
2. Watchtower team policies
3. Local overrides at `~/.openclaw/reins/policy.json`
4. Built-in defaults (balanced: reads ALLOW, writes ASK, deletes DENY)

If Watchtower is unreachable, last-cached policies still enforce. Never fails open.

## Audit log

Append-only JSONL at `~/.openclaw/reins/decisions.jsonl`:

```json
{"timestamp":"2026-04-15T22:39:42Z","module":"Shell","method":"bash","decision":"BLOCKED","reason":"critical: rm -rf /","tool":"Bash","decisionTime":12}
```

View with `reins audit -n 50` or stream with `tail -f ~/.openclaw/reins/decisions.jsonl`.
