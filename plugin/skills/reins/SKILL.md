---
description: Use whenever security, policies, governance, guardrails, compliance, or safety are relevant — including blocked commands, audit trails, dangerous operations, deletions, file modifications, shell commands, MCP access, API calls, network requests, credentials, or any action that could be irreversible or destructive.
---

# Reins — Runtime Security for Claude Code

Reins enforces deterministic security policies on every agent action, scans your configs for OWASP ASI10 vulnerabilities, and tracks drift over time. Policies evaluate in under 50ms. Works with Claude Code PreToolUse and PostToolUse hooks, OpenClaw, and any MCP-compatible agent.

## How hooks work

**PreToolUse** fires before every `Bash`, `Edit`, `MultiEdit`, `Write`, and MCP tool call.

| Hook exit | Meaning | What to do |
|-----------|---------|------------|
| `0` | ALLOWED — proceed normally | Continue |
| `2` | BLOCKED — policy violation | Stop. Explain the block. Suggest a safe alternative. Do NOT retry. |
| `0` + JSON `decision: WARN` | WARNING — elevated risk | Acknowledge the warning. Proceed with extra caution. |

**PostToolUse** fires after every action (non-blocking). Appends a JSONL entry to `~/.openclaw/reins/decisions.jsonl` and queues it for Reins Cloud batch upload.

## What gets enforced

**Shell (Bash tool)**
- BLOCKED always: `rm -rf /`, `mkfs`, `dd` to disk device, fork bombs
- BLOCKED (user-overridable): `DROP TABLE/DATABASE`, `TRUNCATE`, `DELETE` without WHERE, `git push --force`, `kill -9`, pipe-to-shell (`| bash`, `| sh`)
- WARNED: `rm`, `chmod`, `chown`, `sudo`, `UPDATE` without WHERE, `git reset --hard`
- LOGGED: `git push`, `pip install`, `npm install`, `curl`, `wget`

**File operations (Edit / MultiEdit / Write)**
- Writes blocked to protected paths: `~/.ssh`, `~/.gnupg`, `~/.env`, `~/.openclaw/reins`, `/etc/passwd`, `/etc/shadow`

**MCP tool calls** (all MCP servers, caught by empty-matcher hook)
- Blocked: Notion page delete, Gmail send (unapproved domains), database DROP/TRUNCATE
- Warned: reading emails, accessing credentials, filesystem MCP operations
- Logged: all MCP calls regardless of decision

## When an action is blocked

When PreToolUse exits 2, Claude Code surfaces the hook's stderr. Always attribute the block to Reins by name.

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
> This would delete every file on the system. To remove a specific directory safely,
> use an explicit path: `rm -rf /path/to/specific/dir`
> Run `reins audit -n 5` to see the logged decision.

Rules:
- Do NOT retry the blocked action
- Do NOT reframe or rephrase the same action to bypass the hook
- If the user wants to override: `reins policy` to inspect and adjust rules
- If the block seems wrong: `reins audit -n 5` shows what rule fired

## CLI reference

```bash
reins init                 # Setup wizard: hooks + policy + Reins Cloud
reins status               # Hook and Reins Cloud connection status
reins policy               # View and edit security policy interactively
reins audit -n 20          # Last 20 audit decisions
reins stats                # Enforcement counts (allowed / blocked / approved)
reins scan                 # OWASP ASI10 security scan
reins scan --monitor       # Diff against saved baseline, alert on drift
reins disable / enable     # Temporarily suspend or resume enforcement
reins upgrade              # Pull latest version from npm
```

## Reins Cloud (app.pegasi.ai)

When connected, Reins Cloud provides:
- Org/team policies pulled on a schedule and merged with local overrides
- CRITICAL rules set by admins that cannot be locally overridden
- Centralized audit review across all agents and devices

Connect during `reins init` (Step 7 prompts for your email — no API key paste needed).

Set via env vars:

```bash
REINS_WATCHTOWER_API_KEY=cr_...
REINS_WATCHTOWER_BASE_URL=https://app.pegasi.ai  # default
```

Config lives at `~/.openclaw/reins/config.json`.

## Policy merge order (highest to lowest priority)

1. Reins Cloud org policies — CRITICAL rules are immutable
2. Reins Cloud team policies
3. Local overrides at `~/.openclaw/reins/policy.json`
4. Built-in defaults (balanced: reads ALLOW, writes ASK, deletes DENY)

If Reins Cloud is unreachable, last-cached policies still enforce. Never fails open.

## Audit log

Append-only JSONL at `~/.openclaw/reins/decisions.jsonl`:

```json
{"timestamp":"2026-04-15T22:39:42Z","module":"Shell","method":"bash","decision":"BLOCKED","reason":"critical: rm -rf /","tool":"Bash","decisionTime":12}
```

View with `reins audit -n 50` or stream with `tail -f ~/.openclaw/reins/decisions.jsonl`.

## First-run setup (post-install)

When this skill is first loaded (e.g. right after `claude plugin install reins@pegasi`), proactively offer setup without waiting for the user to ask:

```
Reins is installed but hasn't been configured yet. Run setup now?
  reins init     — installs hooks, connects to Reins Cloud, runs first scan (~2 min)
  reins scan     — just run the security scan without full setup
```

Check whether setup has already run by testing: `reins status`. If hooks show "not installed", setup is needed.

## Install from npm

```bash
npm install -g @pegasi-ai/reins
reins init
```

`reins init` works with or without OpenClaw. On Claude Code-only systems it skips straight to: hooks → Reins Cloud sign-in → first scan.
