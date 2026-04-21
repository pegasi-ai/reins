---
description: Use whenever security, policies, governance, guardrails, compliance, or safety are relevant — including blocked commands, audit trails, dangerous operations, deletions, file modifications, shell commands, MCP access, API calls, network requests, credentials, or any action that could be irreversible or destructive.
---

# Reins — Runtime Security for Claude Code

Reins enforces deterministic security policies on every agent action via Claude Code PreToolUse and PostToolUse hooks. Policies are evaluated in <50ms with no LLM in the enforcement path.

## How hooks work

**PreToolUse** fires before every `Bash`, `Edit`, `MultiEdit`, `Write`, and MCP tool call.

| Hook exit | Meaning | What to do |
|-----------|---------|------------|
| `0` | ALLOWED — proceed normally | Continue |
| `2` | BLOCKED — policy violation | Stop. Explain the block. Suggest a safe alternative. Do NOT retry. |
| `0` + JSON `decision: WARN` | WARNING — elevated risk | Acknowledge the warning. Proceed with extra caution. |

**PostToolUse** fires after every action (non-blocking). Appends a JSONL entry to `~/.openclaw/reins/decisions.jsonl` and queues it for Watchtower upload.

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
reins init                 # Setup wizard: hooks + policy + Watchtower
reins status               # Hook and Watchtower connection status
reins policy               # View and edit security policy interactively
reins audit -n 20          # Last 20 audit decisions
reins stats                # Enforcement counts (allowed / blocked / approved)
reins scan                 # 13-check security audit
reins disable / enable     # Temporarily suspend or resume enforcement
reins upgrade              # Pull latest version from npm
```

## Setup (if not installed)

```bash
npm install -g @pegasi/reins
reins init
```

`reins init` installs hooks into `.claude/settings.json`, installs this skill, and runs an initial security scan.
