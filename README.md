<div align="center">
  <img src="logo.png" alt="ClawReins Logo" width="360"/>
  <h1>🦞 + 🪢 ClawReins</h1>
  <p><strong>Browser-aware, trajectory-aware, human-routable intervention for OpenClaw.</strong></p>

  <p>
    <a href="https://github.com/pegasi-ai/clawreins">github.com/pegasi-ai/clawreins</a>
  </p>

  <p>
    <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
    <a href="http://www.typescriptlang.org/"><img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%23007ACC.svg" alt="TypeScript"></a>
    <img src="https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen" alt="Node.js >= 18.0.0">
  </p>
</div>

> OpenClaw is powerful. That's the problem.

This is why we built ClawReins - because confirm before acting only works if you understand what the agent is actually doing.

ClawReins is AI safety middleware for [OpenClaw](https://github.com/openclaw/openclaw). It goes beyond tool interception:
- **Browser-state awareness**: detects CAPTCHA, 2FA, and challenge walls before actions continue
- **Irreversibility scoring**: distinguishes risky actions from catastrophic ones
- **Multi-turn simulation**: runs ToolShield-style sandbox tests on new tools before production
- **Runtime intervention**: pauses, captures context, routes to human via WhatsApp/Telegram, resumes cleanly

**OpenClaw cannot be its own watchdog. Neither can any CUA.**

## Demo

![ClawReins demo](./clawreins-demo.gif)

ClawReins prevents destructive actions by requiring explicit, time-boxed approval and logging every decision.  
High-impact action gating: explicit approval -> safe stop -> audit trail.  
Gmail automation is gated: ClawReins blocks destructive inbox actions unless you explicitly approve (`YES`/`ALLOW`).

## Why?

OpenClaw can execute shell commands, modify files, and access your APIs. OS-level isolation (containers, VMs) protects your **host machine**, but it doesn't protect the **services your agent has access to**.

ClawReins solves this by hooking into OpenClaw's `before_tool_call` plugin event. Before any dangerous action executes (writes, deletes, shell commands, API calls), the agent pauses and waits for your decision. In a terminal, you get an interactive prompt. On messaging channels (WhatsApp, Telegram), the agent asks for YES/NO/ALLOW or explicit CONFIRM token (for irreversible actions) via a dedicated `clawreins_respond` tool. Every choice is logged to an immutable audit trail. Think of it as `sudo` for your AI agent: nothing happens without your explicit permission.

## Features

- 🧭 **Browser State Awareness** - Detects likely CAPTCHA / Cloudflare / 2FA challenges (including iframe signals)
- 🔐 **Irreversibility Scoring** - Scores each action (0-100) and escalates high-irreversibility actions to explicit confirmation
- 🧠 **Memory Risk Forecasting** - Tracks drift/salami/commitment signals and predicts dangerous turn `N+1` trajectories
- 🛡️ **ToolShield by Default** - `clawreins init` syncs ToolShield guardrails into OpenClaw instructions
- ♻️ **Persistent Browser Sessions** - Reuses encrypted local auth/session state across agent runs
- 💬 **Channel Support** - Works in terminal, WhatsApp, Telegram via `clawreins_respond` tool
- 📊 **Full Audit Trail** - Every decision logged (JSON Lines format)
- ⚡ **Zero Latency** - Runs in-process, no external policy API calls

## Quick Start

### Prerequisites
- Node.js >= 18.0.0
- OpenClaw installed

### Installation

```bash
# Install plugin
openclaw plugins install clawreins@beta

# Run setup
node ~/.openclaw/extensions/clawreins/dist/cli/index.js init

# Reload gateway
openclaw gateway restart
```

Done! ClawReins is now protecting your OpenClaw instance.

`clawreins init` now enables ToolShield by default:
- Uses bundled ToolShield core from this repo first (`src/core/toolshield`)
- Falls back to auto-install via `pip` only if bundled core is unavailable
- Syncs bundled experiences into OpenClaw `AGENTS.md`
- Keeps ClawReins runtime interception + ToolShield instruction hardening aligned

## ToolShield Sync (One Command)

If you use ToolShield for instruction-level hardening, sync it directly into your
OpenClaw `AGENTS.md` through ClawReins:

```bash
clawreins toolshield-sync
```

What it does:
- Uses bundled ToolShield core from `src/core/toolshield` when available
- Falls back to installed/pip ToolShield if bundled core is unavailable
- Removes previously injected ToolShield guidelines by default (idempotent sync)
- Imports bundled experiences into OpenClaw instructions (`AGENTS.md`)

ToolShield project reference: [CHATS-lab/ToolShield](https://github.com/CHATS-lab/ToolShield)

Useful overrides:

```bash
# Use a different bundled model
clawreins toolshield-sync --model claude-sonnet-4.5

# Custom OpenClaw home/profile
OPENCLAW_HOME=~/.openclaw-profile-a clawreins toolshield-sync

# Target a custom AGENTS.md path
clawreins toolshield-sync --agents-file /path/to/AGENTS.md

# Force a specific bundled ToolShield source root
clawreins toolshield-sync --bundled-dir /path/to/toolshield-root

# Do not auto-install ToolShield (fail if missing)
clawreins toolshield-sync --no-install

# Append without unloading existing ToolShield section
clawreins toolshield-sync --append
```

## How It Works

### Terminal Mode (TTY)

```
Agent calls tool: write('/etc/passwd', 'hacked')
  → before_tool_call hook fires
  → ClawReins checks policy: write = ASK
  → Interactive prompt:
    ┌─────────────────────────────────────┐
    │ 🦞 CLAWREINS SECURITY ALERT         │
    │                                     │
    │ Module: FileSystem                  │
    │ Method: write                       │
    │ Args: ["/etc/passwd", "hacked"]     │
    │                                     │
    │ ❯ ✓ Approve                         │
    │   ✗ Reject                          │
    └─────────────────────────────────────┘
  → You reject → { block: true }
  → Decision logged to audit trail
```

### Channel Mode (WhatsApp / Telegram)

```
Agent calls tool: bash('rm -rf /tmp/data')
  → before_tool_call → policy = ASK → blocked (pending approval)
  → Agent asks user for approval (or explicit token for irreversible actions)

User replies YES (normal risk):
  → Agent calls clawreins_respond({ decision: "yes" })
  → before_tool_call intercepts → approves pending entry
  → Agent retries bash('rm -rf /tmp/data') → approved ✓

User replies NO:
  → Agent calls clawreins_respond({ decision: "no" })
  → before_tool_call intercepts → denies pending entry
  → Agent does NOT retry → cancelled ✓

For high irreversibility actions:
  → ClawReins returns token requirement (e.g. CONFIRM-AB12CD)
  → Agent calls clawreins_respond({ decision: "confirm", confirmation: "CONFIRM-AB12CD" })
  → Retry proceeds only after token match ✓
```

The `clawreins_respond` tool is registered automatically via `api.registerTool()` when the gateway supports it (`yes`, `no`, `allow`, `confirm`).

### Memory-Aware Pre-Turn Forecasting

Before execution, ClawReins now evaluates accumulated session memory and predicts
high-risk turn `N+1` trajectories.

Signals:
- **Drift score**: semantic drift from initial intent to current trajectory
- **Salami index**: low-risk looking steps composing into a harmful chain
- **Commitment creep**: rising irreversibility and narrowing rollback options

When memory trajectory risk crosses threshold, ClawReins escalates to HITL before
execution and includes predicted next-step danger paths in the approval summary.

## Security Policies

ClawReins uses three decision types:

| Policy | Behavior |
|--------|----------|
| **ALLOW** | Execute immediately (e.g., file reads) |
| **ASK** | Prompt for approval (e.g., file writes) |
| **DENY** | Block automatically (e.g., file deletes) |

Default policy (Balanced):
- FileSystem: read=ALLOW, write=ASK, delete=DENY
- Shell: bash=ASK, exec=ASK
- Browser: screenshot=ALLOW, navigate/click/type/evaluate=ASK
- Gateway: sendMessage=ASK
- Network: fetch=ASK, request=ASK
- Everything else: ASK (fail-secure default)

## CLI Commands

```bash
clawreins init        # Interactive setup wizard
clawreins configure   # Alias for init (OpenClaw configure entrypoint)
clawreins configure --non-interactive --json  # Automation-friendly machine output
clawreins policy      # Manage security policies
clawreins stats       # View statistics
clawreins audit       # View decision history
clawreins reset       # Reset statistics
clawreins disable     # Temporarily disable
clawreins enable      # Re-enable
clawreins toolshield-sync  # Sync ToolShield guardrails into AGENTS.md
```

## Example: View Audit Trail

```bash
$ clawreins audit --lines 5

16:05:00 | FileSystem.read              | ALLOWED    |   0.0s
16:06:00 | FileSystem.write             | APPROVED   |   3.5s (human)
16:07:00 | Shell.bash                   | REJECTED   |   1.2s (human)
16:08:00 | FileSystem.delete            | BLOCKED    |   0.0s - Policy: DENY
```

## Example: View Statistics

```bash
$ clawreins stats

📊 ClawReins Statistics

Total Calls:    142

Decisions:
  ✅ Allowed:      35 (24.6%)
  ✅ Approved:     89 (62.7%) - by user
  ❌ Rejected:     12 (8.5%)  - by user
  🚫 Blocked:       6 (4.2%)  - by policy

Average Decision Time: 2.8s
```

## Data Storage

All data stored in `~/.openclaw/clawreins/`:

```
~/.openclaw/clawreins/
├── policy.json       # Your security rules
├── decisions.jsonl   # Audit trail (append-only)
├── stats.json        # Statistics
├── browser-sessions.json  # Encrypted persistent browser auth/session state
└── clawreins.log          # Application logs
```

## Use as a Library

```typescript
import { Interceptor, createToolCallHook } from 'clawreins';

// Create interceptor with default policy
const interceptor = new Interceptor();

// Create a hook handler for OpenClaw's before_tool_call event
const hook = createToolCallHook(interceptor);

// Register with the OpenClaw plugin API
api.on('before_tool_call', hook);
```

## Protected Tools

ClawReins intercepts every tool mapped in `TOOL_TO_MODULE`:
- **FileSystem**: read, write, edit, glob
- **Shell**: bash, exec
- **Browser**: navigate, screenshot, click, type, evaluate
- **Network**: fetch, request, webhook, download
- **Gateway**: listSessions, listNodes, sendMessage

Any unmapped tool falls through to `defaultAction` (ASK by default).

## Architecture

```
src/
├── core/
│   ├── Interceptor.ts    # Policy evaluation engine
│   ├── Arbitrator.ts     # Human-in-the-loop (TTY prompt / channel queue)
│   ├── ApprovalQueue.ts  # In-memory approval state for channel mode
│   ├── MemoryRiskForecaster.ts  # Drift/salami/commitment pre-turn forecasting
│   ├── toolshield/       # Bundled ToolShield core used for default sync
│   └── Logger.ts         # Winston-based logging
├── plugin/
│   ├── index.ts              # Plugin entry point (hook + tool registration)
│   ├── tool-interceptor.ts   # before_tool_call handler + clawreins_respond intercept
│   └── config-manager.ts     # OpenClaw config management (register/unregister)
├── storage/        # Persistence (PolicyStore, DecisionLog, StatsTracker)
├── cli/            # Command-line interface
├── toolshield/     # ToolShield sync integration helpers
├── types.ts        # TypeScript definitions
└── config.ts       # Default policies
```

## Development

```bash
# Clone repo
git clone github.com/pegasi-ai/clawreins
cd clawreins

# Install dependencies
npm install

# Build
npm run build

# Test CLI locally
node dist/cli/index.js init

# Link for global testing
npm link
clawreins --help
```

## Security Guarantees

✅ **Zero Trust** - Every action evaluated
✅ **Synchronous Blocking** - Agent waits for approval
✅ **No Bypass** - Plugin hooks intercept all tool calls
✅ **Immutable Audit** - JSON Lines append-only format
✅ **Human Authority** - Critical decisions need approval
✅ **Fail Secure** - Unknown actions default to ASK/DENY

## Contributing

We believe in safe AI. PRs welcome!

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/amazing`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing`
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built for [OpenClaw](https://github.com/openclaw) agents
- ToolShield methodology and implementation from [CHATS-lab/ToolShield](https://github.com/CHATS-lab/ToolShield)
- Inspired by the need for human oversight in AI systems
- Thanks to the AI safety community

---

**Built with ❤️ for a safer AI future.**
