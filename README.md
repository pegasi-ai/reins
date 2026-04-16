<div align="center">
  <img src="logo.png" alt="ClawReins Logo" width="360"/>
  <h1>🔒 ClawReins</h1>
  <p><strong>Runtime security for OpenClaw agents. Scan, fix, monitor.</strong></p>
  <p>
    <a href="https://www.npmjs.com/package/clawreins"><img src="https://img.shields.io/npm/v/clawreins.svg" alt="npm"></a>
    <a href="https://www.npmjs.com/package/clawreins"><img src="https://img.shields.io/npm/dt/clawreins.svg" alt="downloads"></a>
    <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
    <a href="http://www.typescriptlang.org/"><img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%23007ACC.svg" alt="TypeScript"></a>
    <img src="https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen" alt="Node.js >= 18.0.0">
  </p>
</div>

> OpenClaw is powerful. That's the problem. ClawReins is the watchdog layer.

## Quick Start

```bash
npm i -g clawreins
clawreins scan
```

13 security checks in 30 seconds. That's it.

## What it does

- **Scan** — finds security issues in your OpenClaw config (`clawreins scan`)
- **Fix** — auto-remediates what it can (`clawreins scan --fix`)
- **Monitor** — connects to [Watchtower](https://app.pegasi.ai) for continuous drift detection
- **Intercept** — blocks destructive agent actions before they execute
- **Approve** — human-in-the-loop approval for high-risk operations

**OpenClaw cannot be its own watchdog. Neither can any CUA.**

## In The News

- TechCrunch (February 23, 2026): [A Meta AI security researcher said an OpenClaw agent ran amok on her inbox](https://techcrunch.com/2026/02/23/a-meta-ai-security-researcher-said-an-openclaw-agent-ran-amok-on-her-inbox/)

## Security Scan

![ClawReins security scan](./public/clawreins_security_scan.gif)

```bash
clawreins scan            # 25-check security audit
clawreins scan --fix      # Auto-fix with backup
clawreins scan --json     # Machine-readable for CI
clawreins scan --monitor  # Compare against baseline, alert on drift
```

### Security Checks

| Check | Severity | Detects | Auto-fix |
|---|---|---|---|
| `GATEWAY_BINDING` | Critical | Gateway listening on `0.0.0.0` or missing localhost binding | Yes |
| `API_KEYS_EXPOSURE` | Critical | Plaintext API keys, tokens, or secrets in config files | No |
| `FILE_PERMISSIONS` | Critical | Config files readable by group or other users | Yes |
| `HTTPS_TLS` | Warning | Missing HTTPS/TLS configuration | No |
| `SHELL_COMMAND_ALLOWLIST` | Critical | Missing shell allowlist or unrestricted shell execution | Yes |
| `SENSITIVE_DIRECTORIES` | Warning | Agent can access `~/.ssh`, `~/.gnupg`, `~/.aws`, `/etc/shadow` | No |
| `WEBHOOK_AUTH` | Warning | Webhook endpoints without auth tokens | No |
| `SANDBOX_ISOLATION` | Warning | No Docker or sandbox isolation detected | No |
| `DEFAULT_WEAK_CREDENTIALS` | Critical | Default, weak, or missing gateway credentials | No |
| `RATE_LIMITING` | Warning | No gateway throttling or rate limit configured | No |
| `NODEJS_VERSION` | Critical | Node.js affected by CVE-2026-21636 permission bypass | No |
| `CONTROL_UI_AUTH` | Critical | Control UI authentication bypass enabled | Yes |
| `BROWSER_UNSANDBOXED` | Critical | Browser skill missing headless or sandbox protection | No |
| `CHANNEL_DM_POLICY` | Critical | Telegram, WhatsApp, or Discord DMs open to all or wildcard senders | No |
| `MCP_ENABLE_ALL_SERVERS` | Critical | Project MCP servers automatically trusted without individual approval | No |
| `MCP_FILESYSTEM_ROOTS` | Warning | Filesystem MCP servers exposing broad or sensitive roots | No |
| `MCP_SERVER_PINNING` | Warning | MCP server commands using unpinned packages or shell-piped remote installers | No |
| `MCP_REMOTE_TRANSPORT_AUTH` | Critical/Warning | Remote MCP servers using HTTP or HTTPS without auth headers | No |
| `INSTALLED_ARTIFACT_RISK` | Warning | Installed skills/plugins containing risky shell, network, or dynamic-code patterns | No |
| `SKILL_PERMISSION_BOUNDARIES` | Warning | Installed skills/plugins requesting broad or wildcard capabilities | No |
| `LOCAL_STATE_EXPOSURE` | Critical | Local agent state containing plaintext secrets | No |
| `SKILL_EXTERNAL_ORIGIN` | Critical/Warning | Installed skills/plugins sourced from mutable local paths or unpinned external origins | No |
| `WORLD_WRITABLE_ARTIFACTS` | Critical/Warning | Installed skills/plugins or local state writable by group/other users | No |
| `PLUGIN_DEPENDENCY_PINNING` | Warning | Plugin package dependencies that use ranges, wildcards, or mutable sources instead of exact versions | No |
| `SENSITIVE_SCOPE_DECLARATIONS` | Critical/Warning | High-impact skill/plugin scopes without corresponding ASK/DENY policy coverage | No |

Exit codes: `0` = SECURE, `1` = NEEDS ATTENTION, `2` = EXPOSED

## Runtime Interception

ClawReins hooks into OpenClaw's `before_tool_call` event. Before any dangerous action executes, the agent pauses and waits for your decision.

```
Agent calls tool: bash('rm -rf /tmp/data')
  → ClawReins intercepts
  → Policy check: bash = ASK
  → Terminal prompt: Approve / Reject
  → You reject → action blocked
  → Decision logged to audit trail
```

Three policy types:

| Policy | Behavior |
|---|---|
| **ALLOW** | Execute immediately (e.g., file reads) |
| **ASK** | Prompt for human approval (e.g., file writes, shell commands) |
| **DENY** | Block automatically (e.g., file deletes) |

Policies are stored as plain JSON at `~/.openclaw/clawreins/policy.json`.

## Watchtower Dashboard

Connect to [Watchtower](https://app.pegasi.ai) for free cloud monitoring:

```bash
clawreins scan
# Say Y when prompted → enter email → dashboard loads at app.pegasi.ai
```

Watchtower gives you:
- Security score timeline and drift alerts
- Scan history across all your agents
- MCP Control Panel (tool allow/block policies)
- Org-wide shell policy enforcement (auto-deny `rm -rf`, `DROP TABLE`, `curl | bash`)
- Full audit log of every agent decision

## OWASP Agentic Skills Top 10

ClawReins maps to 6 of the 10 OWASP AST risks:

| OWASP Risk | Description | ClawReins Coverage |
|---|---|---|
| AST01 — Skill Injection | Malicious instructions in skill files | `CONTROL_UI_AUTH`, `WEBHOOK_AUTH` |
| AST03 — Excessive Permissions | Over-privileged agent access | `SHELL_COMMAND_ALLOWLIST`, `SENSITIVE_DIRECTORIES`, `FILE_PERMISSIONS` |
| AST06 — Supply Chain | Vulnerable dependencies and registries | `NODEJS_VERSION` (CVE detection) |
| AST07 — Sandbox Escape | Agent breaking out of isolation | `SANDBOX_ISOLATION`, `BROWSER_UNSANDBOXED` |
| AST08 — Network Exposure | Unprotected network interfaces | `GATEWAY_BINDING`, `HTTPS_TLS`, `RATE_LIMITING` |
| AST09 — Secrets Exposure | Leaked credentials and tokens | `API_KEYS_EXPOSURE`, `DEFAULT_WEAK_CREDENTIALS` |

Remaining risks (AST02, AST04, AST05, AST10) are on the roadmap. Learn more: [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)

## Why ClawReins?

| | ClawReins | ClawSec | DefenseClaw |
|---|---|---|---|
| Architecture | External to agent (can't be prompt-injected) | Runs inside agent (can be compromised) | External, multi-runtime |
| Install | `npm i -g clawreins` | Skill install | 3 runtimes + Go daemon |
| Hosted dashboard | Yes (Watchtower) | No | No (Splunk only) |
| HITL approvals | Yes | No | No |
| Target user | Developers + small teams | OpenClaw users | Enterprise SOC teams |

## CLI Commands

```bash
clawreins init              # Interactive setup wizard
clawreins scan              # 25-check security audit
clawreins scan --fix        # Auto-fix with backup
clawreins scan --json       # Machine-readable output for CI
clawreins scan --monitor    # Drift detection against baseline
clawreins policy            # Manage security policies
clawreins audit             # View decision history
clawreins stats             # View statistics
clawreins enable / disable  # Toggle protection
```

## Roadmap

### Shipped
- [x] 25-point security scan with auto-fix
- [x] Watchtower dashboard (security score, drift detection, analytics)
- [x] MCP Control Panel (tool allow/block, resource access, audit log)
- [x] Org-wide shell policy (auto-deny dangerous commands)
- [x] HITL approval flow (approve/deny agent actions)
- [x] Magic link auth + CLI signup

### Next
- [ ] `clawreins inventory` — discover all MCP servers, skills, and tools
- [ ] `clawreins audit` — local agent action log
- [ ] OWASP AST05 — SOUL.md / MEMORY.md integrity checks
- [ ] OWASP AST02 — trust prompt configuration validation
- [ ] Skill scanning on install (ClawHavoc IOC detection)
- [ ] Claude Agent SDK hook (`@clawreins/guard`)

### Later
- [ ] Gmail, Slack, GitHub MCP policy templates
- [ ] Runtime supply chain monitoring (OWASP AST04)
- [ ] Behavioral anomaly detection (OWASP AST10)
- [ ] On-prem deployment option
- [ ] SOC 2 / ISO 27001 audit export

## Contributing

We believe in safe AI. PRs welcome!

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/amazing`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing`
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Links

- [Watchtower Dashboard](https://app.pegasi.ai)
- [Blog: Browser Agents Complete the Lethal Trifecta](https://www.pegasi.ai/blog/browser-agents-complete-the-lethal-trifecta)
- [Blog: Dark Agents Are Already Here](https://www.pegasi.ai/blog/dark-agents-are-already-here)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)

---

Built by [Pegasi](https://pegasi.ai) — runtime security for AI agents.
