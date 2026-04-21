<div align="center">
  <img src="./public/reins_logo.png" alt="Reins Logo" width="360"/>
  <h1>🪢 Reins</h1>
  <p><strong>Security controls for AI agents.</strong></p>

  <p>
    <a href="https://github.com/pegasi-ai/reins">github.com/pegasi-ai/reins</a>
  </p>

  <p>
    <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
    <a href="http://www.typescriptlang.org/"><img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%23007ACC.svg" alt="TypeScript"></a>
    <img src="https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen" alt="Node.js >= 18.0.0">
  </p>
</div>

> In Greek myth, Athena gave Bellerophon the golden bridle — reins included — that let him guide Pegasus. Reins applies the same idea to AI agents: raw power is not enough — what matters is making it controllable.

Reins enforces deterministic security policies on every agent action via Claude Code PreToolUse and PostToolUse hooks. Policies are evaluated in under 50ms with no LLM in the enforcement path.

## Quickstart

```bash
npm install -g @pegasi/reins
reins init
```

## Claude Code Skill

Install the Reins skill to give Claude Code awareness of your security posture:

```bash
mkdir -p ~/.claude/skills/reins
curl -o ~/.claude/skills/reins/SKILL.md \
  https://raw.githubusercontent.com/pegasi-ai/reins/main/.claude/skills/reins/SKILL.md
```

Or clone the repo — the skill is included at `.claude/skills/reins/` automatically.

## Demo

![Reins demo](./public/reins-demo.gif)

An OpenClaw agent tries to bulk-delete 4,382 Gmail messages. Reins blocks it before execution.

## What Reins does

- **Prevent** — Block destructive actions before execution. Score irreversibility. Detect risky browser state.
- **Pause** — Route high-impact actions through terminal or messaging approval flows. Require explicit `CONFIRM-*` tokens for catastrophic operations.
- **Prove** — Preserve an immutable audit trail of every decision, approval, and block.

## Security guarantees

- **Zero Trust** — every action evaluated before execution
- **Synchronous** — agent cannot proceed until the hook exits
- **No network in the hot path** — policies cached locally, enforced offline
- **Fail-closed** — any unhandled hook error blocks the action
- **Immutable audit** — append-only JSONL at `~/.openclaw/reins/decisions.jsonl`

## Documentation

Full docs at [reins.sh/docs](https://reins.sh/docs):

- [Getting Started](https://reins.sh/docs/getting-started)
- [How It Works](https://reins.sh/docs/how-it-works)
- [Security Policies](https://reins.sh/docs/policies)
- [CLI Reference](https://reins.sh/docs/cli)
- [Security Scan](https://reins.sh/docs/scan)
- [Reins Cloud](https://reins.sh/docs/reins-cloud)
- [Use as a Library](https://reins.sh/docs/library)
- [Architecture](https://reins.sh/docs/architecture)

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
