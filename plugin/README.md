# Reins — Claude Code Plugin

Runtime security for AI agents. Blocks destructive actions before execution, routes high-impact operations through human approval, and maintains an immutable audit trail.

## Prerequisites

```bash
npm install -g @pegasi/reins
reins init
```

The plugin hooks call the globally installed `@pegasi/reins` package. `reins init` configures your security level, connects to Watchtower, and runs an initial scan.

## What this plugin installs

| Component | What it does |
|-----------|-------------|
| **PreToolUse hooks** | Intercept every `Bash`, `Edit`, `MultiEdit`, `Write`, and MCP call before execution |
| **PostToolUse hooks** | Log every decision to `~/.openclaw/reins/decisions.jsonl` |
| **`reins` skill** | Teaches Claude how to respond when an action is blocked |

## Install

**From marketplace:**
```
/plugin install reins
```

**Local (development):**
```bash
claude --plugin-dir ./plugin
```

## Testing

```bash
# Test the hook directly
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | reins-pre-hook

# Check status
reins status
reins audit -n 5
```

## Links

- [Docs](https://app.pegasi.ai/docs)
- [Watchtower Dashboard](https://app.pegasi.ai)
- [npm package](https://www.npmjs.com/package/@pegasi/reins)
- [GitHub](https://github.com/pegasi-ai/reins)
