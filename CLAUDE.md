# Reins — Agent Guide

You are working on **Reins**, security controls for AI agents. Reins ships as a Claude Code plugin that intercepts tool calls (PreToolUse / PostToolUse hooks) and blocks destructive actions before they execute.

## Read this before you start

1. **`FEATURE_SPEC.md`** — the active feature brief. Open it first.
2. **`README.md`** — what Reins is and how policies work end-to-end.
3. **`.claude-plugin/plugin.json`**, **`plugin/hooks/hooks.json`** — plugin manifest + hook wiring. Don't recreate; extend.

## Model

Use **Opus 4.7** (`claude-opus-4-7`) for all agent work on this repo. Do not downgrade to Haiku for "speed" — security logic and edge cases need the stronger model.

## Existing scaffolding — don't reinvent

These already exist. Extend them; don't rewrite:

| Concern | File |
|---|---|
| Pattern classifier | `src/core/DestructiveClassifier.ts` |
| Reversibility scorer | `src/core/IrreversibilityScorer.ts` |
| Pre-tool-use hook entrypoint | `src/hooks/pre-tool-use.ts` |
| Post-tool-use hook | `src/hooks/post-tool-use.ts` |
| Policy cache (sub-50ms eval) | `src/storage/PolicyStore.ts` |
| Plugin entrypoint | `src/plugin/index.ts` |
| Hook declarations | `plugin/hooks/hooks.json` |
| User-facing skill (block message) | `plugin/skills/reins/SKILL.md` |
| Audit log location | `~/.openclaw/reins/decisions.jsonl` |

## Conventions

- **TypeScript strict.** No `any` without a comment explaining why.
- **ESM.** `"type": "module"`, `.js` extensions in relative imports.
- **Node built-in test runner** (`node --test`). No Jest. New tests go in `test/*.test.mjs`.
- **Hooks must be synchronous + fail-closed.** Exit code `0` = ALLOW, `2` = BLOCK. Unhandled errors must block, not allow.
- **<50ms hot path.** Don't add network calls or heavy I/O inside hook evaluation. Cache via `PolicyStore`.
- **Append-only audit log.** Never modify or delete entries in `decisions.jsonl`.

## Verification (run before declaring done)

```bash
npm run build && npm test          # type-check + full test suite
npm run lint                        # eslint
npm run demo:destructive            # smoke-test destructive intercept
```

Then run the **sandbox toy-task harness** described in `FEATURE_SPEC.md` § "Sandbox verification". Every parallel agent must run this and paste the result into their PR description before declaring their slice done.

## What NOT to touch unless your slice owns it

- `plugin/hooks/hooks.json` matchers — coordinated; one PR at a time.
- `~/.openclaw/reins/decisions.jsonl` schema — additive only, never breaking.
- `package.json` `name` / `version` — release manager owns these.

## Out of scope for current feature

- MCP server beyond what already exists.
- Cloud sync of audit logs.
- GUI / dashboard.
- Anything not directly serving "block destructive actions on Claude Code via /plugin install."
