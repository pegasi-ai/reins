# Customizing Security Policies

ClawReins ships with a balanced default policy, but every rule is editable. Policies are stored as plain JSON at `~/.openclaw/clawreins/policy.json` and take effect on the next gateway restart — no code changes needed.

## Policy structure

```json
{
  "defaultAction": "ASK",
  "modules": {
    "FileSystem": {
      "read":   { "action": "ALLOW", "description": "Read-only access is generally safe" },
      "write":  { "action": "ASK",   "description": "Modification of files requires approval" },
      "delete": { "action": "DENY",  "description": "Deletion is strictly prohibited" }
    },
    "Shell": {
      "bash":  { "action": "ASK", "description": "Shell command execution risk" },
      "exec":  { "action": "ASK", "description": "Arbitrary Code Execution (RCE) risk" },
      "spawn": { "action": "ASK", "description": "Process spawning risk" }
    },
    "Browser": {
      "navigate":   { "action": "ASK",   "description": "Navigation can trigger auth walls and sensitive workflows" },
      "click":      { "action": "ASK",   "description": "Clicks can submit irreversible actions" },
      "type":       { "action": "ASK",   "description": "Typing can submit credentials or confirmations" },
      "evaluate":   { "action": "ASK",   "description": "Browser script execution may bypass UI safeguards" },
      "screenshot": { "action": "ALLOW", "description": "Screenshots are allowed to support challenge verification" }
    },
    "Gateway": {
      "sendMessage": { "action": "ASK", "description": "Outbound messages may be irreversible/public" }
    },
    "Network": {
      "fetch":   { "action": "ASK", "description": "Potential data exfiltration" },
      "request": { "action": "ASK", "description": "HTTP request may leak data" }
    }
  }
}
```

## Decision types

| Action | Behavior |
|--------|----------|
| `ALLOW` | Execute immediately, no prompt |
| `ASK`   | Pause and require human approval |
| `DENY`  | Block automatically, no prompt |

`defaultAction` is the fallback for any tool not explicitly listed — `ASK` by default (fail-secure).

## Path filtering

Rules can restrict which paths a tool can touch:

```json
"write": {
  "action": "ASK",
  "allowPaths": ["/workspace/**", "/tmp/**"],
  "denyPaths":  ["**/.env", "**/.ssh/**", "/etc/**"]
}
```

- `allowPaths` — the call is **DENIED** unless the target path matches at least one pattern.
- `denyPaths` — the call is **DENIED** if the target path matches any pattern, regardless of `allowPaths`.

Both fields accept glob patterns.

## Editing your policy

Open the policy file directly:

```bash
$EDITOR ~/.openclaw/clawreins/policy.json
```

Then restart the gateway to apply changes:

```bash
openclaw gateway restart
```

Or reset to defaults:

```bash
clawreins policy reset
```

## Example: lock down shell access

```json
"Shell": {
  "bash":  { "action": "DENY", "description": "Shell disabled" },
  "exec":  { "action": "DENY", "description": "Exec disabled" },
  "spawn": { "action": "DENY", "description": "Spawn disabled" }
}
```

## Example: allow all filesystem reads without prompts, deny writes outside workspace

```json
"FileSystem": {
  "read":  { "action": "ALLOW" },
  "write": {
    "action": "ASK",
    "allowPaths": ["/workspace/**"]
  },
  "delete": { "action": "DENY" }
}
```
