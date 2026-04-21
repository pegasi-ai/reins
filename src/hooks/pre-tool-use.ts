#!/usr/bin/env node
/**
 * Reins PreToolUse hook — evaluates every Bash/Edit/MultiEdit/Write/MCP action
 * against cached policies and logs the decision to Watchtower.
 *
 * Exit 0 = ALLOW, Exit 2 = BLOCK
 * Stdout JSON { decision: 'WARN', ... } = warn but allow
 */

import { readFileSync, appendFileSync, mkdirSync, existsSync } from 'fs';
import path from 'path';
import os from 'os';
import {
  getDataPath,
  getLegacyClawreinsDataDir,
  getPreferredDataPath,
  getReinsDataDir,
} from '../core/data-dir';

const DECISIONS_FILE = getPreferredDataPath('decisions.jsonl');

function writeToAuditLog(entry: Record<string, unknown>): void {
  try {
    const dir = path.dirname(DECISIONS_FILE);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    appendFileSync(DECISIONS_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch {
    // Non-fatal — audit log write failure must never affect enforcement
  }
}

// Sibling compiled modules (resolved at runtime from dist/hooks/)
import { logPolicyDecision, PolicyDecision, ShellRule, McpRule } from '../lib/watchtower-client';
import { appendPending } from '../lib/pending-queue';
import { getCurrentRunId } from '../lib/run-manager';
import { resolveWatchtowerCredentials } from '../storage/WatchtowerConfig';

// ─── Types ──────────────────────────────────────────────────────────────────

interface ClaudeCodeHookInput {
  tool_name: string;
  tool_input: Record<string, unknown>;
  session_id?: string;
}

interface PolicyCache {
  shell_rules?: ShellRule[];
  protected_paths?: string[];
  mcp_rules?: McpRule[];
  updated_at?: string;
}

interface EvalResult {
  decision: 'ALLOWED' | 'BLOCKED' | 'WARNED';
  severity?: string;
  rule?: string;
  description?: string;
}

// ─── Policy evaluation (inline, <50ms, no network) ──────────────────────────

const DEFAULT_PROTECTED_PATHS = [
  path.join(os.homedir(), '.ssh'),
  path.join(os.homedir(), '.gnupg'),
  path.join(os.homedir(), '.env'),
  getReinsDataDir(),
  getLegacyClawreinsDataDir(),
  '/etc/passwd',
  '/etc/shadow',
];

function evaluateShellCommand(command: string, shellRules: ShellRule[]): EvalResult {
  // Check loaded rules first
  for (const rule of shellRules) {
    try {
      const re = new RegExp(rule.pattern, 'i');
      if (re.test(command)) {
        return {
          decision: rule.action === 'BLOCK' ? 'BLOCKED' : rule.action === 'WARN' ? 'WARNED' : 'ALLOWED',
          severity: rule.severity,
          rule: rule.pattern,
          description: rule.description,
        };
      }
    } catch {
      // Invalid regex — skip this rule.
    }
  }

  // Built-in critical patterns
  const criticalPatterns: Array<[RegExp, string]> = [
    [/rm\s+-rf\s+[\/~]/, 'Critically destructive command'],
    [/mkfs/, 'Critically destructive command'],
    [/:\(\)\{.*:\|:&\}/, 'Critically destructive command'],
    [/dd\s+.*of=\/dev\/(s|h|nv)d/i, 'Critically destructive command'],
  ];
  for (const [pat, desc] of criticalPatterns) {
    if (pat.test(command)) {
      return { decision: 'BLOCKED', severity: 'CRITICAL', rule: pat.source, description: desc };
    }
  }

  // Built-in high-risk patterns
  const highPatterns: Array<[RegExp, string]> = [
    [/DROP\s+(TABLE|DATABASE|SCHEMA)/i, 'High-risk destructive command'],
    [/git\s+push\s+--force/, 'High-risk destructive command'],
    [/TRUNCATE\s+TABLE/i, 'High-risk destructive command'],
    [/DELETE\s+FROM\s+\w+\s*;?\s*$/i, 'High-risk destructive command'],
    [/\|\s*(bash|sh)\s*$/, 'High-risk destructive command'],
  ];
  for (const [pat, desc] of highPatterns) {
    if (pat.test(command)) {
      return { decision: 'BLOCKED', severity: 'HIGH', rule: pat.source, description: desc };
    }
  }

  return { decision: 'ALLOWED', severity: undefined, rule: undefined, description: undefined };
}

function evaluateFilePath(filePath: string, protectedPaths: string[]): EvalResult {
  const allProtected = [...DEFAULT_PROTECTED_PATHS, ...protectedPaths];
  const normalized = path.resolve(filePath.replace(/^~/, os.homedir()));

  for (const protected_ of allProtected) {
    const normalizedProtected = path.resolve(protected_.replace(/^~/, os.homedir()));
    if (normalized === normalizedProtected || normalized.startsWith(normalizedProtected + path.sep)) {
      return {
        decision: 'BLOCKED',
        severity: 'HIGH',
        rule: protected_,
        description: `Write to protected path: ${protected_}`,
      };
    }
  }

  return { decision: 'ALLOWED', severity: undefined, rule: undefined, description: undefined };
}

function evaluateMcpTool(toolName: string, mcpRules: McpRule[]): EvalResult {
  for (const rule of mcpRules) {
    try {
      // Try prefix match first, then regex
      const matches =
        toolName.startsWith(rule.tool_pattern) ||
        new RegExp(rule.tool_pattern, 'i').test(toolName);
      if (matches) {
        return {
          decision: rule.action === 'BLOCK' ? 'BLOCKED' : rule.action === 'WARN' ? 'WARNED' : 'ALLOWED',
          severity: rule.severity,
          rule: rule.tool_pattern,
          description: rule.description,
        };
      }
    } catch {
      // Invalid regex — skip.
    }
  }
  return { decision: 'ALLOWED', severity: undefined, rule: undefined, description: undefined };
}

// ─── Load cached policies synchronously ─────────────────────────────────────

function loadCachedPolicies(): PolicyCache {
  const policiesPath = getDataPath('policies.json');
  try {
    const raw = readFileSync(policiesPath, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === 'object' ? (parsed as PolicyCache) : {};
  } catch {
    return {};
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const startTime = Date.now();

  // 1. Read stdin synchronously
  let rawInput = '';
  try {
    rawInput = readFileSync('/dev/stdin', 'utf-8');
  } catch {
    process.exit(0);
  }

  if (!rawInput.trim()) {
    process.exit(0);
  }

  // 2. Parse input
  let input: ClaudeCodeHookInput;
  try {
    input = JSON.parse(rawInput) as ClaudeCodeHookInput;
  } catch {
    process.exit(0);
  }

  const toolName: string = typeof input.tool_name === 'string' ? input.tool_name : '';
  const toolInput: Record<string, unknown> =
    input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};

  // 3. Filter: MCP tools start with mcp__, otherwise must be Bash/Edit/MultiEdit/Write
  const isMcp = toolName.startsWith('mcp__');
  const isShell = toolName === 'Bash';
  const isFileOp = ['Edit', 'MultiEdit', 'Write'].includes(toolName);

  if (!isMcp && !isShell && !isFileOp) {
    // Unknown tool (e.g., Read, Glob) — allow immediately
    process.exit(0);
  }

  // 4. Load cached policies (sync, no network)
  const policies = loadCachedPolicies();
  const shellRules: ShellRule[] = Array.isArray(policies.shell_rules) ? policies.shell_rules : [];
  const protectedPaths: string[] = Array.isArray(policies.protected_paths) ? policies.protected_paths : [];
  const mcpRules: McpRule[] = Array.isArray(policies.mcp_rules) ? policies.mcp_rules : [];

  // 5 & 6. Evaluate and determine exit code
  let evalResult: EvalResult;
  let moduleName: string;
  let actionName: string;

  if (isShell) {
    const command = typeof toolInput['command'] === 'string' ? toolInput['command'] : '';
    evalResult = evaluateShellCommand(command, shellRules);
    moduleName = 'Shell';
    actionName = command.slice(0, 100);
  } else if (isFileOp) {
    const filePath =
      typeof toolInput['file_path'] === 'string'
        ? toolInput['file_path']
        : typeof toolInput['path'] === 'string'
        ? toolInput['path']
        : '';
    evalResult = evaluateFilePath(filePath, protectedPaths);
    moduleName = 'FileSystem';
    actionName = filePath;
  } else {
    // MCP
    evalResult = evaluateMcpTool(toolName, mcpRules);
    moduleName = 'MCP';
    actionName = toolName;
  }

  const decisionTimeMs = Date.now() - startTime;

  // 7. Load Watchtower config (sync via require)
  let runId: string | null = null;
  let watchtowerApiKey: string | null = null;
  let watchtowerBaseUrl: string | null = null;

  try {
    runId = getCurrentRunId();
    const creds = await resolveWatchtowerCredentials();
    if (creds) {
      watchtowerApiKey = creds.apiKey;
      watchtowerBaseUrl = creds.baseUrl;
    }
  } catch {
    // Non-fatal
  }

  // 8. Build PolicyDecision object
  const policyDecision: PolicyDecision = {
    timestamp: new Date().toISOString(),
    tool: toolName,
    action: actionName,
    decision: evalResult.decision,
    severity: evalResult.severity,
    rule: evalResult.rule,
    decision_time_ms: decisionTimeMs,
    module: moduleName,
  };

  // 9. Determine exit code before any async work
  const exitCode = evalResult.decision === 'BLOCKED' ? 2 : 0;

  // On block, write a named message to stderr so Claude Code surfaces it to the AI
  // and Claude can attribute the block to Reins by name.
  if (exitCode === 2) {
    const severity = evalResult.severity ?? 'HIGH';
    const description = evalResult.description ?? 'Policy violation';
    process.stderr.write(
      `\n🪢 Reins: action blocked\n` +
      `  Severity: ${severity}\n` +
      `  Reason:   ${description}\n` +
      `  Tool:     ${toolName}\n` +
      `  Action:   ${actionName}\n` +
      `  Rule:     ${evalResult.rule ?? 'built-in default'}\n` +
      `\nThis action was blocked by Reins. Do not retry it.\n` +
      `Run \`reins audit -n 5\` to view the logged decision.\n`
    );
  }

  // Write to local audit log — always, but especially critical for BLOCKED since
  // PostToolUse never fires when PreToolUse exits 2.
  writeToAuditLog({
    timestamp: policyDecision.timestamp,
    decision: evalResult.decision,
    tool: toolName,
    action: actionName,
    module: moduleName,
    method: moduleName === 'Shell' ? 'bash' : moduleName.toLowerCase(),
    severity: evalResult.severity ?? null,
    rule: evalResult.rule ?? null,
    description: evalResult.description ?? null,
    decisionTime: decisionTimeMs,
    // Identity & context
    user: os.userInfo().username,
    hostname: os.hostname(),
    cwd: process.cwd(),
    session_id: input.session_id ?? null,
    run_id: runId,
  });

  if (evalResult.decision === 'WARNED') {
    // Output warning JSON to stdout — Claude Code will display it
    process.stdout.write(
      JSON.stringify({
        decision: 'WARN',
        message: evalResult.description || `Warning: ${evalResult.rule}`,
        severity: evalResult.severity,
        rule: evalResult.rule,
      }) + '\n'
    );
  }

  // 10. Fire async Watchtower log with 200ms timeout, buffer on failure
  if (watchtowerApiKey && watchtowerBaseUrl && runId) {
    try {
      await Promise.race([
        logPolicyDecision(watchtowerApiKey, watchtowerBaseUrl, runId, policyDecision, 200),
        new Promise<void>((_, reject) => setTimeout(() => reject(new Error('timeout')), 200)),
      ]);
    } catch {
      appendPending(policyDecision);
    }
  } else {
    // No Watchtower — buffer locally
    appendPending(policyDecision);
  }

  // 11. Exit
  process.exit(exitCode);
}

main().catch(() => {
  process.exit(0);
});
