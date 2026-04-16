#!/usr/bin/env node
/**
 * Reins PostToolUse hook — non-blocking audit logger.
 * Appends every completed tool action to decisions.jsonl and,
 * if connected, ships it to Watchtower with a 200ms timeout.
 *
 * Always exits 0.
 */

import { readFileSync, appendFileSync, mkdirSync, existsSync } from 'fs';
import path from 'path';
import os from 'os';

import { logPolicyDecision, PolicyDecision } from '../lib/watchtower-client';
import { appendPending } from '../lib/pending-queue';
import { getCurrentRunId } from '../lib/run-manager';
import { resolveWatchtowerCredentials } from '../storage/WatchtowerConfig';

// ─── Types ──────────────────────────────────────────────────────────────────

interface ClaudeCodePostHookInput {
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response?: unknown;
  session_id?: string;
}

interface AuditEntry {
  timestamp: string;
  decision: string;
  tool: string;
  action: string;
  module: string;
  method: string;
  decision_time_ms: number;
  user: string;
  hostname: string;
  cwd: string;
  session_id: string | null;
  run_id: string | null;
}

// ─── Paths ───────────────────────────────────────────────────────────────────

const DECISIONS_FILE = path.join(os.homedir(), '.openclaw', 'clawreins', 'decisions.jsonl');

function ensureDecisionsDir(): void {
  const dir = path.dirname(DECISIONS_FILE);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

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
  let input: ClaudeCodePostHookInput;
  try {
    input = JSON.parse(rawInput) as ClaudeCodePostHookInput;
  } catch {
    process.exit(0);
  }

  const toolName: string = typeof input.tool_name === 'string' ? input.tool_name : 'unknown';
  const toolInput: Record<string, unknown> =
    input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};

  // Determine module and method from tool name
  let moduleName: string;
  let methodName: string;
  let actionSummary: string;

  if (toolName.startsWith('mcp__')) {
    moduleName = 'MCP';
    methodName = toolName;
    actionSummary = toolName;
  } else if (toolName === 'Bash') {
    moduleName = 'Shell';
    methodName = 'bash';
    const cmd = typeof toolInput['command'] === 'string' ? toolInput['command'] : '';
    actionSummary = cmd.slice(0, 120);
  } else if (['Edit', 'MultiEdit', 'Write'].includes(toolName)) {
    moduleName = 'FileSystem';
    methodName = toolName.toLowerCase();
    const fp =
      typeof toolInput['file_path'] === 'string'
        ? toolInput['file_path']
        : typeof toolInput['path'] === 'string'
        ? toolInput['path']
        : '';
    actionSummary = fp;
  } else {
    moduleName = 'Other';
    methodName = toolName.toLowerCase();
    actionSummary = toolName;
  }

  const decisionTimeMs = Date.now() - startTime;

  // 3. Build audit entry
  const auditEntry: AuditEntry = {
    timestamp: new Date().toISOString(),
    decision: 'ALLOWED',
    tool: toolName,
    action: actionSummary,
    module: moduleName,
    method: methodName,
    decision_time_ms: decisionTimeMs,
    // Identity & context
    user: os.userInfo().username,
    hostname: os.hostname(),
    cwd: process.cwd(),
    session_id: input.session_id ?? null,
    run_id: getCurrentRunId(),
  };

  // 4. Append to decisions.jsonl (sync)
  try {
    ensureDecisionsDir();
    appendFileSync(DECISIONS_FILE, JSON.stringify(auditEntry) + '\n', 'utf8');
  } catch {
    // Non-fatal.
  }

  // 5. Load config + run_id
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
    // Non-fatal.
  }

  // 6. If connected, POST to Watchtower with 200ms timeout
  if (watchtowerApiKey && watchtowerBaseUrl && runId) {
    const policyDecision: PolicyDecision = {
      timestamp: auditEntry.timestamp,
      tool: toolName,
      action: actionSummary,
      decision: 'ALLOWED',
      severity: undefined,
      rule: undefined,
      decision_time_ms: decisionTimeMs,
      module: moduleName,
    };

    try {
      await Promise.race([
        logPolicyDecision(watchtowerApiKey, watchtowerBaseUrl, runId, policyDecision, 200),
        new Promise<void>((_, reject) => setTimeout(() => reject(new Error('timeout')), 200)),
      ]);
    } catch {
      appendPending(policyDecision);
    }
  }

  // 7. Always exit 0
  process.exit(0);
}

main().catch(() => {
  process.exit(0);
});
