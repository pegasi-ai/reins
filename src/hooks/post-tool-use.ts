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
import { getPreferredDataPath } from '../core/data-dir';

import { logPolicyDecision, PolicyDecision } from '../lib/watchtower-client';
import { appendPending } from '../lib/pending-queue';
import { getCurrentRunId } from '../lib/run-manager';
import { resolveWatchtowerCredentials } from '../storage/WatchtowerConfig';
import { buildAuditEnvelope } from '../lib/audit-schema';
import { getClaudeToolMetadata, resolveHookAgentType } from '../lib/claude-tool-metadata';

// ─── Types ──────────────────────────────────────────────────────────────────

interface ClaudeCodePostHookInput {
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response?: unknown;
  model?: string;
  usage?: unknown;
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
  decisionTime: number;
  schema_version: string;
  agent_type: string;
  run_started_at: string | null;
  run_ended_at: string | null;
  principal: unknown;
  model: string | null;
  tokens: unknown;
  touched_resources: unknown[];
  policy_decisions: unknown[];
}

// ─── Paths ───────────────────────────────────────────────────────────────────

const DECISIONS_FILE = getPreferredDataPath('decisions.jsonl');

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

  const metadata = getClaudeToolMetadata(toolName, toolInput);
  const moduleName = metadata.moduleName;
  const methodName = metadata.methodName;
  const actionSummary = metadata.actionSummary;

  const decisionTimeMs = Date.now() - startTime;
  const timestamp = new Date().toISOString();
  const runId = getCurrentRunId();
  const policyId = `${moduleName}.${methodName}`;
  const envelope = buildAuditEnvelope({
    timestamp,
    agentType: resolveHookAgentType(),
    sessionId: input.session_id ?? null,
    toolName,
    moduleName,
    methodName,
    payload: toolInput,
    decision: 'ALLOWED',
    policyId,
    reason: actionSummary,
    metadataSources: [input, toolInput, input.tool_response],
  });

  // 3. Build audit entry
  const auditEntry: AuditEntry = {
    timestamp,
    decision: 'ALLOWED',
    tool: toolName,
    action: actionSummary,
    module: moduleName,
    method: methodName,
    decision_time_ms: decisionTimeMs,
    decisionTime: decisionTimeMs,
    // Identity & context
    user: os.userInfo().username,
    hostname: os.hostname(),
    cwd: process.cwd(),
    session_id: input.session_id ?? null,
    run_id: runId,
    schema_version: envelope.schema_version,
    agent_type: envelope.agent_type,
    run_started_at: envelope.run_started_at,
    run_ended_at: envelope.run_ended_at,
    principal: envelope.principal,
    model: envelope.model,
    tokens: envelope.tokens,
    touched_resources: envelope.touched_resources,
    policy_decisions: envelope.policy_decisions,
  };

  // 4. Append to decisions.jsonl (sync)
  try {
    ensureDecisionsDir();
    appendFileSync(DECISIONS_FILE, JSON.stringify(auditEntry) + '\n', 'utf8');
  } catch {
    // Non-fatal.
  }

  // 5. Load Watchtower credentials
  let watchtowerApiKey: string | null = null;
  let watchtowerBaseUrl: string | null = null;

  try {
    const creds = await resolveWatchtowerCredentials();
    if (creds) {
      watchtowerApiKey = creds.apiKey;
      watchtowerBaseUrl = creds.baseUrl;
    }
  } catch {
    // Non-fatal.
  }

  // 6. If connected, POST to Watchtower with 200ms timeout
  if (watchtowerApiKey && watchtowerBaseUrl) {
    const policyDecision: PolicyDecision = {
      timestamp: auditEntry.timestamp,
      tool: toolName,
      action: actionSummary,
      decision: 'ALLOWED',
      decisionTime: decisionTimeMs,
      module: moduleName,
      method: methodName,
      run_id: runId,
    };

    try {
      await Promise.race([
        logPolicyDecision(watchtowerApiKey, watchtowerBaseUrl, '', policyDecision, 200),
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
