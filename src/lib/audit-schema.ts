import { existsSync, readFileSync } from 'fs';
import os from 'os';
import { getDataPath } from '../core/data-dir';
import { getAuthFilePath } from '../storage/AuthStore';
import { getCurrentRunState } from './run-manager';

export const AUDIT_SCHEMA_VERSION = '1.0';

export type AuditAgentType = 'claude_code' | 'cowork' | 'openclaw' | 'unknown';
export type AuditResourceType = 'file' | 'url' | 'mcp_tool' | 'api' | 'command' | 'tool';
export type AuditResourceAction =
  | 'read'
  | 'write'
  | 'delete'
  | 'call'
  | 'execute'
  | 'list'
  | 'navigate';
export type AuditPolicyOutcome = 'allowed' | 'warned' | 'blocked' | 'approved' | 'rejected';
export type AuditPrincipalType = 'user' | 'service_account' | 'local_user' | 'unknown';

export interface AuditPrincipal {
  id: string;
  type: AuditPrincipalType;
  display_name?: string;
  email?: string;
}

export interface AuditTokenUsage {
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
}

export interface TouchedResource {
  timestamp: string;
  type: AuditResourceType;
  identifier: string;
  action: AuditResourceAction;
  allowed: boolean;
  policy_id?: string;
}

export interface AuditPolicyDecision {
  timestamp: string;
  decision: AuditPolicyOutcome;
  allowed: boolean;
  policy_id?: string;
  reason?: string;
  severity?: string;
  intervention_type?: string;
}

export interface AuditEnvelope {
  schema_version: string;
  agent_type: AuditAgentType;
  session_id: string | null;
  run_id: string | null;
  run_started_at: string | null;
  run_ended_at: string | null;
  principal: AuditPrincipal | null;
  model: string | null;
  tokens: AuditTokenUsage | null;
  touched_resources: TouchedResource[];
  policy_decisions: AuditPolicyDecision[];
}

interface BuildAuditEnvelopeInput {
  timestamp: string;
  agentType: AuditAgentType;
  sessionId?: string | null;
  toolName: string;
  moduleName?: string;
  methodName?: string;
  payload?: unknown;
  decision?: string | null;
  policyId?: string | null;
  reason?: string | null;
  severity?: string | null;
  interventionType?: string | null;
  policyDecisions?: AuditPolicyDecision[];
  metadataSources?: unknown[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function readJsonFileSync(filePath: string): Record<string, unknown> | null {
  try {
    if (!existsSync(filePath)) return null;
    const raw = readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function getNestedValue(source: unknown, pathSegments: string[]): unknown {
  let current = source;
  for (const segment of pathSegments) {
    if (!isRecord(current)) return undefined;
    current = current[segment];
  }
  return current;
}

function getStringAtPaths(sources: unknown[], paths: string[][]): string | null {
  for (const source of sources) {
    for (const pathSegments of paths) {
      const value = getNestedValue(source, pathSegments);
      if (typeof value === 'string' && value.trim()) {
        return value.trim();
      }
    }
  }
  return null;
}

function getNumberAtPaths(sources: unknown[], paths: string[][]): number | null {
  for (const source of sources) {
    for (const pathSegments of paths) {
      const value = getNestedValue(source, pathSegments);
      if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
      }
      if (typeof value === 'string' && value.trim()) {
        const parsed = Number(value);
        if (Number.isFinite(parsed)) {
          return parsed;
        }
      }
    }
  }
  return null;
}

function normalizeDecision(decision: string | null | undefined): AuditPolicyOutcome | null {
  switch ((decision || '').toUpperCase()) {
    case 'ALLOWED':
    case 'ALLOW':
      return 'allowed';
    case 'WARNED':
    case 'WARN':
      return 'warned';
    case 'BLOCKED':
    case 'DENY':
    case 'DENIED':
      return 'blocked';
    case 'APPROVED':
      return 'approved';
    case 'REJECTED':
      return 'rejected';
    default:
      return null;
  }
}

function decisionAllows(decision: string | null | undefined): boolean {
  const normalized = normalizeDecision(decision);
  return normalized === 'allowed' || normalized === 'warned' || normalized === 'approved';
}

function resolveModelFromEnv(): string | null {
  const candidates = [
    process.env.REINS_AGENT_MODEL,
    process.env.OPENCLAW_MODEL,
    process.env.CLAUDE_CODE_MODEL,
    process.env.ANTHROPIC_MODEL,
    process.env.OPENAI_MODEL,
    process.env.MODEL,
    process.env.TOOLSHIELD_MODEL_NAME,
  ];

  for (const candidate of candidates) {
    if (candidate && candidate.trim()) {
      return candidate.trim();
    }
  }

  return null;
}

export function extractModelFromSources(sources: unknown[]): string | null {
  return (
    getStringAtPaths(sources, [
      ['model'],
      ['model_name'],
      ['modelName'],
      ['metadata', 'model'],
      ['metadata', 'model_name'],
      ['tool_response', 'model'],
      ['tool_response', 'model_name'],
      ['tool_response', 'metadata', 'model'],
      ['usage', 'model'],
      ['token_usage', 'model'],
    ]) || resolveModelFromEnv()
  );
}

export function extractTokenUsageFromSources(sources: unknown[]): AuditTokenUsage | null {
  const inputTokens =
    getNumberAtPaths(sources, [
      ['usage', 'input_tokens'],
      ['usage', 'inputTokens'],
      ['usage', 'prompt_tokens'],
      ['usage', 'promptTokens'],
      ['token_usage', 'input_tokens'],
      ['token_usage', 'prompt_tokens'],
      ['tool_response', 'usage', 'input_tokens'],
      ['tool_response', 'usage', 'inputTokens'],
      ['tool_response', 'usage', 'prompt_tokens'],
      ['tool_response', 'usage', 'promptTokens'],
      ['metadata', 'usage', 'input_tokens'],
      ['metadata', 'usage', 'prompt_tokens'],
    ]) ?? undefined;
  const outputTokens =
    getNumberAtPaths(sources, [
      ['usage', 'output_tokens'],
      ['usage', 'outputTokens'],
      ['usage', 'completion_tokens'],
      ['usage', 'completionTokens'],
      ['token_usage', 'output_tokens'],
      ['token_usage', 'completion_tokens'],
      ['tool_response', 'usage', 'output_tokens'],
      ['tool_response', 'usage', 'outputTokens'],
      ['tool_response', 'usage', 'completion_tokens'],
      ['tool_response', 'usage', 'completionTokens'],
      ['metadata', 'usage', 'output_tokens'],
      ['metadata', 'usage', 'completion_tokens'],
    ]) ?? undefined;
  const totalTokens =
    getNumberAtPaths(sources, [
      ['usage', 'total_tokens'],
      ['usage', 'totalTokens'],
      ['token_usage', 'total_tokens'],
      ['tool_response', 'usage', 'total_tokens'],
      ['tool_response', 'usage', 'totalTokens'],
      ['metadata', 'usage', 'total_tokens'],
    ]) ?? (inputTokens !== undefined || outputTokens !== undefined
      ? (inputTokens || 0) + (outputTokens || 0)
      : undefined);

  if (inputTokens === undefined && outputTokens === undefined && totalTokens === undefined) {
    return null;
  }

  return {
    ...(inputTokens !== undefined ? { input_tokens: inputTokens } : {}),
    ...(outputTokens !== undefined ? { output_tokens: outputTokens } : {}),
    ...(totalTokens !== undefined ? { total_tokens: totalTokens } : {}),
  };
}

function normalizeResourceIdentifier(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 512) return null;
  return trimmed;
}

function collectStringValues(
  value: unknown,
  allowedKeys: Set<string>,
  results: Set<string>,
  depth = 0
): void {
  if (depth > 3 || value === null || value === undefined) {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectStringValues(item, allowedKeys, results, depth + 1);
    }
    return;
  }

  if (!isRecord(value)) {
    return;
  }

  for (const [rawKey, entry] of Object.entries(value)) {
    const key = rawKey.toLowerCase();

    if (allowedKeys.has(key)) {
      if (typeof entry === 'string') {
        const normalized = normalizeResourceIdentifier(entry);
        if (normalized) results.add(normalized);
      } else if (Array.isArray(entry)) {
        for (const item of entry) {
          if (typeof item === 'string') {
            const normalized = normalizeResourceIdentifier(item);
            if (normalized) results.add(normalized);
          }
        }
      }
    }

    if (isRecord(entry) || Array.isArray(entry)) {
      collectStringValues(entry, allowedKeys, results, depth + 1);
    }
  }
}

function inferResourceAction(
  moduleName: string | undefined,
  methodName: string | undefined,
  toolName: string
): AuditResourceAction {
  const moduleLower = (moduleName || '').toLowerCase();
  const methodLower = (methodName || '').toLowerCase();
  const toolLower = toolName.toLowerCase();

  if (
    methodLower.includes('delete')
    || toolLower.includes('delete')
    || toolLower.includes('remove')
    || toolLower.includes('trash')
    || toolLower.includes('emptytrash')
  ) {
    return 'delete';
  }
  if (moduleLower === 'filesystem') {
    if (methodLower.includes('write') || toolLower === 'edit' || toolLower === 'write') {
      return 'write';
    }
    if (methodLower.includes('list') || toolLower === 'glob') {
      return 'list';
    }
    return 'read';
  }
  if (moduleLower === 'shell') {
    return 'execute';
  }
  if (moduleLower === 'browser' && methodLower.includes('navigate')) {
    return 'navigate';
  }
  return 'call';
}

function inferUrlResourceType(moduleName: string | undefined): AuditResourceType {
  const moduleLower = (moduleName || '').toLowerCase();
  if (moduleLower === 'network' || moduleLower === 'gateway') {
    return 'api';
  }
  return 'url';
}

export function buildTouchedResources(input: {
  timestamp: string;
  toolName: string;
  moduleName?: string;
  methodName?: string;
  payload?: unknown;
  decision?: string | null;
  policyId?: string | null;
}): TouchedResource[] {
  const action = inferResourceAction(input.moduleName, input.methodName, input.toolName);
  const allowed = decisionAllows(input.decision);
  const resources: TouchedResource[] = [];
  const seen = new Set<string>();
  const payload = Array.isArray(input.payload) ? input.payload[0] : input.payload;
  const pathValues = new Set<string>();
  const urlValues = new Set<string>();
  const commandValues = new Set<string>();

  collectStringValues(
    payload,
    new Set([
      'path',
      'paths',
      'file',
      'file_path',
      'filepath',
      'target',
      'targets',
      'source',
      'source_path',
      'destination',
      'destination_path',
      'old_path',
      'new_path',
      'files',
    ]),
    pathValues
  );
  collectStringValues(
    payload,
    new Set([
      'url',
      'urls',
      'uri',
      'href',
      'endpoint',
      'endpoints',
      'base_url',
      'download_url',
      'upload_url',
      'src',
    ]),
    urlValues
  );
  collectStringValues(payload, new Set(['command', 'cmd']), commandValues);

  const pushResource = (type: AuditResourceType, identifier: string): void => {
    const key = `${type}|${action}|${identifier}`;
    if (seen.has(key)) return;
    seen.add(key);
    resources.push({
      timestamp: input.timestamp,
      type,
      identifier,
      action,
      allowed,
      ...(input.policyId ? { policy_id: input.policyId } : {}),
    });
  };

  if (input.toolName.startsWith('mcp__')) {
    pushResource('mcp_tool', input.toolName);
  } else if ((input.moduleName || '').toLowerCase() !== 'shell') {
    pushResource('tool', input.toolName);
  }

  for (const command of commandValues) {
    pushResource('command', command);
  }
  for (const filePath of pathValues) {
    pushResource('file', filePath);
  }
  for (const url of urlValues) {
    pushResource(inferUrlResourceType(input.moduleName), url);
  }

  return resources;
}

export function resolvePrincipalSync(): AuditPrincipal | null {
  const envId = process.env.REINS_PRINCIPAL_ID?.trim();
  const envEmail = process.env.REINS_PRINCIPAL_EMAIL?.trim();
  const envName = process.env.REINS_PRINCIPAL_NAME?.trim();
  const envType = process.env.REINS_PRINCIPAL_TYPE?.trim() as AuditPrincipalType | undefined;

  if (envId || envEmail || envName) {
    return {
      id: envId || envEmail || envName || 'unknown',
      type: envType || 'user',
      ...(envName ? { display_name: envName } : {}),
      ...(envEmail ? { email: envEmail } : {}),
    };
  }

  const authRecord = readJsonFileSync(getAuthFilePath());
  if (authRecord && isRecord(authRecord.user)) {
    const user = authRecord.user;
    const id = typeof user.id === 'string' && user.id ? user.id : undefined;
    const email = typeof user.email === 'string' && user.email ? user.email : undefined;
    const name = typeof user.name === 'string' && user.name ? user.name : undefined;
    if (id || email || name) {
      return {
        id: id || email || name || 'unknown',
        type: 'user',
        ...(name ? { display_name: name } : {}),
        ...(email ? { email } : {}),
      };
    }
  }

  const configRecord = readJsonFileSync(getDataPath('config.json'));
  const watchtower = configRecord && isRecord(configRecord.watchtower)
    ? configRecord.watchtower
    : null;
  if (watchtower) {
    const email = typeof watchtower.email === 'string' && watchtower.email ? watchtower.email : undefined;
    if (email) {
      return {
        id: email,
        type: 'user',
        email,
      };
    }
  }

  try {
    const username = os.userInfo().username;
    if (username) {
      return {
        id: username,
        type: 'local_user',
        display_name: username,
      };
    }
  } catch {
    // Ignore and fall through.
  }

  return null;
}

export function createAuditPolicyDecision(input: {
  timestamp: string;
  decision: string;
  policyId?: string | null;
  reason?: string | null;
  severity?: string | null;
  interventionType?: string | null;
}): AuditPolicyDecision | null {
  const normalizedDecision = normalizeDecision(input.decision);
  if (!normalizedDecision) {
    return null;
  }

  return {
    timestamp: input.timestamp,
    decision: normalizedDecision,
    allowed: decisionAllows(input.decision),
    ...(input.policyId ? { policy_id: input.policyId } : {}),
    ...(input.reason ? { reason: input.reason } : {}),
    ...(input.severity ? { severity: input.severity } : {}),
    ...(input.interventionType ? { intervention_type: input.interventionType } : {}),
  };
}

export function buildAuditEnvelope(input: BuildAuditEnvelopeInput): AuditEnvelope {
  const runState = getCurrentRunState();
  const metadataSources = input.metadataSources || [];
  const policyDecisions = input.policyDecisions
    ?? (() => {
      const entry = createAuditPolicyDecision({
        timestamp: input.timestamp,
        decision: input.decision || '',
        policyId: input.policyId,
        reason: input.reason,
        severity: input.severity,
        interventionType: input.interventionType,
      });
      return entry ? [entry] : [];
    })();

  return {
    schema_version: AUDIT_SCHEMA_VERSION,
    agent_type: input.agentType,
    session_id: input.sessionId ?? null,
    run_id: runState?.run_id ?? null,
    run_started_at: runState?.started_at ?? null,
    run_ended_at: runState?.ended_at ?? null,
    principal: resolvePrincipalSync(),
    model: extractModelFromSources(metadataSources),
    tokens: extractTokenUsageFromSources(metadataSources),
    touched_resources: buildTouchedResources({
      timestamp: input.timestamp,
      toolName: input.toolName,
      moduleName: input.moduleName,
      methodName: input.methodName,
      payload: input.payload,
      decision: input.decision,
      policyId: input.policyId,
    }),
    policy_decisions: policyDecisions,
  };
}
