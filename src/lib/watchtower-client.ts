/**
 * Watchtower REST API client
 * All imports are Node.js built-ins only — no chalk, no winston, no external deps.
 */

import https from 'https';
import http from 'http';
import { URL } from 'url';

// ─── Exported interfaces ───────────────────────────────────────────────────

export interface ValidateKeyResult {
  org_id: string;
  team_id: string;
  device_id: string;
  email: string;
}

export interface ShellRule {
  pattern: string;
  action: 'BLOCK' | 'WARN' | 'LOG';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface McpRule {
  tool_pattern: string;
  action: 'BLOCK' | 'WARN' | 'LOG';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface PolicyBundle {
  shell_rules: ShellRule[];
  protected_paths: string[];
  mcp_rules: McpRule[];
  updated_at: string;
}

export interface SignupCliResult {
  api_key: string;
  dashboard_url: string;
  message: string;
}

/**
 * POST /api/auth/signup-cli — creates or signs in a user by email and returns
 * a fresh API key + magic-link dashboard URL. No prior key needed.
 */
export async function signupCli(
  email: string,
  baseUrl: string
): Promise<SignupCliResult> {
  const url = buildWatchtowerUrl(baseUrl, '/api/auth/signup-cli');
  const { status, body } = await nodeRequest(
    'POST',
    url,
    {},
    JSON.stringify({ email }),
    15_000
  );

  if (status < 200 || status >= 300) {
    throw new Error(`Reins Cloud signup failed: HTTP ${status} — ${body.trim()}`);
  }

  const raw = JSON.parse(body) as unknown;
  const p = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const api_key = typeof p['api_key'] === 'string' ? p['api_key'] : '';
  const dashboard_url = typeof p['dashboard_url'] === 'string' ? p['dashboard_url'] : baseUrl;
  const message = typeof p['message'] === 'string' ? p['message'] : '';

  if (!api_key) {
    throw new Error('Reins Cloud signup returned no API key.');
  }

  return { api_key, dashboard_url, message };
}

export interface RunStartPayload {
  hostname: string;
  cwd: string;
  claude_code_session_id?: string;
}

export interface RunResult {
  run_id: string;
}

export interface PolicyDecision {
  timestamp: string;
  tool: string;
  action: string;
  decision: 'ALLOWED' | 'BLOCKED' | 'WARNED';
  severity?: string;
  rule?: string;
  decision_time_ms: number;
  module: string;
}

// ─── Internal helpers ──────────────────────────────────────────────────────

function isLoopbackHost(host: string): boolean {
  return ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host.toLowerCase());
}

/**
 * Joins a base URL with a path, stripping trailing slashes from base.
 */
export function buildWatchtowerUrl(baseUrl: string, urlPath: string): string {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error(`Invalid Reins Cloud base URL: ${baseUrl}`);
  }

  if (
    parsed.protocol !== 'https:' &&
    !(parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname))
  ) {
    throw new Error('Reins Cloud base URL must use HTTPS (or http://localhost).');
  }

  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}${urlPath}`;
  return parsed.toString();
}

/**
 * Minimal fetch-like helper using Node.js http/https built-ins.
 * Returns { status, body } or throws on network error.
 */
function nodeRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string | null,
  timeoutMs: number
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch (e) {
      reject(e);
      return;
    }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
        ...(body !== null ? { 'Content-Length': Buffer.byteLength(body).toString() } : {}),
      },
    };

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
      res.on('error', reject);
    });

    req.on('error', reject);

    const timer = setTimeout(() => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    req.on('close', () => clearTimeout(timer));

    if (body !== null) {
      req.write(body);
    }
    req.end();
  });
}

function bearerHeaders(apiKey: string): Record<string, string> {
  return { Authorization: `Bearer ${apiKey}` };
}

// ─── Public API functions ──────────────────────────────────────────────────

/**
 * POST /api/keys/validate — validates an API key and returns org/team/device/email.
 */
export async function validateApiKey(
  apiKey: string,
  baseUrl: string
): Promise<ValidateKeyResult> {
  const url = buildWatchtowerUrl(baseUrl, '/api/keys/validate');
  const { status, body } = await nodeRequest(
    'POST',
    url,
    bearerHeaders(apiKey),
    JSON.stringify({ api_key: apiKey }),
    10_000
  );

  if (status < 200 || status >= 300) {
    throw new Error(`Reins Cloud key validation failed: HTTP ${status} — ${body.trim()}`);
  }

  const payload = JSON.parse(body) as unknown;
  if (!payload || typeof payload !== 'object') {
    throw new Error('Reins Cloud key validation returned an unexpected response.');
  }
  const p = payload as Record<string, unknown>;
  return {
    org_id: typeof p['org_id'] === 'string' ? p['org_id'] : '',
    team_id: typeof p['team_id'] === 'string' ? p['team_id'] : '',
    device_id: typeof p['device_id'] === 'string' ? p['device_id'] : '',
    email: typeof p['email'] === 'string' ? p['email'] : '',
  };
}

/**
 * GET /api/policies — fetch the full policy bundle.
 * Normalizes missing array fields to empty arrays.
 */
export async function fetchPolicies(
  apiKey: string,
  baseUrl: string,
  timeoutMs = 15_000
): Promise<PolicyBundle> {
  const url = buildWatchtowerUrl(baseUrl, '/api/policies');
  const { status, body } = await nodeRequest('GET', url, bearerHeaders(apiKey), null, timeoutMs);

  if (status < 200 || status >= 300) {
    throw new Error(`Failed to fetch policies: HTTP ${status} — ${body.trim()}`);
  }

  const raw = JSON.parse(body) as unknown;
  const p = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  return {
    shell_rules: Array.isArray(p['shell_rules']) ? (p['shell_rules'] as ShellRule[]) : [],
    protected_paths: Array.isArray(p['protected_paths']) ? (p['protected_paths'] as string[]) : [],
    mcp_rules: Array.isArray(p['mcp_rules']) ? (p['mcp_rules'] as McpRule[]) : [],
    updated_at: typeof p['updated_at'] === 'string' ? p['updated_at'] : new Date().toISOString(),
  };
}

/**
 * GET /api/settings/shell_policies — fetch shell policy rules.
 * Handles both array response and { rules: [] } response shapes.
 */
export async function fetchShellPolicies(
  apiKey: string,
  baseUrl: string
): Promise<ShellRule[]> {
  const url = buildWatchtowerUrl(baseUrl, '/api/settings/shell_policies');
  const { status, body } = await nodeRequest('GET', url, bearerHeaders(apiKey), null, 15_000);

  if (status < 200 || status >= 300) {
    throw new Error(`Failed to fetch shell policies: HTTP ${status} — ${body.trim()}`);
  }

  const raw = JSON.parse(body) as unknown;

  if (Array.isArray(raw)) {
    return raw as ShellRule[];
  }

  if (raw && typeof raw === 'object') {
    const r = raw as Record<string, unknown>;
    if (Array.isArray(r['rules'])) {
      return r['rules'] as ShellRule[];
    }
  }

  return [];
}

/**
 * POST /api/ingest/runs/start — starts a new run and returns the run_id.
 */
export async function startRun(
  apiKey: string,
  baseUrl: string,
  payload: RunStartPayload
): Promise<RunResult> {
  const url = buildWatchtowerUrl(baseUrl, '/api/ingest/runs/start');
  const { status, body } = await nodeRequest(
    'POST',
    url,
    bearerHeaders(apiKey),
    JSON.stringify(payload),
    10_000
  );

  if (status < 200 || status >= 300) {
    throw new Error(`Failed to start run: HTTP ${status} — ${body.trim()}`);
  }

  const raw = JSON.parse(body) as unknown;
  const p = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const runId = typeof p['run_id'] === 'string' ? p['run_id'] : '';
  if (!runId) {
    throw new Error('startRun: response missing run_id');
  }
  return { run_id: runId };
}

/**
 * POST /api/runs/:id/policy_decisions — logs a single decision.
 * Default timeout is 200ms (fire-and-forget from hooks).
 */
export async function logPolicyDecision(
  apiKey: string,
  baseUrl: string,
  runId: string,
  decision: PolicyDecision,
  timeoutMs = 200
): Promise<void> {
  const url = buildWatchtowerUrl(baseUrl, `/api/runs/${runId}/policy_decisions`);
  await nodeRequest('POST', url, bearerHeaders(apiKey), JSON.stringify(decision), timeoutMs);
  // We intentionally do not throw on non-2xx here — hooks must never block on this.
}

/**
 * Batch flush pending decisions. Returns counts of successes and failures.
 * Never throws — catches per-item failures.
 */
export async function flushDecisions(
  apiKey: string,
  baseUrl: string,
  runId: string,
  decisions: PolicyDecision[]
): Promise<{ succeeded: number; failed: number }> {
  let succeeded = 0;
  let failed = 0;

  for (const decision of decisions) {
    try {
      const url = buildWatchtowerUrl(baseUrl, `/api/runs/${runId}/policy_decisions`);
      const { status } = await nodeRequest(
        'POST',
        url,
        bearerHeaders(apiKey),
        JSON.stringify(decision),
        10_000
      );
      if (status >= 200 && status < 300) {
        succeeded++;
      } else {
        failed++;
      }
    } catch {
      failed++;
    }
  }

  return { succeeded, failed };
}
