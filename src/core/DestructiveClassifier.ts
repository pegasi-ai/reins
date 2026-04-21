/**
 * Reins destructive action classifier.
 * Lightweight regex/heuristic classifier for pre-execution gating.
 */

import crypto from 'crypto';
import os from 'os';
import path from 'path';

export type DestructiveSeverity = 'HIGH' | 'CATASTROPHIC';

export interface DestructiveClassification {
  isDestructive: boolean;
  severity: DestructiveSeverity;
  reasons: string[];
  bulkCount?: number;
  target?: string;
}

export interface DestructiveClassifierMeta {
  moduleName?: string;
  methodName?: string;
  bulkThreshold?: number;
}

const DEFAULT_BULK_THRESHOLD = 20;
const BULK_KEY_HINTS =
  /(count|total|ids?|messages?|emails?|items?|records?|rows?|users?|files?|bulk)/i;
const HIGH_RISK_VERBS = [
  'delete',
  'remove',
  'rm',
  'purge',
  'empty',
  'revoke',
  'disable',
  'terminate',
  'reset',
  'wipe',
  'drop',
  'truncate',
  'overwrite',
];

function parseBulkThreshold(value: string | undefined): number {
  if (!value) return DEFAULT_BULK_THRESHOLD;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_BULK_THRESHOLD;
}

export function getBulkThreshold(): number {
  return parseBulkThreshold(process.env.REINS_BULK_THRESHOLD || process.env.CLAWREINS_BULK_THRESHOLD);
}

export function isDestructiveGatingEnabled(): boolean {
  return (process.env.REINS_DESTRUCTIVE_GATING || process.env.CLAWREINS_DESTRUCTIVE_GATING || 'on').toLowerCase() !== 'off';
}

function stableStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function flattenText(value: unknown): string {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(flattenText).join(' ');
  if (typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).map(flattenText).join(' ');
  }
  return '';
}

function collectNumericSignals(value: unknown, currentPath: string = ''): Array<{ path: string; value: number }> {
  const signals: Array<{ path: string; value: number }> = [];

  if (typeof value === 'number' && Number.isFinite(value)) {
    signals.push({ path: currentPath || 'value', value });
    return signals;
  }

  if (Array.isArray(value)) {
    signals.push({ path: `${currentPath || 'array'}.length`, value: value.length });
    value.forEach((item, index) => {
      signals.push(...collectNumericSignals(item, `${currentPath}[${index}]`));
    });
    return signals;
  }

  if (typeof value === 'string') {
    const destructiveCountRegex =
      /\b(?:delete|remove|rm|purge|trash|empty|wipe|drop|truncate|overwrite)\D{0,16}(\d{2,})\b/gi;
    let destructiveMatch: RegExpExecArray | null;
    while ((destructiveMatch = destructiveCountRegex.exec(value)) !== null) {
      signals.push({ path: `${currentPath || 'string'}.destructive_count`, value: Number(destructiveMatch[1]) });
    }

    const itemCountRegex = /\b(\d{2,})\s*(emails?|messages?|items?|records?|rows?|users?|files?)\b/gi;
    let itemMatch: RegExpExecArray | null;
    while ((itemMatch = itemCountRegex.exec(value)) !== null) {
      signals.push({ path: `${currentPath || 'string'}.${itemMatch[2]}`, value: Number(itemMatch[1]) });
    }
    return signals;
  }

  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const nextPath = currentPath ? `${currentPath}.${key}` : key;
      signals.push(...collectNumericSignals(child, nextPath));
    }
  }

  return signals;
}

function containsRiskVerb(text: string): boolean {
  const lower = text.toLowerCase();
  return HIGH_RISK_VERBS.some((verb) => new RegExp(`\\b${verb}\\b`, 'i').test(lower));
}

function detectBulkCount(args: unknown, threshold: number): number | undefined {
  const candidates = collectNumericSignals(args).filter((signal) => signal.value > threshold);
  if (candidates.length === 0) return undefined;

  const hinted = candidates.filter((candidate) => BULK_KEY_HINTS.test(candidate.path));
  const pool = hinted.length > 0 ? hinted : candidates;
  return pool.reduce((max, candidate) => Math.max(max, candidate.value), 0);
}

function extractTarget(toolName: string, args: unknown): string | undefined {
  const text = flattenText(args);
  const fullText = `${toolName} ${text}`;

  const inboxMatch = /in:(inbox|trash|spam|sent|drafts)/i.exec(fullText);
  if (inboxMatch) {
    return `gmail.com (${inboxMatch[1].toLowerCase()})`;
  }

  const pathMatch =
    /((?:\/|~\/)[\w./-]+|[a-zA-Z]:\\[^\s]+)/.exec(fullText);
  if (pathMatch) {
    return pathMatch[1];
  }

  const urlMatch = /(https?:\/\/[^\s"'<>]+)/i.exec(fullText);
  if (urlMatch) {
    try {
      return new URL(urlMatch[1]).host;
    } catch {
      return urlMatch[1];
    }
  }

  return undefined;
}

function getPathCandidates(args: unknown): string[] {
  if (!args || typeof args !== 'object') return [];

  const out: string[] = [];
  const walk = (value: unknown): void => {
    if (typeof value === 'string') {
      if (value.startsWith('/') || value.startsWith('~/') || /^[a-zA-Z]:\\/.test(value)) {
        out.push(value);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(walk);
      return;
    }
    if (value && typeof value === 'object') {
      Object.values(value as Record<string, unknown>).forEach(walk);
    }
  };

  walk(args);
  return out;
}

function isSensitivePath(pathValue: string): boolean {
  const normalized = pathValue.toLowerCase();
  return (
    normalized.startsWith('/etc') ||
    normalized.includes('/.ssh') ||
    normalized.includes('keychain') ||
    normalized.includes('library/keychains') ||
    normalized.includes('appdata\\local\\google\\chrome\\user data') ||
    normalized.includes('/.config/google-chrome') ||
    normalized.includes('/.mozilla/firefox')
  );
}

function isTempPath(pathValue: string): boolean {
  const expanded = pathValue.startsWith('~/')
    ? path.join(os.homedir(), pathValue.slice(2))
    : pathValue;
  const normalized = expanded.toLowerCase();
  const tempRoot = os.tmpdir().toLowerCase();
  return normalized.startsWith('/tmp') || normalized.startsWith('/var/tmp') || normalized.startsWith(tempRoot);
}

function asCommand(args: unknown): string {
  if (typeof args === 'string') return args;
  if (args && typeof args === 'object') {
    const obj = args as Record<string, unknown>;
    for (const key of ['command', 'cmd', 'script', 'input']) {
      const value = obj[key];
      if (typeof value === 'string') {
        return value;
      }
    }
  }
  return flattenText(args);
}

function pushUnique(reasons: string[], reason: string): void {
  if (!reasons.includes(reason)) {
    reasons.push(reason);
  }
}

export function hashArgs(args: unknown): string {
  const raw = stableStringify(args);
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

export function classifyDestructiveAction(
  toolName: string,
  args: unknown,
  meta: DestructiveClassifierMeta = {}
): DestructiveClassification {
  const bulkThreshold = meta.bulkThreshold ?? getBulkThreshold();
  const moduleName = (meta.moduleName || '').toLowerCase();
  const methodName = (meta.methodName || '').toLowerCase();
  const normalizedTool = toolName.toLowerCase();
  const text = `${normalizedTool} ${flattenText(args).toLowerCase()}`;
  const reasons: string[] = [];

  const bulkCount = detectBulkCount(args, bulkThreshold);
  if (bulkCount !== undefined) {
    pushUnique(reasons, 'bulk_delete');
  }

  if (containsRiskVerb(text)) {
    pushUnique(reasons, 'destructive_verb');
  }

  let catastrophic = false;

  // Gmail catastrophic buckets
  if (normalizedTool.includes('gmail') || moduleName === 'gmail') {
    if (/empty|purge|trash all|delete all/.test(text)) {
      catastrophic = true;
      pushUnique(reasons, 'gmail_full_purge');
    }
    if ((normalizedTool.includes('deletemessages') || methodName === 'deletemessages') && bulkCount !== undefined) {
      catastrophic = true;
      pushUnique(reasons, 'gmail_bulk_delete');
    }
    if (/delete(label|folder)|remove(label|folder)/.test(text)) {
      catastrophic = true;
      pushUnique(reasons, 'gmail_delete_label');
    }
  }

  // Shell catastrophic buckets
  if (moduleName === 'shell' || normalizedTool === 'bash' || normalizedTool === 'exec') {
    const command = asCommand(args).toLowerCase();
    if (
      /\brm\s+-rf\b/.test(command) ||
      /\bdel\s+\/[sqf]/.test(command) ||
      /\brmdir\s+\/s\b/.test(command) ||
      /\bremove-item\b/.test(command) ||
      /\bformat\b/.test(command) ||
      /\bdiskpart\b/.test(command)
    ) {
      catastrophic = true;
      pushUnique(reasons, 'shell_wipe_command');
    }
  }

  // Filesystem catastrophic buckets
  const pathCandidates = getPathCandidates(args);
  if (moduleName === 'filesystem') {
    const recursiveFlag = stableStringify(args).toLowerCase().includes('"recursive":true');
    if ((methodName === 'delete' || methodName === 'remove') && recursiveFlag) {
      catastrophic = true;
      pushUnique(reasons, 'filesystem_recursive_delete');
    }

    if (methodName === 'delete') {
      const outsideTemp = pathCandidates.some((pathValue) => !isTempPath(pathValue));
      if (outsideTemp) {
        catastrophic = true;
        pushUnique(reasons, 'filesystem_delete_outside_temp');
      }
    }
  }

  if (pathCandidates.some(isSensitivePath)) {
    catastrophic = true;
    pushUnique(reasons, 'sensitive_path');
  }

  // Billing / payment / credentials
  if (/update[_\s-]?payment[_\s-]?method|card|bank|wire/.test(text)) {
    catastrophic = true;
    pushUnique(reasons, 'billing_change');
  }

  // Access control destructive operations
  if (/revoke.*admin|delete.*user|disable.*sso|remove.*admin/.test(text)) {
    catastrophic = true;
    pushUnique(reasons, 'access_control_change');
  }

  // Optional network host risk (quick heuristic)
  if (moduleName === 'network' || /(request|webhook|fetch)/.test(normalizedTool)) {
    const urlMatch = /(https?:\/\/[^\s"'<>]+)/i.exec(text);
    if (urlMatch) {
      try {
        const host = new URL(urlMatch[1]).hostname.toLowerCase();
        if (!host.endsWith('.local') && host !== 'localhost' && !host.startsWith('127.')) {
          pushUnique(reasons, 'network_unknown_host');
        }
      } catch {
        // ignore parse failures
      }
    }
  }

  const isDestructive = catastrophic || reasons.length > 0;
  const severity: DestructiveSeverity = catastrophic ? 'CATASTROPHIC' : 'HIGH';

  return {
    isDestructive,
    severity,
    reasons,
    bulkCount,
    target: extractTarget(toolName, args),
  };
}
