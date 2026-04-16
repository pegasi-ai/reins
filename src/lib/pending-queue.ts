/**
 * Buffer/flush decisions that failed to reach Watchtower.
 * Pure Node.js built-ins only — no external deps.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

import type { PolicyDecision } from './watchtower-client';

const PENDING_FILE = path.join(os.homedir(), '.openclaw', 'clawreins', 'pending.jsonl');

function ensurePendingDir(): void {
  const dir = path.dirname(PENDING_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/**
 * Sync-append a single decision to pending.jsonl.
 * Never throws.
 */
export function appendPending(entry: PolicyDecision): void {
  try {
    ensurePendingDir();
    fs.appendFileSync(PENDING_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch {
    // Intentionally swallow — pending queue must never crash the hook.
  }
}

/**
 * Sync-read all pending decisions from pending.jsonl.
 * Ignores malformed lines and missing file.
 */
export function readPending(): PolicyDecision[] {
  try {
    if (!fs.existsSync(PENDING_FILE)) {
      return [];
    }
    const content = fs.readFileSync(PENDING_FILE, 'utf8');
    const results: PolicyDecision[] = [];
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        results.push(JSON.parse(trimmed) as PolicyDecision);
      } catch {
        // Skip malformed lines.
      }
    }
    return results;
  } catch {
    return [];
  }
}

/**
 * Sync-delete (truncate) pending.jsonl.
 */
export function clearPending(): void {
  try {
    if (fs.existsSync(PENDING_FILE)) {
      fs.unlinkSync(PENDING_FILE);
    }
  } catch {
    // Ignore.
  }
}

/**
 * Sync-count of pending decisions. Returns 0 if file is missing.
 */
export function pendingCount(): number {
  try {
    if (!fs.existsSync(PENDING_FILE)) {
      return 0;
    }
    const content = fs.readFileSync(PENDING_FILE, 'utf8');
    return content
      .split('\n')
      .filter((line) => line.trim().length > 0).length;
  } catch {
    return 0;
  }
}
