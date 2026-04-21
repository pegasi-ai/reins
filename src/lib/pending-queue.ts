/**
 * Buffer/flush decisions that failed to reach Watchtower.
 * Pure Node.js built-ins only — no external deps.
 */

import fs from 'fs';

import type { PolicyDecision } from './watchtower-client';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';

function ensurePendingDir(): void {
  const reinsDataDir = getReinsDataDir();
  if (!fs.existsSync(reinsDataDir)) {
    fs.mkdirSync(reinsDataDir, { recursive: true });
  }
}

/**
 * Sync-append a single decision to pending.jsonl.
 * Never throws.
 */
export function appendPending(entry: PolicyDecision): void {
  try {
    ensurePendingDir();
    fs.appendFileSync(getPreferredDataPath('pending.jsonl'), JSON.stringify(entry) + '\n', 'utf8');
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
    const pendingFile = getDataPath('pending.jsonl');
    if (!fs.existsSync(pendingFile)) {
      return [];
    }
    const content = fs.readFileSync(pendingFile, 'utf8');
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
    const pendingFile = getDataPath('pending.jsonl');
    if (fs.existsSync(pendingFile)) {
      fs.unlinkSync(pendingFile);
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
    const pendingFile = getDataPath('pending.jsonl');
    if (!fs.existsSync(pendingFile)) {
      return 0;
    }
    const content = fs.readFileSync(pendingFile, 'utf8');
    return content
      .split('\n')
      .filter((line) => line.trim().length > 0).length;
  } catch {
    return 0;
  }
}
