/**
 * Lazy run lifecycle manager.
 * Pure Node.js built-ins only — no external deps, no imports from the rest of the codebase.
 */

import fs from 'fs';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';

export interface CurrentRun {
  run_id: string;
  started_at: string;
  ended_at?: string | null;
}

function ensureRunDir(): void {
  const reinsDataDir = getReinsDataDir();
  if (!fs.existsSync(reinsDataDir)) {
    fs.mkdirSync(reinsDataDir, { recursive: true });
  }
}

export function getCurrentRunState(): CurrentRun | null {
  try {
    const currentRunFile = getDataPath('current_run.json');
    if (!fs.existsSync(currentRunFile)) {
      return null;
    }
    const raw = fs.readFileSync(currentRunFile, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === 'object') {
      const record = parsed as Record<string, unknown>;
      if (typeof record['run_id'] === 'string' && record['run_id'].length > 0) {
        return {
          run_id: record['run_id'],
          started_at:
            typeof record['started_at'] === 'string' ? record['started_at'] : new Date().toISOString(),
          ended_at: typeof record['ended_at'] === 'string' ? record['ended_at'] : null,
        };
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Sync-read current_run.json and return the run_id, or null if missing/invalid.
 */
export function getCurrentRunId(): string | null {
  return getCurrentRunState()?.run_id ?? null;
}

/**
 * Sync-write current_run.json with the given run_id.
 */
export function saveCurrentRun(run_id: string): void {
  ensureRunDir();
  const entry: CurrentRun = {
    run_id,
    started_at: new Date().toISOString(),
  };
  fs.writeFileSync(getPreferredDataPath('current_run.json'), JSON.stringify(entry, null, 2), 'utf8');
}

/**
 * Sync-delete current_run.json if it exists.
 */
export function clearCurrentRun(): void {
  try {
    const currentRunFile = getDataPath('current_run.json');
    if (fs.existsSync(currentRunFile)) {
      fs.unlinkSync(currentRunFile);
    }
  } catch {
    // Ignore.
  }
}
