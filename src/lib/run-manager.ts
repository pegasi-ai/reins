/**
 * Lazy run lifecycle manager.
 * Pure Node.js built-ins only — no external deps, no imports from the rest of the codebase.
 */

import fs from 'fs';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';

interface CurrentRun {
  run_id: string;
  started_at: string;
}

function ensureRunDir(): void {
  const reinsDataDir = getReinsDataDir();
  if (!fs.existsSync(reinsDataDir)) {
    fs.mkdirSync(reinsDataDir, { recursive: true });
  }
}

/**
 * Sync-read current_run.json and return the run_id, or null if missing/invalid.
 */
export function getCurrentRunId(): string | null {
  try {
    const currentRunFile = getDataPath('current_run.json');
    if (!fs.existsSync(currentRunFile)) {
      return null;
    }
    const raw = fs.readFileSync(currentRunFile, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === 'object') {
      const r = parsed as Record<string, unknown>;
      if (typeof r['run_id'] === 'string' && r['run_id'].length > 0) {
        return r['run_id'];
      }
    }
    return null;
  } catch {
    return null;
  }
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
