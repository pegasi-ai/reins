/**
 * Lazy run lifecycle manager.
 * Pure Node.js built-ins only — no external deps, no imports from the rest of the codebase.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

const CURRENT_RUN_FILE = path.join(os.homedir(), '.openclaw', 'clawreins', 'current_run.json');

interface CurrentRun {
  run_id: string;
  started_at: string;
}

function ensureRunDir(): void {
  const dir = path.dirname(CURRENT_RUN_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/**
 * Sync-read current_run.json and return the run_id, or null if missing/invalid.
 */
export function getCurrentRunId(): string | null {
  try {
    if (!fs.existsSync(CURRENT_RUN_FILE)) {
      return null;
    }
    const raw = fs.readFileSync(CURRENT_RUN_FILE, 'utf8');
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
  fs.writeFileSync(CURRENT_RUN_FILE, JSON.stringify(entry, null, 2), 'utf8');
}

/**
 * Sync-delete current_run.json if it exists.
 */
export function clearCurrentRun(): void {
  try {
    if (fs.existsSync(CURRENT_RUN_FILE)) {
      fs.unlinkSync(CURRENT_RUN_FILE);
    }
  } catch {
    // Ignore.
  }
}
