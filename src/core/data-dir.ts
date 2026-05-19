import { existsSync, mkdirSync } from 'fs';
import os from 'os';
import path from 'path';

export function getOpenclawHome(): string {
  if (process.env.OPENCLAW_HOME) return process.env.OPENCLAW_HOME;

  const home = os.homedir();

  // Prefer an already-existing openclaw home
  const openclawHome = path.join(home, '.openclaw');
  if (existsSync(openclawHome)) return openclawHome;

  // If Claude Code is present but not OpenClaw, use ~/.claude/reins
  const claudeHome = path.join(home, '.claude');
  if (existsSync(claudeHome)) return claudeHome;

  // Fall back to ~/.openclaw (will be created on first write)
  return openclawHome;
}

export function getReinsDataDir(): string {
  return path.join(getOpenclawHome(), 'reins');
}

export function getLegacyClawreinsDataDir(): string {
  return path.join(getOpenclawHome(), 'clawreins');
}

export function resolveDataDir(): string {
  const reinsDataDir = getReinsDataDir();
  if (existsSync(reinsDataDir)) {
    return reinsDataDir;
  }
  const legacyDataDir = getLegacyClawreinsDataDir();
  if (existsSync(legacyDataDir)) {
    return legacyDataDir;
  }
  return reinsDataDir;
}

export function ensurePreferredDataDirSync(): string {
  const reinsDataDir = getReinsDataDir();
  if (!existsSync(reinsDataDir)) {
    mkdirSync(reinsDataDir, { recursive: true });
  }
  return reinsDataDir;
}

export function getPreferredDataPath(...segments: string[]): string {
  return path.join(getReinsDataDir(), ...segments);
}

export function getDataPath(...segments: string[]): string {
  const preferredPath = getPreferredDataPath(...segments);
  if (existsSync(preferredPath)) {
    return preferredPath;
  }

  const legacyPath = path.join(getLegacyClawreinsDataDir(), ...segments);
  if (existsSync(legacyPath)) {
    return legacyPath;
  }

  return preferredPath;
}
