import { existsSync, mkdirSync } from 'fs';
import os from 'os';
import path from 'path';

export function getOpenclawHome(): string {
  return process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
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
