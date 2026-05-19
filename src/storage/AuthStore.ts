import { chmodSync } from 'fs';
import os from 'os';
import path from 'path';
import fs from 'fs-extra';

export type AuthUserRole = 'dev' | 'admin';

export interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  role: AuthUserRole;
}

export interface AuthSession {
  access_token: string;
  refresh_token: string;
  access_token_expires_at: string;
  refresh_token_expires_at: string;
  user: AuthenticatedUser;
}

function getPlatformConfigRoot(): string {
  const xdgConfigHome = process.env.XDG_CONFIG_HOME?.trim();
  if (xdgConfigHome) {
    return xdgConfigHome;
  }

  if (process.platform === 'win32') {
    const appData = process.env.APPDATA?.trim();
    if (appData) {
      return appData;
    }
  }

  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support');
  }

  return path.join(os.homedir(), '.config');
}

export function getAuthConfigDir(): string {
  return path.join(getPlatformConfigRoot(), 'reins');
}

export function getAuthFilePath(): string {
  return path.join(getAuthConfigDir(), 'auth.json');
}

export async function loadAuthSession(): Promise<AuthSession | null> {
  const authFile = getAuthFilePath();
  if (!(await fs.pathExists(authFile))) {
    return null;
  }

  const raw = (await fs.readJson(authFile)) as unknown;
  if (!raw || typeof raw !== 'object') {
    return null;
  }

  const record = raw as Record<string, unknown>;
  const userRaw = record['user'];
  const userRecord = userRaw && typeof userRaw === 'object'
    ? userRaw as Record<string, unknown>
    : null;

  if (!userRecord) {
    return null;
  }

  const accessToken = typeof record['access_token'] === 'string' ? record['access_token'] : '';
  const refreshToken = typeof record['refresh_token'] === 'string' ? record['refresh_token'] : '';
  const accessTokenExpiresAt =
    typeof record['access_token_expires_at'] === 'string' ? record['access_token_expires_at'] : '';
  const refreshTokenExpiresAt =
    typeof record['refresh_token_expires_at'] === 'string' ? record['refresh_token_expires_at'] : '';
  const role = userRecord['role'];

  if (
    !accessToken
    || !refreshToken
    || !accessTokenExpiresAt
    || !refreshTokenExpiresAt
    || typeof userRecord['id'] !== 'string'
    || typeof userRecord['name'] !== 'string'
    || typeof userRecord['email'] !== 'string'
    || (role !== 'dev' && role !== 'admin')
  ) {
    return null;
  }

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    access_token_expires_at: accessTokenExpiresAt,
    refresh_token_expires_at: refreshTokenExpiresAt,
    user: {
      id: userRecord['id'],
      name: userRecord['name'],
      email: userRecord['email'],
      role,
    },
  };
}

export async function saveAuthSession(session: AuthSession): Promise<string> {
  const authFile = getAuthFilePath();
  await fs.ensureDir(path.dirname(authFile));
  await fs.writeJson(authFile, session, { spaces: 2 });

  try {
    chmodSync(authFile, 0o600);
  } catch {
    // Ignore chmod failures on platforms/filesystems without POSIX modes.
  }

  return authFile;
}

export async function clearAuthSession(): Promise<void> {
  await fs.remove(getAuthFilePath());
}

function parseIsoTimestamp(value: string): number {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : Number.NaN;
}

export function isExpired(isoTimestamp: string): boolean {
  const timestamp = parseIsoTimestamp(isoTimestamp);
  return Number.isNaN(timestamp) || timestamp <= Date.now();
}

export function expiresWithin(isoTimestamp: string, windowMs: number): boolean {
  const timestamp = parseIsoTimestamp(isoTimestamp);
  return Number.isNaN(timestamp) || timestamp - Date.now() <= windowMs;
}
