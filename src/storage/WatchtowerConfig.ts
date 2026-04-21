import { chmodSync } from 'fs';
import fs from 'fs-extra';
import { logger } from '../core/Logger';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';
import {
  AuthSession,
  clearAuthSession,
  expiresWithin,
  isExpired,
  loadAuthSession,
  saveAuthSession,
} from './AuthStore';
import { CliAuthCompleteResponse, WatchtowerHttpError, refreshCliAuthSession } from '../lib/watchtower-client';

export const DEFAULT_WATCHTOWER_BASE_URL = 'https://app.pegasi.ai';
export const INTERNAL_BASE_URL_GATE_ENV = 'REINS_INTERNAL';

export type InternalWatchtowerBaseUrlTarget = 'local' | 'staging' | 'production';

export interface WatchtowerSettings {
  apiKey?: string;
  baseUrl?: string;
  baseUrlTarget?: InternalWatchtowerBaseUrlTarget;
  connectedAt?: string;
  dashboardUrl?: string;
  email?: string;
  org_id?: string;
  team_id?: string;
  device_id?: string;
}

interface ReinsConfigFile {
  watchtower?: WatchtowerSettings;
  [key: string]: unknown;
}

export interface WatchtowerCredentials {
  apiKey: string;
  baseUrl: string;
  dashboardUrl?: string;
  email?: string;
  source: 'config' | 'env';
}

export interface CliAuthAccess {
  accessToken: string;
  baseUrl: string;
  dashboardUrl?: string;
  email?: string;
  source: 'config';
}

function toAuthSession(response: CliAuthCompleteResponse): AuthSession {
  return {
    access_token: response.access_token,
    refresh_token: response.refresh_token,
    access_token_expires_at: response.access_token_expires_at,
    refresh_token_expires_at: response.refresh_token_expires_at,
    user: response.user,
  };
}

async function refreshStoredSession(
  session: AuthSession,
  baseUrl: string,
  currentSettings: WatchtowerSettings | null
): Promise<AuthSession | null> {
  try {
    const refreshed = await refreshCliAuthSession(session.refresh_token, baseUrl);
    const nextSession = toAuthSession(refreshed);
    await saveAuthSession(nextSession);
    await saveWatchtowerSettings({
      ...currentSettings,
      baseUrl,
      dashboardUrl: refreshed.dashboard_url || currentSettings?.dashboardUrl,
      email: refreshed.user.email,
      connectedAt: new Date().toISOString(),
    });
    return nextSession;
  } catch (error) {
    if (error instanceof WatchtowerHttpError && (error.status === 401 || error.status === 403)) {
      await clearAuthSession();
      logger.warn('Stored CLI auth session was rejected and has been cleared.', { status: error.status });
      return null;
    }

    logger.warn('Failed to refresh stored CLI auth session.', { error, baseUrl });
    return null;
  }
}

function getWatchtowerConfigFilePath(): string {
  return getDataPath('config.json');
}

async function loadReinsConfigFile(): Promise<ReinsConfigFile> {
  const configFile = getWatchtowerConfigFilePath();
  await fs.ensureDir(getReinsDataDir());

  if (!(await fs.pathExists(configFile))) {
    return {};
  }

  const raw = (await fs.readJson(configFile)) as unknown;
  return raw && typeof raw === 'object' ? (raw as ReinsConfigFile) : {};
}

export async function loadWatchtowerSettings(): Promise<WatchtowerSettings | null> {
  try {
    const config = await loadReinsConfigFile();
    const settings = config.watchtower;
    return settings && typeof settings === 'object' ? settings : null;
  } catch (error) {
    logger.warn('Failed to load Watchtower settings', { error, path: getWatchtowerConfigFilePath() });
    return null;
  }
}

export function isInternalBaseUrlSwitchingEnabled(): boolean {
  return process.env[INTERNAL_BASE_URL_GATE_ENV]?.trim() === '1';
}

export function resolveInternalBaseUrlTarget(target: InternalWatchtowerBaseUrlTarget): string {
  if (target === 'local') {
    return process.env.REINS_INTERNAL_BASE_URL_LOCAL?.trim() || 'http://localhost:3000';
  }

  if (target === 'staging') {
    const stagingUrl = process.env.REINS_INTERNAL_BASE_URL_STAGING?.trim();
    if (!stagingUrl) {
      throw new Error('REINS_INTERNAL_BASE_URL_STAGING is not configured.');
    }
    return stagingUrl;
  }

  return process.env.REINS_INTERNAL_BASE_URL_PRODUCTION?.trim() || DEFAULT_WATCHTOWER_BASE_URL;
}

export async function saveWatchtowerSettings(settings: WatchtowerSettings): Promise<string> {
  const configFile = getPreferredDataPath('config.json');
  const config = await loadReinsConfigFile();
  config.watchtower = {
    ...config.watchtower,
    ...settings,
    connectedAt: settings.connectedAt || new Date().toISOString(),
  };

  await fs.ensureDir(getReinsDataDir());
  await fs.writeJson(configFile, config, { spaces: 2 });

  try {
    chmodSync(configFile, 0o600);
  } catch {
    // Ignore chmod failures on platforms/filesystems that do not support POSIX modes.
  }

  return configFile;
}

export async function resolveWatchtowerCredentials(): Promise<WatchtowerCredentials | null> {
  const envBaseUrl =
    process.env.REINS_WATCHTOWER_BASE_URL?.trim()
    || process.env.CLAWREINS_WATCHTOWER_BASE_URL?.trim();
  const envApiKey =
    process.env.REINS_WATCHTOWER_API_KEY?.trim()
    || process.env.CLAWREINS_WATCHTOWER_API_KEY?.trim();

  if (envBaseUrl && envApiKey) {
    return {
      apiKey: envApiKey,
      baseUrl: envBaseUrl,
      source: 'env',
    };
  }

  const saved = await loadWatchtowerSettings();
  const baseUrl = saved?.baseUrl?.trim() || envBaseUrl || DEFAULT_WATCHTOWER_BASE_URL;
  let session = await loadAuthSession();

  if (session) {
    if (isExpired(session.refresh_token_expires_at)) {
      await clearAuthSession();
      session = null;
    } else if (expiresWithin(session.access_token_expires_at, 60_000)) {
      session = await refreshStoredSession(session, baseUrl, saved);
    }
  }

  const savedApiKey = saved?.apiKey?.trim();
  if (savedApiKey) {
    return {
      apiKey: savedApiKey,
      baseUrl,
      dashboardUrl: saved?.dashboardUrl?.trim(),
      email: session?.user.email || saved?.email?.trim(),
      source: 'config',
    };
  }

  if (session && !isExpired(session.access_token_expires_at)) {
    return {
      apiKey: session.access_token,
      baseUrl,
      dashboardUrl: saved?.dashboardUrl?.trim(),
      email: session.user.email,
      source: 'config',
    };
  }

  if (!savedApiKey) {
    return null;
  }

  return {
    apiKey: savedApiKey,
    baseUrl,
    dashboardUrl: saved?.dashboardUrl?.trim(),
    email: saved?.email?.trim(),
    source: 'config',
  };
}

export async function resolveCliAuthAccess(): Promise<CliAuthAccess | null> {
  const saved = await loadWatchtowerSettings();
  const baseUrl =
    saved?.baseUrl?.trim()
    || process.env.REINS_WATCHTOWER_BASE_URL?.trim()
    || process.env.CLAWREINS_WATCHTOWER_BASE_URL?.trim()
    || DEFAULT_WATCHTOWER_BASE_URL;

  let session = await loadAuthSession();

  if (!session) {
    return null;
  }

  if (isExpired(session.refresh_token_expires_at)) {
    await clearAuthSession();
    return null;
  }

  if (expiresWithin(session.access_token_expires_at, 60_000)) {
    session = await refreshStoredSession(session, baseUrl, saved);
  }

  if (!session || isExpired(session.access_token_expires_at)) {
    return null;
  }

  return {
    accessToken: session.access_token,
    baseUrl,
    dashboardUrl: saved?.dashboardUrl?.trim(),
    email: session.user.email,
    source: 'config',
  };
}

export function getWatchtowerConfigPath(): string {
  return getWatchtowerConfigFilePath();
}
