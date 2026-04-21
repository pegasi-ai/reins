import { chmodSync } from 'fs';
import fs from 'fs-extra';
import { logger } from '../core/Logger';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';

export const DEFAULT_WATCHTOWER_BASE_URL = 'https://app.pegasi.ai';

export interface WatchtowerSettings {
  apiKey?: string;
  baseUrl?: string;
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
  const savedApiKey = saved?.apiKey?.trim();
  if (!savedApiKey) {
    return null;
  }

  return {
    apiKey: savedApiKey,
    baseUrl: saved?.baseUrl?.trim() || DEFAULT_WATCHTOWER_BASE_URL,
    dashboardUrl: saved?.dashboardUrl?.trim(),
    email: saved?.email?.trim(),
    source: 'config',
  };
}

export function getWatchtowerConfigPath(): string {
  return getWatchtowerConfigFilePath();
}
