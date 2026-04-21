/**
 * Persistent browser session state store.
 *
 * Stores auth/session payloads encrypted on local disk so browser automation can
 * resume authenticated runs across agent restarts.
 */

import crypto from 'crypto';
import fs from 'fs-extra';
import os from 'os';
import { logger } from '../core/Logger';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';

interface StoredRecord {
  updatedAt: string;
  host?: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

interface StoreEnvelope {
  version: string;
  records: Record<string, StoredRecord>;
}

export interface SessionInjectionResult {
  params: Record<string, unknown>;
  injectedFields: string[];
}

const SESSION_FIELDS = [
  'storageState',
  'cookies',
  'localStorage',
  'sessionState',
  'authState',
  'ssoToken',
  'ssoTokens',
];

function deriveKey(): Buffer {
  const seed =
    process.env.REINS_SESSION_KEY
    || process.env.CLAWREINS_SESSION_KEY
    || `${os.homedir()}|${os.hostname()}|reins-browser-sessions`;
  return crypto.createHash('sha256').update(seed).digest();
}

function encryptJson(payload: unknown): { iv: string; tag: string; ciphertext: string } {
  const iv = crypto.randomBytes(12);
  const key = deriveKey();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptJson(record: StoredRecord): Record<string, unknown> | null {
  try {
    const key = deriveKey();
    const iv = Buffer.from(record.iv, 'base64');
    const tag = Buffer.from(record.tag, 'base64');
    const ciphertext = Buffer.from(record.ciphertext, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = JSON.parse(plaintext.toString('utf8'));
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch (error) {
    logger.warn('BrowserSessionStore: failed to decrypt session record', { error });
    return null;
  }
}

function loadStore(): StoreEnvelope {
  try {
    const storeFile = getDataPath('browser-sessions.json');
    fs.ensureDirSync(getReinsDataDir());
    if (!fs.pathExistsSync(storeFile)) {
      return { version: '1.0.0', records: {} };
    }
    const envelope = fs.readJsonSync(storeFile) as StoreEnvelope;
    if (!envelope.records || typeof envelope.records !== 'object') {
      return { version: '1.0.0', records: {} };
    }
    return envelope;
  } catch (error) {
    logger.warn('BrowserSessionStore: failed to load store, reinitializing', { error });
    return { version: '1.0.0', records: {} };
  }
}

function saveStore(envelope: StoreEnvelope): void {
  fs.ensureDirSync(getReinsDataDir());
  fs.writeJsonSync(getPreferredDataPath('browser-sessions.json'), envelope, { spaces: 2 });
}

function extractHost(params: Record<string, unknown>): string | undefined {
  const candidate =
    (typeof params.url === 'string' && params.url) ||
    (typeof params.href === 'string' && params.href) ||
    (typeof params.target === 'string' && params.target);

  if (!candidate) return undefined;
  try {
    const url = new URL(candidate);
    return url.host;
  } catch {
    return undefined;
  }
}

function extractStatePayload(params: Record<string, unknown>): Record<string, unknown> {
  const payload: Record<string, unknown> = {};

  for (const field of SESSION_FIELDS) {
    if (params[field] !== undefined) {
      payload[field] = params[field];
    }
  }

  if (typeof params.headers === 'object' && params.headers !== null) {
    const headers = params.headers as Record<string, unknown>;
    const auth = headers.Authorization ?? headers.authorization;
    const cookie = headers.Cookie ?? headers.cookie;
    if (auth !== undefined || cookie !== undefined) {
      payload.headers = {
        ...(auth !== undefined ? { authorization: auth } : {}),
        ...(cookie !== undefined ? { cookie } : {}),
      };
    }
  }

  return payload;
}

export class BrowserSessionStore {
  static buildSessionId(sessionKey: string | undefined, params: Record<string, unknown>): string {
    const host = extractHost(params) || 'unknown-host';
    const scope = sessionKey || 'global';
    return `${scope}::${host}`;
  }

  static captureState(sessionId: string, params: Record<string, unknown>): string[] {
    const payload = extractStatePayload(params);
    const fields = Object.keys(payload);
    if (fields.length === 0) {
      return [];
    }

    const host = extractHost(params);
    const encrypted = encryptJson(payload);
    const store = loadStore();
    store.records[sessionId] = {
      updatedAt: new Date().toISOString(),
      host,
      ...encrypted,
    };
    saveStore(store);

    logger.info('BrowserSessionStore: captured browser session state', {
      sessionId,
      fields,
      host,
    });

    return fields;
  }

  static injectState(
    sessionId: string,
    params: Record<string, unknown>
  ): SessionInjectionResult {
    const store = loadStore();
    const record = store.records[sessionId];
    if (!record) {
      return { params, injectedFields: [] };
    }

    const persisted = decryptJson(record);
    if (!persisted) {
      return { params, injectedFields: [] };
    }

    const nextParams: Record<string, unknown> = { ...params };
    const injectedFields: string[] = [];

    for (const field of SESSION_FIELDS) {
      if (nextParams[field] === undefined && persisted[field] !== undefined) {
        nextParams[field] = persisted[field];
        injectedFields.push(field);
      }
    }

    if (persisted.headers && typeof persisted.headers === 'object') {
      const persistedHeaders = persisted.headers as Record<string, unknown>;
      if (Object.keys(persistedHeaders).length > 0) {
        const currentHeaders =
          typeof nextParams.headers === 'object' && nextParams.headers !== null
            ? ({ ...(nextParams.headers as Record<string, unknown>) } as Record<string, unknown>)
            : {};

        if (currentHeaders.authorization === undefined && currentHeaders.Authorization === undefined) {
          if (persistedHeaders.authorization !== undefined) {
            currentHeaders.authorization = persistedHeaders.authorization;
            injectedFields.push('headers.authorization');
          }
        }

        if (currentHeaders.cookie === undefined && currentHeaders.Cookie === undefined) {
          if (persistedHeaders.cookie !== undefined) {
            currentHeaders.cookie = persistedHeaders.cookie;
            injectedFields.push('headers.cookie');
          }
        }

        if (Object.keys(currentHeaders).length > 0) {
          nextParams.headers = currentHeaders;
        }
      }
    }

    return { params: nextParams, injectedFields };
  }
}
