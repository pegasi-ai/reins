import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  clearAuthSession,
  getAuthFilePath,
  loadAuthSession,
  saveAuthSession,
} = require('../dist/storage/AuthStore.js');
const {
  internalBaseUrlCommand,
} = require('../dist/cli/commands/internal-base-url.js');
const {
  loadWatchtowerSettings,
  resolveInternalBaseUrlTarget,
} = require('../dist/storage/WatchtowerConfig.js');

test('AuthStore saves, loads, and clears auth.json under the platform config dir', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-auth-store-'));
  const originalXdg = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = tempRoot;

  try {
    const authPath = getAuthFilePath();
    assert.equal(authPath, path.join(tempRoot, 'reins', 'auth.json'));

    await saveAuthSession({
      access_token: 'cli_sess_access',
      refresh_token: 'cli_sess_refresh',
      access_token_expires_at: '2026-04-21T10:15:00Z',
      refresh_token_expires_at: '2026-05-21T10:00:00Z',
      user: {
        id: 'user_123',
        name: 'Kevin Wu',
        email: 'user@example.com',
        role: 'dev',
      },
    });

    const loaded = await loadAuthSession();
    assert.equal(loaded.access_token, 'cli_sess_access');
    assert.equal(loaded.user.email, 'user@example.com');

    await clearAuthSession();
    assert.equal(await loadAuthSession(), null);
  } finally {
    if (originalXdg === undefined) {
      delete process.env.XDG_CONFIG_HOME;
    } else {
      process.env.XDG_CONFIG_HOME = originalXdg;
    }
  }
});

test('internal base URL command is gated and persists the selected target', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-internal-base-url-'));
  const openclawHome = path.join(tempRoot, 'openclaw-home');
  mkdirSync(openclawHome, { recursive: true });

  const originalInternal = process.env.REINS_INTERNAL;
  const originalStaging = process.env.REINS_INTERNAL_BASE_URL_STAGING;
  const originalOpenclawHome = process.env.OPENCLAW_HOME;

  try {
    process.env.REINS_INTERNAL = '1';
    process.env.REINS_INTERNAL_BASE_URL_STAGING = 'https://staging.example.test';
    process.env.OPENCLAW_HOME = openclawHome;

    assert.equal(resolveInternalBaseUrlTarget('local'), 'http://localhost:3000');
    assert.equal(resolveInternalBaseUrlTarget('staging'), 'https://staging.example.test');

    await internalBaseUrlCommand('staging');
    const settings = await loadWatchtowerSettings();

    assert.equal(settings.baseUrlTarget, 'staging');
    assert.equal(settings.baseUrl, 'https://staging.example.test');
  } finally {
    if (originalInternal === undefined) {
      delete process.env.REINS_INTERNAL;
    } else {
      process.env.REINS_INTERNAL = originalInternal;
    }

    if (originalStaging === undefined) {
      delete process.env.REINS_INTERNAL_BASE_URL_STAGING;
    } else {
      process.env.REINS_INTERNAL_BASE_URL_STAGING = originalStaging;
    }

    if (originalOpenclawHome === undefined) {
      delete process.env.OPENCLAW_HOME;
    } else {
      process.env.OPENCLAW_HOME = originalOpenclawHome;
    }
  }
});
