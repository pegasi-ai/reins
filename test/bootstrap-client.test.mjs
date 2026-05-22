import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import https from 'node:https';
import { Readable } from 'node:stream';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
const { redeemReinsBootstrap } = require('../dist/lib/watchtower-client.js');
const {
  getWatchtowerConfigPath,
  resolveWatchtowerBootstrap,
  saveWatchtowerSettings,
} = require('../dist/storage/WatchtowerConfig.js');

test('resolveWatchtowerBootstrap reads token from environment', async () => {
  const originalToken = process.env.REINS_ENROLLMENT_TOKEN;
  const originalBaseUrl = process.env.REINS_CLOUD_BASE_URL;
  try {
    process.env.REINS_ENROLLMENT_TOKEN = 'bootstrap_123';
    process.env.REINS_CLOUD_BASE_URL = 'https://app-staging.pegasi.ai';
    const bootstrap = await resolveWatchtowerBootstrap();
    assert.deepEqual(bootstrap, {
      token: 'bootstrap_123',
      baseUrl: 'https://app-staging.pegasi.ai',
    });
  } finally {
    if (originalToken === undefined) {
      delete process.env.REINS_ENROLLMENT_TOKEN;
    } else {
      process.env.REINS_ENROLLMENT_TOKEN = originalToken;
    }
    if (originalBaseUrl === undefined) {
      delete process.env.REINS_CLOUD_BASE_URL;
    } else {
      process.env.REINS_CLOUD_BASE_URL = originalBaseUrl;
    }
  }
});

test('redeemReinsBootstrap exchanges a token for an org-scoped api key', async () => {
  const originalRequest = https.request;
  const captured = {};

  https.request = (options, callback) => {
    Object.assign(captured, options);
    const response = new Readable({ read() {} });
    response.statusCode = 200;
    process.nextTick(() => {
      callback(response);
      response.push(JSON.stringify({
        api_key: 'cr_test_key',
        organization: { id: 'org_alpha', name: 'Alpha Org' },
      }));
      response.push(null);
    });

    return {
      on() { return this; },
      write() {},
      end() {},
      destroy() {},
    };
  };

  try {
    const result = await redeemReinsBootstrap('bootstrap_123', 'https://app-staging.pegasi.ai');
    assert.equal(result.api_key, 'cr_test_key');
    assert.deepEqual(result.organization, { id: 'org_alpha', name: 'Alpha Org' });
    assert.match(String(captured.path), /\/api\/auth\/reins-bootstrap\/redeem$/);
  } finally {
    https.request = originalRequest;
  }
});

test('saveWatchtowerSettings writes bootstrapToken into config', async () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'reins-bootstrap-'));
  const originalXdg = process.env.XDG_CONFIG_HOME;
  try {
    process.env.XDG_CONFIG_HOME = tempRoot;
    await saveWatchtowerSettings({
      bootstrapToken: 'bootstrap_456',
      baseUrl: 'https://app-staging.pegasi.ai',
    });
    const config = JSON.parse(readFileSync(getWatchtowerConfigPath(), 'utf8'));
    assert.equal(config.watchtower.bootstrapToken, 'bootstrap_456');
    assert.equal(config.watchtower.baseUrl, 'https://app-staging.pegasi.ai');
  } finally {
    if (originalXdg === undefined) {
      delete process.env.XDG_CONFIG_HOME;
    } else {
      process.env.XDG_CONFIG_HOME = originalXdg;
    }
  }
});
