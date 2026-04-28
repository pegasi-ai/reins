/**
 * Granular allow (allowForSessionGranular) tests
 * Covers: glob matching on primary arg, session-prefix scoping,
 * blanket allowForSessionKeys, interaction between granular and blanket.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, mkdirSync } from 'node:fs';

const openclawHome = mkdtempSync(path.join(os.tmpdir(), 'clawreins-granular-'));
mkdirSync(openclawHome, { recursive: true });
process.env.OPENCLAW_HOME = openclawHome;
process.env.CLAWREINS_DESTRUCTIVE_GATING = 'off';

const require = createRequire(import.meta.url);
const { Interceptor } = require('../dist/core/Interceptor.js');
const { createToolCallHook } = require('../dist/plugin/tool-interceptor.js');

// ---------------------------------------------------------------------------
// allowForSessionKeys (blanket session allow)
// ---------------------------------------------------------------------------

test('allowForSessionKeys passes ALLOW action for matching session prefix', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        Shell: {
          bash: {
            action: 'ASK',
            allowForSessionKeys: ['agent:main:cron:job-123'],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'bash', params: { command: 'echo hello' } },
    { toolName: 'bash', sessionKey: 'agent:main:cron:job-123' }
  );
  assert.notEqual(result?.block, true, 'blanket allow for matching session should pass');
});

test('allowForSessionKeys does NOT apply to a different session', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        Shell: {
          bash: {
            action: 'DENY',
            allowForSessionKeys: ['agent:main:cron:job-123'],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'bash', params: { command: 'echo hello' } },
    { toolName: 'bash', sessionKey: 'agent:main:cron:job-DIFFERENT' }
  );
  assert.equal(result?.block, true, 'blanket allow should not apply to a different session');
});

// ---------------------------------------------------------------------------
// allowForSessionGranular (glob on primary arg)
// ---------------------------------------------------------------------------

test('allowForSessionGranular allows exact file path match', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        FileSystem: {
          read: {
            action: 'ASK',
            allowForSessionGranular: [
              { sessionKeyPrefix: 'agent:main:cron:job-abc', argGlob: '/home/user/report.csv' },
            ],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: '/home/user/report.csv' } },
    { toolName: 'read', sessionKey: 'agent:main:cron:job-abc' }
  );
  assert.notEqual(result?.block, true, 'exact file path match should be allowed');
});

test('allowForSessionGranular blocks a different file path', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        FileSystem: {
          read: {
            action: 'DENY',
            allowForSessionGranular: [
              { sessionKeyPrefix: 'agent:main:cron:job-abc', argGlob: '/home/user/report.csv' },
            ],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: '/home/user/other.csv' } },
    { toolName: 'read', sessionKey: 'agent:main:cron:job-abc' }
  );
  assert.equal(result?.block, true, 'different file path should be blocked');
});

test('allowForSessionGranular with wildcard glob allows matching paths', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        FileSystem: {
          read: {
            action: 'ASK',
            allowForSessionGranular: [
              { sessionKeyPrefix: 'agent:main:cron:job-abc', argGlob: '/home/user/reports/**' },
            ],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: '/home/user/reports/2026/q1.csv' } },
    { toolName: 'read', sessionKey: 'agent:main:cron:job-abc' }
  );
  assert.notEqual(result?.block, true, 'wildcard glob should match nested paths');
});

test('allowForSessionGranular does not apply to a different session', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        FileSystem: {
          read: {
            action: 'DENY',
            allowForSessionGranular: [
              { sessionKeyPrefix: 'agent:main:cron:job-abc', argGlob: '/home/user/report.csv' },
            ],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: '/home/user/report.csv' } },
    { toolName: 'read', sessionKey: 'agent:main:cron:job-DIFFERENT' }
  );
  assert.equal(result?.block, true, 'granular allow for different session should not apply');
});

test('allowForSessionGranular applies when session key starts with the prefix', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        Shell: {
          bash: {
            action: 'ASK',
            allowForSessionGranular: [
              { sessionKeyPrefix: 'agent:main:cron:job-abc', argGlob: 'python run.py' },
            ],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  // session key is the prefix itself (or has additional suffix)
  const result = await hook(
    { toolName: 'bash', params: { command: 'python run.py' } },
    { toolName: 'bash', sessionKey: 'agent:main:cron:job-abc:run-42' }
  );
  assert.notEqual(result?.block, true, 'session key starting with prefix should match');
});

// ---------------------------------------------------------------------------
// Blanket vs granular interaction
// ---------------------------------------------------------------------------

test('blanket allowForSessionKeys takes effect even if granular does not match', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        Shell: {
          bash: {
            action: 'ASK',
            allowForSessionKeys: ['agent:main:cron:job-xyz'],
            allowForSessionGranular: [
              { sessionKeyPrefix: 'agent:main:cron:job-xyz', argGlob: 'python specific.py' },
            ],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  // Command doesn't match granular glob, but session matches blanket allowForSessionKeys
  const result = await hook(
    { toolName: 'bash', params: { command: 'ls -la' } },
    { toolName: 'bash', sessionKey: 'agent:main:cron:job-xyz' }
  );
  assert.notEqual(result?.block, true, 'blanket allow should pass even when granular glob does not match');
});
