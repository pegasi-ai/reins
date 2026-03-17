import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, mkdirSync } from 'node:fs';

const openclawHome = mkdtempSync(path.join(os.tmpdir(), 'clawreins-policy-tests-'));
mkdirSync(openclawHome, { recursive: true });
process.env.OPENCLAW_HOME = openclawHome;
// Disable destructive gating so classifier doesn't override policy decisions
process.env.CLAWREINS_DESTRUCTIVE_GATING = 'off';

const require = createRequire(import.meta.url);
const { Interceptor } = require('../dist/core/Interceptor.js');
const { createToolCallHook } = require('../dist/plugin/tool-interceptor.js');

// Temp dirs used as stand-ins for real paths — no real directories assumed
const allowedDir = mkdtempSync(path.join(os.tmpdir(), 'clawreins-allowed-'));
const outsideDir = mkdtempSync(path.join(os.tmpdir(), 'clawreins-outside-'));
const secretsDir = path.join(allowedDir, 'secrets');
const allowedFile = path.join(allowedDir, 'output.txt');
const outsideFile = path.join(outsideDir, 'other.txt');
const secretsFile = path.join(secretsDir, 'keys.json');
const nestedFile = path.join(allowedDir, 'subdir', 'readme.md');

// ---------------------------------------------------------------------------
// defaultAction
// ---------------------------------------------------------------------------

test('defaultAction DENY blocks unmapped tools', async () => {
  const interceptor = new Interceptor(
    { defaultAction: 'DENY', modules: {} },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'unknown_tool', params: {} },
    { toolName: 'unknown_tool', sessionKey: 'policy:default-deny' }
  );

  assert.equal(result.block, true);
});

test('defaultAction ALLOW passes unmapped tools', async () => {
  const interceptor = new Interceptor(
    { defaultAction: 'ALLOW', modules: {} },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'unknown_tool', params: {} },
    { toolName: 'unknown_tool', sessionKey: 'policy:default-allow' }
  );

  assert.notEqual(result.block, true);
});

// ---------------------------------------------------------------------------
// Custom per-module rules
// ---------------------------------------------------------------------------

test('custom rule ALLOW lets read through without approval', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        FileSystem: {
          read: { action: 'ALLOW', description: 'reads explicitly permitted' },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: allowedFile } },
    { toolName: 'read', sessionKey: 'policy:custom-allow' }
  );

  assert.notEqual(result.block, true);
});

test('custom rule DENY blocks read even when defaultAction is ALLOW', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          read: { action: 'DENY', description: 'reads locked down' },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: allowedFile } },
    { toolName: 'read', sessionKey: 'policy:custom-deny' }
  );

  assert.equal(result.block, true);
});

// ---------------------------------------------------------------------------
// allowPaths
// ---------------------------------------------------------------------------

test('allowPaths denies write to path outside the allowlist', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          write: { action: 'ALLOW', allowPaths: [`${allowedDir}/**`] },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'write', params: { path: outsideFile } },
    { toolName: 'write', sessionKey: 'policy:allow-paths-deny' }
  );

  assert.equal(result.block, true);
});

test('allowPaths passes write to path inside the allowlist', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          write: { action: 'ALLOW', allowPaths: [`${allowedDir}/**`] },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'write', params: { path: allowedFile } },
    { toolName: 'write', sessionKey: 'policy:allow-paths-pass' }
  );

  assert.notEqual(result.block, true);
});

// ---------------------------------------------------------------------------
// denyPaths
// ---------------------------------------------------------------------------

test('denyPaths blocks path matching deny pattern even when action is ALLOW', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          read: { action: 'ALLOW', denyPaths: ['**/secrets/**'] },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: secretsFile } },
    { toolName: 'read', sessionKey: 'policy:deny-paths' }
  );

  assert.equal(result.block, true);
});

test('denyPaths takes precedence over allowPaths', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          read: {
            action: 'ALLOW',
            allowPaths: [`${allowedDir}/**`],
            denyPaths: ['**/secrets/**'],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: secretsFile } },
    { toolName: 'read', sessionKey: 'policy:deny-over-allow' }
  );

  assert.equal(result.block, true);
});

test('path not matching denyPaths passes through', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          read: {
            action: 'ALLOW',
            allowPaths: [`${allowedDir}/**`],
            denyPaths: ['**/secrets/**'],
          },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: nestedFile } },
    { toolName: 'read', sessionKey: 'policy:deny-paths-no-match' }
  );

  assert.notEqual(result.block, true);
});

// ---------------------------------------------------------------------------
// edit and write share the same rule
// ---------------------------------------------------------------------------

test('edit tool respects the write rule (ALLOW)', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        FileSystem: {
          write: { action: 'ALLOW' },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'edit', params: { path: allowedFile } },
    { toolName: 'edit', sessionKey: 'policy:edit-as-write-allow' }
  );

  assert.notEqual(result.block, true);
});

test('edit tool respects the write rule (DENY)', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          write: { action: 'DENY' },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'edit', params: { path: allowedFile } },
    { toolName: 'edit', sessionKey: 'policy:edit-as-write-deny' }
  );

  assert.equal(result.block, true);
});

// ---------------------------------------------------------------------------
// Bug fixes
// ---------------------------------------------------------------------------

test('tilde in denyPaths expands correctly and blocks ~/.ssh paths', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          read: { action: 'ALLOW', denyPaths: ['~/.ssh/**'] },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: '~/.ssh/id_rsa' } },
    { toolName: 'read', sessionKey: 'policy:tilde-deny' }
  );

  assert.equal(result.block, true);
});

test('** in allowPaths matches the directory root itself', async () => {
  const interceptor = new Interceptor(
    {
      defaultAction: 'ALLOW',
      modules: {
        FileSystem: {
          read: { action: 'ALLOW', allowPaths: [`${allowedDir}/**`] },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    { toolName: 'read', params: { path: allowedDir } },
    { toolName: 'read', sessionKey: 'policy:glob-root' }
  );

  assert.notEqual(result.block, true);
});
