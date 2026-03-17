import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, mkdirSync } from 'node:fs';

const openclawHome = mkdtempSync(path.join(os.tmpdir(), 'clawreins-destructive-tests-'));
mkdirSync(openclawHome, { recursive: true });
process.env.OPENCLAW_HOME = openclawHome;
process.env.CLAWREINS_DESTRUCTIVE_GATING = 'on';
process.env.CLAWREINS_BULK_THRESHOLD = '20';

const require = createRequire(import.meta.url);
const { Interceptor } = require('../dist/core/Interceptor.js');
const { createToolCallHook } = require('../dist/plugin/tool-interceptor.js');
const { approvalQueue } = require('../dist/core/ApprovalQueue.js');

function allowAllPolicy() {
  return {
    defaultAction: 'ALLOW',
    modules: {},
  };
}

test('destructive tool call is blocked without approval', async () => {
  const interceptor = new Interceptor(allowAllPolicy());
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    {
      toolName: 'write',
      params: {
        path: '/tmp/demo.txt',
        content: 'overwrite this file',
      },
    },
    {
      toolName: 'write',
      sessionKey: 'it:no-approval',
    }
  );

  assert.equal(result.block, true);
});

test('HIGH destructive action executes after OOB !approve', async () => {
  const interceptor = new Interceptor(allowAllPolicy());
  const hook = createToolCallHook(interceptor);
  const sessionKey = 'it:high-oob';

  const first = await hook(
    { toolName: 'write', params: { path: '/tmp/high-risk.txt', content: 'overwrite' } },
    { toolName: 'write', sessionKey }
  );

  assert.equal(first.block, true);
  // Token must NOT appear in blockReason — the agent cannot see it.
  assert.doesNotMatch(first.blockReason || '', /CONFIRM-/);

  // Simulate human typing !approve <token> — resolved via approvalQueue directly.
  const info = approvalQueue.getNotificationInfo(sessionKey, 'FileSystem', 'write');
  assert.ok(info?.token, 'expected a token in the pending queue entry');
  const resolved = approvalQueue.resolveByToken(info.token, 'approve');
  assert.equal(resolved, true);

  const second = await hook(
    { toolName: 'write', params: { path: '/tmp/high-risk.txt', content: 'overwrite' } },
    { toolName: 'write', sessionKey }
  );

  assert.notEqual(second.block, true);
});

test('CATASTROPHIC action executes after OOB !approve with token', async () => {
  const interceptor = new Interceptor(allowAllPolicy());
  const hook = createToolCallHook(interceptor);
  const sessionKey = 'it:cat-oob';

  const first = await hook(
    { toolName: 'bash', params: { command: 'rm -rf /' } },
    { toolName: 'bash', sessionKey }
  );

  assert.equal(first.block, true);
  // Token must NOT appear in blockReason — agent cannot self-approve.
  assert.doesNotMatch(first.blockReason || '', /CONFIRM-/);

  // Wrong token is rejected.
  assert.equal(approvalQueue.resolveByToken('CONFIRM-WRONG1', 'approve'), false);

  // Correct token (from queue) resolves.
  const info = approvalQueue.getNotificationInfo(sessionKey, 'Shell', 'bash');
  assert.ok(info?.token, 'expected a token in the pending queue entry');
  assert.equal(approvalQueue.resolveByToken(info.token, 'approve'), true);

  const second = await hook(
    { toolName: 'bash', params: { command: 'rm -rf /' } },
    { toolName: 'bash', sessionKey }
  );

  assert.notEqual(second.block, true);
});
