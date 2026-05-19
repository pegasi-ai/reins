import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

process.env.REINS_DESTRUCTIVE_GATING = 'off';

const require = createRequire(import.meta.url);
const { Interceptor } = require('../dist/core/Interceptor.js');
const { createToolCallHook } = require('../dist/plugin/tool-interceptor.js');

function makeOpenclawHome(prefix) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  const openclawHome = path.join(root, '.openclaw');
  mkdirSync(openclawHome, { recursive: true });
  return { root, openclawHome };
}

function readDecisionLog(openclawHome) {
  const decisionsPath = path.join(openclawHome, 'reins', 'decisions.jsonl');
  const lines = readFileSync(decisionsPath, 'utf8').trim().split('\n').filter(Boolean);
  return lines.map((line) => JSON.parse(line));
}

test('Claude Code posthook writes versioned audit metadata', () => {
  const { openclawHome } = makeOpenclawHome('reins-audit-claude-');
  const hookPath = path.join(process.cwd(), 'dist', 'hooks', 'post-tool-use.js');

  const result = spawnSync(
    'node',
    [hookPath],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        OPENCLAW_HOME: openclawHome,
        REINS_PRINCIPAL_ID: 'ben@example.com',
        REINS_PRINCIPAL_EMAIL: 'ben@example.com',
        REINS_PRINCIPAL_NAME: 'Ben',
      },
      input: JSON.stringify({
        tool_name: 'Write',
        tool_input: { file_path: '/tmp/report.md' },
        session_id: 'claude-session-1',
        model: 'gpt-5.4',
        usage: { input_tokens: 12, output_tokens: 8, total_tokens: 20 },
      }),
      encoding: 'utf8',
    }
  );

  assert.equal(result.status, 0);
  const [entry] = readDecisionLog(openclawHome);
  assert.equal(entry.schema_version, '1.0');
  assert.equal(entry.agent_type, 'claude_code');
  assert.equal(entry.session_id, 'claude-session-1');
  assert.equal(entry.model, 'gpt-5.4');
  assert.deepEqual(entry.tokens, { input_tokens: 12, output_tokens: 8, total_tokens: 20 });
  assert.equal(entry.principal.id, 'ben@example.com');
  assert.equal(entry.policy_decisions[0].decision, 'allowed');
  assert.deepEqual(entry.touched_resources, [
    {
      timestamp: entry.timestamp,
      type: 'tool',
      identifier: 'Write',
      action: 'write',
      allowed: true,
      policy_id: 'FileSystem.write',
    },
    {
      timestamp: entry.timestamp,
      type: 'file',
      identifier: '/tmp/report.md',
      action: 'write',
      allowed: true,
      policy_id: 'FileSystem.write',
    },
  ]);
});

test('Claude Code prehook audits Read tool actions', () => {
  const { openclawHome } = makeOpenclawHome('reins-audit-claude-read-');
  const hookPath = path.join(process.cwd(), 'dist', 'hooks', 'pre-tool-use.js');

  const result = spawnSync(
    'node',
    [hookPath],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        OPENCLAW_HOME: openclawHome,
        REINS_PRINCIPAL_ID: 'reader@example.com',
      },
      input: JSON.stringify({
        tool_name: 'Read',
        tool_input: { file_path: '/tmp/input.txt' },
        session_id: 'claude-read-1',
        model: 'gpt-5.4',
      }),
      encoding: 'utf8',
    }
  );

  assert.equal(result.status, 0);
  const [entry] = readDecisionLog(openclawHome);
  assert.equal(entry.agent_type, 'claude_code');
  assert.equal(entry.module, 'FileSystem');
  assert.equal(entry.method, 'read');
  assert.equal(entry.policy_decisions[0].decision, 'allowed');
  assert.deepEqual(entry.touched_resources, [
    {
      timestamp: entry.timestamp,
      type: 'tool',
      identifier: 'Read',
      action: 'read',
      allowed: true,
      policy_id: 'FileSystem.read',
    },
    {
      timestamp: entry.timestamp,
      type: 'file',
      identifier: '/tmp/input.txt',
      action: 'read',
      allowed: true,
      policy_id: 'FileSystem.read',
    },
  ]);
});

test('Cowork hook installation writes cowork agent marker into cowork settings', () => {
  const projectRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-cowork-install-'));
  const homeRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-cowork-home-'));
  mkdirSync(path.join(projectRoot, '.cowork'), { recursive: true });
  mkdirSync(path.join(homeRoot, '.cowork'), { recursive: true });

  const script = `
    const path = require('path');
    process.chdir(${JSON.stringify(projectRoot)});
    process.env.HOME = ${JSON.stringify(homeRoot)};
    const { installClaudeCodeHooks } = require(${JSON.stringify(path.join(process.cwd(), 'dist', 'lib', 'hook-installer.js'))});
    installClaudeCodeHooks().then((result) => {
      process.stdout.write(JSON.stringify(result));
    }).catch((error) => {
      console.error(error);
      process.exit(1);
    });
  `;
  const result = spawnSync('node', ['-e', script], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });

  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.ok(parsed.installedPaths.some((entry) => entry.endsWith('.cowork/settings.json')));
  const coworkSettings = JSON.parse(
    readFileSync(path.join(projectRoot, '.cowork', 'settings.json'), 'utf8')
  );
  const commands = coworkSettings.hooks.PreToolUse.flatMap((group) =>
    group.hooks.map((hook) => hook.command)
  );
  assert.ok(commands.some((command) => command.includes('REINS_AGENT_TYPE=cowork')));
});

test('OpenClaw interceptor logs structured touched resources and agent identity', async () => {
  const { openclawHome } = makeOpenclawHome('reins-audit-openclaw-');
  process.env.OPENCLAW_HOME = openclawHome;
  process.env.REINS_PRINCIPAL_ID = 'gal@example.com';
  process.env.REINS_PRINCIPAL_EMAIL = 'gal@example.com';
  process.env.REINS_PRINCIPAL_NAME = 'Gal';
  process.env.REINS_DESTRUCTIVE_GATING = 'off';

  const interceptor = new Interceptor(
    {
      defaultAction: 'DENY',
      modules: {
        Shell: {
          bash: { action: 'DENY', description: 'shell locked down' },
        },
      },
    },
    false
  );
  const hook = createToolCallHook(interceptor);

  const result = await hook(
    {
      toolName: 'bash',
      params: { command: 'rm -rf /tmp/example' },
    },
    {
      toolName: 'bash',
      sessionKey: 'openclaw-session-1',
      model: 'claude-4.6',
      usage: { input_tokens: 30, output_tokens: 10 },
    }
  );

  assert.equal(result.block, true);
  const [entry] = readDecisionLog(openclawHome);
  assert.equal(entry.schema_version, '1.0');
  assert.equal(entry.agent_type, 'openclaw');
  assert.equal(entry.session_id, 'openclaw-session-1');
  assert.equal(entry.model, 'claude-4.6');
  assert.deepEqual(entry.tokens, { input_tokens: 30, output_tokens: 10, total_tokens: 40 });
  assert.equal(entry.principal.id, 'gal@example.com');
  assert.equal(entry.policy_decisions[0].decision, 'blocked');
  assert.deepEqual(entry.touched_resources, [
    {
      timestamp: entry.timestamp,
      type: 'command',
      identifier: 'rm -rf /tmp/example',
      action: 'execute',
      allowed: false,
      policy_id: 'Shell.bash',
    },
  ]);
});
