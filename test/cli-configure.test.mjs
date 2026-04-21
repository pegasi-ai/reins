import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const cliPath = path.join(repoRoot, 'dist', 'cli', 'index.js');

function runCli(args, env) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    env: { ...process.env, ...env },
    encoding: 'utf8',
  });
}

function isInsidePath(targetPath, rootPath) {
  const relative = path.relative(rootPath, targetPath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

test('reins configure --non-interactive --json succeeds in temp OPENCLAW_HOME', () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-configure-success-'));
  const openclawHome = path.join(tempRoot, 'openclaw-home');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  mkdirSync(openclawHome, { recursive: true });

  const result = runCli(['configure', '--non-interactive', '--json'], {
    OPENCLAW_HOME: openclawHome,
    OPENCLAW_CONFIG: openclawConfig,
    OPENCLAW_PLUGIN_ID: 'reins',
    OPENCLAW_PLUGIN_DIR: path.join(openclawHome, 'extensions', 'reins'),
    LOG_LEVEL: 'error',
  });

  assert.equal(result.status, 0, `stderr: ${result.stderr}`);

  const stdout = result.stdout.trim();
  assert.ok(stdout.length > 0, 'expected JSON output');
  assert.equal(stdout.split('\n').length, 1, 'expected exactly one JSON line on stdout');

  const payload = JSON.parse(stdout);
  assert.equal(payload.ok, true);
  assert.equal(payload.openclawHome, openclawHome);
  assert.equal(payload.configPath, openclawConfig);
  assert.ok(existsSync(payload.policyPath), 'policy file should exist');
  assert.ok(existsSync(payload.configPath), 'openclaw config should exist');
  assert.ok(isInsidePath(payload.policyPath, openclawHome));
  assert.ok(isInsidePath(payload.configPath, openclawHome));
});

test('reins configure --non-interactive --json fails for custom security without modules', () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-configure-fail-'));
  const openclawHome = path.join(tempRoot, 'openclaw-home');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  mkdirSync(openclawHome, { recursive: true });

  const result = runCli([
    'configure',
    '--non-interactive',
    '--json',
    '--security-level',
    'custom',
  ], {
    OPENCLAW_HOME: openclawHome,
    OPENCLAW_CONFIG: openclawConfig,
    LOG_LEVEL: 'error',
  });

  assert.notEqual(result.status, 0);

  const stdout = result.stdout.trim();
  assert.ok(stdout.length > 0, 'expected JSON output on failure');
  assert.equal(stdout.split('\n').length, 1, 'expected exactly one JSON line on stdout');

  const payload = JSON.parse(stdout);
  assert.equal(payload.ok, false);
  assert.equal(payload.error.code, 'E_MISSING_REQUIRED');
});
