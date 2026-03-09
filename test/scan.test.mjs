import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { SecurityScanner } = require('../dist/core/SecurityScanner.js');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const cliPath = path.join(repoRoot, 'dist', 'cli', 'index.js');
const dockerExpectedStatus = existsSync('/.dockerenv') ? 'PASS' : 'WARN';

function makeOpenClawHome(prefix) {
  return mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeJson(filePath, value) {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function getCheck(report, id) {
  const check = report.checks.find((entry) => entry.id === id);
  assert.ok(check, `missing check ${id}`);
  return check;
}

async function runScanner(openclawHome) {
  process.env.OPENCLAW_HOME = openclawHome;
  const scanner = new SecurityScanner();
  return scanner.run();
}

function runCli(args, env) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    env: { ...process.env, ...env, LOG_LEVEL: 'error' },
    encoding: 'utf8',
  });
}

test('SecurityScanner warns cleanly when openclaw.json is missing', async () => {
  const openclawHome = makeOpenClawHome('clawreins-scan-missing-');

  const report = await runScanner(openclawHome);

  assert.equal(report.total, 5);
  assert.equal(report.score, 0);
  assert.equal(report.verdict, 'NEEDS ATTENTION');
  assert.equal(getCheck(report, 'GATEWAY_EXPOSED').message, 'config file not found');
  assert.equal(getCheck(report, 'GATEWAY_EXPOSED').status, 'WARN');
  assert.equal(getCheck(report, 'PLAINTEXT_KEYS').message, 'config file not found');
  assert.equal(getCheck(report, 'PLAINTEXT_KEYS').status, 'WARN');
  assert.equal(getCheck(report, 'SHELL_UNRESTRICTED').message, 'config file not found');
  assert.equal(getCheck(report, 'SHELL_UNRESTRICTED').status, 'WARN');
  assert.equal(getCheck(report, 'BROWSER_UNSANDBOXED').message, 'config file not found');
  assert.equal(getCheck(report, 'BROWSER_UNSANDBOXED').status, 'WARN');
  assert.equal(getCheck(report, 'NO_DOCKER').status, dockerExpectedStatus);
});

test('SecurityScanner reports EXPOSED for unsafe gateway, plaintext secrets, unrestricted shell, and browser config', async () => {
  const openclawHome = makeOpenClawHome('clawreins-scan-exposed-');

  writeJson(path.join(openclawHome, 'openclaw.json'), {
    gateway: { host: '0.0.0.0' },
    credentials: { apiKey: 'sk-test-1234567890' },
    shell: { action: 'ALLOW' },
    browser: { headless: false, sandbox: false },
  });

  const report = await runScanner(openclawHome);

  assert.equal(report.total, 5);
  assert.equal(report.verdict, 'EXPOSED');
  assert.equal(getCheck(report, 'GATEWAY_EXPOSED').status, 'FAIL');
  assert.match(getCheck(report, 'GATEWAY_EXPOSED').message, /0\.0\.0\.0/);
  assert.equal(getCheck(report, 'PLAINTEXT_KEYS').status, 'FAIL');
  assert.match(getCheck(report, 'PLAINTEXT_KEYS').message, /API key found/i);
  assert.equal(getCheck(report, 'SHELL_UNRESTRICTED').status, 'FAIL');
  assert.equal(getCheck(report, 'BROWSER_UNSANDBOXED').status, 'FAIL');
  assert.equal(getCheck(report, 'NO_DOCKER').status, dockerExpectedStatus);
});

test('SecurityScanner passes gateway, key, shell, and browser checks for a hardened config', async () => {
  const openclawHome = makeOpenClawHome('clawreins-scan-hardened-');

  writeJson(path.join(openclawHome, 'openclaw.json'), {
    gateway: { host: '127.0.0.1' },
    browser: { headless: true },
  });
  writeJson(path.join(openclawHome, 'clawreins', 'policy.json'), {
    version: '1.0.0',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    defaultAction: 'ASK',
    modules: {
      Shell: {
        bash: { action: 'DENY' },
      },
    },
  });

  const report = await runScanner(openclawHome);

  assert.equal(getCheck(report, 'GATEWAY_EXPOSED').status, 'PASS');
  assert.equal(getCheck(report, 'PLAINTEXT_KEYS').status, 'PASS');
  assert.equal(getCheck(report, 'SHELL_UNRESTRICTED').status, 'PASS');
  assert.equal(getCheck(report, 'BROWSER_UNSANDBOXED').status, 'PASS');
  assert.equal(getCheck(report, 'NO_DOCKER').status, dockerExpectedStatus);
  assert.equal(report.score, dockerExpectedStatus === 'PASS' ? 5 : 4);
  assert.equal(report.verdict, dockerExpectedStatus === 'PASS' ? 'SECURE' : 'NEEDS ATTENTION');
});

test('clawreins scan --json returns machine-readable report and EXPOSED exit code', () => {
  const openclawHome = makeOpenClawHome('clawreins-scan-cli-');

  writeJson(path.join(openclawHome, 'openclaw.json'), {
    gateway: {},
    browser: {},
    shell: { action: 'ALLOW' },
    auth: { token: 'not-in-env' },
  });

  const result = runCli(['scan', '--json'], {
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(result.status, 2, `stderr: ${result.stderr}`);
  assert.ok(result.stdout.trim().length > 0, 'expected JSON output');

  const payload = JSON.parse(result.stdout);
  assert.equal(payload.total, 5);
  assert.equal(payload.verdict, 'EXPOSED');
  assert.equal(getCheck(payload, 'GATEWAY_EXPOSED').status, 'FAIL');
  assert.equal(getCheck(payload, 'PLAINTEXT_KEYS').status, 'FAIL');
});
