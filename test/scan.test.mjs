import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { SecurityScanner } = require('../dist/core/SecurityScanner.js');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const cliPath = path.join(repoRoot, 'dist', 'cli', 'index.js');

function makeTempRoot(prefix) {
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

function isNodeVersionVulnerable(version) {
  const compare = (left, right) => {
    const leftParts = left.split('.').map((part) => Number.parseInt(part, 10) || 0);
    const rightParts = right.split('.').map((part) => Number.parseInt(part, 10) || 0);
    const maxLength = Math.max(leftParts.length, rightParts.length);

    for (let index = 0; index < maxLength; index += 1) {
      const leftValue = leftParts[index] || 0;
      const rightValue = rightParts[index] || 0;
      if (leftValue !== rightValue) {
        return leftValue > rightValue ? 1 : -1;
      }
    }

    return 0;
  };

  return compare(version, '22.14.0') < 0 || (compare(version, '23.0.0') >= 0 && compare(version, '23.6.1') < 0);
}

async function runScanner(openclawHome, homeDir = os.homedir()) {
  const previousOpenclawHome = process.env.OPENCLAW_HOME;
  const previousHome = process.env.HOME;
  process.env.OPENCLAW_HOME = openclawHome;
  process.env.HOME = homeDir;

  try {
    const scanner = new SecurityScanner();
    return await scanner.run();
  } finally {
    if (typeof previousOpenclawHome === 'string') {
      process.env.OPENCLAW_HOME = previousOpenclawHome;
    } else {
      delete process.env.OPENCLAW_HOME;
    }

    if (typeof previousHome === 'string') {
      process.env.HOME = previousHome;
    } else {
      delete process.env.HOME;
    }
  }
}

function runCli(args, env) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    env: { ...process.env, ...env, LOG_LEVEL: 'error' },
    encoding: 'utf8',
  });
}

test('SecurityScanner reports 13 checks and warns when primary config is missing', async () => {
  const homeDir = makeTempRoot('clawreins-scan-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  mkdirSync(openclawHome, { recursive: true });

  const report = await runScanner(openclawHome, homeDir);

  assert.equal(report.total, 13);
  assert.equal(report.verdict, 'EXPOSED');
  assert.equal(getCheck(report, 'GATEWAY_BINDING').status, 'WARN');
  assert.equal(getCheck(report, 'API_KEYS_EXPOSURE').status, 'WARN');
  assert.equal(getCheck(report, 'BROWSER_UNSANDBOXED').status, 'WARN');
  assert.equal(getCheck(report, 'SHELL_COMMAND_ALLOWLIST').status, 'FAIL');
});

test('SecurityScanner reports exposed configurations across the expanded scan set', async () => {
  const homeDir = makeTempRoot('clawreins-scan-exposed-home-');
  const openclawHome = path.join(homeDir, '.openclaw');

  writeJson(path.join(openclawHome, 'openclaw.json'), {
    gateway: { host: '0.0.0.0' },
    credentials: { apiKey: 'sk-ant-test-1234567890' },
    shell: { action: 'ALLOW' },
    auth: { token: 'changeme' },
    authBypass: true,
    browser: { headless: false, sandbox: false },
    webhookUrl: 'https://example.test/webhook',
  });
  chmodSync(path.join(openclawHome, 'openclaw.json'), 0o644);

  const report = await runScanner(openclawHome, homeDir);

  assert.equal(report.total, 13);
  assert.equal(report.verdict, 'EXPOSED');
  assert.equal(getCheck(report, 'GATEWAY_BINDING').status, 'FAIL');
  assert.equal(getCheck(report, 'API_KEYS_EXPOSURE').status, 'FAIL');
  assert.equal(getCheck(report, 'FILE_PERMISSIONS').status, 'FAIL');
  assert.equal(getCheck(report, 'SHELL_COMMAND_ALLOWLIST').status, 'FAIL');
  assert.equal(getCheck(report, 'DEFAULT_WEAK_CREDENTIALS').status, 'FAIL');
  assert.equal(getCheck(report, 'CONTROL_UI_AUTH').status, 'FAIL');
  assert.equal(getCheck(report, 'BROWSER_UNSANDBOXED').status, 'FAIL');
});

test('SecurityScanner recognizes a hardened config and computes environment-driven verdicts correctly', async () => {
  const homeDir = makeTempRoot('clawreins-scan-hardened-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    tls: true,
    sandbox: true,
    rateLimit: { maxRequests: 100 },
    browser: { headless: true, sandbox: true },
    denyPaths: ['~/.ssh', '~/.gnupg', '~/.aws', '/etc/shadow'],
    tools: {
      exec: {
        safeBins: ['ls', 'cat', 'grep'],
      },
    },
  });
  chmodSync(openclawConfig, 0o600);
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

  const report = await runScanner(openclawHome, homeDir);
  const nodeStatus = isNodeVersionVulnerable(process.versions.node) ? 'FAIL' : 'PASS';

  assert.equal(report.total, 13);
  assert.equal(getCheck(report, 'GATEWAY_BINDING').status, 'PASS');
  assert.equal(getCheck(report, 'API_KEYS_EXPOSURE').status, 'PASS');
  assert.equal(getCheck(report, 'FILE_PERMISSIONS').status, 'PASS');
  assert.equal(getCheck(report, 'HTTPS_TLS').status, 'PASS');
  assert.equal(getCheck(report, 'SHELL_COMMAND_ALLOWLIST').status, 'PASS');
  assert.equal(getCheck(report, 'SENSITIVE_DIRECTORIES').status, 'PASS');
  assert.equal(getCheck(report, 'SANDBOX_ISOLATION').status, 'PASS');
  assert.equal(getCheck(report, 'DEFAULT_WEAK_CREDENTIALS').status, 'PASS');
  assert.equal(getCheck(report, 'RATE_LIMITING').status, 'PASS');
  assert.equal(getCheck(report, 'CONTROL_UI_AUTH').status, 'PASS');
  assert.equal(getCheck(report, 'BROWSER_UNSANDBOXED').status, 'PASS');
  assert.equal(getCheck(report, 'NODEJS_VERSION').status, nodeStatus);
  assert.equal(report.verdict, nodeStatus === 'FAIL' ? 'EXPOSED' : 'SECURE');
});

test('clawreins scan --json returns 13 checks and an EXPOSED exit code for unsafe configs', () => {
  const homeDir = makeTempRoot('clawreins-scan-cli-home-');
  const openclawHome = path.join(homeDir, '.openclaw');

  writeJson(path.join(openclawHome, 'openclaw.json'), {
    gateway: { host: '0.0.0.0' },
    auth: { token: 'changeme' },
    browser: {},
  });

  const result = runCli(['scan', '--json'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(result.status, 2, `stderr: ${result.stderr}`);

  const payload = JSON.parse(result.stdout);
  assert.equal(payload.total, 13);
  assert.equal(payload.verdict, 'EXPOSED');
  assert.equal(getCheck(payload, 'GATEWAY_BINDING').status, 'FAIL');
  assert.equal(getCheck(payload, 'DEFAULT_WEAK_CREDENTIALS').status, 'FAIL');
});

test('clawreins scan --fix --yes creates a backup and applies supported remediations', () => {
  const homeDir = makeTempRoot('clawreins-scan-fix-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  writeJson(openclawConfig, {
    gateway: { host: '0.0.0.0' },
    auth: { token: 'supersecuretoken123' },
    authBypass: true,
    browser: { headless: true },
  });
  chmodSync(openclawConfig, 0o644);

  const result = runCli(['scan', '--fix', '--yes'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.match(result.stdout, /Applied \d+ fix\(es\)\./);

  const updatedConfig = JSON.parse(readFileSync(openclawConfig, 'utf8'));
  assert.equal(updatedConfig.gateway.host, '127.0.0.1');
  assert.equal(updatedConfig.authBypass, false);
  assert.deepEqual(updatedConfig.tools.exec.safeBins.slice(0, 3), ['ls', 'cat', 'head']);
  assert.equal(statSync(openclawConfig).mode & 0o777, 0o600);

  const backupRoot = path.join(homeDir, '.scan-backup');
  assert.ok(existsSync(backupRoot), 'expected backup directory to exist');
  assert.ok(readdirSync(backupRoot).length > 0, 'expected at least one timestamped backup');
});

test('clawreins scan --html does not crash when the system opener is unavailable', () => {
  const homeDir = makeTempRoot('clawreins-scan-html-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    browser: { headless: true },
    tools: {
      exec: {
        safeBins: ['ls'],
      },
    },
    sandbox: true,
    rateLimit: { maxRequests: 10 },
  });
  chmodSync(openclawConfig, 0o600);

  const result = runCli(['scan', '--html'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
    PATH: '',
  });

  assert.notEqual(result.status, null);
  assert.match(result.stdout, /HTML report:/);
  assert.match(result.stdout, /Unable to open HTML report automatically\./);
  assert.ok(existsSync(path.join(openclawHome, 'clawreins', 'scan-report.html')));
});
