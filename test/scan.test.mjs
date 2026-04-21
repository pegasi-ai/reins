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
const { scanCommand, enrollWatchtowerWithEmail } = require('../dist/cli/scan.js');
const { buildWatchtowerArtifact } = require('../dist/cli/watchtower-artifact.js');

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

function runCli(args, env, options = {}) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    env: { ...process.env, ...env, LOG_LEVEL: 'error' },
    encoding: 'utf8',
    ...options,
  });
}

async function withMockedFetch(handler, run) {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = handler;

  try {
    return await run();
  } finally {
    globalThis.fetch = previousFetch;
  }
}

async function withCapturedConsole(run) {
  const entries = { log: [], error: [] };
  const previousLog = console.log;
  const previousError = console.error;

  console.log = (...args) => {
    entries.log.push(args.map((arg) => String(arg)).join(' '));
  };
  console.error = (...args) => {
    entries.error.push(args.map((arg) => String(arg)).join(' '));
  };

  try {
    await run();
  } finally {
    console.log = previousLog;
    console.error = previousError;
  }

  return entries;
}

test('SecurityScanner reports 13 checks and warns when primary config is missing', async () => {
  const homeDir = makeTempRoot('reins-scan-home-');
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
  const homeDir = makeTempRoot('reins-scan-exposed-home-');
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
  const homeDir = makeTempRoot('reins-scan-hardened-home-');
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
  writeJson(path.join(openclawHome, 'reins', 'policy.json'), {
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

test('reins scan --json returns 13 checks and an EXPOSED exit code for unsafe configs', () => {
  const homeDir = makeTempRoot('reins-scan-cli-home-');
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

test('reins scan writes an HTML report and prints a file link by default', () => {
  const homeDir = makeTempRoot('reins-scan-default-html-home-');
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

  const result = runCli(['scan'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  const reportPath = path.join(homeDir, 'Downloads', 'scan-report.html');
  assert.notEqual(result.status, null);
  assert.match(result.stdout, /HTML Report:/);
  assert.match(result.stdout, /Saved to:/);
  assert.match(result.stdout, /Open: file:\/\//);
  assert.ok(existsSync(reportPath));
});

test('reins scan --fix --yes creates a backup and applies supported remediations', () => {
  const homeDir = makeTempRoot('reins-scan-fix-home-');
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

  assert.match(result.stdout, /Fix Results:/);
  assert.match(result.stdout, /Applied \d+ fix\(es\)\./);
  assert.match(result.stdout, /Backup created:/);
  assert.match(result.stdout, /Post-Fix Verdict:/);
  assert.match(result.stdout, /Open: file:\/\//);

  const updatedConfig = JSON.parse(readFileSync(openclawConfig, 'utf8'));
  assert.equal(updatedConfig.gateway.host, '127.0.0.1');
  assert.equal(updatedConfig.authBypass, false);
  assert.deepEqual(updatedConfig.tools.exec.safeBins.slice(0, 3), ['ls', 'cat', 'head']);
  assert.equal(statSync(openclawConfig).mode & 0o777, 0o600);

  const backupRoot = path.join(homeDir, '.scan-backup');
  assert.ok(existsSync(backupRoot), 'expected backup directory to exist');
  assert.ok(readdirSync(backupRoot).length > 0, 'expected at least one timestamped backup');
  assert.ok(existsSync(path.join(homeDir, 'Downloads', 'scan-report.html')));
});

test('reins scan --fix --yes binds gateway host when it is missing from config', () => {
  const homeDir = makeTempRoot('reins-scan-fix-missing-host-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  writeJson(openclawConfig, {
    gateway: {},
    auth: { token: 'supersecuretoken123' },
    browser: { headless: true },
    tools: {
      exec: {
        safeBins: ['ls'],
      },
    },
  });
  chmodSync(openclawConfig, 0o600);

  const result = runCli(['scan', '--fix', '--yes'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.match(result.stdout, /Fix Results:/);
  assert.match(result.stdout, /Bind gateway host to 127\.0\.0\.1/);
  assert.match(result.stdout, /Applied 1 fix\(es\)\./);
  assert.match(result.stdout, /Post-Fix Verdict:/);

  const updatedConfig = JSON.parse(readFileSync(openclawConfig, 'utf8'));
  assert.equal(updatedConfig.gateway.host, '127.0.0.1');
});

test('reins scan --fix --yes does not inject gateway config into unrelated JSON files', () => {
  const homeDir = makeTempRoot('reins-scan-fix-unrelated-json-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');
  const unrelatedConfig = path.join(openclawHome, 'config.json');

  writeJson(openclawConfig, {
    gateway: {},
    auth: { token: 'supersecuretoken123' },
    browser: { headless: true },
    tools: {
      exec: {
        safeBins: ['ls'],
      },
    },
  });
  writeJson(unrelatedConfig, {
    theme: 'dark',
  });
  chmodSync(openclawConfig, 0o600);
  chmodSync(unrelatedConfig, 0o600);

  const result = runCli(['scan', '--fix', '--yes'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.notEqual(result.status, null);

  const updatedOpenclawConfig = JSON.parse(readFileSync(openclawConfig, 'utf8'));
  const updatedUnrelatedConfig = JSON.parse(readFileSync(unrelatedConfig, 'utf8'));
  assert.equal(updatedOpenclawConfig.gateway.host, '127.0.0.1');
  assert.deepEqual(updatedUnrelatedConfig, { theme: 'dark' });
});

test('reins scan --fix --yes does not overwrite non-object gateway values', () => {
  const homeDir = makeTempRoot('reins-scan-fix-nonobject-gateway-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  writeJson(openclawConfig, {
    gateway: null,
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

  const before = readFileSync(openclawConfig, 'utf8');
  const result = runCli(['scan', '--fix', '--yes'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.notEqual(result.status, null);
  assert.match(result.stdout, /No supported auto-fixes for the current findings\./);
  assert.equal(readFileSync(openclawConfig, 'utf8'), before);
});

test('reins scan --fix --yes lists WARN findings when no auto-fixes are available', () => {
  const homeDir = makeTempRoot('reins-scan-fix-warn-only-home-');
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
  });
  chmodSync(openclawConfig, 0o600);

  const result = runCli(['scan', '--fix', '--yes'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(result.status, 1, `stderr: ${result.stderr}`);
  assert.match(result.stdout, /No supported auto-fixes for the current findings\./);
  assert.match(result.stdout, /Manual review required for:/);
  assert.match(result.stdout, /HTTPS_TLS:/);
});

test('reins scan --monitor creates a baseline state file on first run', () => {
  const homeDir = makeTempRoot('reins-scan-monitor-home-');
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

  const result = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  const statePath = path.join(openclawHome, 'reins', 'scan-state.json');
  const baselinePath = path.join(openclawHome, 'reins', 'config-base.json');
  assert.notEqual(result.status, null);
  assert.match(result.stdout, /Drift Monitor:/);
  assert.match(result.stdout, /Baseline saved:/);
  assert.match(result.stdout, /Config baseline saved:/);
  assert.ok(existsSync(statePath));
  assert.ok(existsSync(baselinePath));

  const state = JSON.parse(readFileSync(statePath, 'utf8'));
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  assert.equal(state.report.total, 13);
  assert.equal(baseline.gateway.host, '127.0.0.1');
});

test('reins scan --monitor keeps comparing against the saved config baseline until reset', () => {
  const homeDir = makeTempRoot('reins-scan-monitor-config-base-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');
  const baselinePath = path.join(openclawHome, 'reins', 'config-base.json');

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

  const firstResult = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });
  assert.notEqual(firstResult.status, null);

  const initialBaseline = readFileSync(baselinePath, 'utf8');

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    browser: { headless: true },
    tools: {
      exec: {
        safeBins: ['ls', 'cat'],
      },
    },
    sandbox: true,
    rateLimit: { maxRequests: 10 },
  });
  chmodSync(openclawConfig, 0o600);

  const secondResult = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(secondResult.status, 1, `stderr: ${secondResult.stderr}`);
  assert.match(secondResult.stdout, /Configuration drift detected\./);
  assert.match(secondResult.stdout, /CONFIG CHANGED: tools\.exec\.safeBins/);
  assert.equal(readFileSync(baselinePath, 'utf8'), initialBaseline);
});

test('reins scan --monitor --reset-baseline replaces the saved config baseline', () => {
  const homeDir = makeTempRoot('reins-scan-monitor-reset-base-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');
  const baselinePath = path.join(openclawHome, 'reins', 'config-base.json');

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

  const firstResult = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });
  assert.notEqual(firstResult.status, null);

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    browser: { headless: true },
    tools: {
      exec: {
        safeBins: ['ls', 'cat'],
      },
    },
    sandbox: true,
    rateLimit: { maxRequests: 10 },
  });
  chmodSync(openclawConfig, 0o600);

  const resetResult = runCli(['scan', '--monitor', '--reset-baseline'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(resetResult.status, 1, `stderr: ${resetResult.stderr}`);
  assert.match(resetResult.stdout, /No drift detected since the previous scan\./);

  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  assert.deepEqual(baseline.tools.exec.safeBins, ['ls', 'cat']);

  const followupResult = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(followupResult.status, 1, `stderr: ${followupResult.stderr}`);
  assert.doesNotMatch(followupResult.stdout, /CONFIG CHANGED: tools\.exec\.safeBins/);
});

test('reins scan --monitor alerts when a check worsens relative to the saved baseline', () => {
  const homeDir = makeTempRoot('reins-scan-monitor-drift-home-');
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

  const firstResult = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });
  assert.notEqual(firstResult.status, null);

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    authBypass: true,
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

  const secondResult = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(secondResult.status, 2, `stderr: ${secondResult.stderr}`);
  assert.match(secondResult.stdout, /Configuration drift detected\./);
  assert.match(secondResult.stdout, /CONTROL_UI_AUTH: PASS -> FAIL/);
});

test('reins scan --monitor can invoke an alert command when drift is detected', () => {
  const homeDir = makeTempRoot('reins-scan-monitor-alert-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');
  const alertOutput = path.join(homeDir, 'alert.txt');
  const alertCommand = `${JSON.stringify(process.execPath)} -e ${JSON.stringify(
    "require('fs').writeFileSync(process.env.REINS_ALERT_OUT, process.env.REINS_SCAN_SUMMARY)"
  )}`;

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

  const firstResult = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });
  assert.notEqual(firstResult.status, null);

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    authBypass: true,
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

  const secondResult = runCli(['scan', '--monitor', '--alert-command', alertCommand], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
    REINS_ALERT_OUT: alertOutput,
  });

  assert.equal(secondResult.status, 2, `stderr: ${secondResult.stderr}`);
  assert.match(secondResult.stdout, /Alert Command:/);
  assert.ok(existsSync(alertOutput));
  assert.match(readFileSync(alertOutput, 'utf8'), /CONTROL_UI_AUTH: PASS -> FAIL/);
});

test('reins scan --monitor treats newly introduced unhealthy checks as drift', async () => {
  const homeDir = makeTempRoot('reins-scan-monitor-new-check-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');
  const statePath = path.join(openclawHome, 'reins', 'scan-state.json');

  writeJson(openclawConfig, {
    gateway: { host: '0.0.0.0' },
    auth: { token: '${GATEWAY_TOKEN}' },
    authBypass: true,
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

  const currentReport = await runScanner(openclawHome, homeDir);
  writeJson(statePath, {
    savedAt: new Date().toISOString(),
    report: {
      ...currentReport,
      checks: currentReport.checks.filter((check) => check.id !== 'CONTROL_UI_AUTH'),
    },
  });

  const result = runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  assert.equal(result.status, 2, `stderr: ${result.stderr}`);
  assert.match(result.stdout, /Configuration drift detected\./);
  assert.match(result.stdout, /CONTROL_UI_AUTH: NEW -> FAIL/);
});

test('reins scan --monitor preserves the scan exit code when the alert command cannot start', () => {
  const homeDir = makeTempRoot('reins-scan-monitor-alert-spawn-home-');
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

  runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    authBypass: true,
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

  const result = runCli(['scan', '--monitor', '--alert-command', 'echo should-not-run'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
    SHELL: path.join(homeDir, 'missing-shell'),
  });

  assert.equal(result.status, 2, `stderr: ${result.stderr}`);
  assert.match(result.stdout, /Alert Command:/);
  assert.match(result.stdout, /Notification command could not be started\./);
});

test('reins scan --monitor times out a hung alert command', () => {
  const homeDir = makeTempRoot('reins-scan-monitor-alert-timeout-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');
  const alertCommand = `${JSON.stringify(process.execPath)} -e ${JSON.stringify('setTimeout(() => {}, 1000)')}`;

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

  runCli(['scan', '--monitor'], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
  });

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    authBypass: true,
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

  const result = runCli(['scan', '--monitor', '--alert-command', alertCommand], {
    HOME: homeDir,
    OPENCLAW_HOME: openclawHome,
    REINS_ALERT_TIMEOUT_MS: '50',
  });

  assert.equal(result.status, 2, `stderr: ${result.stderr}`);
  assert.match(result.stdout, /Alert Command:/);
  assert.match(result.stdout, /Notification command timed out after 50ms\./);
});

test('enrollWatchtowerWithEmail provisions an API key and saves it to local config', async () => {
  const homeDir = makeTempRoot('reins-watchtower-enroll-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    browser: { headless: true, sandbox: true },
    tools: {
      exec: {
        safeBins: ['ls'],
      },
    },
    sandbox: true,
    rateLimit: { maxRequests: 10 },
  });
  chmodSync(openclawConfig, 0o600);

  const report = await runScanner(openclawHome, homeDir);
  const artifact = buildWatchtowerArtifact('reins scan', report, null);
  const fetchCalls = [];

  const previousOpenclawHome = process.env.OPENCLAW_HOME;
  const previousHome = process.env.HOME;

  process.env.OPENCLAW_HOME = openclawHome;
  process.env.HOME = homeDir;

  try {
    const result = await withMockedFetch(async (url, options) => {
      fetchCalls.push({ options, url: String(url) });
      return {
        ok: true,
        json: async () => ({
          api_key: 'wt-api-key-1234567890',
          dashboard_url: 'https://app.pegasi.ai/dashboard/abc123',
        }),
        status: 200,
        statusText: 'OK',
      };
    }, async () => enrollWatchtowerWithEmail('calin@example.com', artifact, 'https://app.pegasi.ai'));

    assert.equal(result.dashboardUrl, 'https://app.pegasi.ai/dashboard/abc123');
    assert.equal(result.configPath, path.join(openclawHome, 'reins', 'config.json'));
    assert.equal(result.status, 'created');
    assert.equal(fetchCalls.length, 1);
    assert.equal(fetchCalls[0].url, 'https://app.pegasi.ai/api/auth/signup-cli');

    const payload = JSON.parse(fetchCalls[0].options.body);
    assert.equal(payload.email, 'calin@example.com');
    assert.equal(payload.repository.displayName, artifact.target.display_name);
    assert.equal(payload.repository.id, artifact.target.id);

    const savedConfig = JSON.parse(readFileSync(result.configPath, 'utf8'));
    assert.equal(savedConfig.watchtower.apiKey, 'wt-api-key-1234567890');
    assert.equal(savedConfig.watchtower.baseUrl, 'https://app.pegasi.ai');
    assert.equal(savedConfig.watchtower.dashboardUrl, 'https://app.pegasi.ai/dashboard/abc123');
    assert.equal(savedConfig.watchtower.email, 'calin@example.com');
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
});

test('enrollWatchtowerWithEmail handles existing accounts without issuing a new API key', async () => {
  const homeDir = makeTempRoot('reins-watchtower-existing-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    browser: { headless: true, sandbox: true },
    tools: {
      exec: {
        safeBins: ['ls'],
      },
    },
    sandbox: true,
    rateLimit: { maxRequests: 10 },
  });
  chmodSync(openclawConfig, 0o600);

  const report = await runScanner(openclawHome, homeDir);
  const artifact = buildWatchtowerArtifact('reins scan', report, null);
  const previousOpenclawHome = process.env.OPENCLAW_HOME;
  const previousHome = process.env.HOME;

  process.env.OPENCLAW_HOME = openclawHome;
  process.env.HOME = homeDir;

  try {
    const result = await withMockedFetch(async () => ({
      ok: true,
      json: async () => ({
        api_key: null,
        dashboard_url: 'https://app.pegasi.ai/dashboard/usr_existing',
        message: 'Account exists. Check your email for dashboard access. Your original API key is in ~/.openclaw/reins/config.json',
      }),
      status: 200,
      statusText: 'OK',
    }), async () => enrollWatchtowerWithEmail('calin@example.com', artifact, 'https://app.pegasi.ai'));

    assert.equal(result.status, 'existing');
    assert.equal(result.configPath, null);
    assert.equal(result.dashboardUrl, 'https://app.pegasi.ai/dashboard/usr_existing');
    assert.match(result.message, /Account exists/);
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
});

test('reins scan uploads to Watchtower using saved local config without env vars', async () => {
  const homeDir = makeTempRoot('reins-watchtower-upload-home-');
  const openclawHome = path.join(homeDir, '.openclaw');
  const openclawConfig = path.join(openclawHome, 'openclaw.json');
  const reinsConfig = path.join(openclawHome, 'reins', 'config.json');

  writeJson(openclawConfig, {
    gateway: { host: '127.0.0.1' },
    auth: { token: '${GATEWAY_TOKEN}' },
    browser: { headless: true, sandbox: true },
    tools: {
      exec: {
        safeBins: ['ls'],
      },
    },
    sandbox: true,
    rateLimit: { maxRequests: 10 },
  });
  chmodSync(openclawConfig, 0o600);

  writeJson(reinsConfig, {
    watchtower: {
      apiKey: 'wt-saved-key-1234567890',
      baseUrl: 'https://app.pegasi.ai',
      dashboardUrl: 'https://app.pegasi.ai/dashboard/abc123',
      email: 'calin@example.com',
    },
  });
  chmodSync(reinsConfig, 0o600);

  const previousOpenclawHome = process.env.OPENCLAW_HOME;
  const previousHome = process.env.HOME;
  const previousExitCode = process.exitCode;
  const previousWatchtowerBaseUrl = process.env.REINS_WATCHTOWER_BASE_URL;
  const previousWatchtowerApiKey = process.env.REINS_WATCHTOWER_API_KEY;
  const fetchCalls = [];

  process.env.OPENCLAW_HOME = openclawHome;
  process.env.HOME = homeDir;
  delete process.env.REINS_WATCHTOWER_BASE_URL;
  delete process.env.REINS_WATCHTOWER_API_KEY;

  try {
    const consoleEntries = await withMockedFetch(async (url, options) => {
      fetchCalls.push({ options, url: String(url) });
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => '',
      };
    }, async () => withCapturedConsole(async () => {
      await scanCommand({});
    }));

    assert.equal(fetchCalls.length, 1);
    assert.equal(fetchCalls[0].url, 'https://app.pegasi.ai/api/scan-artifacts/ingest');
    assert.equal(fetchCalls[0].options.headers['x-api-key'], 'wt-saved-key-1234567890');

    const payload = JSON.parse(fetchCalls[0].options.body);
    assert.equal(payload.source.producer, 'reins');
    assert.equal(payload.target.kind, 'repository');

    assert.match(consoleEntries.log.join('\n'), /Watchtower Upload:/);
    assert.match(consoleEntries.log.join('\n'), /Uploaded to https:\/\/app\.pegasi\.ai\/api\/scan-artifacts\/ingest\./);
  } finally {
    process.exitCode = previousExitCode;

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

    if (typeof previousWatchtowerBaseUrl === 'string') {
      process.env.REINS_WATCHTOWER_BASE_URL = previousWatchtowerBaseUrl;
    } else {
      delete process.env.REINS_WATCHTOWER_BASE_URL;
    }

    if (typeof previousWatchtowerApiKey === 'string') {
      process.env.REINS_WATCHTOWER_API_KEY = previousWatchtowerApiKey;
    } else {
      delete process.env.REINS_WATCHTOWER_API_KEY;
    }
  }
});

test('reins scan --html does not crash when the system opener is unavailable', () => {
  const homeDir = makeTempRoot('reins-scan-html-home-');
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

  const reportPath = path.join(homeDir, 'Downloads', 'scan-report.html');
  assert.notEqual(result.status, null);
  assert.match(result.stdout, /HTML Report:/);
  assert.match(result.stdout, /Open: file:\/\//);
  assert.match(result.stdout, /Auto-open: requested/);
  assert.match(result.stdout, /Auto-open unavailable\. Use the file link above\./);
  assert.ok(existsSync(reportPath));
});
