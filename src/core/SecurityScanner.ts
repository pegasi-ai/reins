/**
 * ClawReins Security Scanner
 * Audits local OpenClaw-style installations for common security misconfigurations.
 */

import { constants as FsConstants } from 'fs';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';

export interface ScanCheck {
  id: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  message: string;
  remediation?: string;
}

export interface ScanReport {
  checks: ScanCheck[];
  score: number;
  total: number;
  verdict: 'SECURE' | 'NEEDS ATTENTION' | 'EXPOSED';
  timestamp: string;
}

export interface FixAction {
  id: 'REBIND_GATEWAY' | 'FIX_PERMISSIONS' | 'ADD_SAFEBINS' | 'DISABLE_AUTH_BYPASS';
  description: string;
}

export interface FixResult {
  backupPath?: string;
  appliedActions: FixAction['id'][];
  touchedFiles: string[];
}

interface ConfigSnapshot {
  path: string;
  name: string;
  exists: boolean;
  raw?: string;
  json?: unknown;
  mode?: number;
  error?: string;
}

interface ScanContext {
  configFiles: ConfigSnapshot[];
  openclawConfig: ConfigSnapshot;
  policyConfig: ConfigSnapshot;
  inDocker: boolean;
  nodeVersion: string;
  checkLiveGatewayListeners: boolean;
}

interface ShellSignals {
  hasAllowlist: boolean;
  hasDeny: boolean;
  hasAllow: boolean;
  hasAsk: boolean;
}

const CONFIG_NAMES = [
  'config.yaml',
  'config.yml',
  'config.json',
  'clawdbot.json',
  'moltbot.json',
  'openclaw.json',
  'gateway.yaml',
  '.env',
  'docker-compose.yml',
] as const;

const SAFE_BINS = [
  'ls',
  'cat',
  'head',
  'tail',
  'grep',
  'find',
  'wc',
  'echo',
  'date',
  'pwd',
  'whoami',
  'git',
  'node',
  'npm',
  'npx',
  'python',
  'python3',
  'pip',
  'curl',
] as const;

const REMEDIATIONS = {
  gateway:
    'Set "gateway": { "host": "127.0.0.1" } in openclaw.json, then access via SSH tunnel only',
  plaintextKeys: 'Move sensitive values to ~/.openclaw/.env and reference via process.env',
  filePermissions: 'Set config file permissions to 600 (chmod 600 <config-file>)',
  tls: 'Configure HTTPS/TLS with a certificate before exposing the gateway outside localhost',
  shellAllowlist: 'Add tools.exec.safeBins or an equivalent allowlist to restrict shell execution',
  sensitiveDirs: 'Deny access to ~/.ssh, ~/.gnupg, ~/.aws, and /etc/shadow in tool config',
  webhookAuth: 'Require an auth token or shared secret for all webhook endpoints',
  sandbox: 'Run OpenClaw inside Docker or another sandboxed environment',
  weakCredentials: 'Set a strong gateway token and remove default or undefined credentials',
  rateLimiting: 'Configure rate limiting or throttling on the gateway',
  nodeVersion: 'Upgrade Node.js to a version not affected by CVE-2026-21636',
  controlUiAuth: 'Disable auth bypass flags and require authentication for the Control UI',
  browser: 'Set headless: true in your browser skill config to reduce DOM prompt-injection risk',
} as const;

const KEY_VALUE_PATTERNS = (key: string): RegExp[] => [
  new RegExp(`"${escapeRegex(key)}"\\s*:\\s*"([^"]+)"`, 'i'),
  new RegExp(`"${escapeRegex(key)}"\\s*:\\s*([^",\\s}]+)`, 'i'),
  new RegExp(`^\\s*${escapeRegex(key)}\\s*:\\s*([^#\\n]+)`, 'im'),
];

const API_KEY_PATTERNS = [
  /sk-ant-[a-zA-Z0-9_-]+/,
  /sk-[a-zA-Z0-9]{20,}/,
  /ANTHROPIC_API_KEY\s*[:=]/i,
  /OPENAI_API_KEY\s*[:=]/i,
  /api[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}/i,
  /token\s*[:=]\s*["']?[a-zA-Z0-9._-]{20,}/i,
];

const SHELL_ALLOWLIST_PATTERN = /(safeBins|allowlist|allow_list|allowList|allowedCommands|exec\.allow)/i;
const SHELL_ALLOW_PATTERN = /shell|bash|exec|spawn/i;
const SHELL_DECISION_ALLOW_PATTERN = /("action"|"defaultAction"|action|defaultAction|mode)\s*[:=]\s*["']?ALLOW["']?/i;
const SHELL_DECISION_ASK_PATTERN = /("action"|"defaultAction"|action|defaultAction|mode)\s*[:=]\s*["']?ASK["']?/i;
const SHELL_DECISION_DENY_PATTERN = /("action"|"defaultAction"|action|defaultAction|mode)\s*[:=]\s*["']?DENY["']?/i;
const TLS_PATTERN = /(https|tls|ssl|cert|certificate)/i;
const WEBHOOK_PATTERN = /webhook/i;
const WEBHOOK_AUTH_PATTERN = /webhook[\s\S]{0,200}(auth|token|secret|key)/i;
const SANDBOX_PATTERN = /"?(sandbox|docker|container|isolation)"?\s*[:=]\s*(true|enabled|yes)/i;
const WEAK_CREDENTIAL_PATTERN =
  /"?token"?\s*[:=]\s*['"]?(undefined|changeme|password|admin|default|test|12345)['"]?/i;
const GATEWAY_TOKEN_PATTERN =
  /(gateway.*token|gatewayToken|GATEWAY_TOKEN|"token"\s*:\s*"[^"]{8,}")/i;
const RATE_LIMIT_PATTERN = /(rateLimit|rate_limit|throttle|maxRequests)/i;
const CONTROL_UI_BYPASS_PATTERN =
  /"?(authBypass|auth_bypass|skipAuth|noAuth|disableAuth)"?\s*[:=]\s*(true|yes|1)/i;
const BROWSER_CONTEXT_PATTERN = /browser/i;

export class SecurityScanner {
  private readonly userHome: string;
  private readonly cwd: string;
  private readonly openclawHome: string;
  private readonly openclawConfigPath: string;
  private readonly policyPath: string;

  constructor() {
    this.userHome = os.homedir();
    this.cwd = process.cwd();
    this.openclawHome = process.env.OPENCLAW_HOME || path.join(this.userHome, '.openclaw');
    this.openclawConfigPath = process.env.OPENCLAW_CONFIG || path.join(this.openclawHome, 'openclaw.json');
    this.policyPath = path.join(this.openclawHome, 'clawreins', 'policy.json');
  }

  async run(): Promise<ScanReport> {
    const context = await this.loadContext();
    const checks = await this.buildChecks(context);

    return {
      checks,
      score: checks.filter((check) => check.status === 'PASS').length,
      total: checks.length,
      verdict: checks.some((check) => check.status === 'FAIL')
        ? 'EXPOSED'
        : checks.some((check) => check.status === 'WARN')
          ? 'NEEDS ATTENTION'
          : 'SECURE',
      timestamp: new Date().toISOString(),
    };
  }

  async planFixes(): Promise<FixAction[]> {
    const context = await this.loadContext();
    return this.computeFixActions(context);
  }

  async applyFixes(): Promise<FixResult> {
    const context = await this.loadContext();
    const actions = this.computeFixActions(context);

    if (actions.length === 0) {
      return {
        appliedActions: [],
        touchedFiles: [],
      };
    }

    const backupPath = await this.backupConfigFiles(context.configFiles);
    const touchedFiles = new Set<string>();

    for (const action of actions) {
      switch (action.id) {
        case 'REBIND_GATEWAY':
          this.addTouched(await this.rebindGateway(context.configFiles), touchedFiles);
          break;
        case 'FIX_PERMISSIONS':
          this.addTouched(await this.fixPermissions(context.configFiles), touchedFiles);
          break;
        case 'ADD_SAFEBINS':
          this.addTouched(await this.addSafeBins(context.configFiles), touchedFiles);
          break;
        case 'DISABLE_AUTH_BYPASS':
          this.addTouched(await this.disableAuthBypass(context.configFiles), touchedFiles);
          break;
      }
    }

    return {
      backupPath,
      appliedActions: actions.map((action) => action.id),
      touchedFiles: Array.from(touchedFiles),
    };
  }

  private async buildChecks(context: ScanContext): Promise<ScanCheck[]> {
    return [
      await this.checkGatewayBinding(context),
      await this.checkApiKeysExposure(context),
      await this.checkFilePermissions(context),
      await this.checkHttpsTls(context),
      await this.checkShellAllowlist(context),
      await this.checkSensitiveDirectories(context),
      await this.checkWebhookAuth(context),
      await this.checkSandboxIsolation(context),
      await this.checkWeakCredentials(context),
      await this.checkRateLimiting(context),
      await this.checkNodeVersion(context),
      await this.checkControlUiAuth(context),
      await this.checkBrowserUnsandboxed(context),
    ];
  }

  private async loadContext(): Promise<ScanContext> {
    const configPaths = await this.discoverConfigPaths();
    const configFiles = await Promise.all(configPaths.map((filePath) => this.readConfig(filePath)));

    return {
      configFiles,
      openclawConfig: await this.readConfig(this.openclawConfigPath),
      policyConfig: await this.readConfig(this.policyPath),
      inDocker: await this.detectDocker(),
      nodeVersion: process.versions.node,
      checkLiveGatewayListeners: !process.env.OPENCLAW_HOME,
    };
  }

  private async discoverConfigPaths(): Promise<string[]> {
    const searchDirs: string[] = [];
    const explicitOpenclawHome = process.env.OPENCLAW_HOME;
    const explicitMoltbotHome = process.env.MOLTBOT_HOME;

    if (explicitOpenclawHome) {
      searchDirs.push(explicitOpenclawHome);
    }
    if (explicitMoltbotHome) {
      searchDirs.push(explicitMoltbotHome);
    }

    if (!explicitOpenclawHome && !explicitMoltbotHome) {
      searchDirs.push(
        path.join(this.userHome, '.openclaw'),
        path.join(this.userHome, '.clawdbot'),
        path.join(this.userHome, '.moltbot'),
        this.cwd,
        '/etc/openclaw'
      );
    }

    const deduped = new Set<string>();

    for (const directory of searchDirs) {
      if (!(await fs.pathExists(directory))) {
        continue;
      }

      let stats;
      try {
        stats = await fs.stat(directory);
      } catch {
        continue;
      }

      if (!stats.isDirectory()) {
        continue;
      }

      for (const fileName of CONFIG_NAMES) {
        const fullPath = path.join(directory, fileName);
        if (!(await fs.pathExists(fullPath))) {
          continue;
        }

        try {
          deduped.add(await fs.realpath(fullPath));
        } catch {
          deduped.add(fullPath);
        }
      }
    }

    if (await fs.pathExists(this.openclawConfigPath)) {
      try {
        deduped.add(await fs.realpath(this.openclawConfigPath));
      } catch {
        deduped.add(this.openclawConfigPath);
      }
    }

    return Array.from(deduped).sort();
  }

  private async readConfig(filePath: string): Promise<ConfigSnapshot> {
    try {
      if (!(await fs.pathExists(filePath))) {
        return {
          path: filePath,
          name: path.basename(filePath),
          exists: false,
        };
      }

      const stats = await fs.stat(filePath);
      const raw = await fs.readFile(filePath, 'utf8');
      const snapshot: ConfigSnapshot = {
        path: filePath,
        name: path.basename(filePath),
        exists: true,
        raw,
        mode: stats.mode & 0o777,
      };

      if (path.extname(filePath).toLowerCase() === '.json') {
        try {
          snapshot.json = JSON.parse(raw) as unknown;
        } catch (error) {
          snapshot.error = error instanceof Error ? error.message : 'failed to parse config file';
        }
      }

      return snapshot;
    } catch (error) {
      return {
        path: filePath,
        name: path.basename(filePath),
        exists: true,
        error: error instanceof Error ? error.message : 'failed to read config file',
      };
    }
  }

  private async detectDocker(): Promise<boolean> {
    try {
      if (await fs.pathExists('/.dockerenv')) {
        return true;
      }
    } catch {
      // Ignore and continue to cgroup fallback.
    }

    try {
      const cgroup = await fs.readFile('/proc/1/cgroup', 'utf8');
      return /docker|containerd/i.test(cgroup);
    } catch {
      return false;
    }
  }

  private async checkGatewayBinding(context: ScanContext): Promise<ScanCheck> {
    const wildcardListener = context.checkLiveGatewayListeners
      ? await this.findWildcardGatewayListener()
      : null;
    if (wildcardListener) {
      return this.fail(
        'GATEWAY_BINDING',
        `gateway exposed on ${wildcardListener}`,
        REMEDIATIONS.gateway
      );
    }

    const gatewayHost = this.readNestedString(context.openclawConfig.json, ['gateway', 'host']);
    if (gatewayHost === '127.0.0.1') {
      return this.pass('GATEWAY_BINDING', 'host bound to 127.0.0.1');
    }

    const discoveredHost = this.findFirstConfigValue(context.configFiles, ['host', 'bind', 'address', 'listen']);
    if (discoveredHost === '0.0.0.0') {
      return this.fail('GATEWAY_BINDING', 'gateway exposed on 0.0.0.0', REMEDIATIONS.gateway);
    }

    if (!context.openclawConfig.exists && context.configFiles.length === 0) {
      return this.warn('GATEWAY_BINDING', 'config file not found', REMEDIATIONS.gateway);
    }

    if (gatewayHost) {
      return this.fail('GATEWAY_BINDING', `host bound to ${gatewayHost}`, REMEDIATIONS.gateway);
    }

    return this.fail('GATEWAY_BINDING', 'gateway host missing from config', REMEDIATIONS.gateway);
  }

  private async checkApiKeysExposure(context: ScanContext): Promise<ScanCheck> {
    const candidateFiles = context.configFiles.filter((file) => file.exists && file.name !== '.env');
    if (candidateFiles.length === 0 && !context.openclawConfig.exists) {
      return this.warn('API_KEYS_EXPOSURE', 'config file not found', REMEDIATIONS.plaintextKeys);
    }

    const recursiveMatch = context.openclawConfig.json
      ? this.findSensitiveValue(context.openclawConfig.json)
      : null;
    if (recursiveMatch) {
      return this.fail(
        'API_KEYS_EXPOSURE',
        `${this.formatSensitiveLabel(recursiveMatch)} found in ${context.openclawConfig.name}`,
        REMEDIATIONS.plaintextKeys
      );
    }

    for (const file of candidateFiles) {
      const { raw } = file;
      if (raw && API_KEY_PATTERNS.some((pattern) => pattern.test(raw))) {
        return this.fail(
          'API_KEYS_EXPOSURE',
          `plaintext API key or token found in ${file.name}`,
          REMEDIATIONS.plaintextKeys
        );
      }
    }

    return this.pass('API_KEYS_EXPOSURE', 'no plaintext API keys found in config files');
  }

  private async checkFilePermissions(context: ScanContext): Promise<ScanCheck> {
    const badFiles = context.configFiles.filter(
      (file) => file.exists && typeof file.mode === 'number' && (file.mode & 0o077) !== 0
    );

    if (badFiles.length === 0) {
      return this.pass(
        'FILE_PERMISSIONS',
        context.configFiles.length > 0 ? 'config file permissions are restricted' : 'no config files found to check'
      );
    }

    return this.fail(
      'FILE_PERMISSIONS',
      `loose permissions on ${badFiles.map((file) => `${file.name} (${formatMode(file.mode)})`).join(', ')}`,
      REMEDIATIONS.filePermissions
    );
  }

  private async checkHttpsTls(context: ScanContext): Promise<ScanCheck> {
    if (context.configFiles.some((file) => file.raw && TLS_PATTERN.test(file.raw))) {
      return this.pass('HTTPS_TLS', 'HTTPS/TLS configuration detected');
    }

    return this.warn('HTTPS_TLS', 'HTTPS/TLS not configured', REMEDIATIONS.tls);
  }

  private async checkShellAllowlist(context: ScanContext): Promise<ScanCheck> {
    const signals = this.readShellSignals(context);

    if (signals.hasAllowlist || signals.hasDeny) {
      return this.pass('SHELL_COMMAND_ALLOWLIST', 'shell command allowlist configured');
    }

    if (signals.hasAllow) {
      return this.fail(
        'SHELL_COMMAND_ALLOWLIST',
        'shell access allowed without restrictions',
        REMEDIATIONS.shellAllowlist
      );
    }

    return this.fail(
      'SHELL_COMMAND_ALLOWLIST',
      signals.hasAsk
        ? 'shell access requires approval but no allowlist is configured'
        : 'no shell command allowlist configured',
      REMEDIATIONS.shellAllowlist
    );
  }

  private async checkSensitiveDirectories(context: ScanContext): Promise<ScanCheck> {
    const sensitiveTargets = [
      path.join(this.userHome, '.ssh'),
      path.join(this.userHome, '.gnupg'),
      path.join(this.userHome, '.aws'),
      '/etc/shadow',
    ];
    const accessible: string[] = [];

    for (const target of sensitiveTargets) {
      try {
        await fs.access(target, FsConstants.R_OK);
        accessible.push(target);
      } catch {
        // Not readable; skip.
      }
    }

    const excluded = context.configFiles.some((file) =>
      Boolean(file.raw && /(exclude|deny|block)[\s\S]{0,200}(\.ssh|\.gnupg|\.aws|\/etc\/shadow)/i.test(file.raw))
    );

    if (accessible.length > 0 && !excluded) {
      return this.warn(
        'SENSITIVE_DIRECTORIES',
        `sensitive directories accessible (${accessible.map((value) => value.replace(this.userHome, '~')).join(', ')})`,
        REMEDIATIONS.sensitiveDirs
      );
    }

    return this.pass('SENSITIVE_DIRECTORIES', 'sensitive directories protected or excluded');
  }

  private async checkWebhookAuth(context: ScanContext): Promise<ScanCheck> {
    for (const file of context.configFiles) {
      if (!file.raw || !WEBHOOK_PATTERN.test(file.raw)) {
        continue;
      }

      if (!WEBHOOK_AUTH_PATTERN.test(file.raw)) {
        return this.warn(
          'WEBHOOK_AUTH',
          `webhook endpoints found without auth tokens in ${file.name}`,
          REMEDIATIONS.webhookAuth
        );
      }
    }

    return this.pass('WEBHOOK_AUTH', 'webhook auth configured or no webhooks found');
  }

  private async checkSandboxIsolation(context: ScanContext): Promise<ScanCheck> {
    if (context.inDocker || context.configFiles.some((file) => Boolean(file.raw && SANDBOX_PATTERN.test(file.raw)))) {
      return this.pass('SANDBOX_ISOLATION', 'sandbox or container isolation detected');
    }

    return this.warn(
      'SANDBOX_ISOLATION',
      'no sandbox or Docker isolation detected',
      REMEDIATIONS.sandbox
    );
  }

  private async checkWeakCredentials(context: ScanContext): Promise<ScanCheck> {
    const raws = context.configFiles.map((file) => file.raw).filter((raw): raw is string => typeof raw === 'string');

    if (raws.some((raw) => WEAK_CREDENTIAL_PATTERN.test(raw))) {
      return this.fail(
        'DEFAULT_WEAK_CREDENTIALS',
        'default or weak credentials detected',
        REMEDIATIONS.weakCredentials
      );
    }

    if (raws.length > 0 && !raws.some((raw) => GATEWAY_TOKEN_PATTERN.test(raw))) {
      return this.fail(
        'DEFAULT_WEAK_CREDENTIALS',
        'no gateway auth token configured',
        REMEDIATIONS.weakCredentials
      );
    }

    return this.pass('DEFAULT_WEAK_CREDENTIALS', 'gateway credentials are configured and not using defaults');
  }

  private async checkRateLimiting(context: ScanContext): Promise<ScanCheck> {
    if (context.configFiles.some((file) => Boolean(file.raw && RATE_LIMIT_PATTERN.test(file.raw)))) {
      return this.pass('RATE_LIMITING', 'rate limiting configured');
    }

    return this.warn('RATE_LIMITING', 'no rate limiting configured', REMEDIATIONS.rateLimiting);
  }

  private async checkNodeVersion(context: ScanContext): Promise<ScanCheck> {
    if (!context.nodeVersion) {
      return this.pass('NODEJS_VERSION', 'Node.js not found');
    }

    if (this.isNodeVersionVulnerable(context.nodeVersion)) {
      return this.fail(
        'NODEJS_VERSION',
        `Node.js ${context.nodeVersion} may be vulnerable to CVE-2026-21636`,
        REMEDIATIONS.nodeVersion
      );
    }

    return this.pass(
      'NODEJS_VERSION',
      `Node.js ${context.nodeVersion} is not affected by CVE-2026-21636`
    );
  }

  private async checkControlUiAuth(context: ScanContext): Promise<ScanCheck> {
    const affected = context.configFiles.find((file) => Boolean(file.raw && CONTROL_UI_BYPASS_PATTERN.test(file.raw)));
    if (affected) {
      return this.fail(
        'CONTROL_UI_AUTH',
        `Control UI auth bypass is enabled in ${affected.name}`,
        REMEDIATIONS.controlUiAuth
      );
    }

    return this.pass('CONTROL_UI_AUTH', 'Control UI auth bypass disabled');
  }

  private async checkBrowserUnsandboxed(context: ScanContext): Promise<ScanCheck> {
    if (!context.openclawConfig.exists && context.configFiles.length === 0) {
      return this.warn('BROWSER_UNSANDBOXED', 'config file not found', REMEDIATIONS.browser);
    }

    if (this.hasBrowserProtection(context.openclawConfig.json)) {
      return this.pass('BROWSER_UNSANDBOXED', 'browser sandbox flags detected');
    }

    for (const file of context.configFiles) {
      if (this.hasBrowserProtection(file.json) || this.hasBrowserProtectionInRaw(file.raw)) {
        return this.pass('BROWSER_UNSANDBOXED', 'browser sandbox flags detected');
      }
    }

    return this.fail('BROWSER_UNSANDBOXED', 'browser is not sandboxed', REMEDIATIONS.browser);
  }

  private computeFixActions(context: ScanContext): FixAction[] {
    const actions: FixAction[] = [];

    if (this.canFixGatewayBinding(context)) {
      actions.push({
        id: 'REBIND_GATEWAY',
        description: 'Bind gateway host to 127.0.0.1',
      });
    }

    if (
      context.configFiles.some(
        (file) => file.exists && typeof file.mode === 'number' && (file.mode & 0o077) !== 0
      )
    ) {
      actions.push({
        id: 'FIX_PERMISSIONS',
        description: 'Set config file permissions to 600',
      });
    }

    const shellSignals = this.readShellSignals(context);
    if (!shellSignals.hasAllowlist && !shellSignals.hasDeny) {
      actions.push({
        id: 'ADD_SAFEBINS',
        description: 'Add a default safeBins shell allowlist',
      });
    }

    if (context.configFiles.some((file) => Boolean(file.raw && CONTROL_UI_BYPASS_PATTERN.test(file.raw)))) {
      actions.push({
        id: 'DISABLE_AUTH_BYPASS',
        description: 'Disable Control UI auth bypass flags',
      });
    }

    return actions;
  }

  private async backupConfigFiles(configFiles: ConfigSnapshot[]): Promise<string> {
    const backupRoot = path.join(this.userHome, '.scan-backup', new Date().toISOString().replace(/[:.]/g, '-'));
    await fs.ensureDir(backupRoot);

    let index = 0;
    for (const file of configFiles) {
      if (!file.exists) {
        continue;
      }

      index += 1;
      await fs.copy(file.path, path.join(backupRoot, `${String(index).padStart(2, '0')}-${file.name}`));
    }

    return backupRoot;
  }

  private async rebindGateway(configFiles: ConfigSnapshot[]): Promise<string[]> {
    const touched: string[] = [];

    for (const file of configFiles) {
      if (!file.exists) {
        continue;
      }

      let raw: string;
      try {
        raw = await fs.readFile(file.path, 'utf8');
      } catch {
        continue;
      }

      const ext = path.extname(file.path).toLowerCase();
      if (ext === '.json') {
        try {
          const parsed = JSON.parse(raw) as unknown;
          const updatedJson = this.withGatewayHostBoundLocal(parsed);
          if (JSON.stringify(updatedJson) !== JSON.stringify(parsed)) {
            await fs.writeJson(file.path, updatedJson, { spaces: 2 });
            touched.push(file.path);
            continue;
          }
        } catch {
          // Fall back to text replacement below.
        }
      }
      const updated = this.rebindGatewayRaw(raw);
      if (updated !== raw) {
        await fs.writeFile(file.path, updated, 'utf8');
        touched.push(file.path);
      }
    }

    return touched;
  }

  private canFixGatewayBinding(context: ScanContext): boolean {
    if (context.openclawConfig.exists && this.isRecord(context.openclawConfig.json)) {
      const bound = this.withGatewayHostBoundLocal(context.openclawConfig.json);
      if (JSON.stringify(bound) !== JSON.stringify(context.openclawConfig.json)) {
        return true;
      }
    }

    return context.configFiles.some((file) => Boolean(file.raw && this.rebindGatewayRaw(file.raw) !== file.raw));
  }
  private rebindGatewayRaw(raw: string): string {
    return raw.replace(
      /((?:"(?:host|bind|address|listen)"|(?:host|bind|address|listen))\s*[:=]\s*["']?)0\.0\.0\.0(["']?)/gi,
      '$1127.0.0.1$2'
    );
  }

  private withGatewayHostBoundLocal(value: unknown): Record<string, unknown> {
    const root = this.isRecord(value) ? { ...value } : {};
    const gateway = this.isRecord(root.gateway) ? { ...root.gateway } : {};
    const host = typeof gateway.host === 'string' ? gateway.host : undefined;

    if (!host || host === '0.0.0.0') {
      gateway.host = '127.0.0.1';
    }

    root.gateway = gateway;
    return root;
  }
  private async fixPermissions(configFiles: ConfigSnapshot[]): Promise<string[]> {
    const touched: string[] = [];

    for (const file of configFiles) {
      if (!file.exists) {
        continue;
      }

      try {
        await fs.chmod(file.path, 0o600);
        touched.push(file.path);
      } catch {
        // Ignore files we cannot chmod.
      }
    }

    return touched;
  }

  private async addSafeBins(configFiles: ConfigSnapshot[]): Promise<string[]> {
    const target = this.selectPrimaryConfig(configFiles);
    if (!target || !target.exists) {
      return [];
    }

    let raw: string;
    try {
      raw = await fs.readFile(target.path, 'utf8');
    } catch {
      return [];
    }

    if (SHELL_ALLOWLIST_PATTERN.test(raw)) {
      return [];
    }

    const ext = path.extname(target.path).toLowerCase();
    if (ext === '.json') {
      try {
        const parsed = JSON.parse(raw) as unknown;
        const updated = this.withSafeBins(parsed);
        await fs.writeJson(target.path, updated, { spaces: 2 });
        return [target.path];
      } catch {
        // Fall through to text append.
      }
    }

    if (ext === '.json') {
      const updated = this.injectSafeBinsJsonText(raw);
      if (updated !== raw) {
        await fs.writeFile(target.path, updated, 'utf8');
        return [target.path];
      }
      return [];
    }

    {
      const newline = raw.endsWith('\n') ? '' : '\n';
      const yamlBlock = `${newline}tools:\n  exec:\n    safeBins:\n${SAFE_BINS.map((entry) => `      - ${entry}`).join('\n')}\n`;
      await fs.writeFile(target.path, `${raw}${yamlBlock}`, 'utf8');
      return [target.path];
    }
  }

  private injectSafeBinsJsonText(raw: string): string {
    const insertion = `"tools": {\n    "exec": {\n      "safeBins": ${JSON.stringify(SAFE_BINS)}\n    }\n  }`;

    if (/^\s*{\s*}\s*$/.test(raw)) {
      return `{\n  ${insertion}\n}\n`;
    }

    const trimmed = raw.trimEnd();
    if (!trimmed.endsWith('}')) {
      return raw;
    }

    return `${trimmed.replace(/}$/, '')}${trimmed.includes('{') && trimmed !== '{' ? ',\n  ' : '\n  '}${insertion}\n}\n`;
  }

  private async disableAuthBypass(configFiles: ConfigSnapshot[]): Promise<string[]> {
    const touched: string[] = [];

    for (const file of configFiles) {
      if (!file.exists) {
        continue;
      }

      let raw: string;
      try {
        raw = await fs.readFile(file.path, 'utf8');
      } catch {
        continue;
      }

      const updated = raw.replace(
        /(("?(?:authBypass|auth_bypass|skipAuth|noAuth|disableAuth)"?)\s*[:=]\s*)(true|yes|1)/gi,
        '$1false'
      );

      if (updated !== raw) {
        await fs.writeFile(file.path, updated, 'utf8');
        touched.push(file.path);
      }
    }

    return touched;
  }

  private withSafeBins(value: unknown): Record<string, unknown> {
    const root = this.isRecord(value) ? { ...value } : {};
    const tools = this.isRecord(root.tools) ? { ...root.tools } : {};
    const exec = this.isRecord(tools.exec) ? { ...tools.exec } : {};

    exec.safeBins = [...SAFE_BINS];
    tools.exec = exec;
    root.tools = tools;

    return root;
  }

  private selectPrimaryConfig(configFiles: ConfigSnapshot[]): ConfigSnapshot | undefined {
    const preferredNames = new Set(['openclaw.json', 'config.json', 'config.yaml', 'config.yml']);

    return (
      configFiles.find((file) => file.exists && preferredNames.has(file.name))
      || configFiles.find((file) => file.exists && ['.json', '.yaml', '.yml'].includes(path.extname(file.path)))
    );
  }

  private readShellSignals(context: ScanContext): ShellSignals {
    const raws = [
      context.policyConfig.raw,
      context.openclawConfig.raw,
      ...context.configFiles.map((file) => file.raw),
    ].filter((raw): raw is string => typeof raw === 'string');

    const hasAllowlist = raws.some((raw) => SHELL_ALLOWLIST_PATTERN.test(raw));
    const hasDeny = raws.some((raw) => SHELL_ALLOW_PATTERN.test(raw) && SHELL_DECISION_DENY_PATTERN.test(raw))
      || this.policyHasShellDecision(context.policyConfig.json, 'DENY');
    const hasAllow = raws.some((raw) => SHELL_ALLOW_PATTERN.test(raw) && SHELL_DECISION_ALLOW_PATTERN.test(raw))
      || this.policyHasShellDecision(context.policyConfig.json, 'ALLOW');
    const hasAsk = raws.some((raw) => SHELL_ALLOW_PATTERN.test(raw) && SHELL_DECISION_ASK_PATTERN.test(raw))
      || this.policyHasShellDecision(context.policyConfig.json, 'ASK');

    return {
      hasAllowlist,
      hasDeny,
      hasAllow,
      hasAsk,
    };
  }

  private policyHasShellDecision(value: unknown, decision: 'ALLOW' | 'ASK' | 'DENY'): boolean {
    const root = this.asRecord(value);
    const modules = this.asRecord(root?.modules);
    const shell = this.asRecord(modules?.Shell);

    if (!shell) {
      return false;
    }

    return Object.values(shell).some((rule) => this.asRecord(rule)?.action === decision);
  }

  private findFirstConfigValue(configFiles: ConfigSnapshot[], keys: string[]): string | undefined {
    for (const file of configFiles) {
      if (!file.raw) {
        continue;
      }

      for (const key of keys) {
        const value = this.extractKeyValue(file.raw, key);
        if (value) {
          return value;
        }
      }
    }

    return undefined;
  }

  private extractKeyValue(raw: string, key: string): string | undefined {
    for (const pattern of KEY_VALUE_PATTERNS(key)) {
      const match = raw.match(pattern);
      if (match?.[1]) {
        return match[1].trim().replace(/^['"]|['"]$/g, '');
      }
    }

    return undefined;
  }

  private async findWildcardGatewayListener(): Promise<string | null> {
    try {
      const { spawnSync } = await import('child_process');
      const ports = ['3000', '3001', '8080', '8443'];

      if (process.platform === 'linux') {
        const result = spawnSync('ss', ['-tln'], { encoding: 'utf8' });
        const output = `${result.stdout || ''}${result.stderr || ''}`;
        const found = ports.find((port) => new RegExp(`0\\.0\\.0\\.0:${port}`).test(output));
        return found ? `0.0.0.0:${found}` : null;
      }

      if (process.platform === 'darwin') {
        const result = spawnSync('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], { encoding: 'utf8' });
        const output = `${result.stdout || ''}${result.stderr || ''}`;
        const found = ports.find((port) => new RegExp(`\\*:(${port})\\b`).test(output));
        return found ? `0.0.0.0:${found}` : null;
      }
    } catch {
      // Best-effort only.
    }

    return null;
  }

  private readNestedString(value: unknown, pathParts: string[]): string | undefined {
    let current: unknown = value;

    for (const part of pathParts) {
      const record = this.asRecord(current);
      if (!record || typeof record[part] === 'undefined') {
        return undefined;
      }
      current = record[part];
    }

    return typeof current === 'string' ? current : undefined;
  }

  private hasBrowserProtection(value: unknown, inBrowserContext = false): boolean {
    if (Array.isArray(value)) {
      return value.some((entry) => this.hasBrowserProtection(entry, inBrowserContext));
    }

    const record = this.asRecord(value);
    if (!record) {
      return false;
    }

    const browserContext =
      inBrowserContext || Object.keys(record).some((key) => BROWSER_CONTEXT_PATTERN.test(key));
    if (browserContext && (record.headless === true || record.sandbox === true)) {
      return true;
    }

    return Object.entries(record).some(([key, entry]) =>
      this.hasBrowserProtection(entry, browserContext || BROWSER_CONTEXT_PATTERN.test(key))
    );
  }

  private hasBrowserProtectionInRaw(raw?: string): boolean {
    if (!raw || !BROWSER_CONTEXT_PATTERN.test(raw)) {
      return false;
    }

    return /(headless|sandbox)\s*[:=]\s*(true|yes|1)/i.test(raw);
  }

  private findSensitiveValue(value: unknown, currentKey?: string): string | null {
    if (typeof value === 'string') {
      return currentKey
        && /api[_-]?key|token|secret|password/i.test(currentKey)
        && value.trim()
        && !this.isEnvReference(value)
        ? currentKey
        : null;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        const match = this.findSensitiveValue(entry, currentKey);
        if (match) {
          return match;
        }
      }
      return null;
    }

    const record = this.asRecord(value);
    if (!record) {
      return null;
    }

    for (const [key, entry] of Object.entries(record)) {
      const match = this.findSensitiveValue(entry, key);
      if (match) {
        return match;
      }
    }

    return null;
  }

  private formatSensitiveLabel(key: string): string {
    const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]/g, ' ').toLowerCase();
    if (normalized.includes('api key') || normalized.includes('apikey')) {
      return 'API key';
    }
    if (normalized.includes('password')) {
      return 'password';
    }
    if (normalized.includes('secret')) {
      return 'secret';
    }
    return 'token';
  }

  private isEnvReference(value: string): boolean {
    const trimmed = value.trim();
    return (
      /^process\.env\.[A-Z0-9_]+$/i.test(trimmed)
      || /^\$\{[A-Z0-9_]+\}$/.test(trimmed)
      || /^\$[A-Z0-9_]+$/.test(trimmed)
    );
  }

  private isNodeVersionVulnerable(version: string): boolean {
    if (compareVersions(version, '22.14.0') < 0) {
      return true;
    }

    return compareVersions(version, '23.0.0') >= 0 && compareVersions(version, '23.6.1') < 0;
  }

  private addTouched(paths: string[], target: Set<string>): void {
    paths.forEach((filePath) => target.add(filePath));
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  private asRecord(value: unknown): Record<string, unknown> | null {
    return this.isRecord(value) ? value : null;
  }

  private pass(id: string, message: string): ScanCheck {
    return { id, status: 'PASS', message };
  }

  private warn(id: string, message: string, remediation: string): ScanCheck {
    return { id, status: 'WARN', message, remediation };
  }

  private fail(id: string, message: string, remediation: string): ScanCheck {
    return { id, status: 'FAIL', message, remediation };
  }
}

function compareVersions(left: string, right: string): number {
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
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function formatMode(mode?: number): string {
  return typeof mode === 'number' ? mode.toString(8).padStart(3, '0') : '???';
}
