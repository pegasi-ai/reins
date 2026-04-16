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
  artifactFiles: ConfigSnapshot[];
  stateFiles: ConfigSnapshot[];
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
  channelDmPolicy: 'Restrict Telegram/WhatsApp DMs with dmPolicy "allowlist" and explicit allowFrom entries',
  mcpEnableAll: 'Disable automatic trust of all project MCP servers; approve MCP servers individually',
  mcpFilesystemRoots: 'Limit filesystem MCP roots to narrow project directories and exclude home/system secrets',
  mcpServerPinning: 'Pin MCP server packages to exact versions and avoid shell-piped remote installers',
  mcpRemoteAuth: 'Use HTTPS and authorization headers for remote MCP servers outside localhost',
  installedArtifactRisk: 'Review or remove installed skills/plugins that contain risky shell, network, or dynamic-code patterns',
  skillPermissions: 'Constrain skill/plugin permissions to the minimum required capabilities and avoid wildcard access',
  localStateExposure: 'Remove plaintext secrets from local agent state',
  skillExternalOrigin: 'Pin installed skills/plugins to immutable package versions or commit SHAs from trusted origins',
  worldWritableArtifacts: 'Restrict installed skill/plugin and local state permissions so group/other users cannot modify them',
  pluginDependencyPinning: 'Pin plugin package dependencies to exact versions or immutable sources',
  sensitiveScopeDeclarations: 'Gate high-impact skill/plugin scopes with ASK or DENY policy rules before granting broad access',
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
const MCP_ENABLE_ALL_PATTERN = /"?enableAllProjectMcpServers"?\s*[:=]\s*(true|yes|1)/i;
const RISKY_MCP_INSTALL_PATTERN =
  /(\b(curl|wget)\b[\s\S]{0,160}\|\s*(sh|bash)\b|\b(npx|uvx)\s+(?!-[\w-]+\s+)(@?[\w.-]+(?:\/[\w.-]+)?)(?!@[\w.-])|\b(pip|pip3)\s+install\s+(?!-[\w-]+\s+)([\w.-]+)(?!==|~=|>=|<=|@)|\blatest\b|github:[\w.-]+\/[\w.-]+#[\w./-]+)/i;
const ARTIFACT_SCAN_EXTENSIONS = new Set([
  '.cjs',
  '.env',
  '.js',
  '.json',
  '.md',
  '.mjs',
  '.py',
  '.sh',
  '.toml',
  '.ts',
  '.txt',
  '.yaml',
  '.yml',
]);
const ARTIFACT_ENTRY_FILES = [
  'openclaw.plugin.json',
  'package.json',
  'plugin.json',
  'manifest.json',
  'skill.json',
  'install.sh',
  'postinstall.sh',
  'index.js',
  'index.ts',
] as const;
const RISKY_ARTIFACT_PATTERN =
  /(\b(curl|wget)\b[\s\S]{0,160}\|\s*(sh|bash)\b|\b(base64|openssl)\b[\s\S]{0,120}\|\s*(sh|bash|node|python)\b|Buffer\.from\([^)]*base64[^)]*\)|eval\s*\(|new Function\s*\(|child_process\.(exec|execSync)\s*\(|\bnc\s+.*\s-e\s|\bbash\s+-i\b|\/dev\/tcp\/|rm\s+-rf\s+(\/|~|\$HOME))/i;
const EXTERNAL_ORIGIN_PATTERN =
  /(github:[\w.-]+\/[\w.-]+(#(main|master|head))?|https?:\/\/(github\.com|raw\.githubusercontent\.com|gist\.github\.com)\/[^\s"'`]+((\/tree\/|\/archive\/|#)(main|master|head|latest)\b)?|"?version"?\s*[:=]\s*["']?(latest|\*)["']?|"?source"?\s*[:=]\s*["']?(file:|\/tmp\/|~\/Downloads|\/Users\/[^"']+\/Downloads|~\/Desktop|\/Users\/[^"']+\/Desktop)|"?path"?\s*[:=]\s*["']?(\/tmp\/|~\/Downloads|\/Users\/[^"']+\/Downloads|~\/Desktop|\/Users\/[^"']+\/Desktop))/i;
const PINNED_PACKAGE_VERSION_PATTERN =
  /^(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?|npm:[^@]+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?|https:\/\/github\.com\/[\w.-]+\/[\w.-]+(?:\.git)?#[0-9a-f]{40}|github:[\w.-]+\/[\w.-]+#[0-9a-f]{40})$/i;
const DECLARED_SCOPE_KEYS = ['permissions', 'scopes', 'capabilities', 'access'] as const;
const WILDCARD_SCOPE_VALUES = new Set(['*', 'all', 'full-access', 'full_access', 'unrestricted']);
const AUTH_HEADER_NAMES = new Set(['authorization', 'x-api-key', 'x-api-token']);
const SCOPE_TO_POLICY_MODULES: Array<{ values: string[]; modules: string[] }> = [
  { values: ['filesystem', 'file-system', 'files', 'file'], modules: ['FileSystem'] },
  { values: ['shell', 'exec', 'terminal'], modules: ['Shell'] },
  { values: ['browser'], modules: ['Browser'] },
  { values: ['email', 'gmail', 'calendar', 'drive', 'slack', 'notion', 'payments', 'payment', 'bank', 'aws', 'ssh', 'credentials'], modules: ['Network', 'Gateway'] },
];

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
      await this.checkChannelDmPolicy(context),
      await this.checkMcpEnableAllServers(context),
      await this.checkMcpFilesystemRoots(context),
      await this.checkMcpServerPinning(context),
      await this.checkMcpRemoteTransportAuth(context),
      await this.checkInstalledArtifactRisk(context),
      await this.checkSkillPermissionBoundaries(context),
      await this.checkLocalStateExposure(context),
      await this.checkSkillExternalOrigin(context),
      await this.checkWorldWritableArtifacts(context),
      await this.checkPluginDependencyPinning(context),
      await this.checkSensitiveScopeDeclarations(context),
    ];
  }

  private async loadContext(): Promise<ScanContext> {
    const configPaths = await this.discoverConfigPaths();
    const artifactPaths = await this.discoverArtifactPaths();
    const statePaths = await this.discoverStatePaths();
    const configFiles = await Promise.all(configPaths.map((filePath) => this.readConfig(filePath)));
    const artifactFiles = await Promise.all(artifactPaths.map((filePath) => this.readConfig(filePath)));
    const stateFiles = await Promise.all(statePaths.map((filePath) => this.readConfig(filePath)));

    return {
      configFiles,
      artifactFiles,
      stateFiles,
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

  private async discoverArtifactPaths(): Promise<string[]> {
    const deduped = new Set<string>();
    await this.addArtifactEntryFiles(path.join(this.openclawHome, 'extensions'), deduped);

    const configuredPaths = await this.readConfiguredPluginPaths();
    for (const configuredPath of configuredPaths) {
      await this.addArtifactEntryFiles(configuredPath, deduped);
    }

    return Array.from(deduped).sort();
  }

  private async discoverStatePaths(): Promise<string[]> {
    const candidates = [
      path.join(this.openclawHome, 'workspace', 'AGENTS.md'),
      path.join(this.userHome, '.claude', 'CLAUDE.md'),
    ];
    const deduped = new Set<string>();

    for (const filePath of candidates) {
      await this.addExistingReadableFile(filePath, deduped);
    }

    return Array.from(deduped).sort();
  }

  private async readConfiguredPluginPaths(): Promise<string[]> {
    const config = await this.readConfig(this.openclawConfigPath);
    const entries = this.collectPluginEntries(config.json);
    const pluginPaths = new Set<string>();

    for (const entry of entries) {
      for (const key of ['path', 'dir', 'directory', 'pluginDir']) {
        const value = entry.config[key];
        if (typeof value === 'string') {
          pluginPaths.add(path.resolve(this.openclawHome, expandHome(value, this.userHome)));
        }
      }
    }

    return Array.from(pluginPaths).sort();
  }

  private async addArtifactEntryFiles(directory: string, found: Set<string>): Promise<void> {
    if (!(await fs.pathExists(directory))) {
      return;
    }

    let stats;
    try {
      stats = await fs.stat(directory);
    } catch {
      return;
    }

    if (stats.isFile()) {
      await this.addExistingReadableFile(directory, found);
      return;
    }

    if (!stats.isDirectory()) {
      return;
    }

    let entries: string[];
    try {
      entries = await fs.readdir(directory);
    } catch {
      return;
    }

    for (const fileName of ARTIFACT_ENTRY_FILES) {
      await this.addExistingReadableFile(path.join(directory, fileName), found);
    }

    for (const entry of entries.sort().slice(0, 200)) {
      const childPath = path.join(directory, entry);
      let childStats;
      try {
        childStats = await fs.stat(childPath);
      } catch {
        continue;
      }

      if (!childStats.isDirectory()) {
        continue;
      }

      for (const fileName of ARTIFACT_ENTRY_FILES) {
        await this.addExistingReadableFile(path.join(childPath, fileName), found);
      }
    }
  }

  private async addExistingReadableFile(filePath: string, found: Set<string>): Promise<void> {
    if (!(await fs.pathExists(filePath))) {
      return;
    }

    try {
      const stats = await fs.stat(filePath);
      if (!stats.isFile() || stats.size > 256_000 || !ARTIFACT_SCAN_EXTENSIONS.has(path.extname(filePath).toLowerCase())) {
        return;
      }

      try {
        found.add(await fs.realpath(filePath));
      } catch {
        found.add(filePath);
      }
    } catch {
      // Best-effort discovery only.
    }
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

  private async checkChannelDmPolicy(context: ScanContext): Promise<ScanCheck> {
    const finding = this.findOpenChannelDmPolicy(context.openclawConfig.json);
    if (finding) {
      return this.fail(
        'CHANNEL_DM_POLICY',
        `${finding.channel} DMs are open to ${finding.reason}`,
        REMEDIATIONS.channelDmPolicy
      );
    }

    if (this.hasConfigPattern(context, /dmPolicy\s*[:=]\s*["']?open["']?/i)) {
      return this.fail(
        'CHANNEL_DM_POLICY',
        'channel dmPolicy is open',
        REMEDIATIONS.channelDmPolicy
      );
    }

    return this.pass('CHANNEL_DM_POLICY', 'channel DMs are restricted or not configured');
  }

  private async checkMcpEnableAllServers(context: ScanContext): Promise<ScanCheck> {
    const affected = context.configFiles.find((file) => Boolean(file.raw && MCP_ENABLE_ALL_PATTERN.test(file.raw)));
    if (affected) {
      return this.fail(
        'MCP_ENABLE_ALL_SERVERS',
        `automatic trust for project MCP servers enabled in ${affected.name}`,
        REMEDIATIONS.mcpEnableAll
      );
    }

    return this.pass('MCP_ENABLE_ALL_SERVERS', 'project MCP servers are not automatically trusted');
  }

  private async checkMcpFilesystemRoots(context: ScanContext): Promise<ScanCheck> {
    const riskyRoot = this.findRiskyMcpFilesystemRoot(context.openclawConfig.json);
    if (riskyRoot) {
      return this.warn(
        'MCP_FILESYSTEM_ROOTS',
        `filesystem MCP server exposes broad root ${riskyRoot}`,
        REMEDIATIONS.mcpFilesystemRoots
      );
    }

    if (this.hasConfigPattern(context, /(mcp|filesystem)[\s\S]{0,300}(["']?(~|\$HOME|\.ssh|\.aws|\.gnupg|Downloads)["']?)/i)) {
      return this.warn(
        'MCP_FILESYSTEM_ROOTS',
        'filesystem MCP server may expose broad or sensitive paths',
        REMEDIATIONS.mcpFilesystemRoots
      );
    }

    return this.pass('MCP_FILESYSTEM_ROOTS', 'filesystem MCP roots are narrow or not configured');
  }

  private async checkMcpServerPinning(context: ScanContext): Promise<ScanCheck> {
    const riskyServer = this.findRiskyMcpServerPinning(context.openclawConfig.json);
    if (riskyServer) {
      return this.warn(
        'MCP_SERVER_PINNING',
        `unpinned or shell-installed MCP server dependency found in ${riskyServer}`,
        REMEDIATIONS.mcpServerPinning
      );
    }

    const affected = context.configFiles.find((file) => Boolean(file.raw && RISKY_MCP_INSTALL_PATTERN.test(file.raw)));
    if (affected) {
      return this.warn(
        'MCP_SERVER_PINNING',
        `unpinned or shell-installed MCP server dependency found in ${affected.name}`,
        REMEDIATIONS.mcpServerPinning
      );
    }

    return this.pass('MCP_SERVER_PINNING', 'MCP server commands appear pinned');
  }

  private async checkMcpRemoteTransportAuth(context: ScanContext): Promise<ScanCheck> {
    const finding = this.findMcpRemoteWithoutAuth(context.openclawConfig.json);
    if (finding) {
      const status = finding.url.startsWith('http://') ? 'FAIL' : 'WARN';
      return {
        id: 'MCP_REMOTE_TRANSPORT_AUTH',
        status,
        message: `remote MCP server ${finding.name} uses ${finding.reason}`,
        remediation: REMEDIATIONS.mcpRemoteAuth,
      };
    }

    if (this.hasConfigPattern(context, /\bmcp\b[\s\S]{0,300}\burl\s*[:=]\s*["']http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/i)) {
      return this.fail(
        'MCP_REMOTE_TRANSPORT_AUTH',
        'remote MCP server uses HTTP outside localhost',
        REMEDIATIONS.mcpRemoteAuth
      );
    }

    return this.pass('MCP_REMOTE_TRANSPORT_AUTH', 'remote MCP servers use localhost or authenticated HTTPS');
  }

  private async checkInstalledArtifactRisk(context: ScanContext): Promise<ScanCheck> {
    const affected = context.artifactFiles.find((file) => Boolean(file.raw && RISKY_ARTIFACT_PATTERN.test(file.raw)));
    if (affected) {
      return this.warn(
        'INSTALLED_ARTIFACT_RISK',
        `installed skill/plugin contains risky execution pattern in ${this.relativeHomePath(affected.path)}`,
        REMEDIATIONS.installedArtifactRisk
      );
    }

    return this.pass(
      'INSTALLED_ARTIFACT_RISK',
      context.artifactFiles.length > 0
        ? 'installed skills/plugins do not contain known risky execution patterns'
        : 'no installed skill/plugin artifacts found'
    );
  }

  private async checkSkillPermissionBoundaries(context: ScanContext): Promise<ScanCheck> {
    const affected = context.artifactFiles.find((file) => this.hasBroadDeclaredArtifactPermission(file));
    if (affected) {
      return this.warn(
        'SKILL_PERMISSION_BOUNDARIES',
        `installed skill/plugin declares wildcard or unrestricted capabilities in ${this.relativeHomePath(affected.path)}`,
        REMEDIATIONS.skillPermissions
      );
    }

    return this.pass(
      'SKILL_PERMISSION_BOUNDARIES',
      context.artifactFiles.length > 0
        ? 'installed skill/plugin manifest permissions are scoped or not declared'
        : 'no installed skill/plugin manifest permissions found'
    );
  }

  private async checkLocalStateExposure(context: ScanContext): Promise<ScanCheck> {
    const secret = context.stateFiles.find((file) =>
      Boolean(file.raw && API_KEY_PATTERNS.some((pattern) => pattern.test(file.raw || '')))
    );
    if (secret) {
      return this.fail(
        'LOCAL_STATE_EXPOSURE',
        `plaintext secret found in local agent state ${this.relativeHomePath(secret.path)}`,
        REMEDIATIONS.localStateExposure
      );
    }

    return this.pass(
      'LOCAL_STATE_EXPOSURE',
      context.stateFiles.length > 0
        ? 'local agent state does not contain known plaintext secret patterns'
        : 'no local agent state files found'
    );
  }

  private async checkSkillExternalOrigin(context: ScanContext): Promise<ScanCheck> {
    const finding = this.findRiskyExternalOrigin(context);
    if (finding) {
      const status = finding.reason === 'mutable local path' ? 'FAIL' : 'WARN';
      return {
        id: 'SKILL_EXTERNAL_ORIGIN',
        status,
        message: `${finding.reason} found in ${this.relativeHomePath(finding.file.path)}`,
        remediation: REMEDIATIONS.skillExternalOrigin,
      };
    }

    return this.pass(
      'SKILL_EXTERNAL_ORIGIN',
      context.artifactFiles.length > 0
        ? 'installed skill/plugin origins appear pinned or local-only'
        : 'no installed skill/plugin origins found'
    );
  }

  private async checkWorldWritableArtifacts(context: ScanContext): Promise<ScanCheck> {
    const files = [...context.artifactFiles, ...context.stateFiles];
    const writable = files.find((file) => file.exists && typeof file.mode === 'number' && (file.mode & 0o022) !== 0);
    if (writable) {
      const status = context.artifactFiles.some((file) => file.path === writable.path) ? 'FAIL' : 'WARN';
      return {
        id: 'WORLD_WRITABLE_ARTIFACTS',
        status,
        message: `loose permissions on ${this.relativeHomePath(writable.path)} (${formatMode(writable.mode)})`,
        remediation: REMEDIATIONS.worldWritableArtifacts,
      };
    }

    const writableDirectory = await this.findWritableArtifactDirectory(files);
    if (writableDirectory) {
      return {
        id: 'WORLD_WRITABLE_ARTIFACTS',
        status: writableDirectory.isArtifact ? 'FAIL' : 'WARN',
        message: `loose permissions on ${this.relativeHomePath(writableDirectory.path)} (${formatMode(writableDirectory.mode)})`,
        remediation: REMEDIATIONS.worldWritableArtifacts,
      };
    }

    return this.pass(
      'WORLD_WRITABLE_ARTIFACTS',
      files.length > 0
        ? 'installed skill/plugin and local state permissions are restricted'
        : 'no installed skill/plugin or local state files found'
    );
  }

  private async checkPluginDependencyPinning(context: ScanContext): Promise<ScanCheck> {
    const finding = this.findUnpinnedPluginDependency(context.artifactFiles);
    if (finding) {
      return this.warn(
        'PLUGIN_DEPENDENCY_PINNING',
        `plugin dependency ${finding.name}@${finding.version} is not pinned in ${this.relativeHomePath(finding.file.path)}`,
        REMEDIATIONS.pluginDependencyPinning
      );
    }

    return this.pass(
      'PLUGIN_DEPENDENCY_PINNING',
      context.artifactFiles.length > 0
        ? 'plugin package dependencies are pinned or not declared'
        : 'no plugin package dependencies found'
    );
  }

  private async checkSensitiveScopeDeclarations(context: ScanContext): Promise<ScanCheck> {
    const finding = this.findSensitiveScopeDeclaration(context);
    if (!finding) {
      return this.pass(
        'SENSITIVE_SCOPE_DECLARATIONS',
        context.artifactFiles.length > 0
          ? 'installed skill/plugin scopes are low-impact or not declared'
          : 'no installed skill/plugin scope declarations found'
      );
    }

    const hasCoverage = finding.requiredModules.some((moduleName) =>
      this.policyHasModuleDecision(context.policyConfig.json, moduleName, 'ASK')
      || this.policyHasModuleDecision(context.policyConfig.json, moduleName, 'DENY')
    );

    return {
      id: 'SENSITIVE_SCOPE_DECLARATIONS',
      status: hasCoverage ? 'WARN' : 'FAIL',
      message: hasCoverage
        ? `high-impact skill/plugin scope declared in ${this.relativeHomePath(finding.file.path)}`
        : `high-impact skill/plugin scope lacks ASK/DENY policy coverage in ${this.relativeHomePath(finding.file.path)}`,
      remediation: REMEDIATIONS.sensitiveScopeDeclarations,
    };
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
          if (this.shouldMutateGatewayJson(parsed, file.path)) {
            const updatedJson = this.withGatewayHostBoundLocal(parsed);
            if (JSON.stringify(updatedJson) !== JSON.stringify(parsed)) {
              await fs.writeJson(file.path, updatedJson, { spaces: 2 });
              touched.push(file.path);
              continue;
            }
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

    if (Object.prototype.hasOwnProperty.call(root, 'gateway') && !this.isRecord(root.gateway)) {
      return root;
    }

    const gateway = this.isRecord(root.gateway) ? { ...root.gateway } : {};
    const host = typeof gateway.host === 'string' ? gateway.host : undefined;

    if (!host || host === '0.0.0.0') {
      gateway.host = '127.0.0.1';
    }

    root.gateway = gateway;
    return root;
  }

  private shouldMutateGatewayJson(value: unknown, filePath: string): boolean {
    if (!this.isRecord(value)) {
      return false;
    }

    return filePath === this.openclawConfigPath || Object.prototype.hasOwnProperty.call(value, 'gateway');
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

  private hasConfigPattern(context: ScanContext, pattern: RegExp): boolean {
    return [
      context.policyConfig.raw,
      context.openclawConfig.raw,
      ...context.configFiles.map((file) => file.raw),
    ]
      .filter((raw): raw is string => typeof raw === 'string')
      .some((raw) => pattern.test(raw));
  }

  private findOpenChannelDmPolicy(value: unknown): { channel: string; reason: string } | null {
    const root = this.asRecord(value);
    const channels = this.asRecord(root?.channels);
    if (!channels) {
      return null;
    }

    for (const channel of ['telegram', 'whatsapp', 'discord']) {
      const config = this.asRecord(channels[channel]);
      if (!config) {
        continue;
      }

      const dmPolicy = typeof config.dmPolicy === 'string' ? config.dmPolicy.toLowerCase() : '';
      const allowFrom = Array.isArray(config.allowFrom) ? config.allowFrom : [];
      if (dmPolicy === 'open') {
        return { channel, reason: 'all senders' };
      }
      if (allowFrom.includes('*')) {
        return { channel, reason: 'wildcard senders' };
      }
    }

    return null;
  }

  private findRiskyMcpFilesystemRoot(value: unknown): string | null {
    const servers = this.getMcpServers(value);
    for (const [name, server] of Object.entries(servers)) {
      const command = typeof server.command === 'string' ? server.command.toLowerCase() : '';
      const serverText = JSON.stringify(server).toLowerCase();
      if (!/(filesystem|file-system|fs)/.test(`${name.toLowerCase()} ${command} ${serverText}`)) {
        continue;
      }

      const candidates = this.collectStringValues(server);
      const risky = candidates.find((entry) => this.isRiskyFilesystemRoot(entry));
      if (risky) {
        return risky;
      }
    }

    return null;
  }

  private findRiskyMcpServerPinning(value: unknown): string | null {
    const servers = this.getMcpServers(value);
    for (const [name, server] of Object.entries(servers)) {
      const command = typeof server.command === 'string' ? server.command : '';
      const args = Array.isArray(server.args)
        ? server.args.filter((entry): entry is string => typeof entry === 'string')
        : [];
      const commandLine = [command, ...args].join(' ');

      if (RISKY_MCP_INSTALL_PATTERN.test(commandLine)) {
        return name;
      }
    }

    return null;
  }

  private findMcpRemoteWithoutAuth(value: unknown): { name: string; url: string; reason: string } | null {
    const servers = this.getMcpServers(value);
    for (const [name, server] of Object.entries(servers)) {
      const url = typeof server.url === 'string' ? server.url : undefined;
      if (!url || this.isLocalMcpUrl(url)) {
        continue;
      }

      if (url.startsWith('http://')) {
        return { name, url, reason: 'HTTP outside localhost' };
      }

      if (!this.mcpServerHasAuth(server)) {
        return { name, url, reason: 'HTTPS without auth headers' };
      }
    }

    return null;
  }

  private getMcpServers(value: unknown): Record<string, Record<string, unknown>> {
    const root = this.asRecord(value);
    const mcp = this.asRecord(root?.mcp);
    const servers = this.asRecord(mcp?.servers ?? root?.mcpServers);
    if (!servers) {
      return {};
    }

    const result: Record<string, Record<string, unknown>> = {};
    for (const [name, server] of Object.entries(servers)) {
      const record = this.asRecord(server);
      if (record) {
        result[name] = record;
      }
    }

    return result;
  }

  private collectStringValues(value: unknown): string[] {
    if (typeof value === 'string') {
      return [value];
    }

    if (Array.isArray(value)) {
      return value.flatMap((entry) => this.collectStringValues(entry));
    }

    const record = this.asRecord(value);
    if (!record) {
      return [];
    }

    return Object.values(record).flatMap((entry) => this.collectStringValues(entry));
  }

  private isRiskyFilesystemRoot(value: string): boolean {
    const expandedHome = this.userHome;
    const normalized = value.replace(/^file:\/\//, '').replace(/\/+$/, '') || '/';
    return normalized === '/'
      || normalized === '~'
      || normalized === '$HOME'
      || normalized === expandedHome
      || normalized === '.'
      || normalized.includes('/.ssh')
      || normalized.includes('/.aws')
      || normalized.includes('/.gnupg')
      || /(^|\/)Downloads($|\/)/.test(normalized);
  }

  private isLocalMcpUrl(value: string): boolean {
    try {
      const parsed = new URL(value);
      return ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
    } catch {
      return false;
    }
  }

  private mcpServerHasAuth(server: Record<string, unknown>): boolean {
    const headers = this.asRecord(server.headers);
    if (headers && Object.entries(headers).some(([key, value]) =>
      AUTH_HEADER_NAMES.has(key.toLowerCase()) && typeof value === 'string' && value.trim().length > 0
    )) {
      return true;
    }

    return false;
  }

  private hasBroadDeclaredArtifactPermission(file: ConfigSnapshot): boolean {
    const scopes = this.extractDeclaredScopes(file.json);
    if (scopes.length === 0) {
      return false;
    }

    return scopes.some((scope) => {
      const normalized = this.normalizeScope(scope);
      return WILDCARD_SCOPE_VALUES.has(normalized)
        || normalized.endsWith(':*')
        || normalized.endsWith('.*')
        || normalized.endsWith('/*');
    });
  }

  private findRiskyExternalOrigin(context: ScanContext): { file: ConfigSnapshot; reason: string } | null {
    for (const file of context.artifactFiles) {
      if (!file.raw || !EXTERNAL_ORIGIN_PATTERN.test(file.raw)) {
        continue;
      }

      const reason = /(\/tmp\/|Downloads|Desktop|file:)/i.test(file.raw)
        ? 'mutable local path'
        : 'unpinned external skill/plugin origin';
      return { file, reason };
    }

    for (const entry of this.collectPluginEntries(context.openclawConfig.json)) {
      const values = this.collectStringValues(entry.config).join('\n');
      if (EXTERNAL_ORIGIN_PATTERN.test(values)) {
        const reason = /(\/tmp\/|Downloads|Desktop|file:)/i.test(values)
          ? 'mutable local path'
          : 'unpinned external skill/plugin origin';
        return { file: context.openclawConfig, reason };
      }
    }

    return null;
  }

  private async findWritableArtifactDirectory(
    files: ConfigSnapshot[]
  ): Promise<{ path: string; mode: number; isArtifact: boolean } | null> {
    const checked = new Set<string>();
    for (const file of files) {
      let directory = path.dirname(file.path);
      while (directory.startsWith(this.openclawHome) || directory.startsWith(path.join(this.userHome, '.claude'))) {
        if (checked.has(directory)) {
          break;
        }
        checked.add(directory);

        try {
          const stats = await fs.stat(directory);
          const mode = stats.mode & 0o777;
          if ((mode & 0o022) !== 0) {
            return {
              path: directory,
              mode,
              isArtifact: file.path.startsWith(path.join(this.openclawHome, 'skills'))
                || file.path.startsWith(path.join(this.openclawHome, 'plugins'))
                || file.path.startsWith(path.join(this.openclawHome, 'extensions')),
            };
          }
        } catch {
          break;
        }

        const parent = path.dirname(directory);
        if (parent === directory || directory === this.openclawHome || directory === path.join(this.userHome, '.claude')) {
          break;
        }
        directory = parent;
      }
    }

    return null;
  }

  private findSensitiveScopeDeclaration(
    context: ScanContext
  ): { file: ConfigSnapshot; requiredModules: string[] } | null {
    for (const file of context.artifactFiles) {
      const declaredScopes = this.extractDeclaredScopes(file.json);
      if (declaredScopes.length === 0) {
        continue;
      }

      const requiredModules = this.requiredPolicyModulesForScopes(declaredScopes);
      if (requiredModules.length > 0) {
        return { file, requiredModules };
      }
    }

    return null;
  }

  private findUnpinnedPluginDependency(
    artifactFiles: ConfigSnapshot[]
  ): { file: ConfigSnapshot; name: string; version: string } | null {
    for (const file of artifactFiles) {
      if (file.name !== 'package.json') {
        continue;
      }

      const packageJson = this.asRecord(file.json);
      if (!packageJson) {
        continue;
      }

      for (const sectionName of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        const dependencies = this.asRecord(packageJson[sectionName]);
        if (!dependencies) {
          continue;
        }

        for (const [name, version] of Object.entries(dependencies)) {
          if (typeof version !== 'string' || !this.isPinnedPackageVersion(version)) {
            return { file, name, version: typeof version === 'string' ? version : '<non-string>' };
          }
        }
      }
    }

    return null;
  }

  private isPinnedPackageVersion(value: string): boolean {
    return PINNED_PACKAGE_VERSION_PATTERN.test(value.trim());
  }

  private requiredPolicyModulesForScopes(scopes: string[]): string[] {
    const modules = new Set<string>();
    for (const mapping of SCOPE_TO_POLICY_MODULES) {
      if (scopes.some((scope) => mapping.values.some((value) => this.scopeMatches(scope, value)))) {
        mapping.modules.forEach((moduleName) => modules.add(moduleName));
      }
    }

    return Array.from(modules);
  }

  private extractDeclaredScopes(value: unknown): string[] {
    const record = this.asRecord(value);
    if (!record) {
      return [];
    }

    const scopes: string[] = [];
    for (const key of DECLARED_SCOPE_KEYS) {
      scopes.push(...this.collectScopeValues(record[key]));
    }

    return scopes;
  }

  private collectScopeValues(value: unknown): string[] {
    if (typeof value === 'string') {
      return [value];
    }

    if (Array.isArray(value)) {
      return value.flatMap((entry) => this.collectScopeValues(entry));
    }

    const record = this.asRecord(value);
    if (!record) {
      return [];
    }

    return Object.entries(record).flatMap(([key, entry]) => {
      if (entry === true) {
        return [key];
      }
      return this.collectScopeValues(entry);
    });
  }

  private scopeMatches(scope: string, expected: string): boolean {
    const normalized = this.normalizeScope(scope);
    return normalized === expected
      || normalized.startsWith(`${expected}:`)
      || normalized.startsWith(`${expected}.`)
      || normalized.startsWith(`${expected}/`)
      || normalized.endsWith(`:${expected}`)
      || normalized.endsWith(`.${expected}`)
      || normalized.endsWith(`/${expected}`);
  }

  private normalizeScope(value: string): string {
    return value.trim().toLowerCase().replace(/_/g, '-');
  }

  private collectPluginEntries(value: unknown): Array<{ name: string; config: Record<string, unknown> }> {
    const root = this.asRecord(value);
    const plugins = this.asRecord(root?.plugins);
    const entries = this.asRecord(plugins?.entries ?? root?.pluginEntries);
    if (!entries) {
      return [];
    }

    const result: Array<{ name: string; config: Record<string, unknown> }> = [];
    for (const [name, entry] of Object.entries(entries)) {
      const record = this.asRecord(entry);
      if (record) {
        result.push({ name, config: record });
      }
    }

    return result;
  }

  private relativeHomePath(filePath: string): string {
    if (filePath === this.userHome) {
      return '~';
    }

    if (filePath.startsWith(`${this.userHome}${path.sep}`)) {
      return `~${path.sep}${path.relative(this.userHome, filePath)}`;
    }

    return filePath;
  }

  private policyHasShellDecision(value: unknown, decision: 'ALLOW' | 'ASK' | 'DENY'): boolean {
    return this.policyHasModuleDecision(value, 'Shell', decision);
  }

  private policyHasModuleDecision(value: unknown, moduleName: string, decision: 'ALLOW' | 'ASK' | 'DENY'): boolean {
    const root = this.asRecord(value);
    const modules = this.asRecord(root?.modules);
    const moduleConfig = this.asRecord(modules?.[moduleName]);

    if (!moduleConfig) {
      return false;
    }

    return Object.values(moduleConfig).some((rule) => this.asRecord(rule)?.action === decision);
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

function expandHome(value: string, userHome: string): string {
  if (value === '~') {
    return userHome;
  }

  if (value.startsWith(`~${path.sep}`)) {
    return path.join(userHome, value.slice(2));
  }

  return value;
}

function formatMode(mode?: number): string {
  return typeof mode === 'number' ? mode.toString(8).padStart(3, '0') : '???';
}
