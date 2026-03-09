/**
 * ClawReins Security Scanner
 * Audits local OpenClaw configuration for common security misconfigurations.
 */

import { Dirent } from 'fs';
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

interface JsonSnapshot {
  exists: boolean;
  raw?: string;
  data?: unknown;
  error?: string;
}

interface ShellSignals {
  decisions: Array<'ALLOW' | 'ASK' | 'DENY'>;
  hasRestrictions: boolean;
}

const SENSITIVE_KEY_PATTERN = /api[_-]?key|token|secret|password/i;
const SHELL_KEY_PATTERN = /shell|bash|exec|spawn/i;
const SHELL_RESTRICTION_PATTERN =
  /allowlist|allow_list|allowList|allowedCommands|allowed_commands|commandAllowlist|safeBins|scope/i;
const BROWSER_KEY_PATTERN = /browser/i;
const REMEDIATIONS = {
  gateway:
    'Set "gateway": { "host": "127.0.0.1" } in openclaw.json, then access via SSH tunnel only',
  plaintextKeys: 'Move sensitive values to ~/.openclaw/.env and reference via process.env',
  shell: 'Run: clawreins policy set shell.bash=ASK or restrict via allowlist',
  docker: 'Run OpenClaw inside Docker: docker run --rm -it pegasi/openclaw',
  browser:
    'Set headless: true in your browser skill config to prevent prompt injection via DOM',
} as const;

export class SecurityScanner {
  private readonly openclawHome: string;
  private readonly openclawConfigPath: string;
  private readonly policyPath: string;

  constructor() {
    this.openclawHome = process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
    this.openclawConfigPath = path.join(this.openclawHome, 'openclaw.json');
    this.policyPath = path.join(this.openclawHome, 'clawreins', 'policy.json');
  }

  async run(): Promise<ScanReport> {
    const openclawConfig = await this.readJsonFile(this.openclawConfigPath);
    const policyConfig = await this.readJsonFile(this.policyPath);
    const checks = [
      await this.checkGatewayExposed(openclawConfig),
      await this.checkPlaintextKeys(openclawConfig),
      await this.checkShellUnrestricted(policyConfig, openclawConfig),
      await this.checkNoDocker(),
      await this.checkBrowserUnsandboxed(openclawConfig),
    ];
    const score = checks.filter((check) => check.status === 'PASS').length;
    const total = checks.length;
    const verdict = checks.some((check) => check.status === 'FAIL')
      ? 'EXPOSED'
      : checks.some((check) => check.status === 'WARN')
        ? 'NEEDS ATTENTION'
        : 'SECURE';

    return {
      checks,
      score,
      total,
      verdict,
      timestamp: new Date().toISOString(),
    };
  }

  private async checkGatewayExposed(config: JsonSnapshot): Promise<ScanCheck> {
    if (!config.exists) {
      return this.warn('GATEWAY_EXPOSED', 'config file not found', REMEDIATIONS.gateway);
    }

    if (config.data === undefined) {
      return this.warn(
        'GATEWAY_EXPOSED',
        config.error || 'failed to parse config file',
        REMEDIATIONS.gateway
      );
    }

    const root = this.asRecord(config.data);
    const gateway = this.asRecord(root?.gateway);
    const host = typeof gateway?.host === 'string' ? gateway.host : undefined;

    if (host === '127.0.0.1') {
      return this.pass('GATEWAY_EXPOSED', 'host bound to 127.0.0.1');
    }

    if (!host) {
      return this.fail(
        'GATEWAY_EXPOSED',
        'gateway.host missing from openclaw.json',
        REMEDIATIONS.gateway
      );
    }

    return this.fail('GATEWAY_EXPOSED', `host bound to ${host}`, REMEDIATIONS.gateway);
  }

  private async checkPlaintextKeys(config: JsonSnapshot): Promise<ScanCheck> {
    if (!config.exists) {
      return this.warn('PLAINTEXT_KEYS', 'config file not found', REMEDIATIONS.plaintextKeys);
    }

    if (!config.raw || config.data === undefined) {
      return this.warn(
        'PLAINTEXT_KEYS',
        config.error || 'failed to parse config file',
        REMEDIATIONS.plaintextKeys
      );
    }

    const match = this.findSensitiveValue(config.data);
    if (match) {
      return this.fail(
        'PLAINTEXT_KEYS',
        `${this.formatSensitiveLabel(match)} found in openclaw.json`,
        REMEDIATIONS.plaintextKeys
      );
    }

    return this.pass('PLAINTEXT_KEYS', 'no plaintext keys found in openclaw.json');
  }

  private async checkShellUnrestricted(
    policyConfig: JsonSnapshot,
    openclawConfig: JsonSnapshot
  ): Promise<ScanCheck> {
    const policySignals = this.readClawReinsShellPolicy(policyConfig.data);
    if (policySignals) {
      return this.toShellCheck(policySignals);
    }

    const configSignals = this.readShellSignals(openclawConfig.data);
    if (configSignals) {
      return this.toShellCheck(configSignals);
    }

    if (!openclawConfig.exists) {
      return this.warn('SHELL_UNRESTRICTED', 'config file not found', REMEDIATIONS.shell);
    }

    if (openclawConfig.data === undefined) {
      return this.warn(
        'SHELL_UNRESTRICTED',
        openclawConfig.error || 'failed to parse config file',
        REMEDIATIONS.shell
      );
    }

    return this.warn('SHELL_UNRESTRICTED', 'shell policy not found', REMEDIATIONS.shell);
  }

  private async checkNoDocker(): Promise<ScanCheck> {
    try {
      if (await fs.pathExists('/.dockerenv')) {
        return this.pass('NO_DOCKER', 'running inside Docker container');
      }
    } catch {
      // Advisory-only check; fall through to WARN.
    }

    return this.warn('NO_DOCKER', 'not running in container', REMEDIATIONS.docker);
  }

  private async checkBrowserUnsandboxed(config: JsonSnapshot): Promise<ScanCheck> {
    if (!config.exists) {
      return this.warn('BROWSER_UNSANDBOXED', 'config file not found', REMEDIATIONS.browser);
    }

    if (config.data === undefined) {
      return this.warn(
        'BROWSER_UNSANDBOXED',
        config.error || 'failed to parse config file',
        REMEDIATIONS.browser
      );
    }

    if (this.hasBrowserProtection(config.data)) {
      return this.pass('BROWSER_UNSANDBOXED', 'browser sandbox flags detected');
    }

    const browserConfigs = await this.readBrowserConfigs();
    if (browserConfigs.some((snapshot) => snapshot.data !== undefined && this.hasBrowserProtection(snapshot.data, true))) {
      return this.pass('BROWSER_UNSANDBOXED', 'browser sandbox flags detected');
    }

    return this.fail('BROWSER_UNSANDBOXED', 'browser not sandboxed', REMEDIATIONS.browser);
  }

  private toShellCheck(signals: ShellSignals): ScanCheck {
    if (signals.hasRestrictions || signals.decisions.includes('DENY')) {
      return this.pass('SHELL_UNRESTRICTED', 'shell scope defined');
    }

    if (signals.decisions.includes('ALLOW')) {
      return this.fail(
        'SHELL_UNRESTRICTED',
        'shell access allowed without restrictions',
        REMEDIATIONS.shell
      );
    }

    if (signals.decisions.includes('ASK')) {
      return this.warn(
        'SHELL_UNRESTRICTED',
        'shell requires approval but no allowlist defined',
        REMEDIATIONS.shell
      );
    }

    return this.warn('SHELL_UNRESTRICTED', 'shell policy not found', REMEDIATIONS.shell);
  }

  private readClawReinsShellPolicy(value: unknown): ShellSignals | null {
    const root = this.asRecord(value);
    const modules = this.asRecord(root?.modules);
    const shell = this.asRecord(modules?.Shell);

    if (!shell) {
      return null;
    }

    const decisions = Object.values(shell)
      .map((rule) => this.asRecord(rule))
      .map((rule) => rule?.action)
      .filter((action): action is 'ALLOW' | 'ASK' | 'DENY' =>
        action === 'ALLOW' || action === 'ASK' || action === 'DENY'
      );

    return {
      decisions,
      hasRestrictions: this.hasRestrictionValue(shell),
    };
  }

  private readShellSignals(value: unknown, inShellContext = false): ShellSignals | null {
    if (Array.isArray(value)) {
      for (const item of value) {
        const nested = this.readShellSignals(item, inShellContext);
        if (nested) {
          return nested;
        }
      }
      return null;
    }

    const record = this.asRecord(value);
    if (!record) {
      return null;
    }

    const shellContext =
      inShellContext || Object.keys(record).some((key) => SHELL_KEY_PATTERN.test(key));
    const decisions: Array<'ALLOW' | 'ASK' | 'DENY'> = [];

    if (shellContext) {
      for (const [key, entry] of Object.entries(record)) {
        if ((key === 'action' || key === 'defaultAction' || key === 'mode') && typeof entry === 'string') {
          const normalized = entry.toUpperCase();
          if (normalized === 'ALLOW' || normalized === 'ASK' || normalized === 'DENY') {
            decisions.push(normalized);
          }
        }
      }

      const hasRestrictions = this.hasRestrictionValue(record);
      if (decisions.length > 0 || hasRestrictions) {
        return { decisions, hasRestrictions };
      }
    }

    for (const [key, entry] of Object.entries(record)) {
      const nested = this.readShellSignals(entry, shellContext || SHELL_KEY_PATTERN.test(key));
      if (nested) {
        return nested;
      }
    }

    return null;
  }

  private async readBrowserConfigs(): Promise<JsonSnapshot[]> {
    const files = await this.findBrowserConfigFiles(this.openclawHome);
    const snapshots: JsonSnapshot[] = [];

    for (const filePath of files) {
      if (filePath !== this.openclawConfigPath) {
        snapshots.push(await this.readJsonFile(filePath));
      }
    }

    return snapshots;
  }

  private async findBrowserConfigFiles(
    directory: string,
    depth = 0,
    matches: string[] = []
  ): Promise<string[]> {
    if (depth > 5 || matches.length >= 200) {
      return matches;
    }

    let entries: Dirent[];
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      return matches;
    }

    for (const entry of entries) {
      if (matches.length >= 200) {
        break;
      }

      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await this.findBrowserConfigFiles(fullPath, depth + 1, matches);
        continue;
      }

      if (entry.isFile() && path.extname(entry.name) === '.json' && BROWSER_KEY_PATTERN.test(fullPath)) {
        matches.push(fullPath);
      }
    }

    return matches;
  }

  private hasBrowserProtection(value: unknown, inBrowserContext = false): boolean {
    if (Array.isArray(value)) {
      return value.some((item) => this.hasBrowserProtection(item, inBrowserContext));
    }

    const record = this.asRecord(value);
    if (!record) {
      return false;
    }

    const browserContext =
      inBrowserContext || Object.keys(record).some((key) => BROWSER_KEY_PATTERN.test(key));
    if (browserContext && (record.headless === true || record.sandbox === true)) {
      return true;
    }

    return Object.entries(record).some(([key, entry]) =>
      this.hasBrowserProtection(entry, browserContext || BROWSER_KEY_PATTERN.test(key))
    );
  }

  private findSensitiveValue(value: unknown, currentKey?: string): string | null {
    if (typeof value === 'string') {
      return currentKey && SENSITIVE_KEY_PATTERN.test(currentKey) && value.trim() ? currentKey : null;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        const match = this.findSensitiveValue(item, currentKey);
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
    const normalized = key
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .replace(/[_-]/g, ' ')
      .toLowerCase();
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

  private hasRestrictionValue(value: unknown): boolean {
    if (Array.isArray(value)) {
      return value.some((item) => this.hasRestrictionValue(item));
    }

    const record = this.asRecord(value);
    if (!record) {
      return false;
    }

    return Object.entries(record).some(([key, entry]) => {
      if (SHELL_RESTRICTION_PATTERN.test(key)) {
        return this.isNonEmpty(entry);
      }
      return this.hasRestrictionValue(entry);
    });
  }

  private isNonEmpty(value: unknown): boolean {
    if (typeof value === 'string') {
      return value.trim().length > 0;
    }
    if (Array.isArray(value)) {
      return value.length > 0;
    }
    if (value && typeof value === 'object') {
      return Object.keys(value).length > 0;
    }
    return value === true;
  }

  private async readJsonFile(filePath: string): Promise<JsonSnapshot> {
    try {
      if (!(await fs.pathExists(filePath))) {
        return { exists: false };
      }

      const raw = await fs.readFile(filePath, 'utf-8');
      try {
        return {
          exists: true,
          raw,
          data: JSON.parse(raw) as unknown,
        };
      } catch (error) {
        return {
          exists: true,
          raw,
          error: error instanceof Error ? error.message : 'failed to parse config file',
        };
      }
    } catch (error) {
      return {
        exists: true,
        error: error instanceof Error ? error.message : 'failed to read config file',
      };
    }
  }

  private asRecord(value: unknown): Record<string, unknown> | null {
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
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
