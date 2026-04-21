/**
 * ClaudeCodeScanner
 * Audits a Claude Code installation for OWASP Agentic Skills Top 10 (ASI)
 * and OWASP MCP Top 10 risks.
 *
 * Produces the same ScanCheck[] shape as SecurityScanner so results can be
 * merged into a single ScanReport.
 */

import crypto from 'crypto';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { ScanCheck } from './SecurityScanner';
import { getDataPath } from './data-dir';

// ─── OWASP tag constants ──────────────────────────────────────────────────────

export const OWASP_TAGS = {
  ASI01: 'ASI01',  // Skill / Prompt Injection
  ASI02: 'ASI02',  // Excessive Permissions
  ASI03: 'ASI03',  // Secrets / Credential Exposure
  ASI04: 'ASI04',  // Unprotected Memory
  ASI05: 'ASI05',  // Soul / Code Integrity
  ASI06: 'ASI06',  // Supply Chain
  ASI10: 'ASI10',  // Rogue Agent / Audit Gap
  MCP01: 'MCP01',  // Tool Poisoning
  MCP05: 'MCP05',  // Broken Authentication
  MCP09: 'MCP09',  // Insufficient Logging
} as const;

// ─── Known CVEs ───────────────────────────────────────────────────────────────

interface KnownCve {
  id: string;
  description: string;
  check: (ctx: ScanContext) => boolean;
}

const KNOWN_CVES: KnownCve[] = [
  {
    id: 'CVE-2026-21852',
    description: 'ANTHROPIC_BASE_URL pre-trust — untrusted base URL accepted without validation',
    check: (_ctx) =>
      typeof process.env.ANTHROPIC_BASE_URL === 'string' &&
      !process.env.ANTHROPIC_BASE_URL.startsWith('https://api.anthropic.com'),
  },
  {
    id: 'CVE-2025-59828',
    description: 'Yarn PnP pre-trust — Yarn Plug\'n\'Play resolves untrusted packages before lockfile check',
    check: (ctx) => ctx.hasYarnPnp,
  },
];

// ─── Known legitimate skill / plugin names (for typosquat detection) ─────────

const KNOWN_SKILL_NAMES = new Set([
  'gmail', 'github', 'slack', 'notion', 'filesystem', 'postgres', 'sqlite',
  'brave-search', 'fetch', 'puppeteer', 'playwright', 'sequential-thinking',
  'everything', 'memory', 'time', 'aws', 'gcp', 'azure', 'stripe', 'linear',
  'jira', 'confluence', 'figma', 'dropbox', 'gdrive', 'reins',
]);

// ─── Injection patterns ───────────────────────────────────────────────────────

const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
  /disregard\s+(all\s+)?(previous|prior|above)/i,
  /you\s+are\s+now\s+(a|an)\s+/i,
  /new\s+instructions?:/i,
  /system\s+prompt:/i,
  /\[system\]/i,
  /override\s+(your\s+)?(instructions?|rules?|guidelines?)/i,
  // Hidden unicode: zero-width space, ZWNJ, ZWJ, soft hyphen, BOM
  /[\u200B\u200C\u200D\u00AD\uFEFF]/,
  // Suspiciously large base64 blob (>80 contiguous base64 chars)
  /[A-Za-z0-9+/]{80,}={0,2}/,
];

const SECRET_PATTERNS: RegExp[] = [
  /sk-ant-[a-zA-Z0-9_-]+/,
  /sk-[a-zA-Z0-9]{20,}/,
  /(?:api[_-]?key|token|secret|password)\s*[:=]\s*["']?[a-zA-Z0-9_\-./]{16,}/i,
  /ANTHROPIC_API_KEY\s*[:=]\s*\S/i,
  /OPENAI_API_KEY\s*[:=]\s*\S/i,
  /ghp_[a-zA-Z0-9]{36}/,
  /xoxb-[a-zA-Z0-9-]+/,
  /cr_[a-zA-Z0-9]{20,}/,
  /wt_[a-zA-Z0-9]{20,}/,
];

// ─── Claude Code path helpers ─────────────────────────────────────────────────

function claudeHome(): string {
  return path.join(os.homedir(), '.claude');
}

function globalSettingsPath(): string {
  return path.join(claudeHome(), 'settings.json');
}

function projectSettingsPath(): string {
  return path.join(process.cwd(), '.claude', 'settings.json');
}

function mcpConfigPath(): string {
  return path.join(process.cwd(), '.mcp.json');
}

// ─── Internal types ───────────────────────────────────────────────────────────

interface SettingsJson {
  hooks?: {
    PreToolUse?: Array<{ matcher: string; hooks: unknown[] }>;
    PostToolUse?: Array<{ matcher: string; hooks: unknown[] }>;
  };
  permissions?: {
    allow?: string[];
    deny?: string[];
  };
  [key: string]: unknown;
}

interface McpServer {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  auth?: unknown;
  [key: string]: unknown;
}

interface McpConfig {
  mcpServers?: Record<string, McpServer>;
  [key: string]: unknown;
}

interface ScanContext {
  globalSettings: SettingsJson | null;
  projectSettings: SettingsJson | null;
  mcpConfig: McpConfig | null;
  skillFiles: Array<{ path: string; content: string; name: string }>;
  memoryFiles: Array<{ path: string; content: string }>;
  configFiles: Array<{ path: string; content: string }>;
  hasYarnPnp: boolean;
}

// ─── ClaudeCodeScanner ────────────────────────────────────────────────────────

export class ClaudeCodeScanner {
  private readonly home = os.homedir();

  async run(): Promise<ScanCheck[]> {
    const ctx = await this.buildContext();

    return [
      // ASI01 / MCP01
      this.checkSkillInjection(ctx),
      // ASI02 (permissions)
      this.checkExcessivePermissions(ctx),
      // ASI02 (hook coverage — non-MCP tools)
      this.checkHookCoverage(ctx),
      // MCP09 (MCP audit hook)
      this.checkMcpHookCoverage(ctx),
      // ASI03
      await this.checkConfigSecrets(ctx),
      // ASI04
      this.checkMemorySecrets(ctx),
      // ASI05
      this.checkMemoryIntegrity(ctx),
      // ASI05 (known CVEs)
      this.checkKnownCves(ctx),
      // ASI06 (supply chain — unpinned)
      await this.checkPluginSupplyChain(),
      // ASI06 (supply chain — typosquats)
      this.checkSkillTyposquat(ctx),
      // ASI06 (settings drift)
      await this.checkSettingsDrift(ctx),
      // ASI10
      await this.checkAuditCoverage(ctx),
      // MCP05
      this.checkMcpAuth(ctx),
      // MCP01
      this.checkMcpToolPoisoning(ctx),
    ];
  }

  // ── ASI01 / MCP01 — Skill & Tool Injection ──────────────────────────────────

  private checkSkillInjection(ctx: ScanContext): ScanCheck {
    if (ctx.skillFiles.length === 0) {
      return this.pass('CLAUDE_SKILL_INJECTION', `${OWASP_TAGS.ASI01} no skill files found`);
    }

    for (const file of ctx.skillFiles) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(file.content)) {
          return this.fail(
            'CLAUDE_SKILL_INJECTION',
            `${OWASP_TAGS.ASI01} potential prompt injection pattern in skill: ${file.name}`,
            'Review the skill file for injected instructions. Remove or quarantine untrusted skills.'
          );
        }
      }
    }

    return this.pass(
      'CLAUDE_SKILL_INJECTION',
      `${OWASP_TAGS.ASI01} ${ctx.skillFiles.length} skill file(s) scanned — no injection patterns found`
    );
  }

  // ── ASI02 — Excessive Permissions ───────────────────────────────────────────

  private checkExcessivePermissions(ctx: ScanContext): ScanCheck {
    const dangerousAllows: string[] = [];

    for (const settings of [ctx.globalSettings, ctx.projectSettings]) {
      const allowed = settings?.permissions?.allow ?? [];
      for (const rule of allowed) {
        if (/^(Bash|WebFetch|WebSearch)$/.test(rule.trim())) {
          dangerousAllows.push(rule.trim());
        }
      }
    }

    if (dangerousAllows.length > 0) {
      return this.fail(
        'CLAUDE_EXCESSIVE_PERMISSIONS',
        `${OWASP_TAGS.ASI02} overpermissive allow rules that permit arbitrary commands or URLs: ${dangerousAllows.join(', ')}`,
        'Scope allow rules to specific commands, e.g. Bash(npm run test) instead of bare Bash.'
      );
    }

    return this.pass(
      'CLAUDE_EXCESSIVE_PERMISSIONS',
      `${OWASP_TAGS.ASI02} no unrestricted tool allow rules found`
    );
  }

  // ── ASI02 — Hook Coverage (non-MCP tools) ───────────────────────────────────

  private checkHookCoverage(ctx: ScanContext): ScanCheck {
    const required = ['Bash', 'Edit', 'MultiEdit', 'Write'];
    const covered = this.coveredPreToolMatchers(ctx);
    const missing = required.filter((m) => !covered.has(m));

    if (missing.length > 0) {
      return this.warn(
        'CLAUDE_HOOK_COVERAGE',
        `${OWASP_TAGS.ASI02} PreToolUse hooks missing for: ${missing.join(', ')}`,
        'Run `reins init` to install hooks for all required tool matchers.'
      );
    }

    return this.pass(
      'CLAUDE_HOOK_COVERAGE',
      `${OWASP_TAGS.ASI02} PreToolUse hooks cover all core tool matchers`
    );
  }

  // ── MCP09 — MCP Hook Coverage ────────────────────────────────────────────────

  private checkMcpHookCoverage(ctx: ScanContext): ScanCheck {
    const covered = this.coveredPreToolMatchers(ctx);

    if (!covered.has('')) {
      return this.warn(
        'CLAUDE_MCP_AUDIT',
        `${OWASP_TAGS.MCP09} no PreToolUse hook with empty matcher — MCP tool calls are not intercepted`,
        'Run `reins init` to install the MCP catch-all hook (empty-string matcher).'
      );
    }

    return this.pass(
      'CLAUDE_MCP_AUDIT',
      `${OWASP_TAGS.MCP09} MCP catch-all PreToolUse hook is configured`
    );
  }

  private coveredPreToolMatchers(ctx: ScanContext): Set<string> {
    const covered = new Set<string>();
    for (const settings of [ctx.globalSettings, ctx.projectSettings]) {
      for (const group of settings?.hooks?.PreToolUse ?? []) {
        if (group.hooks?.length > 0) covered.add(group.matcher);
      }
    }
    return covered;
  }

  // ── ASI03 — Credential Leakage in Config Files ──────────────────────────────

  private async checkConfigSecrets(ctx: ScanContext): Promise<ScanCheck> {
    // Re-read settings/mcp files (content not in ctx.configFiles)
    const toScan: Array<{ path: string; content: string }> = [...ctx.configFiles];
    for (const p of [globalSettingsPath(), projectSettingsPath(), mcpConfigPath()]) {
      if (await fs.pathExists(p)) {
        try {
          toScan.push({ path: p, content: await fs.readFile(p, 'utf8') });
        } catch { /* skip */ }
      }
    }

    for (const file of toScan) {
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(file.content)) {
          return this.fail(
            'CLAUDE_CONFIG_SECRETS',
            `${OWASP_TAGS.ASI03} potential secret found in ${path.basename(file.path)} — exposes credentials to any process that can read the file`,
            'Move secrets to environment variables. Reference them as ${ENV_VAR} in config files.'
          );
        }
      }
    }

    return this.pass(
      'CLAUDE_CONFIG_SECRETS',
      `${OWASP_TAGS.ASI03} no secrets detected in Claude Code config files`
    );
  }

  // ── ASI04 — Unprotected Memory ───────────────────────────────────────────────

  private checkMemorySecrets(ctx: ScanContext): ScanCheck {
    for (const file of ctx.memoryFiles) {
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(file.content)) {
          return this.fail(
            'CLAUDE_MEMORY_SECRETS',
            `${OWASP_TAGS.ASI04} potential secret in ${path.basename(file.path)}`,
            'Remove secrets from memory files. Use environment variables or a secrets manager instead.'
          );
        }
      }
    }

    return this.pass(
      'CLAUDE_MEMORY_SECRETS',
      `${OWASP_TAGS.ASI04} no secrets detected in ${ctx.memoryFiles.length} memory file(s)`
    );
  }

  // ── ASI05 — Soul / Memory Integrity ─────────────────────────────────────────

  private checkMemoryIntegrity(ctx: ScanContext): ScanCheck {
    for (const file of ctx.memoryFiles) {
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(file.content)) {
          return this.fail(
            'CLAUDE_MEMORY_INTEGRITY',
            `${OWASP_TAGS.ASI05} injection pattern in ${path.basename(file.path)}`,
            'Review memory/soul files for tampered instructions. Regenerate from a trusted source.'
          );
        }
      }
    }

    return this.pass(
      'CLAUDE_MEMORY_INTEGRITY',
      `${OWASP_TAGS.ASI05} no injection patterns in memory/soul files`
    );
  }

  // ── ASI05 — Known CVEs ───────────────────────────────────────────────────────

  private checkKnownCves(ctx: ScanContext): ScanCheck {
    const triggered = KNOWN_CVES.filter((cve) => cve.check(ctx));

    if (triggered.length > 0) {
      const ids = triggered.map((c) => c.id).join(', ');
      const descriptions = triggered.map((c) => `${c.id}: ${c.description}`).join('; ');
      return this.fail(
        'CLAUDE_KNOWN_CVES',
        `${OWASP_TAGS.ASI05} known CVE(s) detected: ${ids}`,
        `Remediate: ${descriptions}`
      );
    }

    return this.pass(
      'CLAUDE_KNOWN_CVES',
      `${OWASP_TAGS.ASI05} no known CVE conditions detected`
    );
  }

  // ── ASI06 — Supply Chain: Unpinned Plugins ───────────────────────────────────

  private async checkPluginSupplyChain(): Promise<ScanCheck> {
    const installedPluginsPath = path.join(claudeHome(), 'plugins', 'installed_plugins.json');

    if (!(await fs.pathExists(installedPluginsPath))) {
      return this.pass('CLAUDE_SUPPLY_CHAIN', `${OWASP_TAGS.ASI06} no installed plugins found`);
    }

    let installed: Record<string, unknown>;
    try {
      const raw = await fs.readJson(installedPluginsPath) as { plugins?: Record<string, unknown> };
      installed = raw.plugins ?? {};
    } catch {
      return this.warn(
        'CLAUDE_SUPPLY_CHAIN',
        `${OWASP_TAGS.ASI06} could not read installed plugins list`,
        'Manually verify plugin integrity at ~/.claude/plugins/installed_plugins.json'
      );
    }

    const pluginNames = Object.keys(installed);
    if (pluginNames.length === 0) {
      return this.pass('CLAUDE_SUPPLY_CHAIN', `${OWASP_TAGS.ASI06} no installed plugins`);
    }

    const unpinned: string[] = [];
    for (const [name, entries] of Object.entries(installed)) {
      const list = Array.isArray(entries) ? entries : [entries];
      for (const entry of list) {
        const e = entry as Record<string, unknown>;
        if (!e['gitCommitSha']) unpinned.push(name);
      }
    }

    if (unpinned.length > 0) {
      return this.warn(
        'CLAUDE_SUPPLY_CHAIN',
        `${OWASP_TAGS.ASI06} ${unpinned.length} plugin(s) not pinned to a commit SHA — vulnerable to silent updates or supply-chain attacks: ${unpinned.join(', ')}`,
        'Pin plugins to specific versions or commit SHAs to prevent supply chain drift.'
      );
    }

    return this.pass(
      'CLAUDE_SUPPLY_CHAIN',
      `${OWASP_TAGS.ASI06} ${pluginNames.length} plugin(s) installed and SHA-pinned`
    );
  }

  // ── ASI06 — Supply Chain: Typosquat Detection ────────────────────────────────

  private checkSkillTyposquat(ctx: ScanContext): ScanCheck {
    const suspicious: string[] = [];

    for (const file of ctx.skillFiles) {
      const base = file.name.toLowerCase().replace(/[-_\s]/g, '');

      for (const known of KNOWN_SKILL_NAMES) {
        const knownBase = known.replace(/[-_\s]/g, '');
        if (base === knownBase) break; // exact match is fine

        const dist = levenshtein(base, knownBase);
        if (dist === 1 || dist === 2) {
          // Close but not exact — potential typosquat
          if (!suspicious.includes(file.name)) {
            suspicious.push(file.name);
          }
        }
      }
    }

    if (suspicious.length > 0) {
      return this.warn(
        'CLAUDE_SKILL_TYPOSQUAT',
        `${OWASP_TAGS.ASI06} skill name(s) closely resemble known legitimate skills — possible typosquat: ${suspicious.join(', ')}`,
        'Verify the skill source and publisher before use. Remove if origin is unknown.'
      );
    }

    return this.pass(
      'CLAUDE_SKILL_TYPOSQUAT',
      `${OWASP_TAGS.ASI06} no typosquat-like skill names detected`
    );
  }

  // ── ASI06 — Settings Drift ───────────────────────────────────────────────────

  private async checkSettingsDrift(ctx: ScanContext): Promise<ScanCheck> {
    const baselinePath = getDataPath('settings-baseline.json');
    const current = this.securitySnapshot(ctx);
    const currentHash = hashObject(current);

    if (!(await fs.pathExists(baselinePath))) {
      // First run — save baseline
      await fs.writeJson(baselinePath, { hash: currentHash, savedAt: new Date().toISOString() }, { spaces: 2 });
      return this.pass(
        'CLAUDE_SETTINGS_DRIFT',
        `${OWASP_TAGS.ASI06} security baseline established`
      );
    }

    let saved: { hash: string; savedAt: string };
    try {
      saved = await fs.readJson(baselinePath) as { hash: string; savedAt: string };
    } catch {
      return this.warn(
        'CLAUDE_SETTINGS_DRIFT',
        `${OWASP_TAGS.ASI06} could not read settings baseline`,
        'Run `reins scan` to re-establish the baseline.'
      );
    }

    if (saved.hash !== currentHash) {
      // Update baseline for next run
      await fs.writeJson(baselinePath, { hash: currentHash, savedAt: new Date().toISOString() }, { spaces: 2 });
      return this.warn(
        'CLAUDE_SETTINGS_DRIFT',
        `${OWASP_TAGS.ASI06} security-relevant settings changed since ${new Date(saved.savedAt).toLocaleDateString()} — hooks or permissions may have been modified`,
        'Review changes to .claude/settings.json hooks and permissions sections. Run `reins audit` to inspect recent decisions.'
      );
    }

    return this.pass(
      'CLAUDE_SETTINGS_DRIFT',
      `${OWASP_TAGS.ASI06} security settings match baseline — no drift detected`
    );
  }

  private securitySnapshot(ctx: ScanContext): Record<string, unknown> {
    return {
      globalHooks: ctx.globalSettings?.hooks ?? null,
      globalPermissions: ctx.globalSettings?.permissions ?? null,
      projectHooks: ctx.projectSettings?.hooks ?? null,
      projectPermissions: ctx.projectSettings?.permissions ?? null,
    };
  }

  // ── ASI10 — Audit Coverage ───────────────────────────────────────────────────

  private async checkAuditCoverage(ctx: ScanContext): Promise<ScanCheck> {
    // Check PostToolUse hooks exist
    const hasPostHooks = [ctx.globalSettings, ctx.projectSettings].some(
      (s) => (s?.hooks?.PostToolUse ?? []).some((g) => g.hooks?.length > 0)
    );

    if (!hasPostHooks) {
      return this.warn(
        'CLAUDE_AUDIT_COVERAGE',
        `${OWASP_TAGS.ASI10} no PostToolUse hooks configured — agent decisions are not being logged`,
        'Run `reins init` to install PostToolUse hooks that write to the audit trail.'
      );
    }

    // Check audit log exists and is non-empty
    const auditLogPaths = [
      path.join(this.home, '.openclaw', 'reins', 'decisions.jsonl'),
      getDataPath('decisions.jsonl'),
    ];

    for (const logPath of auditLogPaths) {
      if (await fs.pathExists(logPath)) {
        const stats = await fs.stat(logPath);
        if (stats.size > 0) {
          return this.pass(
            'CLAUDE_AUDIT_COVERAGE',
            `${OWASP_TAGS.ASI10} PostToolUse hooks active and audit log contains entries`
          );
        }
      }
    }

    return this.warn(
      'CLAUDE_AUDIT_COVERAGE',
      `${OWASP_TAGS.ASI10} PostToolUse hooks configured but audit log is empty or missing`,
      'Ensure the agent has run at least one action, then check ~/.openclaw/reins/decisions.jsonl'
    );
  }

  // ── MCP05 — Broken Authentication ────────────────────────────────────────────

  private checkMcpAuth(ctx: ScanContext): ScanCheck {
    if (!ctx.mcpConfig?.mcpServers || Object.keys(ctx.mcpConfig.mcpServers).length === 0) {
      return this.pass('CLAUDE_MCP_AUTH', `${OWASP_TAGS.MCP05} no MCP servers configured`);
    }

    const unauthenticated: string[] = [];
    const plaintextKeys: string[] = [];

    for (const [name, server] of Object.entries(ctx.mcpConfig.mcpServers)) {
      if (server.env) {
        for (const [key, value] of Object.entries(server.env)) {
          if (
            /api[_-]?key|token|secret|password/i.test(key) &&
            value.trim().length > 0 &&
            !value.startsWith('$') &&
            !value.startsWith('process.env')
          ) {
            plaintextKeys.push(`${name}.env.${key}`);
          }
        }
      }

      const isRemote = server.args?.some((arg) => /^https?:\/\//i.test(arg));
      if (isRemote && !server.auth && !server.env?.['API_KEY'] && !server.env?.['TOKEN']) {
        unauthenticated.push(name);
      }
    }

    if (plaintextKeys.length > 0) {
      return this.fail(
        'CLAUDE_MCP_AUTH',
        `${OWASP_TAGS.MCP05} plaintext credentials in .mcp.json: ${plaintextKeys.join(', ')}`,
        'Move secrets to environment variables and reference them via ${ENV_VAR} in .mcp.json.'
      );
    }

    if (unauthenticated.length > 0) {
      return this.warn(
        'CLAUDE_MCP_AUTH',
        `${OWASP_TAGS.MCP05} remote MCP servers without visible auth: ${unauthenticated.join(', ')}`,
        'Ensure remote MCP servers require authentication tokens via environment variables.'
      );
    }

    return this.pass('CLAUDE_MCP_AUTH', `${OWASP_TAGS.MCP05} MCP server authentication looks configured`);
  }

  // ── MCP01 — Tool Poisoning ───────────────────────────────────────────────────

  private checkMcpToolPoisoning(ctx: ScanContext): ScanCheck {
    if (!ctx.mcpConfig?.mcpServers || Object.keys(ctx.mcpConfig.mcpServers).length === 0) {
      return this.pass('CLAUDE_MCP_TOOL_POISONING', `${OWASP_TAGS.MCP01} no MCP servers configured`);
    }

    const suspicious: string[] = [];
    for (const [name, server] of Object.entries(ctx.mcpConfig.mcpServers)) {
      const searchText = [name, ...(server.args ?? []), server.command ?? ''].join(' ');
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(searchText)) {
          suspicious.push(name);
          break;
        }
      }
    }

    if (suspicious.length > 0) {
      return this.fail(
        'CLAUDE_MCP_TOOL_POISONING',
        `${OWASP_TAGS.MCP01} suspicious patterns in MCP server config: ${suspicious.join(', ')}`,
        'Review the MCP server configuration. Remove untrusted servers and verify tool descriptions at runtime.'
      );
    }

    return this.pass(
      'CLAUDE_MCP_TOOL_POISONING',
      `${OWASP_TAGS.MCP01} no injection patterns found in MCP server config`
    );
  }

  // ─── Context builder ──────────────────────────────────────────────────────────

  private async buildContext(): Promise<ScanContext> {
    const [globalSettings, projectSettings, mcpConfig, skillFiles, memoryFiles, configFiles, hasYarnPnp] =
      await Promise.all([
        this.loadJson<SettingsJson>(globalSettingsPath()),
        this.loadJson<SettingsJson>(projectSettingsPath()),
        this.loadJson<McpConfig>(mcpConfigPath()),
        this.discoverSkillFiles(),
        this.discoverMemoryFiles(),
        this.discoverConfigFiles(),
        this.detectYarnPnp(),
      ]);

    return { globalSettings, projectSettings, mcpConfig, skillFiles, memoryFiles, configFiles, hasYarnPnp };
  }

  private async discoverSkillFiles(): Promise<Array<{ path: string; content: string; name: string }>> {
    const results: Array<{ path: string; content: string; name: string }> = [];
    const searchDirs = [
      path.join(claudeHome(), 'skills'),
      path.join(claudeHome(), 'plugins', 'cache'),
      path.join(process.cwd(), '.claude', 'skills'),
    ];

    for (const dir of searchDirs) {
      if (!(await fs.pathExists(dir))) continue;
      await this.collectFiles(dir, /SKILL\.md$/i, results, 4);
    }

    return results;
  }

  private async discoverMemoryFiles(): Promise<Array<{ path: string; content: string }>> {
    const results: Array<{ path: string; content: string }> = [];
    const candidates = [
      path.join(claudeHome(), 'MEMORY.md'),
      path.join(claudeHome(), 'SOUL.md'),
      path.join(claudeHome(), 'CLAUDE.md'),
      path.join(process.cwd(), 'MEMORY.md'),
      path.join(process.cwd(), 'SOUL.md'),
      path.join(process.cwd(), 'CLAUDE.md'),
    ];

    const memoryDir = path.join(process.cwd(), '.claude', 'memory');
    if (await fs.pathExists(memoryDir)) {
      await this.collectFiles(memoryDir, /\.md$/i, results, 2);
    }

    for (const filePath of candidates) {
      if (await fs.pathExists(filePath)) {
        try {
          results.push({ path: filePath, content: await fs.readFile(filePath, 'utf8') });
        } catch { /* skip */ }
      }
    }

    return results;
  }

  private async discoverConfigFiles(): Promise<Array<{ path: string; content: string }>> {
    const results: Array<{ path: string; content: string }> = [];
    const candidates = [
      path.join(process.cwd(), '.env'),
      path.join(process.cwd(), '.env.local'),
      path.join(this.home, '.env'),
    ];

    for (const filePath of candidates) {
      if (await fs.pathExists(filePath)) {
        try {
          results.push({ path: filePath, content: await fs.readFile(filePath, 'utf8') });
        } catch { /* skip */ }
      }
    }

    return results;
  }

  private async detectYarnPnp(): Promise<boolean> {
    return fs.pathExists(path.join(process.cwd(), '.pnp.cjs'))
      || fs.pathExists(path.join(process.cwd(), '.pnp.js'));
  }

  private async collectFiles(
    dir: string,
    pattern: RegExp,
    results: Array<{ path: string; content: string; name?: string }>,
    maxDepth: number,
    currentDepth = 0
  ): Promise<void> {
    if (currentDepth > maxDepth) return;

    let entries: fs.Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await this.collectFiles(fullPath, pattern, results, maxDepth, currentDepth + 1);
      } else if (entry.isFile() && pattern.test(entry.name)) {
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          // Skill name = parent directory name
          const name = path.basename(path.dirname(fullPath));
          (results as Array<{ path: string; content: string; name: string }>).push({ path: fullPath, content, name });
        } catch { /* skip */ }
      }
    }
  }

  private async loadJson<T>(filePath: string): Promise<T | null> {
    if (!(await fs.pathExists(filePath))) return null;
    try {
      return (await fs.readJson(filePath)) as T;
    } catch {
      return null;
    }
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────────

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

// ─── Utilities ────────────────────────────────────────────────────────────────

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[m][n];
}

function hashObject(obj: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(obj)).digest('hex').slice(0, 16);
}
