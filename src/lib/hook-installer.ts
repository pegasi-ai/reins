/**
 * Installs / removes / checks Claude Code PreToolUse + PostToolUse hooks
 * in .claude/settings.json (project or global).
 */

import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';

// ─── Constants ─────────────────────────────────────────────────────────────

const HOOK_MATCHERS = ['Bash', 'Edit', 'MultiEdit', 'Write'];
const MCP_MATCHER = '';           // empty string catches all MCP tool calls
const HOOK_MARKER = '_reins';     // marker key on individual hook objects

// Script paths resolved relative to this file's compiled location (dist/lib/)
const preToolUseScript = path.resolve(__dirname, '..', 'hooks', 'pre-tool-use.js');
const postToolUseScript = path.resolve(__dirname, '..', 'hooks', 'post-tool-use.js');

// Settings file paths
type HookAgentType = 'claude_code' | 'cowork';
type HookScope = 'project' | 'global';

interface HookTarget {
  agentType: HookAgentType;
  scope: HookScope;
  settingsPath: string;
  label: string;
  autoCreate: boolean;
}

const hookTargets: HookTarget[] = [
  {
    agentType: 'claude_code',
    scope: 'project',
    settingsPath: path.join(process.cwd(), '.claude', 'settings.json'),
    label: 'Claude Code Project (.claude/settings.json)',
    autoCreate: true,
  },
  {
    agentType: 'claude_code',
    scope: 'global',
    settingsPath: path.join(os.homedir(), '.claude', 'settings.json'),
    label: 'Claude Code Global (~/.claude/settings.json)',
    autoCreate: true,
  },
  {
    agentType: 'cowork',
    scope: 'project',
    settingsPath: path.join(process.cwd(), '.cowork', 'settings.json'),
    label: 'Cowork Project (.cowork/settings.json)',
    autoCreate: false,
  },
  {
    agentType: 'cowork',
    scope: 'project',
    settingsPath: path.join(process.cwd(), '.claude-cowork', 'settings.json'),
    label: 'Cowork Project (.claude-cowork/settings.json)',
    autoCreate: false,
  },
  {
    agentType: 'cowork',
    scope: 'global',
    settingsPath: path.join(os.homedir(), '.cowork', 'settings.json'),
    label: 'Cowork Global (~/.cowork/settings.json)',
    autoCreate: false,
  },
  {
    agentType: 'cowork',
    scope: 'global',
    settingsPath: path.join(os.homedir(), '.claude-cowork', 'settings.json'),
    label: 'Cowork Global (~/.claude-cowork/settings.json)',
    autoCreate: false,
  },
];

// ─── Internal types ─────────────────────────────────────────────────────────

interface HookEntry {
  type: string;
  command: string;
  [HOOK_MARKER]?: boolean;
  [key: string]: unknown;
}

interface MatcherGroup {
  matcher: string;
  hooks: HookEntry[];
}

interface HooksConfig {
  PreToolUse?: MatcherGroup[];
  PostToolUse?: MatcherGroup[];
  [key: string]: unknown;
}

interface SettingsJson {
  hooks?: HooksConfig;
  [key: string]: unknown;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function loadSettings(filePath: string): Promise<SettingsJson> {
  try {
    if (await fs.pathExists(filePath)) {
      const raw = (await fs.readJson(filePath)) as unknown;
      return raw && typeof raw === 'object' ? (raw as SettingsJson) : {};
    }
  } catch {
    // Return empty settings on parse errors.
  }
  return {};
}

function buildMatcherGroups(scriptPath: string, agentType: HookAgentType): MatcherGroup[] {
  const allMatchers = [...HOOK_MATCHERS, MCP_MATCHER];
  return allMatchers.map((matcher) => ({
    matcher,
    hooks: [
      {
        type: 'command',
        command: `REINS_AGENT_TYPE=${agentType} node ${scriptPath}`,
        [HOOK_MARKER]: true,
      },
    ],
  }));
}

function removeReinsHooks(groups: MatcherGroup[]): MatcherGroup[] {
  const result: MatcherGroup[] = [];
  for (const group of groups) {
    const filtered = group.hooks.filter((h) => h[HOOK_MARKER] !== true);
    if (filtered.length > 0) {
      result.push({ ...group, hooks: filtered });
    }
    // If no hooks remain for this matcher, drop the whole group.
  }
  return result;
}

function checkFileForReinsHooks(settings: SettingsJson): boolean {
  const hooks = settings.hooks;
  if (!hooks) return false;
  const pre = hooks.PreToolUse;
  if (!Array.isArray(pre)) return false;
  return pre.some((group) => group.hooks.some((h) => h[HOOK_MARKER] === true));
}

// ─── Public API ─────────────────────────────────────────────────────────────

export async function installClaudeCodeHooks(
  opts: { global?: boolean } = {}
): Promise<{ path: string; alreadyInstalled: boolean; installedPaths: string[] }> {
  const targets = resolveInstallTargets(opts.global ? 'global' : 'project');
  const installedPaths: string[] = [];
  let primaryPath = targets[0]?.settingsPath || '';
  let allAlreadyInstalled = true;

  for (const target of targets) {
    if (!target.autoCreate && !(await shouldInstallCoworkTarget(target.settingsPath))) {
      continue;
    }

    await fs.ensureDir(path.dirname(target.settingsPath));

    const settings = await loadSettings(target.settingsPath);
    const hooks: HooksConfig = settings.hooks && typeof settings.hooks === 'object'
      ? settings.hooks
      : {};

    const existingPre: MatcherGroup[] = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];
    const alreadyInstalled = checkFileForReinsHooks({ ...settings, hooks });
    if (alreadyInstalled) {
      installedPaths.push(target.settingsPath);
      continue;
    }

    const newPreGroups = buildMatcherGroups(preToolUseScript, target.agentType);
    const newPostGroups = buildMatcherGroups(postToolUseScript, target.agentType);

    const mergedPre = [...existingPre, ...newPreGroups];
    const existingPost: MatcherGroup[] = Array.isArray(hooks.PostToolUse) ? hooks.PostToolUse : [];
    const mergedPost = [...existingPost, ...newPostGroups];

    const updatedSettings: SettingsJson = {
      ...settings,
      hooks: {
        ...hooks,
        PreToolUse: mergedPre,
        PostToolUse: mergedPost,
      },
    };

    await fs.writeJson(target.settingsPath, updatedSettings, { spaces: 2 });
    installedPaths.push(target.settingsPath);
    allAlreadyInstalled = false;
  }

  if (installedPaths.length > 0) {
    primaryPath = installedPaths[0];
  }

  return { path: primaryPath, alreadyInstalled: allAlreadyInstalled, installedPaths };
}

export async function uninstallClaudeCodeHooks(
  opts: { global?: boolean } = {}
): Promise<void> {
  const targets = resolveInstallTargets(opts.global ? 'global' : 'project');

  for (const target of targets) {
    if (!(await fs.pathExists(target.settingsPath))) {
      continue;
    }

    const settings = await loadSettings(target.settingsPath);
    const hooks: HooksConfig = settings.hooks && typeof settings.hooks === 'object'
      ? settings.hooks
      : {};

    const pre: MatcherGroup[] = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];
    const post: MatcherGroup[] = Array.isArray(hooks.PostToolUse) ? hooks.PostToolUse : [];

    const updatedSettings: SettingsJson = {
      ...settings,
      hooks: {
        ...hooks,
        PreToolUse: removeReinsHooks(pre),
        PostToolUse: removeReinsHooks(post),
      },
    };

    await fs.writeJson(target.settingsPath, updatedSettings, { spaces: 2 });
  }
}

export function hooksStatus(): {
  projectInstalled: boolean;
  globalInstalled: boolean;
  projectPath: string;
  globalPath: string;
  targets: Array<{
    label: string;
    path: string;
    installed: boolean;
    exists: boolean;
    agentType: HookAgentType;
    scope: HookScope;
  }>;
} {
  function checkSync(filePath: string): boolean {
    try {
      if (!require('fs').existsSync(filePath)) return false;
      const raw = require('fs').readFileSync(filePath, 'utf8') as string;
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== 'object') return false;
      return checkFileForReinsHooks(parsed as SettingsJson);
    } catch {
      return false;
    }
  }

  const targets = hookTargets.map((target) => ({
    label: target.label,
    path: target.settingsPath,
    installed: checkSync(target.settingsPath),
    exists: require('fs').existsSync(target.settingsPath),
    agentType: target.agentType,
    scope: target.scope,
  }));

  return {
    projectInstalled: checkSync(hookTargets[0].settingsPath),
    globalInstalled: checkSync(hookTargets[1].settingsPath),
    projectPath: hookTargets[0].settingsPath,
    globalPath: hookTargets[1].settingsPath,
    targets,
  };
}

function resolveInstallTargets(scope: HookScope): HookTarget[] {
  return hookTargets.filter((target) => target.scope === scope);
}

async function shouldInstallCoworkTarget(settingsPath: string): Promise<boolean> {
  if (await fs.pathExists(settingsPath)) {
    return true;
  }

  const configDir = path.dirname(settingsPath);
  if (await fs.pathExists(configDir)) {
    return true;
  }

  return detectCoworkBinary();
}

function detectCoworkBinary(): boolean {
  for (const binary of ['cowork', 'claude-cowork']) {
    const result = spawnSync(binary, ['--version'], {
      stdio: 'ignore',
      shell: false,
    });
    if (result.status === 0) {
      return true;
    }
  }
  return false;
}
