/**
 * Installs / removes / checks Claude Code PreToolUse + PostToolUse hooks
 * in .claude/settings.json (project or global).
 */

import fs from 'fs-extra';
import path from 'path';
import os from 'os';

// ─── Constants ─────────────────────────────────────────────────────────────

const HOOK_MATCHERS = ['Bash', 'Edit', 'MultiEdit', 'Write'];
const MCP_MATCHER = '';           // empty string catches all MCP tool calls
const HOOK_MARKER = '_reins';     // marker key on individual hook objects

// Script paths resolved relative to this file's compiled location (dist/lib/)
const preToolUseScript = path.resolve(__dirname, '..', 'hooks', 'pre-tool-use.js');
const postToolUseScript = path.resolve(__dirname, '..', 'hooks', 'post-tool-use.js');

// Settings file paths
const projectSettingsPath = path.join(process.cwd(), '.claude', 'settings.json');
const globalSettingsPath = path.join(os.homedir(), '.claude', 'settings.json');

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

function buildMatcherGroups(scriptPath: string): MatcherGroup[] {
  const allMatchers = [...HOOK_MATCHERS, MCP_MATCHER];
  return allMatchers.map((matcher) => ({
    matcher,
    hooks: [
      {
        type: 'command',
        command: `node ${scriptPath}`,
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
): Promise<{ path: string; alreadyInstalled: boolean }> {
  const settingsPath = opts.global ? globalSettingsPath : projectSettingsPath;
  await fs.ensureDir(path.dirname(settingsPath));

  const settings = await loadSettings(settingsPath);
  const hooks: HooksConfig = settings.hooks && typeof settings.hooks === 'object'
    ? settings.hooks
    : {};

  const existingPre: MatcherGroup[] = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];

  // Idempotency: if ANY existing hook has the _reins marker, skip.
  const alreadyInstalled = checkFileForReinsHooks({ ...settings, hooks });
  if (alreadyInstalled) {
    return { path: settingsPath, alreadyInstalled: true };
  }

  // Build new matcher groups to add.
  const newPreGroups = buildMatcherGroups(preToolUseScript);
  const newPostGroups = buildMatcherGroups(postToolUseScript);

  // Merge: keep existing groups that don't already have a _reins hook, then append ours.
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

  await fs.writeJson(settingsPath, updatedSettings, { spaces: 2 });
  return { path: settingsPath, alreadyInstalled: false };
}

export async function uninstallClaudeCodeHooks(
  opts: { global?: boolean } = {}
): Promise<void> {
  const settingsPath = opts.global ? globalSettingsPath : projectSettingsPath;

  if (!(await fs.pathExists(settingsPath))) {
    return;
  }

  const settings = await loadSettings(settingsPath);
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

  await fs.writeJson(settingsPath, updatedSettings, { spaces: 2 });
}

export function hooksStatus(): {
  projectInstalled: boolean;
  globalInstalled: boolean;
  projectPath: string;
  globalPath: string;
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

  return {
    projectInstalled: checkSync(projectSettingsPath),
    globalInstalled: checkSync(globalSettingsPath),
    projectPath: projectSettingsPath,
    globalPath: globalSettingsPath,
  };
}
