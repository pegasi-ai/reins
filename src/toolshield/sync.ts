/**
 * ToolShield integration helpers for Reins.
 *
 * Goal: make ToolShield protection available by default during `reins init`
 * and easy to re-run via a dedicated command.
 */

import os from 'os';
import path from 'path';
import fs from 'fs-extra';
import { spawnSync } from 'child_process';
import { logger } from '../core/Logger';

export interface ToolShieldSyncOptions {
  agentsFile?: string;
  model?: string;
  installIfMissing?: boolean;
  unloadFirst?: boolean;
  pythonBin?: string;
  bundledDir?: string;
}

export interface ToolShieldSyncResult {
  synced: boolean;
  installedNow: boolean;
  agentsFile: string;
  source: 'bundled' | 'pip' | 'none';
  message: string;
}

const DEFAULT_MODEL = 'claude-sonnet-4.5';

function defaultOpenClawHome(): string {
  return process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
}

function defaultAgentsFile(): string {
  return path.join(defaultOpenClawHome(), 'workspace', 'AGENTS.md');
}

function runPython(
  pythonBin: string,
  args: string[],
  env?: NodeJS.ProcessEnv
): { ok: boolean; stdout: string; stderr: string } {
  const res = spawnSync(pythonBin, args, {
    encoding: 'utf8',
    env: env ? { ...process.env, ...env } : process.env,
  });
  return {
    ok: res.status === 0,
    stdout: (res.stdout || '').trim(),
    stderr: (res.stderr || '').trim(),
  };
}

function hasToolShield(pythonBin: string, env?: NodeJS.ProcessEnv): boolean {
  const check = runPython(pythonBin, [
    '-c',
    'import importlib.util,sys;sys.exit(0 if importlib.util.find_spec("toolshield") else 1)',
  ], env);
  return check.ok;
}

function installToolShield(pythonBin: string): boolean {
  const install = runPython(pythonBin, ['-m', 'pip', 'install', '--upgrade', 'toolshield']);
  if (!install.ok) {
    logger.warn('ToolShield installation failed', { stderr: install.stderr, stdout: install.stdout });
    return false;
  }
  return true;
}

function runToolShieldCli(
  pythonBin: string,
  args: string[],
  env?: NodeJS.ProcessEnv
): boolean {
  const run = runPython(pythonBin, ['-m', 'toolshield.cli', ...args], env);
  if (!run.ok) {
    logger.warn('ToolShield CLI invocation failed', {
      args: args.join(' '),
      stderr: run.stderr,
      stdout: run.stdout,
    });
  }
  return run.ok;
}

function findBundledToolShieldRoot(explicitDir?: string): string | null {
  const candidates = [
    explicitDir || '',
    process.env.TOOLSHIELD_BUNDLED_DIR || '',
    path.resolve(__dirname, '../core/toolshield'),
    path.resolve(__dirname, '../../src/core/toolshield'),
    path.resolve(process.cwd(), 'src/core/toolshield'),
  ].filter(Boolean);

  for (const candidate of candidates) {
    const root = path.resolve(candidate);
    const cliPath = path.join(root, 'toolshield', 'cli.py');
    if (fs.existsSync(cliPath)) {
      return root;
    }
  }
  return null;
}

function buildBundledEnv(bundledRoot: string): NodeJS.ProcessEnv {
  const existing = process.env.PYTHONPATH || '';
  const joined = existing
    ? `${bundledRoot}${path.delimiter}${existing}`
    : bundledRoot;
  return { PYTHONPATH: joined };
}

export async function syncToolShieldDefaults(
  options: ToolShieldSyncOptions = {}
): Promise<ToolShieldSyncResult> {
  const pythonBin = options.pythonBin || process.env.PYTHON_BIN || 'python';
  const agentsFile = options.agentsFile || process.env.AGENTS_FILE || defaultAgentsFile();
  const model = options.model || process.env.TOOLSHIELD_MODEL || DEFAULT_MODEL;
  const installIfMissing = options.installIfMissing ?? true;
  const unloadFirst = options.unloadFirst ?? true;
  const bundledRoot = findBundledToolShieldRoot(options.bundledDir);
  const bundledEnv = bundledRoot ? buildBundledEnv(bundledRoot) : undefined;

  await fs.ensureDir(path.dirname(agentsFile));
  await fs.ensureFile(agentsFile);

  const pythonCheck = spawnSync(pythonBin, ['--version'], { encoding: 'utf8' });
  if (pythonCheck.status !== 0) {
    return {
      synced: false,
      installedNow: false,
      agentsFile,
      source: 'none',
      message: `Python runtime not available (${pythonBin}).`,
    };
  }

  let source: 'bundled' | 'pip' | 'none' = 'none';

  if (bundledEnv && hasToolShield(pythonBin, bundledEnv)) {
    source = 'bundled';
  }

  let installedNow = false;
  if (source === 'none' && !hasToolShield(pythonBin)) {
    if (!installIfMissing) {
      return {
        synced: false,
        installedNow: false,
        agentsFile,
        source: 'none',
        message: 'ToolShield is not installed.',
      };
    }

    installedNow = installToolShield(pythonBin);
    if (!installedNow && !hasToolShield(pythonBin)) {
      return {
        synced: false,
        installedNow: false,
        agentsFile,
        source: 'none',
        message: 'Failed to install ToolShield automatically.',
      };
    }
    source = 'pip';
  } else if (source === 'none') {
    source = 'pip';
  }

  if (unloadFirst) {
    // Best-effort idempotency cleanup; do not fail hard if no prior rules exist.
    runToolShieldCli(pythonBin, [
      'unload',
      '--agent',
      'openclaw',
      '--source_location',
      agentsFile,
    ], source === 'bundled' ? bundledEnv : undefined);
  }

  const imported = runToolShieldCli(pythonBin, [
    'import',
    '--all',
    '--model',
    model,
    '--agent',
    'openclaw',
    '--source_location',
    agentsFile,
  ], source === 'bundled' ? bundledEnv : undefined);

  if (!imported) {
    return {
      synced: false,
      installedNow,
      agentsFile,
      source,
      message: `ToolShield import failed for model ${model}.`,
    };
  }

  return {
    synced: true,
    installedNow,
    agentsFile,
    source,
    message: installedNow
      ? `ToolShield installed via pip and synced to ${agentsFile}.`
      : source === 'bundled'
        ? `ToolShield synced from bundled core (${bundledRoot}) to ${agentsFile}.`
        : `ToolShield synced to ${agentsFile}.`,
  };
}
