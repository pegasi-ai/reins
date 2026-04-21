/**
 * reins status — Shows hook installation status and Watchtower connection info.
 */

import fs from 'fs';
import chalk from 'chalk';

import { hooksStatus } from '../../lib/hook-installer';
import { resolveWatchtowerCredentials } from '../../storage/WatchtowerConfig';
import { getCurrentRunId } from '../../lib/run-manager';
import { pendingCount } from '../../lib/pending-queue';
import { getDataPath } from '../../core/data-dir';

interface PolicyCache {
  shell_rules?: unknown[];
  mcp_rules?: unknown[];
  protected_paths?: string[];
  updated_at?: string;
}

function readPoliciesSync(): PolicyCache | null {
  const policiesPath = getDataPath('policies.json');
  try {
    if (!fs.existsSync(policiesPath)) return null;
    const raw = fs.readFileSync(policiesPath, 'utf8');
    return JSON.parse(raw) as PolicyCache;
  } catch {
    return null;
  }
}

function formatTimeSince(isoString: string): string {
  try {
    const then = new Date(isoString).getTime();
    const diffMs = Date.now() - then;
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    return `${Math.floor(diffHour / 24)}d ago`;
  } catch {
    return isoString;
  }
}

function getPoliciesFileStat(): { mtime?: string } {
  const policiesPath = getDataPath('policies.json');
  try {
    const stat = fs.statSync(policiesPath);
    return { mtime: stat.mtime.toISOString() };
  } catch {
    return {};
  }
}

export async function statusCommand(): Promise<void> {
  const sep = '═'.repeat(78);

  console.log('');
  console.log(chalk.bold.cyan(sep));
  console.log(chalk.bold.cyan('   🪢 Reins Status'));
  console.log(chalk.bold.cyan(sep));
  console.log('');

  // ── Hooks ──────────────────────────────────────────────────────────────────
  console.log(chalk.bold('Hooks'));
  const hooks = hooksStatus();

  const projectLabel = 'Project (.claude/settings.json):';
  const globalLabel  = 'Global (~/.claude/settings.json):';

  if (hooks.projectInstalled) {
    console.log(`  ${projectLabel.padEnd(42)} ${chalk.green('✅ installed')}`);
  } else {
    console.log(`  ${projectLabel.padEnd(42)} ${chalk.red('❌ not installed')}`);
  }

  if (hooks.globalInstalled) {
    console.log(`  ${globalLabel.padEnd(42)} ${chalk.green('✅ installed')}`);
  } else {
    console.log(`  ${globalLabel.padEnd(42)} ${chalk.red('❌ not installed')}`);
  }

  console.log('');

  // ── Watchtower ─────────────────────────────────────────────────────────────
  console.log(chalk.bold('Watchtower'));
  const creds = await resolveWatchtowerCredentials();

  if (creds) {
    const connectedLabel = creds.email
      ? `${chalk.green('✅')}  ${creds.email}${creds.source === 'env' ? ' (env)' : ''}`
      : chalk.green('✅  connected');
    console.log(`  Connected:   ${connectedLabel}`);
    console.log(`  Base URL:    ${chalk.dim(creds.baseUrl)}`);

    const stat = getPoliciesFileStat();
    if (stat.mtime) {
      console.log(`  Last sync:   ${chalk.dim(stat.mtime)} ${chalk.dim(`(policies.json)`)}`);
    } else {
      console.log(`  Last sync:   ${chalk.yellow('never — run: reins sync')}`);
    }
  } else {
    console.log(`  Connected:   ${chalk.red('❌ not connected')}`);
    console.log(chalk.dim('  Connect during: reins init  or set REINS_WATCHTOWER_API_KEY'));
  }

  console.log('');

  // ── Session ────────────────────────────────────────────────────────────────
  console.log(chalk.bold('Session'));
  const runId = getCurrentRunId();
  if (runId) {
    console.log(`  Current run: ${chalk.dim(runId)}`);
  } else {
    console.log(`  Current run: ${chalk.dim('none (starts automatically on next hook fire)')}`);
  }

  const pending = pendingCount();
  if (pending > 0) {
    console.log(`  Pending:     ${chalk.yellow(`${pending} audit entries buffered`)} ${chalk.dim('(run: reins sync)')}`);
  } else {
    console.log(`  Pending:     ${chalk.green('0 — all flushed')}`);
  }

  console.log('');

  // ── Policy ─────────────────────────────────────────────────────────────────
  console.log(chalk.bold('Policy'));
  const policies = readPoliciesSync();

  if (policies) {
    const shellCount = Array.isArray(policies.shell_rules) ? policies.shell_rules.length : 0;
    const mcpCount = Array.isArray(policies.mcp_rules) ? policies.mcp_rules.length : 0;
    console.log(`  Source:      ${chalk.dim('Watchtower (team + org)')}`);
    console.log(`  Shell rules: ${shellCount}`);
    console.log(`  MCP rules:   ${mcpCount}`);
    if (policies.updated_at) {
      console.log(`  Updated:     ${chalk.dim(policies.updated_at)} ${chalk.dim(`(${formatTimeSince(policies.updated_at)})`)}`);
    }
  } else {
    console.log(`  Source:      ${chalk.dim('built-in defaults (no policies.json)')}`);
    console.log(chalk.dim('  Run: reins sync  to pull policies from Watchtower'));
  }

  console.log('');
}
