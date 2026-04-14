#!/usr/bin/env node

/**
 * ClawReins CLI Entry Point
 */

import fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import { runInitCommand } from './init';
import { policyCommand } from './commands/policy';
import { statsCommand } from './commands/stats';
import { auditCommand } from './commands/audit';
import { resetCommand } from './commands/reset';
import { disableCommand, enableCommand } from './commands/toggle';
import { toolShieldSyncCommand } from './commands/toolshield-sync';
import { upgradeCommand } from './commands/upgrade';
import { scanCommand } from './scan';

function getCliVersion(): string {
  try {
    const packageJsonPath = path.resolve(__dirname, '..', '..', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as { version?: unknown };
    return typeof packageJson.version === 'string' ? packageJson.version : '1.0.0';
  } catch {
    return '1.0.0';
  }
}

const program = new Command();

program.name('clawreins').description('ClawReins is the runtime security layer for OpenClaw..').version(getCliVersion());

// Initialize/configure ClawReins with OpenClaw
program
  .command('init')
  .alias('configure')
  .description('Setup ClawReins with OpenClaw (interactive wizard)')
  .option('--non-interactive', 'Run without prompts using defaults/flags')
  .option('--json', 'Output machine-readable JSON only')
  .option('--security-level <level>', 'Security preset: permissive|balanced|strict|custom')
  .option('--modules <modules>', 'Comma-separated module list (required for custom in non-interactive mode)')
  .option('--sync-toolshield', 'Sync ToolShield during non-interactive mode')
  .action(runInitCommand);

// Manage security policies
program.command('policy').description('Manage security policies').action(policyCommand);

// View statistics
program.command('stats').description('View security statistics').action(statsCommand);

// View audit trail
program
  .command('audit')
  .description('View decision audit trail')
  .option('-n, --lines <number>', 'Number of recent decisions to show', '50')
  .action(auditCommand);

// Reset stats
program.command('reset').description('Reset statistics').action(resetCommand);

// Disable ClawReins
program.command('disable').description('Temporarily disable ClawReins').action(disableCommand);

// Enable ClawReins
program.command('enable').description('Re-enable ClawReins').action(enableCommand);

// Sync ToolShield experiences into OpenClaw AGENTS.md
program
  .command('toolshield-sync')
  .description('Install/sync ToolShield guardrails into OpenClaw AGENTS.md')
  .option('--model <name>', 'ToolShield bundled model', 'claude-sonnet-4.5')
  .option('--agents-file <path>', 'Custom AGENTS.md target path')
  .option('--bundled-dir <path>', 'Path to bundled ToolShield source root')
  .option('--no-install', 'Do not auto-install ToolShield if missing')
  .option('--append', 'Append without unloading existing ToolShield section')
  .action(toolShieldSyncCommand);

// Upgrade/reinstall ClawReins plugin in OpenClaw
program
  .command('upgrade')
  .alias('update')
  .description('Upgrade ClawReins plugin in OpenClaw (reinstall + restart)')
  .option('--tag <tag>', 'NPM dist-tag to install', 'beta')
  .option('--version <version>', 'Exact version to install (overrides --tag)')
  .option('--configure', 'Run clawreins configure after install')
  .option('--no-restart', 'Skip openclaw gateway restart')
  .action(upgradeCommand);

// Scan OpenClaw installation for common security misconfigurations
program
  .command('scan')
  .description('Audit the local OpenClaw installation for security misconfigurations')
  .option('--fix', 'Create a backup and apply supported remediations')
  .option('--html', 'Write and open an HTML scan report')
  .option('--json', 'Print the raw scan report as JSON')
  .option('--monitor', 'Compare against the last saved scan and alert on configuration drift')
  .option('--reset-baseline', 'Replace the saved config baseline with the current config (use with --monitor)')
  .option('--alert-command <command>', 'Run a notification command when monitor mode detects drift')
  .option('--yes', 'Skip the confirmation prompt when using --fix')
  .action(scanCommand);

program.parse();
