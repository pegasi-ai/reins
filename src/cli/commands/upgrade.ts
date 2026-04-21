/**
 * Reins Upgrade/Update Command
 *
 * Goal: one command to reinstall the latest Reins plugin build in OpenClaw.
 */

import chalk from 'chalk';
import { spawnSync } from 'child_process';
import { logger } from '../../core/Logger';
import { getOpenClawPaths } from '../../plugin/config-manager';
import { initWizard } from '../init';

interface UpgradeCommandOptions {
  tag?: string;
  version?: string;
  configure?: boolean;
  restart?: boolean;
}

interface CommandResult {
  ok: boolean;
  status: number | null;
  error?: Error;
}

function runOpenClaw(args: string[]): CommandResult {
  try {
    const result = spawnSync('openclaw', args, {
      stdio: 'inherit',
      env: process.env,
    });

    return {
      ok: result.status === 0,
      status: result.status,
    };
  } catch (error) {
    return {
      ok: false,
      status: null,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}

function detectOpenClaw(): boolean {
  const check = spawnSync('openclaw', ['--version'], {
    stdio: 'ignore',
    env: process.env,
  });
  return check.status === 0;
}

export async function upgradeCommand(options: UpgradeCommandOptions = {}): Promise<void> {
  try {
    const { pluginId } = getOpenClawPaths();

    if (!detectOpenClaw()) {
      console.error(chalk.red('❌ OpenClaw CLI not found in PATH.'));
      console.error(chalk.dim('Install OpenClaw and retry.'));
      process.exit(1);
      return;
    }

    const tag = options.tag || 'beta';
    const packageSpec = options.version ? `${pluginId}@${options.version}` : `${pluginId}@${tag}`;

    console.log('');
    console.log(chalk.bold.cyan('═'.repeat(80)));
    console.log(chalk.bold.cyan(`   🔄 Reins Update (${packageSpec})`));
    console.log(chalk.bold.cyan('═'.repeat(80)));
    console.log('');

    // Step 1: Best-effort remove (works even if plugin was not installed)
    console.log(chalk.bold('Step 1: Removing previous plugin install (best effort)...'));
    const remove = runOpenClaw(['plugins', 'remove', pluginId]);
    if (remove.ok) {
      console.log(chalk.green(`✅ Removed ${pluginId}`));
    } else {
      console.log(chalk.yellow(`⚠️  Remove skipped/failed (continuing): ${pluginId}`));
    }
    console.log('');

    // Step 2: Install target package version/tag
    console.log(chalk.bold(`Step 2: Installing ${packageSpec}...`));
    const install = runOpenClaw(['plugins', 'install', packageSpec]);
    if (!install.ok) {
      throw new Error(`openclaw plugins install ${packageSpec} failed (status=${install.status})`);
    }
    console.log(chalk.green(`✅ Installed ${packageSpec}`));
    console.log('');

    // Step 3: Optional reconfigure
    if (options.configure) {
      console.log(chalk.bold('Step 3: Running Reins configure wizard...'));
      await initWizard();
      console.log(chalk.green('✅ Configure completed'));
      console.log('');
    }

    // Step 4: Restart gateway unless disabled
    if (options.restart !== false) {
      console.log(chalk.bold('Step 4: Restarting OpenClaw gateway...'));
      const restart = runOpenClaw(['gateway', 'restart']);
      if (!restart.ok) {
        throw new Error(`openclaw gateway restart failed (status=${restart.status})`);
      }
      console.log(chalk.green('✅ Gateway restarted'));
    } else {
      console.log(chalk.yellow('⚠️  Restart skipped. Run: openclaw gateway restart'));
    }

    console.log('');
    console.log(chalk.bold.green('Reins update complete.'));
    if (!options.configure) {
      console.log(chalk.dim('If needed, run: reins configure'));
    }
    console.log('');
  } catch (error) {
    console.error(chalk.red('❌ Reins update failed:'), error);
    logger.error('Upgrade command failed', { error });
    process.exit(1);
  }
}
