/**
 * Reins Enable/Disable Commands
 */

import chalk from 'chalk';
import { loadOpenClawConfig, saveOpenClawConfig } from '../../plugin/config-manager';
import { logger } from '../../core/Logger';

export async function disableCommand(): Promise<void> {
  try {
    const config = await loadOpenClawConfig();

    if (!config?.plugins?.entries?.reins) {
      console.log(chalk.yellow('Reins is not registered in OpenClaw. Run: reins init'));
      process.exit(0);
    }

    config.plugins.entries.reins.enabled = false;
    await saveOpenClawConfig(config);

    console.log(chalk.green('Reins disabled'));
  } catch (error) {
    console.error(chalk.red('Failed to disable Reins:'), error);
    logger.error('Disable command failed', { error });
    process.exit(1);
  }
}

export async function enableCommand(): Promise<void> {
  try {
    const config = await loadOpenClawConfig();

    if (!config?.plugins?.entries?.reins) {
      console.log(chalk.yellow('Reins is not registered in OpenClaw. Run: reins init'));
      process.exit(0);
    }

    config.plugins.entries.reins.enabled = true;
    await saveOpenClawConfig(config);

    console.log(chalk.green('Reins enabled'));
  } catch (error) {
    console.error(chalk.red('Failed to enable Reins:'), error);
    logger.error('Enable command failed', { error });
    process.exit(1);
  }
}
