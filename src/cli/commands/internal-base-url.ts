import chalk from 'chalk';
import {
  InternalWatchtowerBaseUrlTarget,
  isInternalBaseUrlSwitchingEnabled,
  loadWatchtowerSettings,
  resolveInternalBaseUrlTarget,
  saveWatchtowerSettings,
} from '../../storage/WatchtowerConfig';

interface InternalBaseUrlCommandOptions {
  target?: string;
}

function normalizeTarget(value?: string): InternalWatchtowerBaseUrlTarget | null {
  if (value === 'local' || value === 'staging' || value === 'production') {
    return value;
  }
  return null;
}

export async function internalBaseUrlCommand(targetArg?: string, _options?: InternalBaseUrlCommandOptions): Promise<void> {
  if (!isInternalBaseUrlSwitchingEnabled()) {
    throw new Error('This command is not available in OSS builds.');
  }

  const settings = await loadWatchtowerSettings();
  const currentTarget = settings?.baseUrlTarget;
  const currentUrl = settings?.baseUrl?.trim() || '(default)';

  if (!targetArg) {
    console.log('');
    console.log(chalk.bold('reins internal-base-url'));
    console.log(chalk.dim(`  Current target: ${currentTarget || 'custom'}`));
    console.log(chalk.dim(`  Current URL:    ${currentUrl}`));
    console.log('');
    return;
  }

  const target = normalizeTarget(targetArg);
  if (!target) {
    throw new Error('Target must be one of: local, staging, production.');
  }

  const baseUrl = resolveInternalBaseUrlTarget(target);
  await saveWatchtowerSettings({
    ...settings,
    apiKey: undefined,
    baseUrl,
    baseUrlTarget: target,
  });

  console.log('');
  console.log(chalk.bold('reins internal-base-url'));
  console.log(chalk.green(`✓ Active Reins Cloud target set to ${target}`));
  console.log(chalk.dim(`  ${baseUrl}`));
  console.log('');
}
