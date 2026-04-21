import chalk from 'chalk';
import { DEFAULT_WATCHTOWER_BASE_URL, loadWatchtowerSettings } from '../../storage/WatchtowerConfig';
import { runCliLoginFlow } from '../auth';

interface LoginCommandOptions {
  email?: string;
  github?: boolean;
  magicLink?: boolean;
  noBrowser?: boolean;
}

export async function loginCommand(options: LoginCommandOptions): Promise<void> {
  if (options.github && options.magicLink) {
    throw new Error('Choose either --github or --magic-link, not both.');
  }

  const method = options.github ? 'github' : options.magicLink ? 'magic_link' : undefined;
  const settings = await loadWatchtowerSettings();
  const baseUrl =
    settings?.baseUrl?.trim()
    || process.env.REINS_WATCHTOWER_BASE_URL?.trim()
    || process.env.CLAWREINS_WATCHTOWER_BASE_URL?.trim()
    || DEFAULT_WATCHTOWER_BASE_URL;

  console.log('');
  console.log(chalk.bold('reins login'));
  console.log('');

  await runCliLoginFlow({
    baseUrl,
    email: options.email,
    method,
    openBrowser: options.noBrowser !== true,
  });

  console.log('');
}
