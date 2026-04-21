import chalk from 'chalk';
import { loadAuthSession, clearAuthSession } from '../../storage/AuthStore';
import {
  DEFAULT_WATCHTOWER_BASE_URL,
  loadWatchtowerSettings,
  resolveCliAuthAccess,
  saveWatchtowerSettings,
} from '../../storage/WatchtowerConfig';
import { logoutCliAuth } from '../../lib/watchtower-client';

export async function logoutCommand(): Promise<void> {
  console.log('');
  console.log(chalk.bold('reins logout'));
  console.log('');

  const session = await loadAuthSession();
  const settings = await loadWatchtowerSettings();
  const baseUrl = settings?.baseUrl?.trim() || DEFAULT_WATCHTOWER_BASE_URL;

  if (!session) {
    console.log(chalk.yellow('Not signed in.'));
    console.log('');
    return;
  }

  try {
    const creds = await resolveCliAuthAccess();
    const accessToken = creds?.accessToken || session.access_token;
    await logoutCliAuth(accessToken, baseUrl, session.refresh_token);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log(chalk.yellow(`Remote logout failed: ${message}`));
    console.log(chalk.dim('Clearing the local session anyway.'));
  }

  await clearAuthSession();
  await saveWatchtowerSettings({
    apiKey: undefined,
    baseUrl,
    connectedAt: undefined,
    dashboardUrl: undefined,
    email: undefined,
    org_id: undefined,
    team_id: undefined,
    device_id: undefined,
  });

  console.log(chalk.green('✓ Signed out.'));
  console.log('');
}
