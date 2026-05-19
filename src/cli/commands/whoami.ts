import chalk from 'chalk';
import { resolveCliAuthAccess } from '../../storage/WatchtowerConfig';
import { whoAmICliAuth } from '../../lib/watchtower-client';

export async function whoamiCommand(): Promise<void> {
  console.log('');
  console.log(chalk.bold('reins whoami'));
  console.log('');

  const creds = await resolveCliAuthAccess();
  if (!creds) {
    console.log(chalk.yellow('Not signed in.'));
    console.log(chalk.dim('Run: reins login'));
    console.log('');
    return;
  }

  const response = await whoAmICliAuth(creds.accessToken, creds.baseUrl);
  console.log(chalk.green(`Signed in as ${response.user.name}`));
  console.log(chalk.dim(`  Email: ${response.user.email}`));
  console.log(chalk.dim(`  Role:  ${response.user.role}`));
  console.log(chalk.dim(`  Base:  ${creds.baseUrl}`));
  console.log('');
}
