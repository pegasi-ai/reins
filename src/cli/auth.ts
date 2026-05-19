import { spawn } from 'child_process';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { saveWatchtowerSettings } from '../storage/WatchtowerConfig';
import { AuthSession, saveAuthSession } from '../storage/AuthStore';
import {
  CliAuthCompleteResponse,
  CliAuthMethod,
  CliAuthStartResponse,
  startCliAuthLogin,
  exchangeCliAuthLogin,
} from '../lib/watchtower-client';

const DEFAULT_POLL_INTERVAL_MS = 2_000;

export interface CliLoginFlowOptions {
  baseUrl: string;
  email?: string;
  method?: CliAuthMethod;
  openBrowser?: boolean;
}

export interface CliLoginResult {
  authPath: string;
  baseUrl: string;
  configPath: string;
  dashboardUrl: string;
  session: AuthSession;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function toAuthSession(response: CliAuthCompleteResponse): AuthSession {
  return {
    access_token: response.access_token,
    refresh_token: response.refresh_token,
    access_token_expires_at: response.access_token_expires_at,
    refresh_token_expires_at: response.refresh_token_expires_at,
    user: response.user,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function openUrlInBrowser(url: string): void {
  try {
    const command = process.platform === 'darwin'
      ? 'open'
      : process.platform === 'win32'
        ? 'cmd'
        : 'xdg-open';
    const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
    const child = spawn(command, args, {
      detached: true,
      stdio: 'ignore',
    });
    child.on('error', () => {
      // The URL is always printed, so silent failure is acceptable here.
    });
    child.unref();
  } catch {
    // The URL is always printed, so silent failure is acceptable here.
  }
}

async function promptForLoginMethod(): Promise<CliAuthMethod> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Choose a login method with --github or --magic-link when not running interactively.');
  }

  const answer = await inquirer.prompt([
    {
      type: 'list',
      name: 'method',
      message: 'How do you want to sign in?',
      choices: [
        { name: 'GitHub', value: 'github' },
        { name: 'Email (magic link)', value: 'magic_link' },
      ],
      default: 'github',
    },
  ]);

  return answer.method as CliAuthMethod;
}

async function promptForMagicLinkEmail(initialEmail?: string): Promise<string> {
  if (initialEmail?.trim()) {
    const trimmed = initialEmail.trim();
    if (!isValidEmail(trimmed)) {
      throw new Error(`Invalid email address: ${trimmed}`);
    }
    return trimmed;
  }

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Provide --email when using magic link login in a non-interactive shell.');
  }

  const answer = await inquirer.prompt([
    {
      type: 'input',
      name: 'email',
      message: 'Email:',
      validate: (value: string) => isValidEmail(value) || 'Enter a valid email address.',
    },
  ]);

  return String(answer.email).trim();
}

async function persistLogin(response: CliAuthCompleteResponse, baseUrl: string): Promise<CliLoginResult> {
  const session = toAuthSession(response);
  const authPath = await saveAuthSession(session);
  const configPath = await saveWatchtowerSettings({
    apiKey: response.api_key,
    baseUrl,
    connectedAt: new Date().toISOString(),
    dashboardUrl: response.dashboard_url,
    email: response.user.email,
    org_id: undefined,
    team_id: undefined,
    device_id: undefined,
  });

  return {
    authPath,
    baseUrl,
    configPath,
    dashboardUrl: response.dashboard_url,
    session,
  };
}

async function waitForLoginCompletion(startResponse: CliAuthStartResponse, baseUrl: string): Promise<CliAuthCompleteResponse> {
  const deadline = Date.parse(startResponse.expires_at);
  if (!Number.isFinite(deadline)) {
    throw new Error('Login response contained an invalid expires_at timestamp.');
  }

  console.log(chalk.dim('Waiting... (Ctrl+C to cancel)'));

  while (Date.now() <= deadline) {
    const response = await exchangeCliAuthLogin(startResponse.login_id, baseUrl);
    if (response.status === 'complete') {
      return response;
    }

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      break;
    }

    await sleep(Math.min(DEFAULT_POLL_INTERVAL_MS, remainingMs));
  }

  throw new Error(`Login expired at ${startResponse.expires_at}.`);
}

export async function runCliLoginFlow(options: CliLoginFlowOptions): Promise<CliLoginResult> {
  const method = options.method ?? await promptForLoginMethod();
  const email = method === 'magic_link' ? await promptForMagicLinkEmail(options.email) : undefined;
  const startResponse = await startCliAuthLogin(
    method === 'magic_link'
      ? { method, email }
      : { method },
    options.baseUrl
  );

  if (startResponse.method === 'github') {
    if (options.openBrowser !== false) {
      console.log('Opening browser for GitHub sign-in...');
      openUrlInBrowser(startResponse.browser_url);
    } else {
      console.log('GitHub sign-in URL:');
    }
    console.log(chalk.dim(`  ${startResponse.browser_url}`));
  } else {
    const message = startResponse.message.trim() || 'Magic link sent — check your email.';
    console.log(chalk.green(`✓ ${message}`));
  }

  const completed = await waitForLoginCompletion(startResponse, options.baseUrl);
  const persisted = await persistLogin(completed, options.baseUrl);

  console.log(chalk.green(`✓ Signed in as ${completed.user.name} (${completed.user.email})`));

  return persisted;
}
