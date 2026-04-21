/**
 * Reins Init/Configure Wizard
 * Interactive setup for Reins with OpenClaw + automation-friendly mode
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import fs from 'fs-extra';
import path from 'path';
import {
  isOpenClawInstalled,
  registerPlugin,
  isPluginRegistered,
  getOpenClawPaths,
} from '../plugin/config-manager';
import { PolicyStore, PersistedPolicy } from '../storage/PolicyStore';
import { logger, REINS_DATA_DIR } from '../core/Logger';
import { DEFAULT_POLICY } from '../config';
import { SecurityRule } from '../types';
import { getProtectedModules } from '../plugin/tool-interceptor';
import { syncToolShieldDefaults } from '../toolshield/sync';
import { runSetupScan } from './scan';
import { installWatchtowerSchedule, supportsScheduledScans } from './scheduler';
import { resolveWatchtowerCredentials, saveWatchtowerSettings, DEFAULT_WATCHTOWER_BASE_URL } from '../storage/WatchtowerConfig';
import { signupCli, validateApiKey, fetchPolicies, fetchShellPolicies } from '../lib/watchtower-client';
import { installClaudeCodeHooks } from '../lib/hook-installer';

type SecurityLevel = 'permissive' | 'balanced' | 'strict' | 'custom';

interface InitPreset {
  name: string;
  description: string;
  policy: Record<string, Record<string, SecurityRule>>;
}

const SECURITY_PRESETS: Record<Exclude<SecurityLevel, 'custom'>, InitPreset> = {
  permissive: {
    name: '🟢 Permissive',
    description: 'read: ALLOW, write: ASK, delete: ASK, bash: ASK',
    policy: {
      FileSystem: {
        read: { action: 'ALLOW', description: 'Safe read-only' },
        write: { action: 'ASK', description: 'Needs approval' },
        delete: { action: 'ASK', description: 'Requires confirmation' },
      },
      Shell: {
        bash: { action: 'ASK', description: 'RCE risk' },
        exec: { action: 'ASK', description: 'RCE risk' },
      },
    },
  },
  balanced: {
    name: '🟡 Balanced (Recommended)',
    description: 'read: ALLOW, write: ASK, delete: DENY, bash: ASK',
    policy: DEFAULT_POLICY.modules,
  },
  strict: {
    name: '🔴 Strict',
    description: 'read: ASK, write: ASK, delete: DENY, bash: DENY',
    policy: {
      FileSystem: {
        read: { action: 'ASK', description: 'Confirm all reads' },
        write: { action: 'ASK', description: 'Needs approval' },
        delete: { action: 'DENY', description: 'Strictly prohibited' },
      },
      Shell: {
        bash: { action: 'DENY', description: 'RCE blocked' },
        exec: { action: 'DENY', description: 'RCE blocked' },
      },
    },
  },
};

const DEFAULT_MODULES = ['FileSystem', 'Shell', 'Browser'];

export interface InitWizardOptions {
  nonInteractive?: boolean;
  json?: boolean;
  securityLevel?: string;
  modules?: string;
  syncToolshield?: boolean;
}

export interface InitSuccessOutput {
  ok: true;
  configPath: string;
  policyPath: string;
  openclawHome: string;
  restartRecommended: boolean;
  warnings: string[];
  nextSteps: string[];
}

export interface InitFailureOutput {
  ok: false;
  error: {
    message: string;
    code: string;
    details?: Record<string, unknown>;
  };
}

class InitWizardError extends Error {
  code: string;
  details?: Record<string, unknown>;

  constructor(message: string, code: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'InitWizardError';
    this.code = code;
    this.details = details;
  }
}

function disableLoggerOutput(): void {
  for (const transport of logger.transports) {
    transport.silent = true;
  }
}

function parseSecurityLevel(value: string): SecurityLevel {
  if (value === 'permissive' || value === 'balanced' || value === 'strict' || value === 'custom') {
    return value;
  }
  throw new InitWizardError('Invalid security level', 'E_INVALID_OPTION', {
    option: 'securityLevel',
    value,
    allowed: ['permissive', 'balanced', 'strict', 'custom'],
  });
}

function parseModules(input: string | undefined): string[] {
  if (!input) {
    return [];
  }
  return input
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildPolicy(securityLevel: SecurityLevel, selectedModules: string[]): PersistedPolicy {
  const modules: Record<string, Record<string, SecurityRule>> = {};
  const selectedPreset = securityLevel === 'custom' ? null : SECURITY_PRESETS[securityLevel];

  if (selectedPreset) {
    selectedModules.forEach((moduleName) => {
      if (selectedPreset.policy[moduleName]) {
        modules[moduleName] = selectedPreset.policy[moduleName];
      } else {
        modules[moduleName] = {
          '*': { action: 'ASK', description: 'Default security' },
        };
      }
    });
  }

  return {
    version: '1.0.0',
    defaultAction: 'ASK',
    modules,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

function formatError(error: unknown): InitFailureOutput {
  if (error instanceof InitWizardError) {
    return {
      ok: false,
      error: {
        message: error.message,
        code: error.code,
        details: error.details,
      },
    };
  }

  if (error instanceof Error) {
    return {
      ok: false,
      error: {
        message: error.message,
        code: 'E_INIT_FAILED',
      },
    };
  }

  return {
    ok: false,
    error: {
      message: 'Unknown initialization error',
      code: 'E_INIT_FAILED',
    },
  };
}

function findPluginManifestPath(pluginDir: string): string | null {
  const candidates = [pluginDir, path.resolve(__dirname, '..', '..')];

  for (const candidate of candidates) {
    const manifestPath = path.join(candidate, 'openclaw.plugin.json');
    if (fs.existsSync(manifestPath)) {
      return manifestPath;
    }
  }

  return null;
}

function getNextSteps(toolShieldSkipped: boolean): string[] {
  const nextSteps = [
    'Restart OpenClaw gateway: openclaw gateway restart',
    'Edit security policy: reins policy',
    'View audit trail: reins audit',
  ];

  if (toolShieldSkipped) {
    nextSteps.splice(2, 0, 'Sync ToolShield guardrails: reins toolshield-sync');
  }

  return nextSteps;
}

async function maybeOfferWatchtowerSchedule(): Promise<string | null> {
  const credentials = await resolveWatchtowerCredentials();
  if (!credentials || credentials.source !== 'config') {
    return null;
  }

  if (!supportsScheduledScans()) {
    console.log(chalk.yellow('⚠️  Automatic scheduled scans are not supported on this platform.'));
    return null;
  }

  console.log('');
  console.log(chalk.green('✅ Connected to Reins Cloud!'));
  console.log('');

  const { enableSchedule } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'enableSchedule',
      message: '📡 Enable daily automatic scans?',
      default: true,
    },
  ]);

  if (!enableSchedule) {
    return null;
  }

  const result = await installWatchtowerSchedule();
  if (result.alreadyInstalled) {
    console.log('');
    console.log(chalk.green('✅ Daily scan is already scheduled at 9am. Results upload to Reins Cloud automatically.'));
    return result.descriptor;
  }

  console.log('');
  console.log(chalk.green('✅ Daily scan scheduled at 9am. Results upload to Reins Cloud automatically.'));
  return result.descriptor;
}

export async function initWizard(options: InitWizardOptions = {}): Promise<InitSuccessOutput> {
  const nonInteractive = options.nonInteractive === true;
  const jsonMode = options.json === true;
  const warnings: string[] = [];
  const paths = getOpenClawPaths();

  if (!jsonMode) {
    console.log('');
    console.log(chalk.bold.cyan('═'.repeat(80)));
    console.log(chalk.bold.cyan('   🪢 Reins Setup Wizard'));
    console.log(chalk.bold.cyan('   Runtime security and policy enforcement for Claude Code.'));
    console.log(chalk.bold.cyan('═'.repeat(80)));
    console.log('');
  }

  // Step 1: Detect OpenClaw
  if (!jsonMode) {
    console.log(chalk.bold('Step 1: Detecting OpenClaw...'));
  }

  const isInstalled = await isOpenClawInstalled();
  if (!isInstalled) {
    throw new InitWizardError('OpenClaw is not installed or not found.', 'E_OPENCLAW_NOT_FOUND', {
      openclawHome: paths.openclawHome,
    });
  }

  if (!jsonMode) {
    console.log(chalk.green('✅ OpenClaw detected'));
    console.log('');
  }

  // Check if already registered
  const alreadyRegistered = await isPluginRegistered();
  if (alreadyRegistered && !nonInteractive) {
    const { shouldReconfigure } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'shouldReconfigure',
        message: 'Reins is already configured. Reconfigure?',
        default: false,
      },
    ]);

    if (!shouldReconfigure) {
      if (!jsonMode) {
        console.log(chalk.yellow('Setup cancelled.'));
      }
      return {
        ok: true,
        configPath: paths.openclawConfig,
        policyPath: PolicyStore.getPath(),
        openclawHome: paths.openclawHome,
        restartRecommended: false,
        warnings,
        nextSteps: ['Run again when you want to update the configuration.'],
      };
    }
  }

  // Step 2: Choose security level
  let securityLevel: SecurityLevel;
  if (nonInteractive) {
    const fromEnv = process.env.REINS_SECURITY_LEVEL || process.env.CLAWREINS_SECURITY_LEVEL;
    securityLevel = parseSecurityLevel(options.securityLevel || fromEnv || 'balanced');
  } else {
    if (!jsonMode) {
      console.log(chalk.bold('Step 2: Choose your security level'));
      console.log('');
    }

    const answer = await inquirer.prompt([
      {
        type: 'list',
        name: 'securityLevel',
        message: 'Which security policy would you like to use?',
        choices: [
          {
            name: `${SECURITY_PRESETS.permissive.name} - ${SECURITY_PRESETS.permissive.description}`,
            value: 'permissive',
          },
          {
            name: `${SECURITY_PRESETS.balanced.name} - ${SECURITY_PRESETS.balanced.description}`,
            value: 'balanced',
          },
          {
            name: `${SECURITY_PRESETS.strict.name} - ${SECURITY_PRESETS.strict.description}`,
            value: 'strict',
          },
          {
            name: '⚙️  Custom (configure manually after setup)',
            value: 'custom',
          },
        ],
        default: 'balanced',
      },
    ]);

    securityLevel = parseSecurityLevel(answer.securityLevel);

    if (!jsonMode) {
      console.log('');
    }
  }

  // Step 3: Select modules to protect
  const availableModules = getProtectedModules();
  let selectedModules: string[] = [];

  if (nonInteractive) {
    const explicitModules = parseModules(options.modules || process.env.REINS_MODULES || process.env.CLAWREINS_MODULES);

    if (securityLevel === 'custom' && explicitModules.length === 0) {
      throw new InitWizardError(
        'Custom security level requires explicit modules in non-interactive mode.',
        'E_MISSING_REQUIRED',
        {
          required: ['--modules <comma-separated>', 'or REINS_MODULES'],
          securityLevel,
        }
      );
    }

    selectedModules = explicitModules.length > 0 ? explicitModules : DEFAULT_MODULES;

    const unknownModules = selectedModules.filter((moduleName) => !availableModules.includes(moduleName));
    if (unknownModules.length > 0) {
      throw new InitWizardError('One or more modules are invalid.', 'E_INVALID_MODULES', {
        invalidModules: unknownModules,
        allowedModules: availableModules,
      });
    }
  } else {
    if (!jsonMode) {
      console.log(chalk.bold('Step 3: Select which OpenClaw tools to protect'));
      console.log('');
    }

    const answer = await inquirer.prompt([
      {
        type: 'checkbox',
        name: 'selectedModules',
        message: 'Which tool modules should Reins intercept?',
        choices: availableModules.map((mod) => ({
          name: mod,
          value: mod,
          checked: DEFAULT_MODULES.includes(mod),
        })),
      },
    ]);

    selectedModules = answer.selectedModules;

    if (!jsonMode) {
      console.log('');
    }
  }

  // Step 4: Create policy
  if (!jsonMode) {
    console.log(chalk.bold('Step 4: Creating security policy...'));
  }

  const policy = buildPolicy(securityLevel, selectedModules);
  await PolicyStore.save(policy);

  if (!jsonMode) {
    console.log(chalk.green(`✅ Policy saved to ${PolicyStore.getPath()}`));
    console.log('');
  }

  // Step 5: Register plugin in OpenClaw config
  if (!jsonMode) {
    console.log(chalk.bold('Step 5: Registering with OpenClaw...'));

    const manifestPath = findPluginManifestPath(paths.pluginDir);
    if (manifestPath) {
      const pluginRoot = path.dirname(manifestPath);
      console.log(chalk.dim(`  Plugin manifest found: ${manifestPath}`));
      console.log(chalk.dim(`  Install with: openclaw plugins install --link ${pluginRoot}`));
    }
  }

  await registerPlugin(policy.defaultAction);

  if (!jsonMode) {
    console.log(chalk.green('✅ Reins registered in OpenClaw config'));
    console.log('');
  }

  // Step 6: ToolShield defaults
  const shouldSyncToolshield =
    nonInteractive ? options.syncToolshield === true : true;

  if (!jsonMode) {
    console.log(chalk.bold('Step 6: Enabling ToolShield defaults...'));
  }

  let toolShieldSkipped = false;
  if (shouldSyncToolshield) {
    const toolShieldResult = await syncToolShieldDefaults();
    if (toolShieldResult.synced) {
      if (!jsonMode) {
        console.log(chalk.green(`✅ ${toolShieldResult.message}`));
        if (toolShieldResult.installedNow) {
          console.log(chalk.dim('  ToolShield was installed automatically via pip.'));
        }
      }
    } else {
      warnings.push(toolShieldResult.message);
      if (!jsonMode) {
        console.log(chalk.yellow(`⚠️  ${toolShieldResult.message}`));
        console.log(chalk.dim('  You can retry manually with: reins toolshield-sync'));
      }
    }
  } else {
    toolShieldSkipped = true;
    warnings.push('ToolShield sync skipped in non-interactive mode.');
    if (!jsonMode) {
      console.log(chalk.yellow('⚠️  ToolShield sync skipped in non-interactive mode.'));
      console.log(chalk.dim('  You can run: reins toolshield-sync'));
    }
  }

  // Step 7: Watchtower API key + Claude Code hooks (interactive only)
  if (!nonInteractive) {
    const { connectWatchtower } = await inquirer.prompt([{
      type: 'confirm',
      name: 'connectWatchtower',
      message: '📡 Connect to Reins Cloud for centralized policy enforcement & observability?',
      default: false,
    }]);

    if (connectWatchtower) {
      const { email } = await inquirer.prompt([{
        type: 'input',
        name: 'email',
        message: 'Your email address:',
        validate: (v: string) => v.trim().length > 0 || 'Email is required',
      }]);

      const baseUrl = DEFAULT_WATCHTOWER_BASE_URL;

      try {
        console.log(chalk.dim('  Connecting to Reins Cloud...'));
        const signup = await signupCli(email as string, baseUrl);

        const validation = await validateApiKey(signup.api_key, baseUrl);
        await saveWatchtowerSettings({
          apiKey: signup.api_key,
          baseUrl,
          dashboardUrl: signup.dashboard_url,
          email: email as string,
          org_id: validation.org_id,
          team_id: validation.team_id,
          device_id: validation.device_id,
          connectedAt: new Date().toISOString(),
        });

        // Pull initial policies
        const bundle = await fetchPolicies(signup.api_key, baseUrl);
        const policiesPath = path.join(REINS_DATA_DIR, 'policies.json');
        await fs.writeJson(policiesPath, bundle, { spaces: 2 });

        // Merge shell policies
        const shellRules = await fetchShellPolicies(signup.api_key, baseUrl);
        if (shellRules.length > 0) {
          bundle.shell_rules = [...bundle.shell_rules, ...shellRules];
          await fs.writeJson(policiesPath, bundle, { spaces: 2 });
        }

        console.log(chalk.green(`✅ Connected to Reins Cloud (${email})`));
        if (signup.message) {
          console.log(chalk.dim(`  ${signup.message}`));
        }
        console.log(chalk.dim(`  Dashboard: ${signup.dashboard_url}`));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Reins Cloud connection failed: ${msg}`);
        console.log(chalk.yellow(`⚠️  Reins Cloud connection failed: ${msg}`));
      }
    }

    // Install Claude Code hooks
    if (!jsonMode) {
      console.log(chalk.bold('Step 7b: Installing Claude Code hooks...'));
    }
    try {
      const hookResult = await installClaudeCodeHooks();
      if (!jsonMode) {
        if (hookResult.alreadyInstalled) {
          console.log(chalk.green('✅ Claude Code hooks already installed'));
        } else {
          console.log(chalk.green(`✅ Claude Code hooks installed at ${hookResult.path}`));
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      warnings.push(`Claude Code hook installation failed: ${msg}`);
      if (!jsonMode) {
        console.log(chalk.yellow(`⚠️  Hook installation failed: ${msg}`));
      }
    }
  }

  if (!nonInteractive && !jsonMode) {
    console.log('');
    console.log(chalk.bold('Step 8: Running first security scan...'));
    console.log('');

    try {
      await runSetupScan();

      try {
        await maybeOfferWatchtowerSchedule();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        warnings.push(`Scheduled scan setup failed: ${message}`);
        console.log(chalk.yellow(`⚠️  Scheduled scan setup failed: ${message}`));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`Initial security scan failed: ${message}`);
      console.log(chalk.yellow(`⚠️  Initial security scan failed: ${message}`));
      console.log(chalk.dim('  You can retry manually with: reins scan'));
    }
  }

  if (!nonInteractive && !jsonMode) {
    console.log('');
    console.log(chalk.bold('Step 7: Running first security scan...'));
    console.log('');

    try {
      await runSetupScan();

      try {
        await maybeOfferWatchtowerSchedule();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        warnings.push(`Scheduled scan setup failed: ${message}`);
        console.log(chalk.yellow(`⚠️  Scheduled scan setup failed: ${message}`));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`Initial security scan failed: ${message}`);
      console.log(chalk.yellow(`⚠️  Initial security scan failed: ${message}`));
      console.log(chalk.dim('  You can retry manually with: clawreins scan'));
    }
  }

  if (!jsonMode) {
    console.log('');
    console.log(chalk.bold.green('═'.repeat(80)));
    console.log(chalk.bold.green('   ✅ Reins installed successfully!'));
    console.log(chalk.bold.green('═'.repeat(80)));
    console.log('');

    console.log(chalk.bold('Configuration:'));
    console.log(chalk.dim(`  OpenClaw home: ${paths.openclawHome}`));
    console.log(chalk.dim(`  OpenClaw config: ${paths.openclawConfig}`));
    console.log(chalk.dim(`  Plugin dir:      ${paths.pluginDir}`));
    console.log(chalk.dim(`  Policy:          ${PolicyStore.getPath()}`));
    console.log(chalk.dim(`  Audit log:       ${REINS_DATA_DIR}/decisions.jsonl`));
    console.log(chalk.dim(`  Stats:           ${REINS_DATA_DIR}/stats.json`));
    console.log('');

    console.log(chalk.bold('Next steps:'));
    console.log(chalk.cyan('  1. Restart gateway:') + chalk.dim('  openclaw gateway restart'));
    console.log(chalk.cyan('  2. Edit policy:') + chalk.dim('      reins policy'));
    console.log(chalk.cyan('  3. View audit trail:') + chalk.dim('  reins audit'));
    console.log('');
  }

  return {
    ok: true,
    configPath: paths.openclawConfig,
    policyPath: PolicyStore.getPath(),
    openclawHome: paths.openclawHome,
    restartRecommended: true,
    warnings,
    nextSteps: getNextSteps(toolShieldSkipped),
  };
}

export async function runInitCommand(options: InitWizardOptions = {}): Promise<void> {
  const jsonMode = options.json === true;

  if (jsonMode) {
    disableLoggerOutput();
  }

  try {
    const result = await initWizard(options);
    if (jsonMode) {
      process.stdout.write(`${JSON.stringify(result)}\n`);
    }
  } catch (error) {
    const formatted = formatError(error);

    if (jsonMode) {
      process.stdout.write(`${JSON.stringify(formatted)}\n`);
    } else {
      console.error(chalk.red('❌ Setup failed:'), formatted.error.message);
      logger.error('Init/configure command failed', {
        code: formatted.error.code,
        details: formatted.error.details,
      });
    }

    process.exitCode = 1;
  }
}
