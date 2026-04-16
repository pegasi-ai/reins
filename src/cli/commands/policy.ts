/**
 * Reins Policy Management Command
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import { PolicyStore, PersistedPolicy } from '../../storage/PolicyStore';
import { logger } from '../../core/Logger';

export async function policyCommand(): Promise<void> {
  console.log('');
  console.log(chalk.bold.cyan('═'.repeat(80)));
  console.log(chalk.bold.cyan('   🔒 Reins Policy Manager'));
  console.log(chalk.bold.cyan('═'.repeat(80)));
  console.log('');

  try {
    const policy = await PolicyStore.load();

    // Display current policy
    console.log(chalk.bold('Current Security Policy:'));
    console.log(chalk.dim(`  Default Action: ${policy.defaultAction}`));
    console.log(chalk.dim(`  Last Updated: ${policy.updatedAt}`));
    console.log('');

    console.log(chalk.bold('Protected Modules:'));
    Object.entries(policy.modules).forEach(([moduleName, rules]) => {
      console.log(chalk.cyan(`  ${moduleName}:`));
      Object.entries(rules).forEach(([methodName, rule]) => {
        const actionColor =
          rule.action === 'ALLOW' ? chalk.green : rule.action === 'DENY' ? chalk.red : chalk.yellow;
        console.log(
          `    ${methodName}: ${actionColor(rule.action)} ${chalk.dim(
            rule.description ? `- ${rule.description}` : ''
          )}`
        );
        if (rule.allowPaths?.length) {
          console.log(chalk.dim(`      allow: ${rule.allowPaths.join(', ')}`));
        }
        if (rule.denyPaths?.length) {
          console.log(chalk.dim(`      deny:  ${rule.denyPaths.join(', ')}`));
        }
      });
    });
    console.log('');

    // Action menu
    const { action } = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Change default security level', value: 'change_level' },
          { name: 'Modify a specific rule', value: 'modify_rule' },
          { name: 'Add a new module', value: 'add_module' },
          { name: 'Reset to defaults', value: 'reset' },
          { name: 'Exit', value: 'exit' },
        ],
      },
    ]);

    switch (action) {
      case 'change_level':
        await changeDefaultLevel(policy);
        break;
      case 'modify_rule':
        await modifyRule(policy);
        break;
      case 'add_module':
        await addModule(policy);
        break;
      case 'reset':
        await resetPolicy();
        break;
      case 'exit':
        console.log(chalk.dim('Exiting...'));
        break;
    }
  } catch (error) {
    console.error(chalk.red('❌ Failed to manage policy:'), error);
    logger.error('Policy command failed', { error });
    process.exit(1);
  }
}

async function changeDefaultLevel(policy: PersistedPolicy): Promise<void> {
  const { newDefault } = await inquirer.prompt([
    {
      type: 'list',
      name: 'newDefault',
      message: 'Select new default action for unknown tools:',
      choices: ['ALLOW', 'ASK', 'DENY'],
      default: policy.defaultAction,
    },
  ]);

  policy.defaultAction = newDefault;
  await PolicyStore.save(policy);
  console.log(chalk.green(`✅ Default action changed to ${newDefault}`));
  console.log(chalk.yellow('⚠️  Restart OpenClaw for changes to take effect: openclaw restart'));
}

function parseGlobs(input: string): string[] | undefined {
  const parts = input.split(',').map((s) => s.trim()).filter(Boolean);
  return parts.length > 0 ? parts : undefined;
}

async function modifyRule(policy: PersistedPolicy): Promise<void> {
  const modules = Object.keys(policy.modules);

  if (modules.length === 0) {
    console.log(chalk.yellow('No modules configured yet.'));
    return;
  }

  const { moduleName } = await inquirer.prompt([
    {
      type: 'list',
      name: 'moduleName',
      message: 'Select module:',
      choices: modules,
    },
  ]);

  const methods = Object.keys(policy.modules[moduleName]);

  const { methodName } = await inquirer.prompt([
    {
      type: 'list',
      name: 'methodName',
      message: 'Select method:',
      choices: methods,
    },
  ]);

  const currentRule = policy.modules[moduleName][methodName];

  const { newAction, newDescription, newAllowPaths, newDenyPaths } = await inquirer.prompt([
    {
      type: 'list',
      name: 'newAction',
      message: `Current: ${currentRule.action}. New action:`,
      choices: ['ALLOW', 'ASK', 'DENY'],
      default: currentRule.action,
    },
    {
      type: 'input',
      name: 'newDescription',
      message: 'Description (optional):',
      default: currentRule.description || '',
    },
    {
      type: 'input',
      name: 'newAllowPaths',
      message: 'Allowed path patterns (comma-separated globs, leave empty to allow all):',
      default: currentRule.allowPaths?.join(', ') || '',
    },
    {
      type: 'input',
      name: 'newDenyPaths',
      message: 'Denied path patterns (comma-separated globs, leave empty for none):',
      default: currentRule.denyPaths?.join(', ') || '',
    },
  ]);

  policy.modules[moduleName][methodName] = {
    action: newAction,
    description: newDescription || undefined,
    allowPaths: parseGlobs(newAllowPaths),
    denyPaths: parseGlobs(newDenyPaths),
  };

  await PolicyStore.save(policy);
  console.log(chalk.green(`✅ Rule updated: ${moduleName}.${methodName} → ${newAction}`));
  console.log(chalk.yellow('⚠️  Restart OpenClaw for changes to take effect: openclaw restart'));
}

async function addModule(policy: PersistedPolicy): Promise<void> {
  const { moduleName, defaultAction } = await inquirer.prompt([
    {
      type: 'input',
      name: 'moduleName',
      message: 'Module name (e.g., "CustomTool"):',
      validate: (input) => (input.trim() ? true : 'Module name cannot be empty'),
    },
    {
      type: 'list',
      name: 'defaultAction',
      message: 'Default action for this module:',
      choices: ['ALLOW', 'ASK', 'DENY'],
      default: 'ASK',
    },
  ]);

  policy.modules[moduleName] = {
    '*': { action: defaultAction, description: 'Default rule for all methods' },
  };

  await PolicyStore.save(policy);
  console.log(chalk.green(`✅ Module added: ${moduleName}`));
  console.log(chalk.yellow('⚠️  Restart OpenClaw for changes to take effect: openclaw restart'));
}

async function resetPolicy(): Promise<void> {
  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: chalk.red('Are you sure you want to reset to default policy?'),
      default: false,
    },
  ]);

  if (confirm) {
    await PolicyStore.reset();
    console.log(chalk.green('✅ Policy reset to defaults'));
    console.log(chalk.yellow('⚠️  Restart OpenClaw for changes to take effect: openclaw restart'));
  } else {
    console.log(chalk.dim('Reset cancelled'));
  }
}
