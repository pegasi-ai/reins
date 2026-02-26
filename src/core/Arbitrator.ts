/**
 * ClawReins Arbitrator
 * The UI/Prompt Logic for Human-in-the-Loop Decisions
 *
 * Modes:
 *  1. TTY (interactive terminal)      → inquirer prompt
 *  2. Daemon + sessionKey (channel)   → approval queue (block-and-retry via messaging)
 *  3. Daemon without sessionKey       → auto-deny (fail-secure)
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import { ExecutionContext } from '../types';
import { logger } from './Logger';
import { approvalQueue } from './ApprovalQueue';
import { sanitizeToolParams } from './InputSanitizer';

export class Arbitrator {
  async judge(context: ExecutionContext): Promise<boolean> {
    if (process.stdin.isTTY) {
      return this.judgeTTY(context);
    }

    if (context.sessionKey) {
      return this.judgeChannel(context);
    }

    logger.info(
      `ASK policy → auto-denied (no TTY, no session): ${context.moduleName}.${context.methodName}()`,
      { args: context.args }
    );
    return false;
  }

  private async judgeTTY(context: ExecutionContext): Promise<boolean> {
    this.displayBanner();
    this.displayContext(context);

    if (context.intervention?.requiresExplicitConfirmation) {
      return this.judgeTTYExplicitConfirmation(context);
    }

    const answer = await inquirer.prompt([
      {
        type: 'list',
        name: 'decision',
        message: chalk.bold.yellow('⚠️  What should ClawReins do?'),
        choices: [
          {
            name: chalk.green('✓ Approve - Allow this action'),
            value: true,
          },
          {
            name: chalk.red('✗ Reject - Block this action'),
            value: false,
          },
        ],
        default: 1,
      },
    ]);

    console.log('');

    if (answer.decision) {
      console.log(chalk.green('✓ Action APPROVED by user\n'));
    } else {
      console.log(chalk.red('✗ Action REJECTED by user\n'));
    }

    return answer.decision;
  }

  private async judgeTTYExplicitConfirmation(context: ExecutionContext): Promise<boolean> {
    const token = context.intervention?.confirmationToken || 'CONFIRM';
    const summary = context.intervention?.actionSummary || `${context.moduleName}.${context.methodName}()`;

    console.log(chalk.bold.yellow('🔐 Irreversible action requires explicit confirmation.'));
    console.log(chalk.bold.cyan('Action Summary:'), chalk.white(summary));
    console.log(chalk.bold.cyan('Confirmation Token:'), chalk.white(token));
    console.log('');

    const answer = await inquirer.prompt([
      {
        type: 'input',
        name: 'typed',
        message: `Type ${token} to approve, or anything else to reject:`,
      },
    ]);

    const approved = String(answer.typed || '').trim().toUpperCase() === token.toUpperCase();

    console.log('');
    if (approved) {
      console.log(chalk.green('✓ Action APPROVED by explicit confirmation\n'));
    } else {
      console.log(chalk.red('✗ Action REJECTED (confirmation token mismatch)\n'));
    }

    return approved;
  }

  private judgeChannel(context: ExecutionContext): boolean {
    const { sessionKey, moduleName, methodName } = context;
    const strict = context.intervention?.requiresExplicitConfirmation === true;

    if (!strict && approvalQueue.hasBlanketAllow(sessionKey!, moduleName, methodName)) {
      logger.info(`ASK policy → auto-approved (blanket allow): ${moduleName}.${methodName}()`, {
        sessionKey,
      });
      return true;
    }

    if (approvalQueue.consume(sessionKey!, moduleName, methodName)) {
      logger.info(`ASK policy → approved via channel: ${moduleName}.${methodName}()`, {
        sessionKey,
      });
      return true;
    }

    if (!strict && approvalQueue.consumePending(sessionKey!, moduleName, methodName)) {
      logger.info(
        `ASK policy → approved via channel (retry-as-approval): ${moduleName}.${methodName}()`,
        { sessionKey }
      );
      return true;
    }

    approvalQueue.request(sessionKey!, moduleName, methodName, {
      requiresExplicitConfirmation: strict,
      actionSummary: context.intervention?.actionSummary,
      confirmationToken: context.intervention?.confirmationToken,
    });

    logger.info(`ASK policy → awaiting channel approval: ${moduleName}.${methodName}()`, {
      sessionKey,
      requiresExplicitConfirmation: strict,
    });
    return false;
  }

  private displayBanner(): void {
    console.log('');
    console.log(chalk.bgRed.white.bold('═'.repeat(80)));
    console.log(
      chalk.bgRed.white.bold('   🦞 CLAWREINS SECURITY ALERT - HUMAN AUTHORIZATION REQUIRED')
    );
    console.log(chalk.bgRed.white.bold('═'.repeat(80)));
    console.log('');
  }

  private displayContext(context: ExecutionContext): void {
    console.log(chalk.bold.cyan('📦 Module:'), chalk.white(context.moduleName));
    console.log(chalk.bold.cyan('🔧 Method:'), chalk.white(context.methodName));

    if (context.rule.description) {
      console.log(chalk.bold.cyan('⚠️  Risk:'), chalk.yellow(context.rule.description));
    }

    console.log(chalk.bold.cyan('📋 Arguments:'));

    try {
      const argsDisplay = sanitizeToolParams(context.args);
      console.log(chalk.gray(this.indentJson(argsDisplay)));
    } catch {
      console.log(chalk.gray('  [Arguments contain non-serializable data]'));
    }

    console.log('');
    console.log(chalk.dim('─'.repeat(80)));
    console.log('');
  }

  private indentJson(json: string): string {
    return json
      .split('\n')
      .map((line) => '  ' + line)
      .join('\n');
  }
}
