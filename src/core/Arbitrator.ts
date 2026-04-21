/**
 * Reins Arbitrator
 * The UI/Prompt Logic for Human-in-the-Loop Decisions
 *
 * Modes:
 *  1. TTY (interactive terminal)      → inquirer prompt
 *  2. Daemon + sessionKey (channel)   → approval queue (block-and-retry via messaging)
 *  3. Daemon without sessionKey       → auto-deny (fail-secure)
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import crypto from 'crypto';
import { ExecutionContext } from '../types';
import { logger } from './Logger';
import { approvalQueue } from './ApprovalQueue';
import { DecisionLog } from '../storage/DecisionLog';

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
        message: chalk.bold.yellow('⚠️  What should Reins do?'),
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

    await this.logApprovalDecision(context, answer.decision ? 'yes' : 'no', answer.decision);

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

    await this.logApprovalDecision(context, 'confirm', approved, String(answer.typed || ''));

    return approved;
  }

  private async judgeChannel(context: ExecutionContext): Promise<boolean> {
    const { sessionKey, moduleName, methodName } = context;
    const strict = context.intervention?.requiresExplicitConfirmation === true;

    if (approvalQueue.consume(sessionKey!, moduleName, methodName)) {
      logger.info(`ASK policy → approved via channel: ${moduleName}.${methodName}()`, {
        sessionKey,
      });
      return true;
    }

    // Always assign a token so the OOB notifier can reference it in the /approve message.
    const token =
      context.intervention?.confirmationToken || this.generateChannelToken(moduleName, methodName);

    approvalQueue.request(sessionKey!, moduleName, methodName, {
      requiresExplicitConfirmation: strict,
      actionSummary: context.intervention?.actionSummary,
      confirmationToken: token,
      allowRetryAsApproval: false,
    });

    // Fire OOB notification immediately (sends WhatsApp/Telegram message to human).
    // If onBlockCallback is absent, or it returns false (no channel context / send failure),
    // auto-deny immediately rather than stalling for the full TTL.
    if (!context.onBlockCallback) {
      approvalQueue.resolveByToken(token, 'deny');
      logger.info(
        `ASK policy → auto-denied (no onBlockCallback configured): ${moduleName}.${methodName}()`,
        { sessionKey }
      );
      return false;
    }

    const notified = await context.onBlockCallback(sessionKey!, moduleName, methodName);
    if (!notified) {
      // Clean up the queued entry — no one can approve it.
      approvalQueue.resolveByToken(token, 'deny');
      logger.info(
        `ASK policy → auto-denied (no channel context for OOB notification): ${moduleName}.${methodName}()`,
        { sessionKey }
      );
      return false;
    }

    logger.info(`ASK policy → stalling hook until OOB approval: ${moduleName}.${methodName}()`, {
      sessionKey,
      token,
      requiresExplicitConfirmation: strict,
    });

    // Hold the before_tool_call hook open — OpenClaw awaits this Promise.
    // Resolves true when the human sends /approve <token>, false on deny/timeout.
    return approvalQueue.waitForApproval(sessionKey!, moduleName, methodName);
  }

  private generateChannelToken(moduleName: string, methodName: string): string {
    const seed = `${moduleName}.${methodName}:${Date.now()}:${Math.random()}`;
    return `CONFIRM-${crypto.createHash('sha1').update(seed).digest('hex').slice(0, 6).toUpperCase()}`;
  }

  private displayBanner(): void {
    console.log('');
    console.log(chalk.bgRed.white.bold('═'.repeat(80)));
    console.log(
      chalk.bgRed.white.bold('   🪢 REINS SECURITY ALERT - HUMAN AUTHORIZATION REQUIRED')
    );
    console.log(chalk.bgRed.white.bold('═'.repeat(80)));
    console.log('');
  }

  private displayContext(context: ExecutionContext): void {
    if (context.intervention?.cooldownLevel) {
      const level = context.intervention.cooldownLevel;
      const label = level >= 2 ? 'RESTRICTED' : 'HEIGHTENED';
      console.log(
        chalk.bgYellow.black.bold(
          `   COOLDOWN ACTIVE: Level ${level} (${label}) — repeated denials detected   `
        )
      );
      console.log('');
    }

    console.log(chalk.bold.cyan('📦 Module:'), chalk.white(context.moduleName));
    console.log(chalk.bold.cyan('🔧 Method:'), chalk.white(context.methodName));

    if (context.rule.description) {
      console.log(chalk.bold.cyan('⚠️  Risk:'), chalk.yellow(context.rule.description));
    }
    if (context.intervention?.actionSummary) {
      console.log(chalk.bold.cyan('🧾 Intent Summary:'));
      console.log(chalk.gray(this.indentJson(context.intervention.actionSummary)));
    }

    console.log(chalk.bold.cyan('📋 Arguments:'));

    try {
      const argsJson = JSON.stringify(context.args, null, 2);
      console.log(chalk.gray(this.indentJson(argsJson)));
    } catch {
      console.log(chalk.gray('  [Arguments contain non-serializable data]'));
      console.log(chalk.gray('  ' + String(context.args)));
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

  private async logApprovalDecision(
    context: ExecutionContext,
    decision: 'yes' | 'no' | 'allow' | 'confirm',
    approved: boolean,
    confirmation?: string
  ): Promise<void> {
    try {
      await DecisionLog.append({
        timestamp: new Date().toISOString(),
        module: context.moduleName,
        method: context.methodName,
        args: context.args,
        decision: approved ? 'APPROVED' : 'REJECTED',
        decisionTime: 0,
        reason: 'approval_decision',
        eventType: 'approval_decision',
        approved,
        decisionInput: decision,
        confirmation,
      });
    } catch {
      // best-effort only
    }
  }
}
