/**
 * Reins Audit Command
 */

import chalk from 'chalk';
import { DecisionLog } from '../../storage/DecisionLog';
import { logger } from '../../core/Logger';

export async function auditCommand(options: { lines: string }): Promise<void> {
  console.log('');
  console.log(chalk.bold.cyan('═'.repeat(80)));
  console.log(chalk.bold.cyan('   📋 Reins Audit Trail'));
  console.log(chalk.bold.cyan('═'.repeat(80)));
  console.log('');

  try {
    const lineCount = parseInt(options.lines, 10);
    const decisions = await DecisionLog.readLast(lineCount);

    if (decisions.length === 0) {
      console.log(chalk.yellow('No decisions recorded yet.'));
      console.log('');
      return;
    }

    console.log(chalk.dim(`Showing last ${decisions.length} decision(s):`));
    console.log('');

    decisions.forEach((record) => {
      const timestamp = new Date(record.timestamp).toLocaleTimeString();
      const decisionColor =
        record.decision === 'ALLOWED' || record.decision === 'APPROVED' ? chalk.green : chalk.red;

      const decisionText = decisionColor(record.decision.padEnd(10));
      const timeText = chalk.dim(`${(record.decisionTime / 1000).toFixed(1)}s`.padStart(6));
      const userText = record.userId ? chalk.dim(` (${record.userId})`) : '';
      const reasonText = record.reason ? chalk.dim(` - ${record.reason}`) : '';

      console.log(
        `${chalk.dim(timestamp)} | ${chalk.cyan(`${record.module}.${record.method}`.padEnd(25))} | ${decisionText} | ${timeText}${userText}${reasonText}`
      );
    });

    console.log('');
    console.log(chalk.dim(`Audit log: ${DecisionLog.getPath()}`));
    console.log('');
  } catch (error) {
    console.error(chalk.red('❌ Failed to load audit trail:'), error);
    logger.error('Audit command failed', { error });
    process.exit(1);
  }
}
