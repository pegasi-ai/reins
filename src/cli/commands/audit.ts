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
      const decisionTime = typeof record.decisionTime === 'number'
        ? record.decisionTime
        : typeof (record as { decision_time_ms?: unknown }).decision_time_ms === 'number'
          ? (record as { decision_time_ms: number }).decision_time_ms
          : 0;
      const timeText = chalk.dim(`${(decisionTime / 1000).toFixed(1)}s`.padStart(6));
      const userText = record.userId ? chalk.dim(` (${record.userId})`) : '';
      const reasonText = record.reason ? chalk.dim(` - ${record.reason}`) : '';
      const agentText = record.agent_type ? chalk.dim(` [${record.agent_type}]`) : '';
      const modelText = record.model ? chalk.dim(` ${record.model}`) : '';
      const sessionText = record.session_id ? chalk.dim(` session:${record.session_id}`) : '';
      const principalText = record.principal?.email
        ? chalk.dim(` principal:${record.principal.email}`)
        : record.principal?.id
          ? chalk.dim(` principal:${record.principal.id}`)
          : '';

      console.log(
        `${chalk.dim(timestamp)} | ${chalk.cyan(`${record.module}.${record.method}`.padEnd(25))} | ${decisionText} | ${timeText}${agentText}${modelText}${sessionText}${principalText}${userText}${reasonText}`
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
