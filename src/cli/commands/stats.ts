/**
 * Reins Stats Command
 */

import chalk from 'chalk';
import { StatsTracker } from '../../storage/StatsTracker';
import { logger } from '../../core/Logger';

export async function statsCommand(): Promise<void> {
  console.log('');
  console.log(chalk.bold.cyan('═'.repeat(80)));
  console.log(chalk.bold.cyan('   📊 Reins Statistics'));
  console.log(chalk.bold.cyan('═'.repeat(80)));
  console.log('');

  try {
    const stats = await StatsTracker.load();

    if (stats.totalCalls === 0) {
      console.log(chalk.yellow('No activity recorded yet.'));
      console.log('');
      return;
    }

    // Calculate percentages
    const approvedPct = ((stats.approved / stats.totalCalls) * 100).toFixed(1);
    const rejectedPct = ((stats.rejected / stats.totalCalls) * 100).toFixed(1);
    const blockedPct = ((stats.blocked / stats.totalCalls) * 100).toFixed(1);
    const allowedPct = ((stats.allowed / stats.totalCalls) * 100).toFixed(1);

    console.log(chalk.bold('Total Calls:'), chalk.white(stats.totalCalls.toString()));
    console.log('');

    console.log(chalk.bold('Decisions:'));
    console.log(
      `  ${chalk.green('✅ Allowed:')}  ${stats.allowed.toString().padStart(6)} (${allowedPct}%)`
    );
    console.log(
      `  ${chalk.green('✅ Approved:')} ${stats.approved.toString().padStart(6)} (${approvedPct}%) - by user`
    );
    console.log(
      `  ${chalk.red('❌ Rejected:')} ${stats.rejected.toString().padStart(6)} (${rejectedPct}%) - by user`
    );
    console.log(
      `  ${chalk.red('🚫 Blocked:')}  ${stats.blocked.toString().padStart(6)} (${blockedPct}%) - by policy`
    );
    console.log('');

    console.log(
      chalk.bold('Average Decision Time:'),
      chalk.white(`${(stats.avgDecisionTime / 1000).toFixed(1)}s`)
    );
    console.log('');

    console.log(chalk.dim(`Last Reset: ${new Date(stats.lastReset).toLocaleString()}`));
    console.log('');
  } catch (error) {
    console.error(chalk.red('❌ Failed to load statistics:'), error);
    logger.error('Stats command failed', { error });
    process.exit(1);
  }
}
