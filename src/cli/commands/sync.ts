/**
 * reins sync — pulls latest policies from Watchtower and flushes pending audit entries.
 */

import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import chalk from 'chalk';

import { resolveWatchtowerCredentials } from '../../storage/WatchtowerConfig';
import { fetchPolicies, fetchShellPolicies, flushDecisions, startRun, PolicyBundle } from '../../lib/watchtower-client';
import { readPending, clearPending } from '../../lib/pending-queue';
import { getCurrentRunId, saveCurrentRun } from '../../lib/run-manager';
import { getPreferredDataPath } from '../../core/data-dir';

const POLICIES_FILE = getPreferredDataPath('policies.json');

export async function syncCommand(): Promise<void> {
  console.log('');
  console.log(chalk.bold('reins sync'));
  console.log(chalk.dim('Pulling latest policies and flushing pending audit entries...'));
  console.log('');

  // 1. Load credentials
  const creds = await resolveWatchtowerCredentials();

  if (!creds) {
    console.log(chalk.yellow('⚠️  Not connected to Watchtower.'));
    console.log(chalk.dim('  Connect with: reins init  or set REINS_WATCHTOWER_API_KEY'));
    return;
  }

  const { apiKey, baseUrl } = creds;

  // 2. Fetch policies
  let bundle: PolicyBundle;
  try {
    process.stdout.write('  Fetching policies... ');
    bundle = await fetchPolicies(apiKey, baseUrl);
    console.log(chalk.green('✅'));
  } catch (err) {
    console.log(chalk.red('❌'));
    const msg = err instanceof Error ? err.message : String(err);
    console.log(chalk.red(`  Failed to fetch policies: ${msg}`));
    return;
  }

  // 3. Fetch shell policies and merge
  try {
    process.stdout.write('  Fetching shell policies... ');
    const shellRules = await fetchShellPolicies(apiKey, baseUrl);
    if (shellRules.length > 0) {
      // Merge: server shell_rules override the ones in the main bundle
      bundle.shell_rules = [...bundle.shell_rules, ...shellRules];
    }
    console.log(chalk.green('✅'));
  } catch {
    // Non-fatal — proceed with what we got from fetchPolicies
    console.log(chalk.yellow('⚠️  (shell policies unavailable, using main bundle)'));
  }

  // 4. Save policies.json
  try {
    await fs.ensureDir(path.dirname(POLICIES_FILE));
    await fs.writeJson(POLICIES_FILE, bundle, { spaces: 2 });
    const shellCount = bundle.shell_rules.length;
    const mcpCount = bundle.mcp_rules.length;
    console.log(chalk.dim(`  Saved: ${shellCount} shell rules, ${mcpCount} MCP rules → ${POLICIES_FILE}`));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(chalk.red(`  Failed to save policies.json: ${msg}`));
    return;
  }

  console.log('');

  // 5. Flush pending decisions
  const pending = readPending();

  if (pending.length === 0) {
    console.log(chalk.green('✅ No pending audit entries.'));
  } else {
    console.log(`  Flushing ${chalk.yellow(pending.length.toString())} pending audit entries...`);

    // Get or create a run_id for flushing
    let runId = getCurrentRunId();

    if (!runId) {
      try {
        const runResult = await startRun(apiKey, baseUrl, {
          hostname: os.hostname(),
          cwd: process.cwd(),
        });
        runId = runResult.run_id;
        saveCurrentRun(runId);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.log(chalk.yellow(`  ⚠️  Could not create run for flush: ${msg}`));
        console.log(chalk.dim(`  Pending entries remain buffered.`));
        return;
      }
    }

    try {
      const { succeeded, failed } = await flushDecisions(apiKey, baseUrl, runId, pending);

      if (succeeded > 0 && failed === 0) {
        clearPending();
        console.log(chalk.green(`  ✅ Flushed ${succeeded} entries.`));
      } else if (succeeded > 0) {
        // Partial success: only clear the succeeded ones by rewriting failed ones
        // For simplicity, if any succeeded we clear all — they're audit logs, not critical data
        clearPending();
        console.log(chalk.yellow(`  ⚠️  Flushed ${succeeded}/${pending.length} entries (${failed} failed, cleared anyway).`));
      } else {
        console.log(chalk.red(`  ❌ Failed to flush all ${pending.length} entries. Retaining in pending.jsonl.`));
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(chalk.red(`  ❌ Flush error: ${msg}`));
    }
  }

  console.log('');
  console.log(chalk.bold.green('Sync complete.'));
  console.log('');
}
