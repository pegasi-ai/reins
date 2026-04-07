/**
 * ClawReins Security Scan Command
 */

import { spawn } from 'child_process';
import fs from 'fs-extra';
import inquirer from 'inquirer';
import chalk from 'chalk';
import os from 'os';
import path from 'path';
import { FixAction, FixResult, ScanCheck, ScanReport, SecurityScanner } from '../core/SecurityScanner';
import { logger } from '../core/Logger';

interface ScanCommandOptions {
  alertCommand?: string;
  fix?: boolean;
  html?: boolean;
  json?: boolean;
  monitor?: boolean;
  resetBaseline?: boolean;
  yes?: boolean;
}

interface ScanMonitorState {
  savedAt: string;
  report: ScanReport;
}

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

interface ConfigDiffEntry {
  path: string;
  kind: 'added' | 'removed' | 'changed';
  previousValue?: JsonValue;
  currentValue?: JsonValue;
}

interface DriftComparison {
  baselineCreated: boolean;
  baselineReportUnhealthy: boolean;
  configBaselineCreated: boolean;
  corruptedStateRecovered: boolean;
  configChanges: ConfigDiffEntry[];
  verdictWorsened: boolean;
  worsenedChecks: Array<{
    id: string;
    previousStatus: ScanCheck['status'] | 'NEW';
    currentStatus: ScanCheck['status'];
    message: string;
  }>;
  previousTimestamp?: string;
}

const DEFAULT_ALERT_TIMEOUT_MS = 30_000;
const STATUS_STYLES = {
  PASS: { icon: '✅', color: chalk.green },
  WARN: { icon: '⚠️ ', color: chalk.yellow },
  FAIL: { icon: '❌', color: chalk.red },
} as const;

export async function scanCommand(options: ScanCommandOptions): Promise<void> {
  try {
    if (options.fix && options.json) {
      throw new Error('--fix cannot be combined with --json');
    }
    if (options.fix && options.monitor) {
      throw new Error('--fix cannot be combined with --monitor');
    }
    if (options.monitor && options.json) {
      throw new Error('--monitor cannot be combined with --json');
    }
    if (options.alertCommand && !options.monitor) {
      throw new Error('--alert-command requires --monitor');
    }
    if (options.resetBaseline && !options.monitor) {
      throw new Error('--reset-baseline requires --monitor');
    }

    const scanner = new SecurityScanner();
    let report = await scanner.run();
    let monitorComparison: DriftComparison | null = null;

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
      process.exitCode = exitCodeFor(report);
      return;
    }

    renderTerminalReport(report);
    const initialPlan = await scanner.planFixes();

    if (options.fix) {
      const fixResult = await maybeApplyFixes(scanner, initialPlan, options.yes === true, report);

      if (fixResult) {
        console.log('');
        console.log(chalk.bold.cyan('Post-Fix Scan'));
        console.log(chalk.cyan('──────────────────────────────────────────'));
        report = await scanner.run();
        renderChecksOnly(report);
        console.log(chalk.bold('Post-Fix Verdict:'));
        console.log(`  ${renderVerdict(report.verdict)}`);
        console.log('');
      }
    } else if (!options.monitor) {
      await maybeOfferFix(scanner, initialPlan, report);
    }

    const reportPath = await writeHtmlReport(report);
    renderHtmlReportSummary(reportPath, options.html === true);

    if (options.monitor) {
      monitorComparison = await updateMonitorState(report, options.resetBaseline === true);
      renderMonitorSummary(monitorComparison, report);
      await maybeSendMonitorAlert(options.alertCommand, monitorComparison, report, reportPath);
    }
    if (options.html) {
      openHtmlReport(reportPath);
    }

    process.exitCode = exitCodeFor(report);
  } catch (error) {
    console.error(chalk.red('❌ Security scan failed:'), error);
    logger.error('Scan command failed', { error });
    process.exit(1);
  }
}

async function maybeApplyFixes(
  scanner: SecurityScanner,
  actions: FixAction[],
  assumeYes: boolean,
  currentReport: ScanReport
): Promise<FixResult | null> {
  if (actions.length === 0) {
    renderNoFixesAvailable(currentReport);
    return null;
  }

  console.log('');
  console.log(chalk.bold('Auto-Fix Plan:'));
  actions.forEach((action) => {
    console.log(`  ${chalk.cyan('•')} ${action.description}`);
  });

  const confirmed = assumeYes ? true : await confirmFix();
  if (!confirmed) {
    console.log(chalk.dim('Fix cancelled.'));
    return null;
  }

  const result = await scanner.applyFixes();

  console.log('');
  console.log(chalk.bold('Fix Results:'));
  console.log(`  ${chalk.green(`Applied ${result.appliedActions.length} fix(es).`)}`);
  if (result.backupPath) {
    console.log(`  ${chalk.dim(`Backup created: ${result.backupPath}`)}`);
  }
  if (result.touchedFiles.length > 0) {
    console.log(`  ${chalk.dim(`Updated files: ${result.touchedFiles.join(', ')}`)}`);
  }

  return result;
}

async function maybeOfferFix(
  scanner: SecurityScanner,
  actions: FixAction[],
  currentReport: ScanReport
): Promise<void> {
  if (actions.length === 0) {
    renderNoFixesAvailable(currentReport);
    return;
  }

  console.log(chalk.bold('Auto-Fix Available:'));
  console.log(`  ${chalk.dim('Run `clawreins scan --fix` to apply supported remediations.')}`);

  if (!process.stdin.isTTY) {
    console.log('');
    return;
  }

  const { applyFixes } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'applyFixes',
      message: 'Apply supported auto-fixes now?',
      default: false,
    },
  ]);

  if (!applyFixes) {
    console.log('');
    return;
  }

  const fixResult = await maybeApplyFixes(scanner, actions, true, currentReport);
  if (!fixResult) {
    return;
  }

  console.log('');
  console.log(chalk.bold.cyan('Post-Fix Scan'));
  console.log(chalk.cyan('──────────────────────────────────────────'));
  const report = await scanner.run();
  renderChecksOnly(report);
  console.log(chalk.bold('Post-Fix Verdict:'));
  console.log(`  ${renderVerdict(report.verdict)}`);
  console.log('');
}

function renderNoFixesAvailable(report: ScanReport): void {
  const unresolved = report.checks.filter((check) => check.status === 'FAIL' || check.status === 'WARN');

  console.log('');
  console.log(chalk.bold('Fix Results:'));
  console.log(`  ${chalk.yellow('No supported auto-fixes for the current findings.')}`);

  if (unresolved.length > 0) {
    console.log(`  ${chalk.dim('Manual review required for:')}`);
    unresolved.forEach((check) => {
      console.log(`  ${chalk.dim(`- ${check.id}: ${check.message}`)}`);
    });
  }
}

async function updateMonitorState(report: ScanReport, resetBaseline: boolean): Promise<DriftComparison> {
  const statePath = getScanStatePath();
  const snapshotPath = getConfigBaselinePath();
  await fs.ensureDir(path.dirname(statePath));

  let previousState: ScanMonitorState | null = null;
  let previousSnapshot: JsonValue | null = null;
  let corruptedStateRecovered = false;

  try {
    if (await fs.pathExists(statePath)) {
      previousState = await fs.readJson(statePath);
    }
  } catch {
    corruptedStateRecovered = true;
  }

  try {
    if (!resetBaseline && (await fs.pathExists(snapshotPath))) {
      previousSnapshot = (await fs.readJson(snapshotPath)) as JsonValue;
    }
  } catch {
    corruptedStateRecovered = true;
  }

  const currentSnapshot = await loadCurrentConfigSnapshot();
  const comparison = compareReports(previousState?.report, report, corruptedStateRecovered);
  comparison.configBaselineCreated = previousSnapshot === null || resetBaseline;
  comparison.configChanges = compareConfigs(previousSnapshot, currentSnapshot);

  await fs.writeJson(
    statePath,
    {
      savedAt: new Date().toISOString(),
      report,
    } satisfies ScanMonitorState,
    { spaces: 2 }
  );
  if (previousSnapshot === null || resetBaseline) {
    await fs.writeJson(snapshotPath, currentSnapshot, { spaces: 2 });
  }

  return comparison;
}

async function maybeSendMonitorAlert(
  alertCommand: string | undefined,
  comparison: DriftComparison,
  report: ScanReport,
  reportPath: string
): Promise<void> {
  if (!alertCommand || !shouldTriggerDriftAlert(comparison)) {
    return;
  }

  const shell = process.env.SHELL || (process.platform === 'win32' ? process.env.COMSPEC || 'cmd.exe' : '/bin/sh');
  const shellArgs = process.platform === 'win32' ? ['/d', '/s', '/c', alertCommand] : ['-c', alertCommand];
  const timeoutMs = getAlertTimeoutMs();
  const env = {
    ...process.env,
    CLAWREINS_SCAN_ALERT: '1',
    CLAWREINS_SCAN_VERDICT: report.verdict,
    CLAWREINS_SCAN_SCORE: String(report.score),
    CLAWREINS_SCAN_TOTAL: String(report.total),
    CLAWREINS_SCAN_TIMESTAMP: report.timestamp,
    CLAWREINS_SCAN_REPORT_PATH: reportPath,
    CLAWREINS_SCAN_REPORT_URL: toFileUrl(reportPath),
    CLAWREINS_SCAN_STATE_PATH: getScanStatePath(),
    CLAWREINS_SCAN_CONFIG_BASELINE_PATH: getConfigBaselinePath(),
    CLAWREINS_SCAN_SUMMARY: buildAlertSummary(comparison, report),
    CLAWREINS_SCAN_WORSENED_CHECKS: comparison.worsenedChecks.map((change) => change.id).join(','),
  };

  console.log(chalk.bold('Alert Command:'));

  let exitCode: number;
  try {
    exitCode = await new Promise<number>((resolve, reject) => {
      const child = spawn(shell, shellArgs, {
        detached: process.platform !== 'win32',
        env,
        stdio: 'ignore',
      });
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) {
          return;
        }
        settled = true;
        try {
          if (process.platform !== 'win32' && typeof child.pid === 'number') {
            process.kill(-child.pid, 'SIGTERM');
          } else {
            child.kill();
          }
        } catch {
          // Ignore kill failures.
        }
        resolve(124);
      }, timeoutMs);

      child.once('error', (error) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        reject(error);
      });

      child.once('close', (code) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve(code ?? 1);
      });
    });
  } catch (error) {
    console.log(`  ${chalk.red('Notification command could not be started.')}`);
    logger.warn('Scan notification command failed to start', { error, shell, alertCommand });
    return;
  }

  if (exitCode === 0) {
    console.log(`  ${chalk.green('Notification command completed.')}`);
  } else if (exitCode === 124) {
    console.log(`  ${chalk.red(`Notification command timed out after ${timeoutMs}ms.`)}`);
  } else {
    console.log(`  ${chalk.red(`Notification command failed with exit code ${exitCode}.`)}`);
  }
}

function compareReports(
  previous: ScanReport | undefined,
  current: ScanReport,
  corruptedStateRecovered: boolean
): DriftComparison {
  if (!previous) {
    return {
      baselineCreated: true,
      baselineReportUnhealthy: current.verdict !== 'SECURE',
      configBaselineCreated: false,
      corruptedStateRecovered,
      configChanges: [],
      verdictWorsened: false,
      worsenedChecks: [],
    };
  }

  const previousChecks = new Map(previous.checks.map((check) => [check.id, check]));
  const worsenedChecks = current.checks
    .map((check) => {
      const previousCheck = previousChecks.get(check.id);
      if (!previousCheck) {
        return check.status === 'PASS'
          ? null
          : {
              id: check.id,
              previousStatus: 'NEW' as const,
              currentStatus: check.status,
              message: check.message,
            };
      }

      return statusRank(check.status) > statusRank(previousCheck.status)
        ? {
            id: check.id,
            previousStatus: previousCheck.status,
            currentStatus: check.status,
            message: check.message,
          }
        : null;
    })
    .filter((entry): entry is NonNullable<typeof entry> => entry !== null);

  return {
    baselineCreated: false,
    baselineReportUnhealthy: false,
    configBaselineCreated: false,
    corruptedStateRecovered,
    configChanges: [],
    verdictWorsened: verdictRank(current.verdict) > verdictRank(previous.verdict),
    worsenedChecks,
    previousTimestamp: previous.timestamp,
  };
}

function renderMonitorSummary(comparison: DriftComparison, report: ScanReport): void {
  const statePath = getScanStatePath();
  const snapshotPath = getConfigBaselinePath();

  console.log(chalk.bold('Drift Monitor:'));

  if (comparison.corruptedStateRecovered) {
    console.log(`  ${chalk.yellow('Previous monitor state was unreadable. A new baseline was written.')}`);
  }

  if (comparison.baselineCreated) {
    console.log(`  ${chalk.dim(`Baseline saved: ${statePath}`)}`);
    if (comparison.configBaselineCreated) {
      console.log(`  ${chalk.dim(`Config baseline saved: ${snapshotPath}`)}`);
    }

    if (comparison.baselineReportUnhealthy) {
      console.log(`  ${chalk.yellow(`Initial baseline is ${report.verdict}. Future monitor runs will alert on drift.`)}`);
    } else {
      console.log(`  ${chalk.green('Baseline created. No drift to compare yet.')}`);
    }

    return;
  }

  console.log(`  ${chalk.dim(`State file: ${statePath}`)}`);
  if (comparison.previousTimestamp) {
    console.log(`  ${chalk.dim(`Previous scan: ${comparison.previousTimestamp}`)}`);
  }
  console.log(`  ${chalk.dim(`Config baseline: ${snapshotPath}`)}`);

  if (comparison.verdictWorsened || comparison.worsenedChecks.length > 0 || comparison.configChanges.length > 0) {
    console.log(`  ${chalk.red('Configuration drift detected.')}`);

    if (comparison.verdictWorsened) {
      console.log(`  ${chalk.red(`Verdict worsened to ${report.verdict}.`)}`);
    }

    comparison.worsenedChecks.forEach((change) => {
      console.log(
        `  ${chalk.red(`${change.id}: ${change.previousStatus} -> ${change.currentStatus}`)} ${chalk.dim(`(${change.message})`)}`
      );
    });
    comparison.configChanges.forEach((change) => {
      console.log(`  ${chalk.red(`CONFIG ${change.kind.toUpperCase()}: ${change.path}`)}`);
    });

    return;
  }

  console.log(`  ${chalk.green('No drift detected since the previous scan.')}`);
}

function shouldTriggerDriftAlert(comparison: DriftComparison): boolean {
  return comparison.verdictWorsened || comparison.worsenedChecks.length > 0 || comparison.configChanges.length > 0;
}

function buildAlertSummary(comparison: DriftComparison, report: ScanReport): string {
  const changes = comparison.worsenedChecks.map(
    (change) => `${change.id}: ${change.previousStatus} -> ${change.currentStatus}`
  );
  const configChanges = comparison.configChanges.map((change) => `${change.kind.toUpperCase()}: ${change.path}`);

  const parts = [
    `ClawReins drift detected.`,
    `Verdict: ${report.verdict}.`,
    `Score: ${report.score}/${report.total}.`,
  ];

  if (changes.length > 0) {
    parts.push(`Changed checks: ${changes.join('; ')}.`);
  }
  if (configChanges.length > 0) {
    parts.push(`Config changes: ${configChanges.join('; ')}.`);
  }

  return parts.join(' ');
}

function getAlertTimeoutMs(): number {
  const raw = process.env.CLAWREINS_ALERT_TIMEOUT_MS;
  const parsed = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_ALERT_TIMEOUT_MS;
}
async function confirmFix(): Promise<boolean> {
  if (!process.stdin.isTTY) {
    throw new Error('Fix mode requires --yes when stdin is not interactive');
  }

  const { confirmed } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirmed',
      message: 'Create a backup and apply the planned fixes?',
      default: false,
    },
  ]);

  return confirmed;
}

function renderTerminalReport(report: ScanReport): void {
  console.log('');
  console.log(chalk.bold.cyan('🦞 ClawReins Security Scan'));
  console.log(chalk.cyan('──────────────────────────────────────────'));
  renderChecksOnly(report);
}

function renderChecksOnly(report: ScanReport): void {
  report.checks.forEach((check) => {
    const style = STATUS_STYLES[check.status];
    const statusText = style.color(check.status.padEnd(5));
    const idText = chalk.white(check.id.padEnd(28));
    console.log(`${style.icon} ${statusText} ${idText} ${check.message}`);

    if (check.remediation) {
      console.log(`         ${chalk.dim('Fix:')} ${check.remediation}`);
    }
  });

  console.log('');
  console.log(chalk.bold(`Score: ${report.score}/${report.total} checks passed`));
  console.log(renderVerdict(report.verdict));
  console.log('');
}

function renderVerdict(verdict: ScanReport['verdict']): string {
  if (verdict === 'SECURE') {
    return chalk.green('Verdict: ✅ SECURE');
  }

  if (verdict === 'NEEDS ATTENTION') {
    return chalk.yellow('Verdict: ⚠️ NEEDS ATTENTION — review WARN items before running in production');
  }

  return chalk.red('Verdict: ⛔ EXPOSED — fix FAIL items before running in production');
}

async function writeHtmlReport(report: ScanReport): Promise<string> {
  const outputDir = path.join(os.homedir(), 'Downloads');
  const outputPath = path.join(outputDir, 'scan-report.html');

  await fs.ensureDir(outputDir);
  await fs.writeFile(outputPath, buildHtmlReport(report), 'utf8');

  return outputPath;
}

function getScanStatePath(): string {
  const openclawHome = process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
  return path.join(openclawHome, 'clawreins', 'scan-state.json');
}

function getConfigBaselinePath(): string {
  const openclawHome = process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
  return path.join(openclawHome, 'clawreins', 'config-base.json');
}

async function loadCurrentConfigSnapshot(): Promise<JsonValue> {
  const openclawHome = process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
  const openclawConfigPath = process.env.OPENCLAW_CONFIG || path.join(openclawHome, 'openclaw.json');

  if (!(await fs.pathExists(openclawConfigPath))) {
    return {};
  }

  const parsed = (await fs.readJson(openclawConfigPath)) as JsonValue;
  return normalizeJson(parsed);
}

function normalizeJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeJson(entry));
  }

  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, JsonValue>;
    return Object.keys(record)
      .sort()
      .reduce<Record<string, JsonValue>>((accumulator, key) => {
        accumulator[key] = normalizeJson(record[key]);
        return accumulator;
      }, {});
  }

  return value;
}

function compareConfigs(previous: JsonValue | null, current: JsonValue): ConfigDiffEntry[] {
  if (previous === null) {
    return [];
  }

  const changes: ConfigDiffEntry[] = [];
  diffJson('', previous, current, changes);
  return changes;
}

function diffJson(pathPrefix: string, previous: JsonValue, current: JsonValue, changes: ConfigDiffEntry[]): void {
  if (Array.isArray(previous) || Array.isArray(current)) {
    if (!Array.isArray(previous) || !Array.isArray(current) || JSON.stringify(previous) !== JSON.stringify(current)) {
      changes.push({
        path: pathPrefix || '$',
        kind: 'changed',
        previousValue: previous,
        currentValue: current,
      });
    }
    return;
  }

  const previousIsObject = previous !== null && typeof previous === 'object';
  const currentIsObject = current !== null && typeof current === 'object';

  if (!previousIsObject || !currentIsObject) {
    if (previous !== current) {
      changes.push({
        path: pathPrefix || '$',
        kind: 'changed',
        previousValue: previous,
        currentValue: current,
      });
    }
    return;
  }

  const previousRecord = previous as Record<string, JsonValue>;
  const currentRecord = current as Record<string, JsonValue>;
  const keys = new Set([...Object.keys(previousRecord), ...Object.keys(currentRecord)]);

  for (const key of Array.from(keys).sort()) {
    const nextPath = pathPrefix ? `${pathPrefix}.${key}` : key;

    if (!(key in previousRecord)) {
      changes.push({
        path: nextPath,
        kind: 'added',
        currentValue: currentRecord[key],
      });
      continue;
    }

    if (!(key in currentRecord)) {
      changes.push({
        path: nextPath,
        kind: 'removed',
        previousValue: previousRecord[key],
      });
      continue;
    }

    diffJson(nextPath, previousRecord[key], currentRecord[key], changes);
  }
}
function openHtmlReport(reportPath: string): void {
  try {
    if (process.platform === 'darwin') {
      spawnDetached('open', [reportPath]);
      return;
    }

    if (process.platform === 'win32') {
      spawnDetached('cmd', ['/c', 'start', '', reportPath]);
      return;
    }

    spawnDetached('xdg-open', [reportPath]);
  } catch {
    console.log(chalk.yellow('Unable to open HTML report automatically.'));
  }
}

function spawnDetached(command: string, args: string[]): void {
  const child = spawn(command, args, { detached: true, stdio: 'ignore' });
  child.on('error', () => {
    console.log(chalk.yellow('  Auto-open unavailable. Use the file link above.'));
  });
  child.unref();
}

function renderHtmlReportSummary(reportPath: string, autoOpenRequested: boolean): void {
  console.log(chalk.bold('HTML Report:'));
  console.log(`  ${chalk.dim(`Saved to: ${reportPath}`)}`);
  console.log(`  ${chalk.dim(`Open: ${toFileUrl(reportPath)}`)}`);
  if (autoOpenRequested) {
    console.log(`  ${chalk.dim('Auto-open: requested')}`);
  }
}

function buildHtmlReport(report: ScanReport): string {
  const checks = report.checks.map((check) => renderHtmlCheck(check)).join('\n');
  const scoreBar = Array.from({ length: report.total }, (_, index) =>
    `<span class="seg ${index < report.score ? 'filled' : ''}"></span>`
  ).join('');
  const verdictClass = report.verdict === 'SECURE' ? 'pass' : report.verdict === 'NEEDS ATTENTION' ? 'warn' : 'fail';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ClawReins Security Scan</title>
  <style>
    :root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;padding:32px;background:#0d1117;color:#c9d1d9;font:16px/1.5 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",system-ui,monospace}
    main{max-width:960px;margin:0 auto}.pass{color:#3fb950}.warn{color:#d29922}.fail{color:#f85149}.muted{color:#8b949e}
    .panel{border:1px solid #30363d;border-radius:14px;background:#161b22;padding:24px}.header{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}
    .badge{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid currentColor;font-weight:700}.score{display:flex;gap:8px;margin:18px 0}.seg{height:12px;flex:1;border-radius:999px;background:#21262d;border:1px solid #30363d}.seg.filled{background:#3fb950;border-color:#3fb950}
    .checks{display:grid;gap:14px;margin-top:24px}.check{border:1px solid #30363d;border-radius:12px;padding:16px;background:#0d1117}.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
    .msg{margin-top:8px}.fix{margin-top:8px;color:#8b949e}a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}footer{margin-top:24px;color:#8b949e}
  </style>
</head>
<body>
  <main>
    <section class="panel">
      <div class="header">
        <div>
          <h1 style="margin:0 0 8px">ClawReins Security Scan</h1>
          <div class="muted">Scanned at ${escapeHtml(report.timestamp)}</div>
        </div>
        <span class="badge ${verdictClass}">${escapeHtml(report.verdict)}</span>
      </div>
      <div style="margin-top:20px">Score: ${report.score}/${report.total} checks passed</div>
      <div class="score" aria-label="Score bar">${scoreBar}</div>
      <div class="checks">
${checks}
      </div>
      <footer>Secured by <a href="https://github.com/pegasi-ai/clawreins">ClawReins</a></footer>
    </section>
  </main>
</body>
</html>`;
}

function renderHtmlCheck(check: ScanCheck): string {
  const statusClass = check.status === 'PASS' ? 'pass' : check.status === 'WARN' ? 'warn' : 'fail';
  const remediation = check.remediation ? `<div class="fix">Fix: ${escapeHtml(check.remediation)}</div>` : '';

  return `        <article class="check">
          <div class="row">
            <span class="badge ${statusClass}">${escapeHtml(check.status)}</span>
            <strong>${escapeHtml(check.id)}</strong>
          </div>
          <div class="msg">${escapeHtml(check.message)}</div>
          ${remediation}
        </article>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function toFileUrl(reportPath: string): string {
  const normalized = process.platform === 'win32'
    ? reportPath.replace(/\\/g, '/')
    : reportPath;
  return normalized.startsWith('/')
    ? `file://${normalized}`
    : `file:///${normalized}`;
}

function statusRank(status: ScanCheck['status']): number {
  if (status === 'PASS') {
    return 0;
  }
  if (status === 'WARN') {
    return 1;
  }
  return 2;
}

function verdictRank(verdict: ScanReport['verdict']): number {
  if (verdict === 'SECURE') {
    return 0;
  }
  if (verdict === 'NEEDS ATTENTION') {
    return 1;
  }
  return 2;
}
function exitCodeFor(report: ScanReport): 0 | 1 | 2 {
  if (report.verdict === 'SECURE') {
    return 0;
  }
  if (report.verdict === 'NEEDS ATTENTION') {
    return 1;
  }
  return 2;
}
