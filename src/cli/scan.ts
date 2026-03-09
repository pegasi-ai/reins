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
  fix?: boolean;
  html?: boolean;
  json?: boolean;
  yes?: boolean;
}

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

    const scanner = new SecurityScanner();
    let report = await scanner.run();

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
      process.exitCode = exitCodeFor(report);
      return;
    }

    renderTerminalReport(report);

    if (options.fix) {
      const plan = await scanner.planFixes();
      const fixResult = await maybeApplyFixes(scanner, plan, options.yes === true);

      if (fixResult) {
        console.log('');
        console.log(chalk.bold.cyan('Post-Fix Scan'));
        console.log(chalk.cyan('──────────────────────────────────────────'));
        report = await scanner.run();
        renderChecksOnly(report);
      }
    }

    if (options.html) {
      const reportPath = await writeHtmlReport(report);
      console.log(chalk.dim(`HTML report: ${reportPath}`));
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
  assumeYes: boolean
): Promise<FixResult | null> {
  if (actions.length === 0) {
    console.log(chalk.green('No auto-fixable issues detected.'));
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
  console.log(chalk.green(`Applied ${result.appliedActions.length} fix(es).`));
  if (result.backupPath) {
    console.log(chalk.dim(`Backup: ${result.backupPath}`));
  }
  if (result.touchedFiles.length > 0) {
    console.log(chalk.dim(`Updated: ${result.touchedFiles.join(', ')}`));
  }

  return result;
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
  const openclawHome = process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
  const outputDir = path.join(openclawHome, 'clawreins');
  const outputPath = path.join(outputDir, 'scan-report.html');

  await fs.ensureDir(outputDir);
  await fs.writeFile(outputPath, buildHtmlReport(report), 'utf8');

  return outputPath;
}

function openHtmlReport(reportPath: string): void {
  try {
    if (process.platform === 'darwin') {
      spawn('open', [reportPath], { detached: true, stdio: 'ignore' }).unref();
      return;
    }

    if (process.platform === 'win32') {
      spawn('cmd', ['/c', 'start', '', reportPath], { detached: true, stdio: 'ignore' }).unref();
      return;
    }

    spawn('xdg-open', [reportPath], { detached: true, stdio: 'ignore' }).unref();
  } catch {
    console.log(chalk.yellow('Unable to open HTML report automatically.'));
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

function exitCodeFor(report: ScanReport): 0 | 1 | 2 {
  if (report.verdict === 'SECURE') {
    return 0;
  }
  if (report.verdict === 'NEEDS ATTENTION') {
    return 1;
  }
  return 2;
}
