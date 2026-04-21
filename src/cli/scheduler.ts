import { spawnSync } from 'child_process';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { getOpenClawPaths } from '../plugin/config-manager';

export const WATCHTOWER_CRON_MARKER = '# reins-watchtower-scan';
export const LEGACY_WATCHTOWER_CRON_MARKER = '# clawreins-watchtower-scan';
export const WATCHTOWER_LAUNCH_AGENT_LABEL = 'ai.pegasi.reins.watchtower-scan';
const DEFAULT_CRON_SCHEDULE = '0 9 * * *';

export interface InstallScheduleOptions {
  cliScriptPath?: string;
  homeDir?: string;
  nodePath?: string;
  openclawHome?: string;
  platform?: NodeJS.Platform;
  schedule?: string;
  spawnSyncImpl?: typeof spawnSync;
  uid?: number;
}

export interface ScheduleInstallResult {
  alreadyInstalled: boolean;
  descriptor: string;
  kind: 'cron' | 'launchagent';
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function getDefaultCliScriptPath(): string {
  return process.argv[1] ? path.resolve(process.argv[1]) : path.resolve(__dirname, 'index.js');
}

function resolveHomeDir(options: InstallScheduleOptions): string {
  return options.homeDir || os.homedir();
}

function resolveOpenclawHome(options: InstallScheduleOptions): string {
  return options.openclawHome || getOpenClawPaths().openclawHome;
}

function resolvePlatform(options: InstallScheduleOptions): NodeJS.Platform {
  return options.platform || process.platform;
}

function resolveUid(options: InstallScheduleOptions): number {
  if (typeof options.uid === 'number') {
    return options.uid;
  }

  if (typeof process.getuid === 'function') {
    return process.getuid();
  }

  return 0;
}

function getLogPath(options: InstallScheduleOptions): string {
  return path.join(resolveOpenclawHome(options), 'reins', 'scan-monitor.log');
}

export function buildWatchtowerCronEntry(options: InstallScheduleOptions = {}): string {
  const homeDir = resolveHomeDir(options);
  const openclawHome = resolveOpenclawHome(options);
  const nodePath = options.nodePath || process.execPath;
  const cliScriptPath = options.cliScriptPath || getDefaultCliScriptPath();
  const schedule = options.schedule || DEFAULT_CRON_SCHEDULE;
  const logPath = getLogPath(options);

  return [
    schedule,
    `HOME=${shellQuote(homeDir)}`,
    `OPENCLAW_HOME=${shellQuote(openclawHome)}`,
    shellQuote(nodePath),
    shellQuote(cliScriptPath),
    'scan',
    '--monitor',
    `>> ${shellQuote(logPath)} 2>&1`,
    WATCHTOWER_CRON_MARKER,
  ].join(' ');
}

export function mergeCrontabContents(currentContents: string, cronEntry: string): string {
  const preservedLines = currentContents
    .split('\n')
    .map((line) => line.trimEnd())
    .filter(
      (line) => line.length > 0 && !line.includes(WATCHTOWER_CRON_MARKER) && !line.includes(LEGACY_WATCHTOWER_CRON_MARKER)
    );

  preservedLines.push(cronEntry);
  return `${preservedLines.join('\n')}\n`;
}

export function hasWatchtowerCronJob(crontabContents: string): boolean {
  return crontabContents
    .split('\n')
    .some((line) => line.includes(WATCHTOWER_CRON_MARKER) || line.includes(LEGACY_WATCHTOWER_CRON_MARKER));
}

export function getWatchtowerLaunchAgentPath(options: InstallScheduleOptions = {}): string {
  return path.join(resolveHomeDir(options), 'Library', 'LaunchAgents', `${WATCHTOWER_LAUNCH_AGENT_LABEL}.plist`);
}

export function getWatchtowerLaunchAgentSourcePath(options: InstallScheduleOptions = {}): string {
  return path.join(resolveOpenclawHome(options), 'reins', 'launchagents', `${WATCHTOWER_LAUNCH_AGENT_LABEL}.plist`);
}

export function buildWatchtowerLaunchAgentPlist(options: InstallScheduleOptions = {}): string {
  const homeDir = resolveHomeDir(options);
  const openclawHome = resolveOpenclawHome(options);
  const nodePath = options.nodePath || process.execPath;
  const cliScriptPath = options.cliScriptPath || getDefaultCliScriptPath();
  const logPath = getLogPath(options);

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${WATCHTOWER_LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
      <string>${escapeXml(nodePath)}</string>
      <string>${escapeXml(cliScriptPath)}</string>
      <string>scan</string>
      <string>--monitor</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>HOME</key>
      <string>${escapeXml(homeDir)}</string>
      <key>OPENCLAW_HOME</key>
      <string>${escapeXml(openclawHome)}</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>${escapeXml(openclawHome)}</string>
    <key>StandardOutPath</key>
    <string>${escapeXml(logPath)}</string>
    <key>StandardErrorPath</key>
    <string>${escapeXml(logPath)}</string>
    <key>StartCalendarInterval</key>
    <dict>
      <key>Hour</key>
      <integer>9</integer>
      <key>Minute</key>
      <integer>0</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
  </dict>
</plist>
`;
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function supportsScheduledScans(platform = process.platform): boolean {
  return platform !== 'win32';
}

export async function installWatchtowerCronJob(options: InstallScheduleOptions = {}): Promise<ScheduleInstallResult> {
  const spawn = options.spawnSyncImpl || spawnSync;
  const cronEntry = buildWatchtowerCronEntry(options);
  const openclawHome = resolveOpenclawHome(options);

  await fs.ensureDir(path.join(openclawHome, 'reins'));

  const current = spawn('crontab', ['-l'], { encoding: 'utf8' });
  const stderr = `${current.stderr || ''}`.trim();
  const hasNoCrontabMessage = /no crontab/i.test(stderr);

  if (current.status !== 0 && !hasNoCrontabMessage) {
    throw new Error(stderr || 'Failed to read current crontab.');
  }

  const currentContents = current.status === 0 ? `${current.stdout || ''}` : '';
  const alreadyInstalled = hasWatchtowerCronJob(currentContents);
  const nextContents = mergeCrontabContents(currentContents, cronEntry);

  const writeResult = spawn('crontab', ['-'], {
    encoding: 'utf8',
    input: nextContents,
  });

  if (writeResult.status !== 0) {
    const writeError = `${writeResult.stderr || ''}`.trim();
    throw new Error(writeError || 'Failed to install scheduled scan crontab entry.');
  }

  return {
    alreadyInstalled,
    descriptor: cronEntry,
    kind: 'cron',
  };
}

export async function installWatchtowerLaunchAgent(options: InstallScheduleOptions = {}): Promise<ScheduleInstallResult> {
  const spawn = options.spawnSyncImpl || spawnSync;
  const plistPath = getWatchtowerLaunchAgentPath(options);
  const sourcePlistPath = getWatchtowerLaunchAgentSourcePath(options);
  const plistContents = buildWatchtowerLaunchAgentPlist(options);
  const uid = resolveUid(options);

  await fs.ensureDir(path.dirname(sourcePlistPath));
  await fs.ensureDir(path.dirname(plistPath));
  await fs.ensureDir(path.join(resolveOpenclawHome(options), 'reins'));
  const alreadyInstalled = await fs.pathExists(plistPath);
  await fs.writeFile(sourcePlistPath, plistContents, 'utf8');
  await fs.writeFile(plistPath, plistContents, 'utf8');

  const domainTarget = `gui/${uid}/${WATCHTOWER_LAUNCH_AGENT_LABEL}`;
  const bootoutResult = spawn('launchctl', ['bootout', domainTarget], { encoding: 'utf8' });

  if (bootoutResult.status !== 0) {
    const bootoutError = `${bootoutResult.stderr || ''}`.trim();
    const ignorable = /could not find service|service is not loaded|no such process|not loaded/i.test(bootoutError);
    if (bootoutError && !ignorable) {
      throw new Error(bootoutError);
    }
  }

  const bootstrapResult = spawn('launchctl', ['bootstrap', `gui/${uid}`, plistPath], { encoding: 'utf8' });
  if (bootstrapResult.status !== 0) {
    const bootstrapError = `${bootstrapResult.stderr || ''}`.trim();
    throw new Error(bootstrapError || 'Failed to load LaunchAgent.');
  }

  const kickstartResult = spawn('launchctl', ['kickstart', '-k', domainTarget], { encoding: 'utf8' });
  if (kickstartResult.status !== 0) {
    const kickstartError = `${kickstartResult.stderr || ''}`.trim();
    const ignorable = /service cannot load in requested session|not permitted to kickstart/i.test(kickstartError);
    if (kickstartError && !ignorable) {
      throw new Error(kickstartError);
    }
  }

  return {
    alreadyInstalled,
    descriptor: sourcePlistPath,
    kind: 'launchagent',
  };
}

export async function installWatchtowerSchedule(options: InstallScheduleOptions = {}): Promise<ScheduleInstallResult> {
  const platform = resolvePlatform(options);

  if (!supportsScheduledScans(platform)) {
    throw new Error('Scheduled scans are only supported on macOS and Unix-like systems right now.');
  }

  if (platform === 'darwin') {
    return installWatchtowerLaunchAgent(options);
  }

  return installWatchtowerCronJob(options);
}
