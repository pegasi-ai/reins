import { createHash } from 'crypto';
import { spawnSync } from 'child_process';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { ScanCheck, ScanReport } from '../core/SecurityScanner';
import { getDataPath, getPreferredDataPath } from '../core/data-dir';

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface ConfigDiffEntry {
  path: string;
  kind: 'added' | 'removed' | 'changed';
  previousValue?: JsonValue;
  currentValue?: JsonValue;
}

export interface DriftComparison {
  baselineCreated: boolean;
  baselineReset: boolean;
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

export interface WatchtowerScanArtifact {
  artifact_version: '1.0.0';
  source: {
    producer: 'reins';
    integration: 'openclaw';
    command: string;
    mode: 'plain' | 'monitor';
    generated_at: string;
  };
  target: {
    kind: 'repository';
    id: string;
    display_name: string;
  };
  scan_result: {
    verdict: ScanReport['verdict'];
    score: number;
    total: number;
    checks: Array<{
      id: string;
      status: ScanCheck['status'];
      message: string;
      remediation: string | null;
    }>;
  };
  monitor_result: {
    enabled: boolean;
    baseline_created: boolean;
    baseline_reset: boolean;
    config_baseline_created: boolean;
    baseline_report_unhealthy: boolean;
    corrupted_state_recovered: boolean;
    previous_scan_timestamp: string | null;
    drift_detected: boolean;
    verdict_worsened: boolean;
    worsened_checks: Array<{
      id: string;
      previous_status: ScanCheck['status'] | 'NEW';
      current_status: ScanCheck['status'];
      message: string;
    }>;
    config_changes: Array<{
      path: string;
      kind: 'added' | 'removed' | 'changed';
      previous_value: JsonValue | null;
      current_value: JsonValue | null;
    }>;
  };
  source_details: {
    git: {
      root_path: null;
      remote_url: string | null;
    };
    openclaw: {
      home_path: null;
      config_path: null;
      policy_path: null;
    };
    reins: {
      state_path: null;
      config_baseline_path: null;
    };
  };
}

interface WriteWatchtowerArtifactOptions {
  command: string;
  report: ScanReport;
  monitorComparison: DriftComparison | null;
}

const WATCHTOWER_ARTIFACT_VERSION = '1.0.0' as const;

interface GitRepositoryIdentity {
  displayName: string;
  id: string;
  remoteUrl: string | null;
  rootPath: string;
}

function runGitCommand(args: string[], cwd: string): string | null {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });

  if (result.status !== 0) {
    return null;
  }

  const output = result.stdout.trim();
  return output.length > 0 ? output : null;
}

function normalizeRemoteUrl(remoteUrl: string): string {
  const trimmed = remoteUrl.trim().replace(/\.git$/i, '');

  try {
    const url = new URL(trimmed);
    return `${url.hostname}${url.pathname}`.replace(/^\/+/, '').toLowerCase();
  } catch {
    const scpLike = trimmed.match(/^(?:ssh:\/\/)?(?:[^@]+@)?([^:/]+)[:/](.+)$/);
    if (scpLike) {
      return `${scpLike[1]}/${scpLike[2]}`.replace(/^\/+/, '').toLowerCase();
    }
    return trimmed.replace(/^\/+/, '').toLowerCase();
  }
}

function getRemoteDisplayName(normalizedRemote: string): string {
  const parts = normalizedRemote.split('/').filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join('/') : normalizedRemote;
}

export function getRepositoryIdentity(cwd = process.cwd()): GitRepositoryIdentity {
  const repoRoot = runGitCommand(['rev-parse', '--show-toplevel'], cwd) || path.resolve(cwd);
  const remoteUrl = runGitCommand(['config', '--get', 'remote.origin.url'], repoRoot);
  const normalizedRemote = remoteUrl ? normalizeRemoteUrl(remoteUrl) : null;
  const displayName = normalizedRemote ? getRemoteDisplayName(normalizedRemote) : path.basename(repoRoot);
  const id = normalizedRemote
    ? normalizedRemote
    : `local/${createHash('sha256').update(repoRoot).digest('hex').slice(0, 16)}`;

  return {
    displayName,
    id,
    remoteUrl,
    rootPath: repoRoot,
  };
}

export function getOpenclawHomePath(): string {
  return process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
}

export function getOpenclawConfigPath(): string {
  return process.env.OPENCLAW_CONFIG || path.join(getOpenclawHomePath(), 'openclaw.json');
}

export function getScanStatePath(): string {
  return getDataPath('scan-state.json');
}

export function getConfigBaselinePath(): string {
  return getDataPath('config-base.json');
}

function getWatchtowerArtifactPath(): string {
  return getPreferredDataPath('watchtower-scan-artifact.json');
}

export function buildWatchtowerArtifact(
  command: string,
  report: ScanReport,
  monitorComparison: DriftComparison | null
): WatchtowerScanArtifact {
  const repository = getRepositoryIdentity();
  const monitorEnabled = monitorComparison !== null;

  return {
    artifact_version: WATCHTOWER_ARTIFACT_VERSION,
    source: {
      producer: 'reins',
      integration: 'openclaw',
      command,
      mode: monitorEnabled ? 'monitor' : 'plain',
      generated_at: report.timestamp,
    },
    target: {
      kind: 'repository',
      id: repository.id,
      display_name: repository.displayName,
    },
    scan_result: {
      verdict: report.verdict,
      score: report.score,
      total: report.total,
      checks: report.checks.map((check) => ({
        id: check.id,
        status: check.status,
        message: check.message,
        remediation: check.remediation ?? null,
      })),
    },
    monitor_result: {
      enabled: monitorEnabled,
      baseline_created: monitorComparison?.baselineCreated ?? false,
      baseline_reset: monitorComparison?.baselineReset ?? false,
      config_baseline_created: monitorComparison?.configBaselineCreated ?? false,
      baseline_report_unhealthy: monitorComparison?.baselineReportUnhealthy ?? false,
      corrupted_state_recovered: monitorComparison?.corruptedStateRecovered ?? false,
      previous_scan_timestamp: monitorComparison?.previousTimestamp ?? null,
      drift_detected: monitorComparison
        ? monitorComparison.verdictWorsened
          || monitorComparison.worsenedChecks.length > 0
          || monitorComparison.configChanges.length > 0
        : false,
      verdict_worsened: monitorComparison?.verdictWorsened ?? false,
      worsened_checks: monitorComparison?.worsenedChecks.map((change) => ({
        id: change.id,
        previous_status: change.previousStatus,
        current_status: change.currentStatus,
        message: change.message,
      })) ?? [],
      config_changes: monitorComparison?.configChanges.map((change) => ({
        path: change.path,
        kind: change.kind,
        previous_value: change.previousValue ?? null,
        current_value: change.currentValue ?? null,
      })) ?? [],
    },
    source_details: {
      git: {
        root_path: null,
        remote_url: null,
      },
      openclaw: {
        home_path: null,
        config_path: null,
        policy_path: null,
      },
      reins: {
        state_path: null,
        config_baseline_path: null,
      },
    },
  };
}

export async function writeWatchtowerArtifact(options: WriteWatchtowerArtifactOptions): Promise<{
  artifact: WatchtowerScanArtifact;
  artifactPath: string;
}> {
  const artifactPath = getWatchtowerArtifactPath();
  const artifact = buildWatchtowerArtifact(options.command, options.report, options.monitorComparison);

  await fs.ensureDir(path.dirname(artifactPath));
  await fs.writeJson(artifactPath, artifact, { spaces: 2 });

  return {
    artifact,
    artifactPath,
  };
}
