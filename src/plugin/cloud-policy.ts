import { readFileSync } from 'fs';

import { getDataPath } from '../core/data-dir';
import type { SecurityPolicy } from '../types';
import type { McpRule, ShellRule } from '../lib/watchtower-client';

export interface CloudPolicyCache {
  shell_rules: ShellRule[];
  mcp_rules: McpRule[];
  updated_at?: string;
}

export interface RuntimePolicyResolution {
  policy: SecurityPolicy;
  source: 'local' | 'cloud';
  cloudPolicy: CloudPolicyCache | null;
}

const CLOUD_AUTHORITATIVE_POLICY: SecurityPolicy = {
  defaultAction: 'ALLOW',
  modules: {},
};

export function loadCloudPolicyCache(): CloudPolicyCache | null {
  try {
    const raw = readFileSync(getDataPath('policies.json'), 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }

    const record = parsed as Record<string, unknown>;
    return {
      shell_rules: Array.isArray(record['shell_rules']) ? (record['shell_rules'] as ShellRule[]) : [],
      mcp_rules: Array.isArray(record['mcp_rules']) ? (record['mcp_rules'] as McpRule[]) : [],
      updated_at: typeof record['updated_at'] === 'string' ? record['updated_at'] : undefined,
    };
  } catch {
    return null;
  }
}

export function resolveRuntimePolicy(localPolicy: SecurityPolicy): RuntimePolicyResolution {
  const cloudPolicy = loadCloudPolicyCache();
  if (!cloudPolicy) {
    return {
      policy: localPolicy,
      source: 'local',
      cloudPolicy: null,
    };
  }

  return {
    policy: CLOUD_AUTHORITATIVE_POLICY,
    source: 'cloud',
    cloudPolicy,
  };
}

export function getCloudAuthoritativeRuntimePolicy(): RuntimePolicyResolution | null {
  const cloudPolicy = loadCloudPolicyCache();
  if (!cloudPolicy) {
    return null;
  }

  return {
    policy: CLOUD_AUTHORITATIVE_POLICY,
    source: 'cloud',
    cloudPolicy,
  };
}
