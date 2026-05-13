import type { CloudPolicyCache } from './cloud-policy';

export interface CloudRuleMatch {
  action?: 'BLOCK' | 'WARN' | 'LOG';
  severity?: string;
  rule: string;
  description?: string;
}

export function evaluateCloudShellRule(command: string, cloudPolicy: CloudPolicyCache): CloudRuleMatch | null {
  for (const rule of cloudPolicy.shell_rules) {
    try {
      const re = new RegExp(rule.pattern, 'i');
      if (re.test(command)) {
        return {
          action: rule.action,
          severity: rule.severity,
          rule: rule.pattern,
          description: rule.description,
        };
      }
    } catch {
      // Ignore invalid regex patterns from cache.
    }
  }

  return null;
}

export function evaluateCloudMcpRule(toolName: string, cloudPolicy: CloudPolicyCache): CloudRuleMatch | null {
  for (const rule of cloudPolicy.mcp_rules) {
    try {
      const matches =
        toolName.startsWith(rule.tool_pattern) ||
        new RegExp(rule.tool_pattern, 'i').test(toolName);
      if (matches) {
        return {
          action: rule.action,
          severity: rule.severity,
          rule: rule.tool_pattern,
          description: rule.description,
        };
      }
    } catch {
      // Ignore invalid regex patterns from cache.
    }
  }

  return null;
}
