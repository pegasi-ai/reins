export type HookAgentType = 'claude_code' | 'cowork' | 'openclaw';

export interface ClaudeToolMetadata {
  moduleName: string;
  methodName: string;
  actionSummary: string;
  policyKind: 'mcp' | 'shell' | 'file' | 'none';
}

function getString(
  toolInput: Record<string, unknown>,
  keys: string[]
): string {
  for (const key of keys) {
    const value = toolInput[key];
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return '';
}

export function resolveHookAgentType(): HookAgentType {
  const raw = process.env.REINS_AGENT_TYPE;
  if (raw === 'cowork') return 'cowork';
  if (raw === 'openclaw') return 'openclaw';
  return 'claude_code';
}

const AGENT_SLUG: Record<HookAgentType, string> = {
  claude_code: 'claude-code',
  cowork: 'claude-cowork',
  openclaw: 'open-claw',
};

export function agentSlug(agentType: HookAgentType): string {
  return AGENT_SLUG[agentType];
}

export function getClaudeToolMetadata(
  toolName: string,
  toolInput: Record<string, unknown>
): ClaudeToolMetadata {
  const normalizedToolName = toolName.toLowerCase();
  const isFetchTool =
    toolName === 'WebFetch' ||
    normalizedToolName === 'fetch' ||
    normalizedToolName === 'mcp__fetch__fetch' ||
    normalizedToolName === 'mcp__server-fetch__fetch' ||
    normalizedToolName.endsWith('__fetch');

  if (isFetchTool) {
    return {
      moduleName: 'Network',
      methodName: 'fetch',
      actionSummary: getString(toolInput, ['url', 'uri']),
      policyKind: 'none',
    };
  }

  if (toolName.startsWith('mcp__')) {
    return {
      moduleName: 'MCP',
      methodName: toolName,
      actionSummary: toolName,
      policyKind: 'mcp',
    };
  }

  if (toolName === 'Bash') {
    return {
      moduleName: 'Shell',
      methodName: 'bash',
      actionSummary: getString(toolInput, ['command']).slice(0, 120),
      policyKind: 'shell',
    };
  }

  if (['Edit', 'MultiEdit', 'Write', 'NotebookEdit'].includes(toolName)) {
    return {
      moduleName: 'FileSystem',
      methodName: toolName.toLowerCase(),
      actionSummary: getString(toolInput, ['file_path', 'path', 'notebook_path']),
      policyKind: 'file',
    };
  }

  if (['Read', 'NotebookRead'].includes(toolName)) {
    return {
      moduleName: 'FileSystem',
      methodName: toolName.toLowerCase(),
      actionSummary: getString(toolInput, ['file_path', 'path', 'notebook_path']),
      policyKind: 'none',
    };
  }

  if (toolName === 'Glob') {
    return {
      moduleName: 'FileSystem',
      methodName: 'glob',
      actionSummary: getString(toolInput, ['pattern', 'path']),
      policyKind: 'none',
    };
  }

  if (toolName === 'Grep') {
    return {
      moduleName: 'FileSystem',
      methodName: 'grep',
      actionSummary: getString(toolInput, ['pattern', 'query', 'path']),
      policyKind: 'none',
    };
  }

  if (toolName === 'LS') {
    return {
      moduleName: 'FileSystem',
      methodName: 'ls',
      actionSummary: getString(toolInput, ['path']),
      policyKind: 'none',
    };
  }

  if (toolName === 'WebSearch') {
    return {
      moduleName: 'Network',
      methodName: 'websearch',
      actionSummary: getString(toolInput, ['query']),
      policyKind: 'none',
    };
  }

  if (toolName === 'Task') {
    return {
      moduleName: 'Agent',
      methodName: 'task',
      actionSummary: getString(toolInput, ['description', 'prompt']).slice(0, 120),
      policyKind: 'none',
    };
  }

  if (toolName === 'TodoWrite') {
    return {
      moduleName: 'Agent',
      methodName: 'todowrite',
      actionSummary: getString(toolInput, ['todos', 'items']).slice(0, 120),
      policyKind: 'none',
    };
  }

  return {
    moduleName: 'Other',
    methodName: toolName.toLowerCase(),
    actionSummary: toolName,
    policyKind: 'none',
  };
}
