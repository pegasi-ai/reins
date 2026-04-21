/**
 * Reins Tool Interceptor
 * Hook-based interception for OpenClaw's before_tool_call event
 */

import { Interceptor } from '../core/Interceptor';
import { logger } from '../core/Logger';
import { detectBrowserChallenge } from '../core/BrowserChallengeDetector';
import { scoreIrreversibility, IrreversibilityAssessment } from '../core/IrreversibilityScorer';
import { MemoryRiskForecaster, MemoryRiskAssessment } from '../core/MemoryRiskForecaster';
import { trustRateLimiter } from '../core/TrustRateLimiter';
import { InterventionMetadata } from '../types';
import { BrowserSessionStore } from '../storage/BrowserSessionStore';
import {
  classifyDestructiveAction,
  DestructiveClassification,
  getBulkThreshold,
  hashArgs,
  isDestructiveGatingEnabled,
} from '../core/DestructiveClassifier';
import { DecisionLog } from '../storage/DecisionLog';
import crypto from 'crypto';

/**
 * Mapping from flat OpenClaw tool names to Reins module/method pairs.
 */
const TOOL_TO_MODULE: Record<string, { module: string; method: string }> = {
  // FileSystem
  read: { module: 'FileSystem', method: 'read' },
  write: { module: 'FileSystem', method: 'write' },
  edit: { module: 'FileSystem', method: 'write' },
  glob: { module: 'FileSystem', method: 'list' },
  // Shell
  bash: { module: 'Shell', method: 'bash' },
  exec: { module: 'Shell', method: 'exec' },
  // Browser — generic / short names
  browser: { module: 'Browser', method: 'navigate' },
  navigate: { module: 'Browser', method: 'navigate' },
  screenshot: { module: 'Browser', method: 'screenshot' },
  click: { module: 'Browser', method: 'click' },
  type: { module: 'Browser', method: 'type' },
  evaluate: { module: 'Browser', method: 'evaluate' },
  // Browser — MCP Playwright tool names
  'mcp__plugin_playwright_playwright__browser_navigate': { module: 'Browser', method: 'navigate' },
  'mcp__plugin_playwright_playwright__browser_navigate_back': { module: 'Browser', method: 'navigate' },
  'mcp__plugin_playwright_playwright__browser_close': { module: 'Browser', method: 'navigate' },
  'mcp__plugin_playwright_playwright__browser_tabs': { module: 'Browser', method: 'navigate' },
  'mcp__plugin_playwright_playwright__browser_resize': { module: 'Browser', method: 'navigate' },
  'mcp__plugin_playwright_playwright__browser_wait_for': { module: 'Browser', method: 'navigate' },
  'mcp__plugin_playwright_playwright__browser_install': { module: 'Browser', method: 'navigate' },
  'mcp__plugin_playwright_playwright__browser_click': { module: 'Browser', method: 'click' },
  'mcp__plugin_playwright_playwright__browser_drag': { module: 'Browser', method: 'click' },
  'mcp__plugin_playwright_playwright__browser_hover': { module: 'Browser', method: 'click' },
  'mcp__plugin_playwright_playwright__browser_handle_dialog': { module: 'Browser', method: 'click' },
  'mcp__plugin_playwright_playwright__browser_type': { module: 'Browser', method: 'type' },
  'mcp__plugin_playwright_playwright__browser_fill_form': { module: 'Browser', method: 'type' },
  'mcp__plugin_playwright_playwright__browser_press_key': { module: 'Browser', method: 'type' },
  'mcp__plugin_playwright_playwright__browser_select_option': { module: 'Browser', method: 'type' },
  'mcp__plugin_playwright_playwright__browser_file_upload': { module: 'Browser', method: 'type' },
  'mcp__plugin_playwright_playwright__browser_take_screenshot': { module: 'Browser', method: 'screenshot' },
  'mcp__plugin_playwright_playwright__browser_snapshot': { module: 'Browser', method: 'screenshot' },
  'mcp__plugin_playwright_playwright__browser_console_messages': { module: 'Browser', method: 'screenshot' },
  'mcp__plugin_playwright_playwright__browser_network_requests': { module: 'Browser', method: 'screenshot' },
  'mcp__plugin_playwright_playwright__browser_evaluate': { module: 'Browser', method: 'evaluate' },
  'mcp__plugin_playwright_playwright__browser_run_code': { module: 'Browser', method: 'evaluate' },
  // Network
  fetch: { module: 'Network', method: 'fetch' },
  request: { module: 'Network', method: 'request' },
  webhook: { module: 'Network', method: 'webhook' },
  download: { module: 'Network', method: 'download' },
  // Gateway
  list_sessions: { module: 'Gateway', method: 'listSessions' },
  list_nodes: { module: 'Gateway', method: 'listNodes' },
  send_message: { module: 'Gateway', method: 'sendMessage' },
  session_status: { module: 'Gateway', method: 'listSessions' },
  // Gmail-style names used in demos/integrations
  'gmail.deletemessages': { module: 'Gmail', method: 'deleteMessages' },
  'gmail.emptytrash': { module: 'Gmail', method: 'emptyTrash' },
  'gmail.deletelabel': { module: 'Gmail', method: 'deleteLabel' },
};

const FORCE_ASK_IRREVERSIBILITY_THRESHOLD = 55;
const EXPLICIT_CONFIRM_IRREVERSIBILITY_THRESHOLD = ((): number => {
  const raw = process.env.REINS_CONFIRM_THRESHOLD || process.env.CLAWREINS_CONFIRM_THRESHOLD;
  const parsed = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 80;
})();
const EXPLICIT_CONFIRM_MEMORY_THRESHOLD = 85;
const DESTRUCTIVE_GATING_ENABLED = isDestructiveGatingEnabled();
const DESTRUCTIVE_BULK_THRESHOLD = getBulkThreshold();
const memoryForecaster = new MemoryRiskForecaster();

export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

export interface ToolContext {
  agentId?: string;
  sessionKey?: string;
  toolName: string;
}

export interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

export function createToolCallHook(
  interceptor: Interceptor
): (event: BeforeToolCallEvent, ctx: ToolContext) => Promise<BeforeToolCallResult | void> {
  return async (event, ctx): Promise<BeforeToolCallResult | void> => {
    const { toolName } = event;

    try {
    const mapping = TOOL_TO_MODULE[toolName.toLowerCase()];
    const moduleName = mapping?.module ?? 'Unknown';
    const methodName = mapping?.method ?? toolName;

    let params = event.params;
    let shouldReturnParams = false;

    // Persistent browser-session management.
    if (moduleName === 'Browser') {
      const sessionId = BrowserSessionStore.buildSessionId(ctx.sessionKey, params);
      const injection = BrowserSessionStore.injectState(sessionId, params);
      params = injection.params;

      if (injection.injectedFields.length > 0) {
        shouldReturnParams = true;
        logger.info('Browser session state injected', {
          toolName,
          sessionId,
          injectedFields: injection.injectedFields,
        });
      }

      const capturedFields = BrowserSessionStore.captureState(sessionId, params);
      if (capturedFields.length > 0) {
        logger.info('Browser session state captured', {
          toolName,
          sessionId,
          capturedFields,
        });
      }
    }

    const irreversibility = scoreIrreversibility(moduleName, methodName, params);
    const destructiveClassification: DestructiveClassification | undefined = DESTRUCTIVE_GATING_ENABLED
      ? classifyDestructiveAction(toolName, params, {
          moduleName,
          methodName,
          bulkThreshold: DESTRUCTIVE_BULK_THRESHOLD,
        })
      : undefined;

    if (destructiveClassification?.isDestructive) {
      logInterceptEvent({
        eventType: 'destructive_detected',
        moduleName,
        methodName,
        toolName,
        params,
        severity: destructiveClassification.severity,
        reasons: destructiveClassification.reasons,
        bulkCount: destructiveClassification.bulkCount,
        target: destructiveClassification.target,
        argsHash: hashArgs(params),
      });
    }

    const sessionKeyForMemory = ctx.sessionKey || `local:${ctx.agentId || 'default'}`;
    const memoryRisk = memoryForecaster.assess(
      sessionKeyForMemory,
      moduleName,
      methodName,
      params,
      irreversibility
    );
    const intervention = buildInterventionMetadata(
      moduleName,
      methodName,
      toolName,
      params,
      irreversibility,
      memoryRisk,
      destructiveClassification?.isDestructive ? destructiveClassification : undefined,
      sessionKeyForMemory
    );

    if (destructiveClassification?.isDestructive && intervention?.actionSummary) {
      logInterceptEvent({
        eventType: 'approval_requested',
        moduleName,
        methodName,
        toolName,
        params,
        severity: destructiveClassification.severity,
        reasons: destructiveClassification.reasons,
        bulkCount: destructiveClassification.bulkCount,
        target: destructiveClassification.target,
        summary: intervention.actionSummary,
        requireToken: intervention.confirmationToken,
      });
    }

    try {
      await interceptor.evaluate(moduleName, methodName, [params], ctx.sessionKey, intervention);
      if (destructiveClassification?.isDestructive) {
        logInterceptEvent({
          eventType: 'tool_executed',
          moduleName,
          methodName,
          toolName,
          params,
          severity: destructiveClassification.severity,
          reasons: destructiveClassification.reasons,
          bulkCount: destructiveClassification.bulkCount,
          target: destructiveClassification.target,
        });
      }
      return shouldReturnParams ? { params } : {};
    } catch (err: unknown) {
      const reason =
        err instanceof Error
          ? err.message
          : `${moduleName}.${methodName}() blocked by Reins policy`;
      logger.warn(`Blocking ${toolName}: ${reason}`);
      if (destructiveClassification?.isDestructive) {
        logInterceptEvent({
          eventType: 'tool_blocked',
          moduleName,
          methodName,
          toolName,
          params,
          severity: destructiveClassification.severity,
          reasons: destructiveClassification.reasons,
          bulkCount: destructiveClassification.bulkCount,
          target: destructiveClassification.target,
          summary: reason,
        });
      }
      return { block: true, blockReason: reason };
    }
    } catch (unexpectedErr: unknown) {
      // Outer fail-closed guard: any unhandled error in the hook (outside the inner
      // try/catch) must block the tool, not allow it. OpenClaw's hook runner is
      // fail-open — it catches hook exceptions and returns { blocked: false }.
      logger.error(`[tool-interceptor] Unexpected error — blocking ${toolName} (fail-closed)`, {
        error: unexpectedErr,
        toolName,
      });
      return { block: true, blockReason: `Reins: unexpected hook error (fail-closed)` };
    }
  };
}

function buildInterventionMetadata(
  moduleName: string,
  methodName: string,
  toolName: string,
  params: Record<string, unknown>,
  irreversibility: IrreversibilityAssessment,
  memoryRisk: MemoryRiskAssessment,
  destructive: DestructiveClassification | undefined,
  sessionKey: string
): InterventionMetadata | undefined {
  const intervention: InterventionMetadata = {};

  if (destructive?.isDestructive) {
    intervention.forceAsk = true;
    intervention.requiresRespondToolApproval = true;
    intervention.destructiveSeverity = destructive.severity;
    intervention.destructiveReasons = destructive.reasons;
    intervention.destructiveBulkCount = destructive.bulkCount;
    intervention.destructiveTarget = destructive.target;

    if (destructive.severity === 'CATASTROPHIC') {
      intervention.requiresExplicitConfirmation = true;
      intervention.confirmationToken =
        intervention.confirmationToken || generateConfirmationToken(moduleName, methodName);
    }

    intervention.actionSummary = buildDestructiveSummary(
      moduleName,
      methodName,
      destructive
    );
    intervention.interventionReason =
      'Pre-execution destructive action intercept triggered; explicit human authorization required.';
    intervention.overrideDescription = intervention.actionSummary;
  }

  const challenge = detectBrowserChallenge(toolName, params);
  if (challenge.level === 'likely') {
    intervention.forceAsk = true;
    intervention.recommendScreenshotReview = true;
    intervention.overrideDescription = `Browser challenge likely (${challenge.kind}): ${challenge.reasons.join('; ')}`;
    intervention.interventionReason =
      'Detected CAPTCHA/Cloudflare/2FA-like browser state. Human intervention required.';
  } else if (challenge.level === 'possible') {
    intervention.forceAsk = true;
    intervention.recommendScreenshotReview = true;
    intervention.overrideDescription = `Possible browser challenge (${challenge.kind}): ${challenge.reasons.join('; ')}`;
    intervention.interventionReason =
      'Uncertain browser challenge state; run screenshot + vision review before approval.';
  }

  if (irreversibility.score >= FORCE_ASK_IRREVERSIBILITY_THRESHOLD) {
    intervention.forceAsk = true;
    const riskLine =
      `Irreversibility score ${irreversibility.score}/100 (${irreversibility.level}). ` +
      `${irreversibility.reasons.join('; ') || 'High-impact action pattern.'}`;

    intervention.overrideDescription = intervention.overrideDescription
      ? `${intervention.overrideDescription} ${riskLine}`
      : riskLine;
  }

  if (irreversibility.score >= EXPLICIT_CONFIRM_IRREVERSIBILITY_THRESHOLD) {
    intervention.requiresExplicitConfirmation = true;
    if (!intervention.confirmationToken) {
      intervention.confirmationToken = generateConfirmationToken(moduleName, methodName);
    }
    if (!intervention.actionSummary) {
      intervention.actionSummary = irreversibility.summary;
    }
    intervention.interventionReason =
      'Irreversible action detected. Requires explicit token confirmation, not YES/NO.';
  }

  if (memoryRisk.shouldPause) {
    intervention.forceAsk = true;
    const topPaths = memoryRisk.simulatedPaths
      .map((path) => `${path.name} (${path.risk}/100)`)
      .join('; ');
    const memoryLine =
      `Memory risk forecast ${memoryRisk.overallRisk}/100 ` +
      `(drift ${memoryRisk.driftScore}, salami ${memoryRisk.salamiIndex}, commitment ${memoryRisk.commitmentCreep}).`;

    intervention.overrideDescription = intervention.overrideDescription
      ? `${intervention.overrideDescription} ${memoryLine}`
      : memoryLine;

    intervention.interventionReason = topPaths
      ? `Predicted N+1 danger paths: ${topPaths}.`
      : 'Memory drift indicates unsafe next-step trajectory.';

    if (!intervention.actionSummary) {
      intervention.actionSummary = memoryRisk.summary;
    }

    if (memoryRisk.overallRisk >= EXPLICIT_CONFIRM_MEMORY_THRESHOLD) {
      intervention.requiresExplicitConfirmation = true;
      if (!intervention.confirmationToken) {
        intervention.confirmationToken = generateConfirmationToken(moduleName, methodName);
      }
    }
  }

  // Cooldown escalation: tighten posture after repeated denials.
  const escalationState = trustRateLimiter.getState(sessionKey);
  if (escalationState.level >= 1) {
    intervention.forceAsk = true;
    intervention.cooldownLevel = escalationState.level;
    const cooldownLine =
      `Cooldown escalation level ${escalationState.level}: ` +
      `${escalationState.denialCount} denials in the last ${Math.round(escalationState.windowMs / 60_000)} minutes.`;
    intervention.interventionReason = intervention.interventionReason
      ? `${intervention.interventionReason} ${cooldownLine}`
      : cooldownLine;
  }
  if (escalationState.level >= 2) {
    intervention.requiresExplicitConfirmation = true;
    intervention.actionSummary = intervention.actionSummary || `${toolName}(...)`;
  }

  if (Object.keys(intervention).length === 0) {
    return undefined;
  }

  return intervention;
}

function generateConfirmationToken(moduleName: string, methodName: string): string {
  const seed = `${moduleName}.${methodName}:${Date.now()}:${Math.random()}`;
  const digest = crypto.createHash('sha1').update(seed).digest('hex').slice(0, 6).toUpperCase();
  return `CONFIRM-${digest}`;
}

function buildDestructiveSummary(
  moduleName: string,
  methodName: string,
  classification: DestructiveClassification
): string {
  const lines = [
    `⚠ REINS INTERCEPT (${classification.severity})`,
    `Tool: ${moduleName}.${methodName}`,
  ];

  if (classification.target) {
    lines.push(`Target: ${classification.target}`);
  }
  if (classification.bulkCount !== undefined) {
    lines.push(`Bulk: ${classification.bulkCount.toLocaleString()} items`);
  }

  lines.push(`Reasons: ${classification.reasons.join(', ') || 'destructive_signal'}`);
  // Token intentionally omitted — delivered out-of-band only, never in agent context.
  lines.push(`Require: out-of-band human approval`);
  return lines.join('\n');
}

interface InterceptEventInput {
  eventType:
    | 'destructive_detected'
    | 'approval_requested'
    | 'approval_decision'
    | 'tool_executed'
    | 'tool_blocked';
  moduleName: string;
  methodName: string;
  toolName: string;
  params: Record<string, unknown>;
  severity?: 'HIGH' | 'CATASTROPHIC';
  reasons?: string[];
  bulkCount?: number;
  target?: string;
  argsHash?: string;
  summary?: string;
  requireToken?: string;
  approved?: boolean;
  decisionInput?: 'yes' | 'allow' | 'no' | 'confirm';
  confirmation?: string;
}

function logInterceptEvent(input: InterceptEventInput): void {
  const defaultDecisionByEvent: Record<InterceptEventInput['eventType'], 'ALLOWED' | 'APPROVED' | 'REJECTED' | 'BLOCKED'> = {
    destructive_detected: 'BLOCKED',
    approval_requested: 'BLOCKED',
    approval_decision: input.approved ? 'APPROVED' : 'REJECTED',
    tool_executed: 'ALLOWED',
    tool_blocked: 'BLOCKED',
  };

  void DecisionLog.append({
    timestamp: new Date().toISOString(),
    module: input.moduleName,
    method: input.methodName,
    args: [input.params],
    decision: defaultDecisionByEvent[input.eventType],
    decisionTime: 0,
    reason: input.eventType,
    eventType: input.eventType,
    tool: input.toolName,
    severity: input.severity,
    reasons: input.reasons,
    bulkCount: input.bulkCount,
    target: input.target,
    argsHash: input.argsHash,
    summary: input.summary,
    requireToken: input.requireToken,
    approved: input.approved,
    decisionInput: input.decisionInput,
    confirmation: input.confirmation,
  });
}


export function getToolMapping(): Record<string, { module: string; method: string }> {
  return { ...TOOL_TO_MODULE };
}

export function getProtectedModules(): string[] {
  const modules = new Set<string>();
  for (const entry of Object.values(TOOL_TO_MODULE)) {
    modules.add(entry.module);
  }
  return Array.from(modules);
}
