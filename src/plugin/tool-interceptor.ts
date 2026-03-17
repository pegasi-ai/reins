/**
 * ClawReins Tool Interceptor
 * Hook-based interception for OpenClaw's before_tool_call event
 */

import { Interceptor } from '../core/Interceptor';
import { approvalQueue } from '../core/ApprovalQueue';
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
 * Tool name for the custom clawreins_respond tool.
 * The LLM calls this to relay the user's YES/NO/ALLOW/CONFIRM decision.
 */
export const CLAWREINS_RESPOND_TOOL = 'clawreins_respond';

/**
 * Mapping from flat OpenClaw tool names to ClawReins module/method pairs.
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
  // Browser
  navigate: { module: 'Browser', method: 'navigate' },
  screenshot: { module: 'Browser', method: 'screenshot' },
  click: { module: 'Browser', method: 'click' },
  type: { module: 'Browser', method: 'type' },
  evaluate: { module: 'Browser', method: 'evaluate' },
  // Network
  fetch: { module: 'Network', method: 'fetch' },
  request: { module: 'Network', method: 'request' },
  webhook: { module: 'Network', method: 'webhook' },
  download: { module: 'Network', method: 'download' },
  // Gateway
  list_sessions: { module: 'Gateway', method: 'listSessions' },
  list_nodes: { module: 'Gateway', method: 'listNodes' },
  send_message: { module: 'Gateway', method: 'sendMessage' },
  // Gmail-style names used in demos/integrations
  'gmail.deletemessages': { module: 'Gmail', method: 'deleteMessages' },
  'gmail.emptytrash': { module: 'Gmail', method: 'emptyTrash' },
  'gmail.deletelabel': { module: 'Gmail', method: 'deleteLabel' },
};

const FORCE_ASK_IRREVERSIBILITY_THRESHOLD = 55;
const EXPLICIT_CONFIRM_IRREVERSIBILITY_THRESHOLD = ((): number => {
  const raw = process.env.CLAWREINS_CONFIRM_THRESHOLD;
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

    // Intercept our own control tool before any policy evaluation.
    if (toolName === CLAWREINS_RESPOND_TOOL) {
      return handleRespondTool(event.params, ctx);
    }

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
          : `${moduleName}.${methodName}() blocked by ClawReins policy`;
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
      destructive,
      intervention.confirmationToken
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
  classification: DestructiveClassification,
  confirmationToken?: string
): string {
  const lines = [
    `⚠ CLAWREINS INTERCEPT (${classification.severity})`,
    `Tool: ${moduleName}.${methodName}`,
  ];

  if (classification.target) {
    lines.push(`Target: ${classification.target}`);
  }
  if (classification.bulkCount !== undefined) {
    lines.push(`Bulk: ${classification.bulkCount.toLocaleString()} items`);
  }

  lines.push(`Reasons: ${classification.reasons.join(', ') || 'destructive_signal'}`);
  lines.push(
    `Require: ${
      classification.severity === 'CATASTROPHIC'
        ? confirmationToken || 'CONFIRM-XXXXXX'
        : 'YES or ALLOW'
    }`
  );
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

/**
 * Handle the clawreins_respond tool call.
 * Always blocks (this is a control signal, not a real tool execution).
 */
function handleRespondTool(
  params: Record<string, unknown>,
  ctx: ToolContext
): BeforeToolCallResult {
  const BLANKET_DURATION_MS = 15 * 60 * 1000;
  const decision = typeof params.decision === 'string' ? params.decision.toLowerCase() : '';
  const sessionKey = ctx.sessionKey;

  if (!sessionKey) {
    logger.warn(`[${CLAWREINS_RESPOND_TOOL}] No sessionKey in context`);
    return { block: true, blockReason: 'Error: no session context available.' };
  }

  if (decision === 'yes') {
    const strictPending = approvalQueue.getStrictPending(sessionKey);
    if (strictPending.length > 0) {
      const strictLines = strictPending
        .map(
          (p) =>
            `${p.moduleName}.${p.methodName} requires ${p.confirmationToken || 'CONFIRM'} (${p.actionSummary || 'no summary'})`
        )
        .join(' | ');
      logInterceptEvent({
        eventType: 'approval_decision',
        moduleName: 'ClawReins',
        methodName: 'approval',
        toolName: CLAWREINS_RESPOND_TOOL,
        params,
        approved: false,
        decisionInput: 'yes',
      });
      return {
        block: true,
        blockReason:
          `YES is not sufficient for high-irreversibility actions. ` +
          `Use clawreins_respond({ decision: "confirm", confirmation: "<TOKEN>" }). ` +
          `Pending: ${strictLines}`,
      };
    }

    if (!approvalQueue.hasPending(sessionKey)) {
      logger.info(`[${CLAWREINS_RESPOND_TOOL}] No pending approvals for session`, { sessionKey });
      logInterceptEvent({
        eventType: 'approval_decision',
        moduleName: 'ClawReins',
        methodName: 'approval',
        toolName: CLAWREINS_RESPOND_TOOL,
        params,
        approved: false,
        decisionInput: 'yes',
      });
      return { block: true, blockReason: 'No pending approvals to approve.' };
    }
    const count = approvalQueue.approve(sessionKey);
    logger.info(`[${CLAWREINS_RESPOND_TOOL}] APPROVED`, { sessionKey, count });
    logInterceptEvent({
      eventType: 'approval_decision',
      moduleName: 'ClawReins',
      methodName: 'approval',
      toolName: CLAWREINS_RESPOND_TOOL,
      params,
      approved: true,
      decisionInput: 'yes',
    });
    return { block: true, blockReason: 'Approved. Retry the blocked tool.' };
  }

  if (decision === 'confirm') {
    const confirmation =
      typeof params.confirmation === 'string' ? params.confirmation.trim() : '';
    if (!confirmation) {
      logInterceptEvent({
        eventType: 'approval_decision',
        moduleName: 'ClawReins',
        methodName: 'approval',
        toolName: CLAWREINS_RESPOND_TOOL,
        params,
        approved: false,
        decisionInput: 'confirm',
      });
      return {
        block: true,
        blockReason:
          'Missing confirmation token. Use clawreins_respond({ decision: "confirm", confirmation: "CONFIRM-XXXXXX" }).',
      };
    }

    const count = approvalQueue.confirm(sessionKey, confirmation);
    if (count === 0) {
      logInterceptEvent({
        eventType: 'approval_decision',
        moduleName: 'ClawReins',
        methodName: 'approval',
        toolName: CLAWREINS_RESPOND_TOOL,
        params,
        approved: false,
        decisionInput: 'confirm',
        confirmation,
      });
      return {
        block: true,
        blockReason: `No pending strict approvals matched token ${confirmation}.`,
      };
    }

    logger.info(`[${CLAWREINS_RESPOND_TOOL}] EXPLICITLY_CONFIRMED`, {
      sessionKey,
      confirmation,
      count,
    });
    logInterceptEvent({
      eventType: 'approval_decision',
      moduleName: 'ClawReins',
      methodName: 'approval',
      toolName: CLAWREINS_RESPOND_TOOL,
      params,
      approved: true,
      decisionInput: 'confirm',
      confirmation,
    });
    return { block: true, blockReason: 'Explicitly confirmed. Retry the blocked tool.' };
  }

  if (decision === 'no') {
    const count = approvalQueue.deny(sessionKey);
    trustRateLimiter.recordDenial(sessionKey);
    logger.info(`[${CLAWREINS_RESPOND_TOOL}] DENIED`, { sessionKey, count });
    logInterceptEvent({
      eventType: 'approval_decision',
      moduleName: 'ClawReins',
      methodName: 'approval',
      toolName: CLAWREINS_RESPOND_TOOL,
      params,
      approved: false,
      decisionInput: 'no',
    });
    return { block: true, blockReason: 'Denied. Do NOT retry the blocked tool.' };
  }

  if (decision === 'allow') {
    const strictPending = approvalQueue.getStrictPending(sessionKey);
    if (strictPending.length > 0) {
      logInterceptEvent({
        eventType: 'approval_decision',
        moduleName: 'ClawReins',
        methodName: 'approval',
        toolName: CLAWREINS_RESPOND_TOOL,
        params,
        approved: false,
        decisionInput: 'allow',
      });
      return {
        block: true,
        blockReason:
          'ALLOW is not permitted for high-irreversibility actions. Use explicit CONFIRM token.',
      };
    }

    const pending = approvalQueue.getPendingActions(sessionKey);
    if (pending.length === 0) {
      logger.info(`[${CLAWREINS_RESPOND_TOOL}] No pending approvals for ALLOW`, { sessionKey });
      logInterceptEvent({
        eventType: 'approval_decision',
        moduleName: 'ClawReins',
        methodName: 'approval',
        toolName: CLAWREINS_RESPOND_TOOL,
        params,
        approved: false,
        decisionInput: 'allow',
      });
      return { block: true, blockReason: 'No pending approvals to allow.' };
    }
    for (const { moduleName, methodName } of pending) {
      approvalQueue.allowFor(sessionKey, moduleName, methodName, BLANKET_DURATION_MS);
    }
    const count = approvalQueue.approve(sessionKey);
    const rules = pending.map((p) => `${p.moduleName}.${p.methodName}`).join(', ');
    logger.info(`[${CLAWREINS_RESPOND_TOOL}] ALLOW for 15 min`, { sessionKey, rules, count });
    logInterceptEvent({
      eventType: 'approval_decision',
      moduleName: 'ClawReins',
      methodName: 'approval',
      toolName: CLAWREINS_RESPOND_TOOL,
      params,
      approved: true,
      decisionInput: 'allow',
    });
    return { block: true, blockReason: `Approved for 15 minutes: ${rules}. Retry the blocked tool.` };
  }

  logger.warn(`[${CLAWREINS_RESPOND_TOOL}] Invalid decision: "${params.decision}"`, { sessionKey });
  logInterceptEvent({
    eventType: 'approval_decision',
    moduleName: 'ClawReins',
    methodName: 'approval',
    toolName: CLAWREINS_RESPOND_TOOL,
    params,
    approved: false,
    decisionInput: 'no',
  });
  return {
    block: true,
    blockReason: 'Invalid decision. Use "yes", "no", "allow", or "confirm".',
  };
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
