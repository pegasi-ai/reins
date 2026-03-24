/**
 * ClawReins Interceptor
 * The Brain - Runtime Security Evaluation Engine
 */

import crypto from 'crypto';
import path from 'path';
import {
  SecurityPolicy,
  Decision,
  SecurityRule,
  ExecutionContext,
  InterventionMetadata,
} from '../types';
import { DEFAULT_POLICY } from '../config';
import { Arbitrator } from './Arbitrator';
import { DecisionLog, DecisionRecord } from '../storage/DecisionLog';
import { StatsTracker } from '../storage/StatsTracker';
import { trustRateLimiter } from './TrustRateLimiter';
import { logger } from './Logger';
import chalk from 'chalk';

// ---------------------------------------------------------------------------
// Path-policy helpers (no external dependency)
// Supports: * (within a segment), ** (any depth), ? (single char)
// ---------------------------------------------------------------------------

function expandTilde(raw: string): string {
  if (raw === '~' || raw.startsWith('~/') || raw.startsWith('~\\')) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '~';
    return home + raw.slice(1);
  }
  return raw;
}

function matchesGlob(pattern: string, str: string): boolean {
  const norm = str.replace(/\\/g, '/');
  const pat = expandTilde(pattern).replace(/\\/g, '/');

  const regex = pat
    .replace(/[.+^${}()|[\]]/g, '\\$&') // escape regex specials
    .replace(/\*\*/g, '\x00')            // placeholder for **
    .replace(/\*/g, '[^/]*')             // * → any non-slash chars
    .replace(/\?/g, '[^/]')              // ? → single non-slash char
    .replace(/\/\x00/g, '(?:/.+)?')     // /** → slash + content optional (matches dir root)
    .replace(/\x00/g, '.*');             // standalone ** → anything

  return new RegExp(`^${regex}$`).test(norm);
}

/**
 * Extract the path or URL that a tool call is targeting, for path-policy evaluation.
 * Returns null if no target can be determined (policy check is skipped).
 */
function extractTarget(moduleName: string, params: Record<string, unknown>): string | null {
  if (moduleName === 'Browser' || moduleName === 'Network') {
    return (params.url ?? params.src ?? null) as string | null;
  }
  const raw = (params.path ?? params.file_path ?? params.target ?? null) as string | null;
  if (!raw) return null;
  // Expand ~ before resolving so ~/.ssh/id_rsa becomes /home/user/.ssh/id_rsa
  return path.resolve(expandTilde(raw));
}

/**
 * Apply allowPaths / denyPaths from the rule against the actual target.
 * Returns a DENY rule if the path is out of bounds, otherwise returns the rule unchanged.
 */
function applyPathPolicy(
  rule: SecurityRule,
  moduleName: string,
  args: unknown[]
): SecurityRule {
  if (!rule.allowPaths?.length && !rule.denyPaths?.length) return rule;

  const params = (args[0] as Record<string, unknown>) ?? {};
  const target = extractTarget(moduleName, params);

  if (!target) {
    // Path filtering is configured but no recognisable path param was found.
    // Log a warning so this silent bypass is visible in the audit trail.
    logger.warn(
      `applyPathPolicy: path filtering configured for ${moduleName} but no target path found in params — filtering skipped`,
      { params }
    );
    return rule;
  }

  // denyPaths take precedence over allowPaths.
  if (rule.denyPaths?.some((p) => matchesGlob(p, target))) {
    return {
      action: 'DENY',
      description: `Path "${target}" matches a denied pattern`,
    };
  }

  // If allowPaths is set the target must match at least one entry.
  if (rule.allowPaths?.length && !rule.allowPaths.some((p) => matchesGlob(p, target))) {
    return {
      action: 'DENY',
      description: `Path "${target}" is not in the allowed paths list`,
    };
  }

  return rule;
}

// ---------------------------------------------------------------------------

export class Interceptor {
  private policy: SecurityPolicy;
  private arbitrator: Arbitrator;
  private logEnabled: boolean;

  /**
   * Optional callback fired (fire-and-forget) when a tool is blocked in channel mode.
   * The plugin sets this to send an OOB approval notification to the human.
   */
  public onBlockCallback?: (sessionKey: string, moduleName: string, methodName: string) => Promise<boolean>;

  constructor(policy?: SecurityPolicy, logEnabled: boolean = true) {
    this.policy = policy || DEFAULT_POLICY;
    this.arbitrator = new Arbitrator();
    this.logEnabled = logEnabled;
  }

  /**
   * Evaluate the security policy for a tool call.
   */
  async evaluate(
    moduleName: string,
    methodName: string,
    args: unknown[],
    sessionKey?: string,
    intervention?: InterventionMetadata
  ): Promise<void> {
    const baseRule = this.lookupRule(moduleName, methodName);
    // Path-policy check runs before intervention so a denied path is never
    // upgradeable to ASK — it's a hard DENY.
    const originalRule = applyPathPolicy(baseRule, moduleName, args);

    const normalizedIntervention = this.normalizeIntervention(
      moduleName,
      methodName,
      originalRule,
      intervention
    );
    const effectiveRule = this.applyInterventionToRule(
      originalRule,
      moduleName,
      methodName,
      normalizedIntervention
    );

    if (this.logEnabled) {
      this.logInterception(moduleName, methodName, effectiveRule.action);
    }

    const allowed = await this.executeDecision(
      effectiveRule,
      moduleName,
      methodName,
      args,
      sessionKey,
      normalizedIntervention
    );

    if (!allowed) {
      const isChannelMode = !process.stdin.isTTY && sessionKey;
      const detail = effectiveRule.description || 'No description provided.';

      if (isChannelMode) {
        const instructions = this.buildChannelInstructions(
          moduleName,
          methodName,
          normalizedIntervention
        );

        throw new Error(
          `[ClawReins:APPROVAL_REQUIRED] ${moduleName}.${methodName}() is blocked pending human approval. ` +
            `Risk: ${detail}\n` +
            instructions
        );
      }

      throw new Error(
        `ClawReins Security Violation: ${moduleName}.${methodName}() was DENIED. ${detail}`
      );
    }
  }

  private normalizeIntervention(
    moduleName: string,
    methodName: string,
    rule: SecurityRule,
    intervention?: InterventionMetadata
  ): InterventionMetadata | undefined {
    if (!intervention) return undefined;

    const next: InterventionMetadata = { ...intervention };

    if (next.requiresExplicitConfirmation && !next.confirmationToken) {
      next.confirmationToken = this.generateConfirmationToken(moduleName, methodName);
    }

    if (next.overrideDescription && next.interventionReason) {
      next.overrideDescription = `${next.overrideDescription} ${next.interventionReason}`;
    } else if (!next.overrideDescription && next.interventionReason) {
      next.overrideDescription = next.interventionReason;
    }

    // No need to force ASK if policy is already DENY.
    if (rule.action === 'DENY') {
      next.forceAsk = false;
      next.requiresExplicitConfirmation = false;
    }

    return next;
  }

  private generateConfirmationToken(moduleName: string, methodName: string): string {
    const seed = `${moduleName}.${methodName}:${Date.now()}:${Math.random()}`;
    const digest = crypto.createHash('sha1').update(seed).digest('hex').slice(0, 6).toUpperCase();
    return `CONFIRM-${digest}`;
  }

  private applyInterventionToRule(
    rule: SecurityRule,
    moduleName: string,
    methodName: string,
    intervention?: InterventionMetadata
  ): SecurityRule {
    if (!intervention) {
      return rule;
    }

    const description =
      intervention.overrideDescription ||
      rule.description ||
      `Rule evaluation for ${moduleName}.${methodName}`;

    if (rule.action === 'DENY') {
      return { ...rule, description };
    }

    if (intervention.forceAsk && rule.action === 'ALLOW') {
      // Severity tiering: only CATASTROPHIC can override an explicit ALLOW policy.
      // HIGH severity (e.g. bulk heuristics, destructive verbs) must respect the
      // user's decision — they already saw the risk and said ALLOW.
      if (intervention.destructiveSeverity !== undefined) {
        if (intervention.destructiveSeverity !== 'CATASTROPHIC') {
          // HIGH: trust the user's ALLOW policy.
          return rule;
        }
        // CATASTROPHIC: override ALLOW → ASK unless the user has opted out of the safety floor.
        const safetyChecksIgnored =
          this.policy.ignoreSafetyChecks === true ||
          process.env.CLAWREINS_IGNORE_SAFETY_CHECKS?.toLowerCase() === 'true';
        if (safetyChecksIgnored) {
          return rule;
        }
        return { action: 'ASK', description };
      }

      // Non-destructive forceAsk sources (irreversibility score, memory risk,
      // browser challenge, cooldown escalation) keep the existing behaviour.
      return {
        action: 'ASK',
        description,
      };
    }

    if (rule.action === 'ASK' && description !== rule.description) {
      return {
        ...rule,
        description,
      };
    }

    return rule;
  }

  private buildChannelInstructions(
    moduleName: string,
    methodName: string,
    intervention?: InterventionMetadata
  ): string {
    const strict = intervention?.requiresExplicitConfirmation === true;
    const summary = intervention?.actionSummary || `${moduleName}.${methodName}()`;

    const screenshotInstruction = intervention?.recommendScreenshotReview
      ? 'Before asking for approval, call screenshot() and use existing vision reasoning on the image. ' +
        'If still uncertain, escalate with the screenshot in the user message.\n'
      : '';

    if (strict) {
      return (
        `${screenshotInstruction}` +
        `⚠️ HIGH-RISK action requires explicit human confirmation.\n` +
        `Action: ${summary}\n` +
        `An out-of-band approval notification has been sent to the human.\n` +
        `WAIT — do NOT retry this tool. Do NOT attempt to self-approve.`
      );
    }

    return (
      `${screenshotInstruction}` +
      `Action: ${summary}\n` +
      `An approval request has been sent to the human out-of-band.\n` +
      `WAIT for their response before retrying. Do NOT attempt to self-approve.`
    );
  }

  private lookupRule(moduleName: string, methodName: string): SecurityRule {
    const moduleRules = this.policy.modules[moduleName];

    if (moduleRules && moduleRules[methodName]) {
      return moduleRules[methodName];
    }

    return {
      action: this.policy.defaultAction,
      description: `No specific rule defined for ${moduleName}.${methodName}`,
    };
  }

  private async executeDecision(
    rule: SecurityRule,
    moduleName: string,
    methodName: string,
    args: unknown[],
    sessionKey?: string,
    intervention?: InterventionMetadata
  ): Promise<boolean> {
    const startTime = Date.now();

    switch (rule.action) {
      case 'ALLOW': {
        const decisionTime = Date.now() - startTime;
        await this.logDecision({
          timestamp: new Date().toISOString(),
          module: moduleName,
          method: methodName,
          args,
          decision: 'ALLOWED',
          reason: rule.description,
          decisionTime,
        });
        return true;
      }

      case 'DENY': {
        const decisionTime = Date.now() - startTime;
        await this.logDecision({
          timestamp: new Date().toISOString(),
          module: moduleName,
          method: methodName,
          args,
          decision: 'BLOCKED',
          reason: rule.description || 'Policy: DENY',
          decisionTime,
        });
        return false;
      }

      case 'ASK': {
        const context: ExecutionContext = {
          moduleName,
          methodName,
          args,
          rule,
          sessionKey,
          intervention,
          onBlockCallback: this.onBlockCallback,
        };

        const approved = await this.arbitrator.judge(context);
        const decisionTime = Date.now() - startTime;

        if (!approved && process.stdin.isTTY) {
          // TTY: record denial for cooldown escalation.
          trustRateLimiter.recordDenial(sessionKey || 'tty');
        }
        // Channel mode: onBlockCallback is called inside judgeChannel() before stalling.

        await this.logDecision({
          timestamp: new Date().toISOString(),
          module: moduleName,
          method: methodName,
          args,
          decision: approved ? 'APPROVED' : 'REJECTED',
          userId: 'human',
          reason: rule.description,
          decisionTime,
        });

        return approved;
      }

      default:
        throw new Error(`Unknown decision type: ${rule.action}`);
    }
  }

  private async logDecision(record: DecisionRecord): Promise<void> {
    try {
      await DecisionLog.append(record);
      await StatsTracker.increment(record.decision, record.decisionTime);
    } catch (error) {
      logger.error('Failed to log decision', { error });
    }
  }

  private logInterception(moduleName: string, methodName: string, action: Decision): void {
    const coloredAction =
      action === 'ALLOW'
        ? chalk.green(action)
        : action === 'DENY'
          ? chalk.red(action)
          : chalk.yellow(action);

    logger.info(`${chalk.cyan('ClawReins:')} ${moduleName}.${methodName}() → ${coloredAction}`);
  }
}
