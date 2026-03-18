/**
 * ClawReins Interceptor
 * The Brain - Runtime Security Evaluation Engine
 */

import crypto from 'crypto';
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

export class Interceptor {
  private policy: SecurityPolicy;
  private arbitrator: Arbitrator;
  private logEnabled: boolean;

  /**
   * Optional callback fired (fire-and-forget) when a tool is blocked in channel mode.
   * The plugin sets this to send an OOB approval notification to the human.
   */
  public onBlockCallback?: (sessionKey: string, moduleName: string, methodName: string) => void;

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
    const originalRule = this.lookupRule(moduleName, methodName);
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
            `Risk: ${detail}
` +
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
        };

        const approved = await this.arbitrator.judge(context);
        const decisionTime = Date.now() - startTime;

        if (!approved) {
          if (process.stdin.isTTY) {
            // TTY: record denial for cooldown escalation.
            trustRateLimiter.recordDenial(sessionKey || 'tty');
          } else if (sessionKey && this.onBlockCallback) {
            // Channel mode: fire OOB notification (non-blocking).
            this.onBlockCallback(sessionKey, moduleName, methodName);
          }
        }

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
