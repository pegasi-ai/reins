/**
 * ClawReins Type Definitions
 * The strict vocabulary of the security system
 */

/**
 * Security decision types
 * - ALLOW: Execute immediately without prompting
 * - DENY: Block execution and throw error
 * - ASK: Pause and request human decision
 */
export type Decision = 'ALLOW' | 'DENY' | 'ASK';

/**
 * Rule definition for a specific method
 */
export interface SecurityRule {
  action: Decision;
  description?: string; // Optional reasoning for logs and UI
}

/**
 * Complete security policy structure
 */
export interface SecurityPolicy {
  defaultAction: Decision; // Fallback if no rule exists (Paranoia mode)
  modules: {
    [moduleName: string]: {
      [methodName: string]: SecurityRule;
    };
  };
}

export interface InterventionMetadata {
  /** Force human review regardless of normal ALLOW policy (DENY remains DENY). */
  forceAsk?: boolean;
  /** Override the displayed risk description in prompts/logs. */
  overrideDescription?: string;
  /** Extra reason text appended to channel-mode approval instructions. */
  interventionReason?: string;
  /** Escalate from YES/NO to explicit confirmation token flow. */
  requiresExplicitConfirmation?: boolean;
  /** Human-readable summary of the action that needs explicit confirmation. */
  actionSummary?: string;
  /**
   * Confirmation token shown to the user/agent. If omitted, one is generated
   * per request.
   */
  confirmationToken?: string;
  /**
   * If true, channel instructions tell the agent to capture a screenshot and
   * use vision reasoning before asking for approval.
   */
  recommendScreenshotReview?: boolean;
  /** Current cooldown escalation level (0=normal, 1=heightened, 2=restricted). */
  cooldownLevel?: number;
  /** Destructive-intercept severity for UI and audit context. */
  destructiveSeverity?: 'HIGH' | 'CATASTROPHIC';
  /** Reasons from destructive classifier. */
  destructiveReasons?: string[];
  /** Optional bulk count identified by destructive classifier. */
  destructiveBulkCount?: number;
  /** Optional user-facing target (mailbox/path/host). */
  destructiveTarget?: string;
  /** Require channel approvals to come via clawreins_respond (fail-secure if unavailable). */
  requiresRespondToolApproval?: boolean;
}

/**
 * Execution context passed to the Arbitrator
 */
export interface ExecutionContext {
  moduleName: string;
  methodName: string;
  args: unknown[];
  rule: SecurityRule;
  /** OpenClaw session key (e.g. "agent:main:whatsapp:dm:+1555…"). Present in daemon/channel mode. */
  sessionKey?: string;
  intervention?: InterventionMetadata;
}
