/**
 * ClawReins ApprovalQueue
 * In-memory store for channel-based ASK approvals (daemon / messaging mode).
 */

import { logger } from './Logger';

export interface ApprovalRequestOptions {
  requiresExplicitConfirmation?: boolean;
  actionSummary?: string;
  confirmationToken?: string;
  allowRetryAsApproval?: boolean;
}

export interface PendingApprovalInfo {
  moduleName: string;
  methodName: string;
  requiresExplicitConfirmation: boolean;
  actionSummary?: string;
  confirmationToken?: string;
  allowRetryAsApproval: boolean;
}

interface ApprovalEntry extends PendingApprovalInfo {
  sessionKey: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: number;
  expiresAt: number;
}

/** Default time-to-live for an approval entry (2 minutes). */
const DEFAULT_TTL_MS = 120_000;

/**
 * Maximum age for a pending entry to be consumed via retry-as-approval.
 * Strict confirmation entries are never consumed via retry-as-approval.
 */
const CONSUME_MAX_AGE_MS = 60_000;

/** Cleanup runs at most every 30 seconds. */
const CLEANUP_INTERVAL_MS = 30_000;

export class ApprovalQueue {
  private entries = new Map<string, ApprovalEntry>();
  private blanketAllows = new Map<string, number>(); // key → expiresAt
  private lastCleanup = Date.now();
  private ttl: number;

  constructor(ttlMs: number = DEFAULT_TTL_MS) {
    this.ttl = ttlMs;
  }

  // ---------------------------------------------------------------------------
  // Key helpers
  // ---------------------------------------------------------------------------

  /** Composite key: one pending per session + module.method */
  private key(sessionKey: string, moduleName: string, methodName: string): string {
    return `${sessionKey}::${moduleName}.${methodName}`;
  }

  /** All keys belonging to a session (for approve/deny by session). */
  private keysForSession(sessionKey: string): string[] {
    return Array.from(this.entries.keys()).filter((k) => k.startsWith(`${sessionKey}::`));
  }

  // ---------------------------------------------------------------------------
  // Core API
  // ---------------------------------------------------------------------------

  request(
    sessionKey: string,
    moduleName: string,
    methodName: string,
    options: ApprovalRequestOptions = {}
  ): string {
    this.maybeCleanup();
    const k = this.key(sessionKey, moduleName, methodName);
    const existing = this.entries.get(k);

    if (existing && existing.status === 'pending' && Date.now() < existing.expiresAt) {
      const age = Date.now() - existing.createdAt;
      if (age <= CONSUME_MAX_AGE_MS) {
        logger.debug(`ApprovalQueue: pending already exists within retry window, skipping`, {
          sessionKey,
          action: `${moduleName}.${methodName}`,
          ageMs: age,
        });
        return k;
      }
    }

    const entry: ApprovalEntry = {
      sessionKey,
      moduleName,
      methodName,
      requiresExplicitConfirmation: options.requiresExplicitConfirmation ?? false,
      actionSummary: options.actionSummary,
      confirmationToken: options.confirmationToken,
      allowRetryAsApproval: options.allowRetryAsApproval ?? true,
      status: 'pending',
      createdAt: Date.now(),
      expiresAt: Date.now() + this.ttl,
    };

    this.entries.set(k, entry);
    logger.info(`ApprovalQueue: pending request created`, {
      sessionKey,
      action: `${moduleName}.${methodName}`,
      requiresExplicitConfirmation: entry.requiresExplicitConfirmation,
      allowRetryAsApproval: entry.allowRetryAsApproval,
    });
    return k;
  }

  consume(sessionKey: string, moduleName: string, methodName: string): boolean {
    const k = this.key(sessionKey, moduleName, methodName);
    const entry = this.entries.get(k);
    if (entry && entry.status === 'approved' && Date.now() < entry.expiresAt) {
      this.entries.delete(k);
      logger.info(`ApprovalQueue: approval consumed`, {
        sessionKey,
        action: `${moduleName}.${methodName}`,
      });
      return true;
    }

    const expired = entry ? Date.now() >= entry.expiresAt : false;
    logger.debug(`ApprovalQueue.consume: not found/not approved`, {
      sessionKey,
      action: `${moduleName}.${methodName}`,
      entryStatus: entry?.status ?? 'missing',
      expired,
      queueSize: this.entries.size,
    });
    return false;
  }

  consumePending(sessionKey: string, moduleName: string, methodName: string): boolean {
    const k = this.key(sessionKey, moduleName, methodName);
    const entry = this.entries.get(k);

    if (!entry || entry.status !== 'pending' || Date.now() >= entry.expiresAt) {
      return false;
    }

    if (entry.requiresExplicitConfirmation) {
      return false;
    }
    if (!entry.allowRetryAsApproval) {
      return false;
    }

    const age = Date.now() - entry.createdAt;
    if (age > CONSUME_MAX_AGE_MS) {
      logger.info(`ApprovalQueue: pending too old for retry-as-approval, will re-prompt`, {
        sessionKey,
        action: `${moduleName}.${methodName}`,
        ageMs: age,
        maxAgeMs: CONSUME_MAX_AGE_MS,
      });
      return false;
    }

    this.entries.delete(k);
    logger.info(`ApprovalQueue: pending consumed (retry-as-approval)`, {
      sessionKey,
      action: `${moduleName}.${methodName}`,
      ageMs: age,
    });
    return true;
  }

  /** Approve pending non-strict entries in a session (YES flow). */
  approve(sessionKey: string): number {
    this.maybeCleanup();
    let count = 0;

    for (const k of this.keysForSession(sessionKey)) {
      const entry = this.entries.get(k);
      if (!entry) continue;
      if (entry.status !== 'pending' || Date.now() >= entry.expiresAt) continue;
      if (entry.requiresExplicitConfirmation) continue;

      entry.status = 'approved';
      entry.expiresAt = Date.now() + this.ttl;
      count++;

      logger.info(`ApprovalQueue: approved`, {
        sessionKey,
        action: `${entry.moduleName}.${entry.methodName}`,
      });
    }

    return count;
  }

  /** Approve strict entries that match the provided confirmation token. */
  confirm(sessionKey: string, confirmationToken: string): number {
    this.maybeCleanup();
    const normalized = confirmationToken.trim().toUpperCase();
    let count = 0;

    for (const k of this.keysForSession(sessionKey)) {
      const entry = this.entries.get(k);
      if (!entry) continue;
      if (entry.status !== 'pending' || Date.now() >= entry.expiresAt) continue;
      if (!entry.requiresExplicitConfirmation) continue;

      const entryToken = (entry.confirmationToken || '').trim().toUpperCase();
      if (!entryToken || entryToken !== normalized) {
        continue;
      }

      entry.status = 'approved';
      entry.expiresAt = Date.now() + this.ttl;
      count++;

      logger.info(`ApprovalQueue: explicitly confirmed`, {
        sessionKey,
        action: `${entry.moduleName}.${entry.methodName}`,
      });
    }

    return count;
  }

  deny(sessionKey: string): number {
    this.maybeCleanup();
    let count = 0;
    for (const k of this.keysForSession(sessionKey)) {
      const entry = this.entries.get(k)!;
      if (entry.status === 'pending') {
        this.entries.delete(k);
        count++;
        logger.info(`ApprovalQueue: denied`, {
          sessionKey,
          action: `${entry.moduleName}.${entry.methodName}`,
        });
      }
    }
    return count;
  }

  hasPending(sessionKey: string): boolean {
    const keys = this.keysForSession(sessionKey);
    const result = keys.some((k) => {
      const e = this.entries.get(k)!;
      return e.status === 'pending' && Date.now() < e.expiresAt;
    });
    logger.debug(`ApprovalQueue.hasPending`, {
      sessionKey,
      result,
      sessionEntries: keys.length,
      totalSize: this.entries.size,
    });
    return result;
  }

  getPendingActions(
    sessionKey: string,
    includeStrict: boolean = false
  ): Array<{ moduleName: string; methodName: string }> {
    return this.keysForSession(sessionKey)
      .map((k) => this.entries.get(k)!)
      .filter((e) => e.status === 'pending' && Date.now() < e.expiresAt)
      .filter((e) => includeStrict || !e.requiresExplicitConfirmation)
      .map((e) => ({ moduleName: e.moduleName, methodName: e.methodName }));
  }

  getStrictPending(sessionKey: string): PendingApprovalInfo[] {
    return this.keysForSession(sessionKey)
      .map((k) => this.entries.get(k)!)
      .filter((e) => e.status === 'pending' && Date.now() < e.expiresAt)
      .filter((e) => e.requiresExplicitConfirmation)
      .map((e) => ({
        moduleName: e.moduleName,
        methodName: e.methodName,
        requiresExplicitConfirmation: true,
        actionSummary: e.actionSummary,
        confirmationToken: e.confirmationToken,
        allowRetryAsApproval: e.allowRetryAsApproval,
      }));
  }

  // ---------------------------------------------------------------------------
  // Out-of-band token resolution
  // ---------------------------------------------------------------------------

  /**
   * Resolve any pending entry (strict or non-strict) that has the given token.
   * Used by the !approve / !deny commands so the human can approve from their channel.
   */
  resolveByToken(token: string, decision: 'approve' | 'deny'): boolean {
    this.maybeCleanup();
    const normalized = token.trim().toUpperCase();

    for (const [k, entry] of this.entries) {
      if (entry.status !== 'pending' || Date.now() >= entry.expiresAt) continue;
      const entryToken = (entry.confirmationToken || '').trim().toUpperCase();
      if (!entryToken || entryToken !== normalized) continue;

      if (decision === 'approve') {
        entry.status = 'approved';
        entry.expiresAt = Date.now() + this.ttl;
        logger.info('ApprovalQueue: resolved (approved) by token', {
          token: normalized,
          action: `${entry.moduleName}.${entry.methodName}`,
        });
      } else {
        this.entries.delete(k);
        logger.info('ApprovalQueue: resolved (denied) by token', {
          token: normalized,
          action: `${entry.moduleName}.${entry.methodName}`,
        });
      }
      return true;
    }
    return false;
  }

  /**
   * Return the sessionKey for any pending entry that has the given token.
   * Used by the approve command to know which session to signal after approval.
   */
  getSessionKeyByToken(token: string): string | undefined {
    const normalized = token.trim().toUpperCase();
    for (const entry of this.entries.values()) {
      if (entry.status !== 'pending' && entry.status !== 'approved') continue;
      if (Date.now() >= entry.expiresAt) continue;
      const entryToken = (entry.confirmationToken || '').trim().toUpperCase();
      if (entryToken === normalized) return entry.sessionKey;
    }
    return undefined;
  }

  /**
   * Return action info for the approved entry matching a token.
   * Used by sendRetrySignal to build a specific retry message for the agent.
   */
  getApprovedInfo(token: string): { moduleName: string; methodName: string; actionSummary?: string } | undefined {
    const normalized = token.trim().toUpperCase();
    for (const entry of this.entries.values()) {
      if (entry.status !== 'approved') continue;
      if (Date.now() >= entry.expiresAt) continue;
      const entryToken = (entry.confirmationToken || '').trim().toUpperCase();
      if (entryToken === normalized) {
        return { moduleName: entry.moduleName, methodName: entry.methodName, actionSummary: entry.actionSummary };
      }
    }
    return undefined;
  }

  /**
   * Return token + summary for a pending entry in one call.
   * Used by the OOB notifier to build the notification message sent to the human.
   */
  getNotificationInfo(
    sessionKey: string,
    moduleName: string,
    methodName: string
  ): { token: string; summary?: string } | undefined {
    const k = this.key(sessionKey, moduleName, methodName);
    const entry = this.entries.get(k);
    if (!entry || entry.status !== 'pending' || Date.now() >= entry.expiresAt) return undefined;
    if (!entry.confirmationToken) return undefined;
    return { token: entry.confirmationToken, summary: entry.actionSummary };
  }

  /**
   * Stall the caller until the entry is approved, denied, or times out.
   * Polls every 500 ms. Returns true if approved, false otherwise.
   */
  waitForApproval(
    sessionKey: string,
    moduleName: string,
    methodName: string,
    timeoutMs: number = DEFAULT_TTL_MS
  ): Promise<boolean> {
    const k = this.key(sessionKey, moduleName, methodName);
    const deadline = Date.now() + timeoutMs;

    return new Promise<boolean>((resolve) => {
      const tick = (): void => {
        const entry = this.entries.get(k);

        if (!entry || Date.now() >= entry.expiresAt) {
          logger.info('ApprovalQueue: stall ended — expired or removed', {
            sessionKey,
            action: `${moduleName}.${methodName}`,
          });
          resolve(false);
          return;
        }

        if (entry.status === 'approved') {
          this.entries.delete(k);
          logger.info('ApprovalQueue: stall resolved (approved)', {
            sessionKey,
            action: `${moduleName}.${methodName}`,
          });
          resolve(true);
          return;
        }

        if (Date.now() >= deadline) {
          logger.info('ApprovalQueue: stall timed out', {
            sessionKey,
            action: `${moduleName}.${methodName}`,
          });
          resolve(false);
          return;
        }

        setTimeout(tick, 500);
      };

      setTimeout(tick, 500);
    });
  }

  // ---------------------------------------------------------------------------
  // Blanket allows (time-limited auto-approve)
  // ---------------------------------------------------------------------------

  allowFor(sessionKey: string, moduleName: string, methodName: string, durationMs: number): void {
    const k = this.key(sessionKey, moduleName, methodName);
    this.blanketAllows.set(k, Date.now() + durationMs);
    logger.info(`ApprovalQueue: blanket allow created`, {
      sessionKey,
      action: `${moduleName}.${methodName}`,
      durationMs,
    });
  }

  hasBlanketAllow(sessionKey: string, moduleName: string, methodName: string): boolean {
    const k = this.key(sessionKey, moduleName, methodName);
    const expiresAt = this.blanketAllows.get(k);
    if (!expiresAt) return false;
    if (Date.now() >= expiresAt) {
      this.blanketAllows.delete(k);
      return false;
    }
    return true;
  }

  // ---------------------------------------------------------------------------
  // Housekeeping
  // ---------------------------------------------------------------------------

  private maybeCleanup(): void {
    if (Date.now() - this.lastCleanup > CLEANUP_INTERVAL_MS) {
      this.cleanup();
    }
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [k, entry] of this.entries) {
      if (now >= entry.expiresAt) {
        this.entries.delete(k);
      }
    }
    for (const [k, expiresAt] of this.blanketAllows) {
      if (now >= expiresAt) {
        this.blanketAllows.delete(k);
      }
    }
    this.lastCleanup = now;
  }
}

/** Singleton instance shared across the plugin. */
export const approvalQueue = new ApprovalQueue();
