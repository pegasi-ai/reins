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

interface ApprovalEntry {
  sessionKey: string;
  moduleName: string;
  methodName: string;
  requiresExplicitConfirmation: boolean;
  actionSummary?: string;
  confirmationToken?: string;
  allowRetryAsApproval: boolean;
  status: 'pending' | 'approved' | 'denied';
  createdAt: number;
  expiresAt: number;
}

/** Default time-to-live for an approval entry (2 minutes). */
const DEFAULT_TTL_MS = 120_000;

/**
 * Maximum age for a pending entry before a new one is created on re-request.
 */
const CONSUME_MAX_AGE_MS = 60_000;

/** Cleanup runs at most every 30 seconds. */
const CLEANUP_INTERVAL_MS = 30_000;

export class ApprovalQueue {
  private entries = new Map<string, ApprovalEntry>();
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

  // ---------------------------------------------------------------------------
  // Out-of-band token resolution
  // ---------------------------------------------------------------------------

  /**
   * Resolve any pending entry that has the given token.
   * Used by /approve and /deny commands.
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
    this.lastCleanup = now;
  }
}

/** Singleton instance shared across the plugin. */
export const approvalQueue = new ApprovalQueue();
