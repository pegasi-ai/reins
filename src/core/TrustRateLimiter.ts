/**
 * Trust Rate Limiter
 *
 * Tracks per-session denial counts within a rolling time window.
 * When the agent gets denied repeatedly, security posture auto-tightens:
 *
 *   Level 0 (normal):     < 3 denials  → no effect
 *   Level 1 (heightened): 3+ denials   → ALLOW rules become ASK
 *   Level 2 (restricted): 5+ denials   → everything requires explicit confirmation
 *
 * Only counts explicit human rejections (TTY reject / channel NO).
 * Policy DENY (BLOCKED) does not count — that's the policy working as intended.
 */

import { logger } from './Logger';

export type EscalationLevel = 0 | 1 | 2;

export interface TrustRateLimiterState {
  level: EscalationLevel;
  denialCount: number;
  windowMs: number;
  oldestDenialAge: number | null;
}

/** Default rolling window: 10 minutes. */
const DEFAULT_WINDOW_MS = 10 * 60 * 1000;

/** Escalation thresholds. */
const LEVEL_1_THRESHOLD = 3;
const LEVEL_2_THRESHOLD = 5;

interface SessionDenialState {
  /** Timestamps of denials within the current window. */
  timestamps: number[];
}

export class TrustRateLimiter {
  private sessions = new Map<string, SessionDenialState>();
  private windowMs: number;

  constructor(windowMs: number = DEFAULT_WINDOW_MS) {
    this.windowMs = windowMs;
  }

  /**
   * Record a human denial for the given session.
   * Call this when a user rejects an action (TTY reject or channel NO).
   */
  recordDenial(sessionKey: string): void {
    const now = Date.now();
    const state = this.getOrCreate(sessionKey);
    state.timestamps.push(now);
    this.prune(state, now);

    const level = this.computeLevel(state);
    logger.info('TrustRateLimiter: denial recorded', {
      sessionKey,
      denialCount: state.timestamps.length,
      level,
    });
  }

  /**
   * Get the current escalation level for a session.
   * Returns 0 if no escalation is active.
   */
  getLevel(sessionKey: string): EscalationLevel {
    const state = this.sessions.get(sessionKey);
    if (!state) return 0;
    this.prune(state, Date.now());
    return this.computeLevel(state);
  }

  /**
   * Get full state for display/debugging.
   */
  getState(sessionKey: string): TrustRateLimiterState {
    const state = this.sessions.get(sessionKey);
    if (!state) {
      return { level: 0, denialCount: 0, windowMs: this.windowMs, oldestDenialAge: null };
    }

    const now = Date.now();
    this.prune(state, now);

    const oldest = state.timestamps.length > 0 ? now - state.timestamps[0] : null;
    return {
      level: this.computeLevel(state),
      denialCount: state.timestamps.length,
      windowMs: this.windowMs,
      oldestDenialAge: oldest,
    };
  }

  private getOrCreate(sessionKey: string): SessionDenialState {
    let state = this.sessions.get(sessionKey);
    if (!state) {
      state = { timestamps: [] };
      this.sessions.set(sessionKey, state);
    }
    return state;
  }

  private prune(state: SessionDenialState, now: number): void {
    const cutoff = now - this.windowMs;
    while (state.timestamps.length > 0 && state.timestamps[0] < cutoff) {
      state.timestamps.shift();
    }
  }

  private computeLevel(state: SessionDenialState): EscalationLevel {
    const count = state.timestamps.length;
    if (count >= LEVEL_2_THRESHOLD) return 2;
    if (count >= LEVEL_1_THRESHOLD) return 1;
    return 0;
  }
}

/** Singleton instance shared across the plugin. */
export const trustRateLimiter = new TrustRateLimiter();
