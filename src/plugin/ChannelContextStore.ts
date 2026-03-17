/**
 * ChannelContextStore
 *
 * Correlates sessionKey ↔ channel sender info (from/channelId/accountId) so that
 * the OOB notifier knows where to send approval notifications.
 *
 * Strategy:
 *   1. `message_received` fires with {from, channelId, accountId, content} but no sessionKey.
 *      We push it into a short-lived ring buffer.
 *   2. `before_message_write` fires for the same message with sessionKey.
 *      We match by content and bind sessionKey → channelInfo.
 *
 * This works because both hooks fire in the same event-loop sequence for a given
 * inbound message. Concurrent sessions are safe for single-user deployments.
 */

export interface ChannelInfo {
  from: string;
  channelId: string;
  accountId?: string;
}

interface PendingEntry {
  info: ChannelInfo;
  content: string;
  ts: number;
}

/** How long a pending entry is eligible for correlation (ms). */
const PENDING_TTL_MS = 5_000;

/** Maximum ring-buffer size. */
const MAX_PENDING = 32;

export class ChannelContextStore {
  private pending: PendingEntry[] = [];
  private resolved = new Map<string, ChannelInfo>();

  /**
   * Called from the `message_received` hook.
   * Stores channel context so it can be matched to a sessionKey.
   */
  onMessageReceived(from: string, content: string, channelId: string, accountId?: string): void {
    const now = Date.now();
    this.pending = this.pending.filter((e) => now - e.ts < PENDING_TTL_MS);
    if (this.pending.length >= MAX_PENDING) {
      this.pending.shift();
    }
    this.pending.push({ info: { from, channelId, accountId }, content, ts: now });
  }

  /**
   * Called from the `before_message_write` hook for user (role="user") messages.
   * Correlates the message text to a pending entry and binds it to the sessionKey.
   */
  onBeforeMessageWrite(sessionKey: string, messageText: string): void {
    const now = Date.now();
    const idx = this.pending.findIndex(
      (e) => e.content === messageText && now - e.ts < PENDING_TTL_MS
    );
    if (idx !== -1) {
      this.resolved.set(sessionKey, this.pending[idx].info);
      this.pending.splice(idx, 1);
    }
  }

  /** Returns the most recently seen channel info for a session. */
  get(sessionKey: string): ChannelInfo | undefined {
    return this.resolved.get(sessionKey);
  }
}

export const channelContextStore = new ChannelContextStore();
