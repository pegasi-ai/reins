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
   *
   * Primary path: if `conversationId` is provided, derive the sessionKey directly
   * as `agent:main:<conversationId>` (matches OpenClaw's per-channel-peer dmScope)
   * and store immediately — no before_message_write correlation needed.
   *
   * Fallback path: push into the ring buffer for content-based correlation via
   * onBeforeMessageWrite (covers edge cases where conversationId isn't available).
   */
  onMessageReceived(
    from: string,
    content: string,
    channelId: string,
    accountId?: string,
    conversationId?: string
  ): void {
    const info: ChannelInfo = { from, channelId, accountId };

    // Primary: derive sessionKey directly from channelId + from.
    // Covers the common per-channel-peer dmScope:
    //   agent:main:<channelId>:direct:<from>
    // e.g. agent:main:whatsapp:direct:+16505861109
    this.resolved.set(`agent:main:${channelId}:direct:${from}`, info);

    // Secondary: if conversationId is available, also store by that.
    if (conversationId) {
      this.resolved.set(`agent:main:${conversationId}`, info);
    }

    // Fallback ring buffer for content-based correlation via onBeforeMessageWrite.
    const now = Date.now();
    this.pending = this.pending.filter((e) => now - e.ts < PENDING_TTL_MS);
    if (this.pending.length >= MAX_PENDING) {
      this.pending.shift();
    }
    this.pending.push({ info, content, ts: now });
  }

  /**
   * Called from the `before_message_write` hook for user (role="user") messages.
   * Fallback correlation: matches message text to a pending ring-buffer entry.
   */
  onBeforeMessageWrite(sessionKey: string, messageText: string): boolean {
    const now = Date.now();
    const idx = this.pending.findIndex(
      (e) => e.content === messageText && now - e.ts < PENDING_TTL_MS
    );
    if (idx !== -1) {
      this.resolved.set(sessionKey, this.pending[idx].info);
      this.pending.splice(idx, 1);
      return true;
    }
    return false;
  }

  /** Returns the most recently seen channel info for a session. */
  get(sessionKey: string): ChannelInfo | undefined {
    return this.resolved.get(sessionKey);
  }
}

export const channelContextStore = new ChannelContextStore();
