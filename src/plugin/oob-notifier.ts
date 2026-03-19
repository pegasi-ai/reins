/**
 * OOB (Out-of-Band) Approval Notifier
 *
 * When ClawReins blocks a tool call in channel mode, this module sends an
 * approval notification directly to the human's channel — bypassing the agent
 * so the agent never sees the token and cannot self-approve.
 *
 * Supported channels: whatsapp, telegram (extensible).
 */

import { approvalQueue } from '../core/ApprovalQueue';
import { channelContextStore } from './ChannelContextStore';
import { logger } from '../core/Logger';

// ---------------------------------------------------------------------------
// Minimal runtime interface — only the send functions we call
// ---------------------------------------------------------------------------

type SendOpts = { verbose?: boolean; cfg?: unknown; accountId?: string };

interface OobRuntime {
  channel?: {
    whatsapp?: {
      sendMessageWhatsApp?: (to: string, body: string, opts: SendOpts) => Promise<unknown>;
    };
    telegram?: {
      sendMessageTelegram?: (to: string, text: string, opts: SendOpts) => Promise<unknown>;
    };
  };
}

// ---------------------------------------------------------------------------
// Module-level state set once at plugin registration
// ---------------------------------------------------------------------------

export interface FallbackChannel {
  channelId: 'whatsapp' | 'telegram';
  to: string;
  accountId?: string;
}

let _runtime: OobRuntime | undefined;
let _config: unknown;
let _fallbackChannel: FallbackChannel | undefined;

export function initNotifier(runtime: OobRuntime | undefined, config: unknown, fallbackChannel?: FallbackChannel): void {
  _runtime = runtime;
  _config = config;
  _fallbackChannel = fallbackChannel;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Fire-and-forget: look up the pending entry, build a notification message,
 * and dispatch it to the human's channel.
 */
export async function sendApprovalNotification(
  sessionKey: string,
  moduleName: string,
  methodName: string
): Promise<boolean> {
  const info = approvalQueue.getNotificationInfo(sessionKey, moduleName, methodName);
  if (!info) {
    logger.warn('[oob-notifier] No pending entry / token found', {
      sessionKey,
      action: `${moduleName}.${methodName}`,
    });
    return false;
  }

  const channelInfo = channelContextStore.get(sessionKey);
  const target = channelInfo ?? (_fallbackChannel ? {
    channelId: _fallbackChannel.channelId,
    from: _fallbackChannel.to,
    accountId: _fallbackChannel.accountId,
  } : undefined);

  if (!target) {
    logger.warn('[oob-notifier] No channel context and no fallback configured — notification not sent', {
      sessionKey,
    });
    return false;
  }

  if (!channelInfo) {
    logger.info('[oob-notifier] No channel context for session — using fallback channel', {
      sessionKey,
      fallbackChannelId: target.channelId,
    });
  }

  const actionLine = info.summary || `${moduleName}.${methodName}()`;
  const message = [
    '🛡️ ClawReins: approval needed',
    `Action: ${actionLine}`,
    `/approve ${info.token}  to allow`,
    `/deny ${info.token}  to block`,
  ].join('\n');

  return dispatch(target.channelId, target.from, target.accountId, message);
}

/**
 * Send a follow-up message to the agent's session so it retries the approved action.
 * Since selfChatMode=true, a message sent to the user's own number arrives as an
 * inbound user message that the agent sees and will act on.
 */
// ---------------------------------------------------------------------------
// Internal dispatcher
// ---------------------------------------------------------------------------

async function dispatch(
  channelId: string,
  to: string,
  accountId: string | undefined,
  message: string
): Promise<boolean> {
  if (!_runtime?.channel) {
    logger.warn('[oob-notifier] Runtime not initialized or no channel API');
    return false;
  }

  try {
    if (channelId === 'whatsapp') {
      const send = _runtime.channel.whatsapp?.sendMessageWhatsApp;
      if (!send) {
        logger.warn('[oob-notifier] sendMessageWhatsApp not available');
        return false;
      }
      await send(to, message, { verbose: false, cfg: _config, accountId });
      logger.info('[oob-notifier] WhatsApp notification sent', { to });
      return true;
    } else if (channelId === 'telegram') {
      const send = _runtime.channel.telegram?.sendMessageTelegram;
      if (!send) {
        logger.warn('[oob-notifier] sendMessageTelegram not available');
        return false;
      }
      await send(to, message, { cfg: _config, accountId });
      logger.info('[oob-notifier] Telegram notification sent', { to });
      return true;
    } else {
      logger.warn('[oob-notifier] No sender for channel — notification not sent', { channelId });
      return false;
    }
  } catch (err) {
    logger.error('[oob-notifier] Failed to send notification', { channelId, to, error: err });
    return false;
  }
}
