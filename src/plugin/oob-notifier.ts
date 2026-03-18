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

let _runtime: OobRuntime | undefined;
let _config: unknown;

export function initNotifier(runtime: OobRuntime, config: unknown): void {
  _runtime = runtime;
  _config = config;
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
): Promise<void> {
  const info = approvalQueue.getNotificationInfo(sessionKey, moduleName, methodName);
  if (!info) {
    logger.warn('[oob-notifier] No pending entry / token found', {
      sessionKey,
      action: `${moduleName}.${methodName}`,
    });
    return;
  }

  const channelInfo = channelContextStore.get(sessionKey);
  if (!channelInfo) {
    logger.warn('[oob-notifier] No channel context for session — notification not sent', {
      sessionKey,
    });
    return;
  }

  const actionLine = info.summary || `${moduleName}.${methodName}()`;
  const message = [
    '🛡️ ClawReins: approval needed',
    `Action: ${actionLine}`,
    `Reply  !approve ${info.token}  to allow`,
    `       !deny ${info.token}  to block`,
  ].join('\n');

  await dispatch(channelInfo.channelId, channelInfo.from, channelInfo.accountId, message);
}

// ---------------------------------------------------------------------------
// Internal dispatcher
// ---------------------------------------------------------------------------

async function dispatch(
  channelId: string,
  to: string,
  accountId: string | undefined,
  message: string
): Promise<void> {
  if (!_runtime?.channel) {
    logger.warn('[oob-notifier] Runtime not initialized or no channel API');
    return;
  }

  try {
    if (channelId === 'whatsapp') {
      const send = _runtime.channel.whatsapp?.sendMessageWhatsApp;
      if (!send) {
        logger.warn('[oob-notifier] sendMessageWhatsApp not available');
        return;
      }
      await send(to, message, { verbose: false, cfg: _config, accountId });
      logger.info('[oob-notifier] WhatsApp notification sent', { to });
    } else if (channelId === 'telegram') {
      const send = _runtime.channel.telegram?.sendMessageTelegram;
      if (!send) {
        logger.warn('[oob-notifier] sendMessageTelegram not available');
        return;
      }
      await send(to, message, { cfg: _config, accountId });
      logger.info('[oob-notifier] Telegram notification sent', { to });
    } else {
      logger.warn('[oob-notifier] No sender for channel — notification not sent', { channelId });
    }
  } catch (err) {
    logger.error('[oob-notifier] Failed to send notification', { channelId, to, error: err });
  }
}
