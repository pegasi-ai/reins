/**
 * ClawReins approval commands
 *
 * Registers !approve and !deny as plugin commands.
 * OpenClaw routes these BEFORE the LLM loop, so the agent never sees them.
 *
 * Usage:
 *   !approve CONFIRM-AB12CD   → approves the pending action with that token
 *   !deny CONFIRM-AB12CD      → denies the pending action with that token
 */

import { approvalQueue } from '../core/ApprovalQueue';
import { trustRateLimiter } from '../core/TrustRateLimiter';
import { logger } from '../core/Logger';

// ---------------------------------------------------------------------------
// Minimal local types matching OpenClaw's PluginCommandDefinition surface
// ---------------------------------------------------------------------------

interface CommandContext {
  args?: string;
  isAuthorizedSender: boolean;
  from?: string;
}

interface CommandResult {
  text?: string;
  isError?: boolean;
}

export interface CommandDefinition {
  name: string;
  description: string;
  acceptsArgs?: boolean;
  requireAuth?: boolean;
  handler: (ctx: CommandContext) => CommandResult | Promise<CommandResult>;
}

// ---------------------------------------------------------------------------
// Command factories
// ---------------------------------------------------------------------------

export function createApproveCommand(): CommandDefinition {
  return {
    name: 'approve',
    description: 'Approve a pending ClawReins action. Usage: !approve <TOKEN>',
    acceptsArgs: true,
    requireAuth: true,
    handler(ctx: CommandContext): CommandResult {
      if (!ctx.isAuthorizedSender) {
        return { text: 'Not authorized.', isError: true };
      }

      const token = ctx.args?.trim().toUpperCase();
      if (!token) {
        return {
          text: '⚠️ Usage: !approve <TOKEN>\nExample: !approve CONFIRM-AB12CD',
          isError: true,
        };
      }

      const resolved = approvalQueue.resolveByToken(token, 'approve');
      if (!resolved) {
        return {
          text: `⚠️ No pending approval found for ${token}. It may have expired (2 min TTL).`,
          isError: true,
        };
      }

      logger.info('[approval-cmd] Approved by token', { token, from: ctx.from });
      return { text: '✅ Approved. The action will proceed.' };
    },
  };
}

export function createDenyCommand(): CommandDefinition {
  return {
    name: 'deny',
    description: 'Deny a pending ClawReins action. Usage: !deny <TOKEN>',
    acceptsArgs: true,
    requireAuth: true,
    handler(ctx: CommandContext): CommandResult {
      if (!ctx.isAuthorizedSender) {
        return { text: 'Not authorized.', isError: true };
      }

      const token = ctx.args?.trim().toUpperCase();
      if (!token) {
        return {
          text: '⚠️ Usage: !deny <TOKEN>\nExample: !deny CONFIRM-AB12CD',
          isError: true,
        };
      }

      const resolved = approvalQueue.resolveByToken(token, 'deny');
      if (!resolved) {
        return {
          text: `⚠️ No pending approval found for ${token}. It may have expired (2 min TTL).`,
          isError: true,
        };
      }

      // Record the denial for cooldown escalation (same as TTY deny path).
      // We don't have sessionKey here, so we use the token as a stable key.
      trustRateLimiter.recordDenial(token);

      logger.info('[approval-cmd] Denied by token', { token, from: ctx.from });
      return { text: '🚫 Denied. The action has been blocked.' };
    },
  };
}
