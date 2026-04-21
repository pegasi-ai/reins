/**
 * Reins Plugin Entry Point
 * OpenClaw plugin integration.
 *
 * IMPORTANT: register() must be SYNCHRONOUS — the OpenClaw gateway
 * ignores async plugin registration (the returned promise is not awaited).
 *
 * Hooks:
 *  before_tool_call      → tool interception (policy evaluation)
 *  message_received      → capture channel context (from/channelId) for OOB notifications
 *  before_message_write  → correlate sessionKey to channel context
 *
 * Commands:
 *  !approve <TOKEN>  → approve pending action (processed before LLM, agent never sees it)
 *  !deny    <TOKEN>  → deny pending action
 */

import { Interceptor } from '../core/Interceptor';
import { PolicyStore } from '../storage/PolicyStore';
import { logger } from '../core/Logger';
import { createToolCallHook } from './tool-interceptor';
import { channelContextStore } from './ChannelContextStore';
import { initNotifier, sendApprovalNotification, type FallbackChannel } from './oob-notifier';
import { createApproveCommand, createDenyCommand } from './approval-commands';
import path from 'path';
import { readFileSync } from 'fs';

export interface ReinsConfig {
  enabled?: boolean;
  defaultAction?: 'ALLOW' | 'DENY' | 'ASK';
  fallbackChannel?: FallbackChannel;
}

export interface ReinsPluginManifest {
  id: string;
  displayName: string;
  version: string;
  configure: {
    command: string;
  };
}

function getPackageVersion(): string {
  try {
    const packageJsonPath = path.join(__dirname, '..', '..', 'package.json');
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8')) as { version?: string };
    return packageJson.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const ReinsManifest: ReinsPluginManifest = {
  id: 'reins',
  displayName: 'Reins',
  version: getPackageVersion(),
  configure: {
    command: 'reins configure',
  },
};

// ---------------------------------------------------------------------------
// Minimal OpenClaw plugin API surface used by Reins.
// All methods are optional — the gateway may not support all of them.
// ---------------------------------------------------------------------------

interface OobRuntimeChannel {
  channel?: {
    whatsapp?: {
      sendMessageWhatsApp?: (
        to: string,
        body: string,
        opts: { verbose?: boolean; cfg?: unknown; accountId?: string }
      ) => Promise<unknown>;
    };
    telegram?: {
      sendMessageTelegram?: (
        to: string,
        text: string,
        opts: { cfg?: unknown; accountId?: string }
      ) => Promise<unknown>;
    };
  };
}

interface OpenClawPluginApi {
  config?: unknown;
  runtime?: OobRuntimeChannel;
  on?(
    hookName: string,
    handler: (...args: unknown[]) => unknown,
    opts?: { priority?: number }
  ): void;
  registerCommand?(command: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    handler: (ctx: unknown) => unknown;
  }): void;
}

// ---------------------------------------------------------------------------
// Hook registration helpers
// ---------------------------------------------------------------------------

function tryOn(
  api: OpenClawPluginApi,
  hookName: string,
  handler: (...args: unknown[]) => unknown,
  label: string
): boolean {
  try {
    if (!api.on) {
      logger.debug(`[plugin] ${label}: api.on not available`);
      return false;
    }
    api.on(hookName, handler);
    logger.info(`[plugin] ${label}: registered`);
    return true;
  } catch (err) {
    logger.warn(`[plugin] ${label}: api.on('${hookName}') threw`, { error: err });
    return false;
  }
}

function tryRegisterCommand(
  api: OpenClawPluginApi,
  command: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    handler: (ctx: unknown) => unknown;
  },
  label: string
): boolean {
  try {
    if (!api.registerCommand) {
      logger.debug(`[plugin] ${label}: api.registerCommand not available`);
      return false;
    }
    api.registerCommand(command);
    logger.info(`[plugin] ${label}: registered command !${command.name}`);
    return true;
  } catch (err) {
    logger.warn(`[plugin] ${label}: api.registerCommand threw`, { error: err });
    return false;
  }
}

// ---------------------------------------------------------------------------
// Text extraction helper for before_message_write correlation
// ---------------------------------------------------------------------------

function extractMessageText(
  content: unknown
): string | undefined {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    const block = (content as Array<{ type?: string; text?: string }>).find(
      (b) => b.type === 'text'
    );
    return block?.text;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Plugin registration
// ---------------------------------------------------------------------------

export default {
  id: 'reins',
  name: 'Reins',
  manifest: ReinsManifest,

  register(api: OpenClawPluginApi): void {
    logger.info('Reins plugin loading...');

    try {
      const policy = PolicyStore.loadSync();
      logger.info('Security policy loaded', {
        defaultAction: policy.defaultAction,
        moduleCount: Object.keys(policy.modules).length,
      });

      const interceptor = new Interceptor(policy);

      // -------------------------------------------------------------------
      // OOB notifier: initialise with runtime send functions + gateway config
      // -------------------------------------------------------------------
      // OpenClaw passes the full openclaw.json as api.config; the plugin's own
      // config section is nested at plugins.entries.reins.config.
      const globalConfig = api.config as {
        plugins?: { entries?: { reins?: { config?: ReinsConfig }; clawreins?: { config?: ReinsConfig } } };
      } | undefined;
      const pluginConfig = globalConfig?.plugins?.entries?.reins?.config
        || globalConfig?.plugins?.entries?.clawreins?.config;
      logger.info('[plugin] pluginConfig at init', { pluginConfig: JSON.stringify(pluginConfig) });
      initNotifier(api.runtime, api.config, pluginConfig?.fallbackChannel);

      // Wire the notifier callback so Interceptor can trigger notifications.
      interceptor.onBlockCallback = (sessionKey, moduleName, methodName) => {
        return sendApprovalNotification(sessionKey, moduleName, methodName);
      };

      // -------------------------------------------------------------------
      // Hook: before_tool_call — policy evaluation
      // -------------------------------------------------------------------
      const toolHook = createToolCallHook(interceptor);
      tryOn(
        api,
        'before_tool_call',
        toolHook as (...args: unknown[]) => unknown,
        'before_tool_call'
      );

      // -------------------------------------------------------------------
      // Hook: message_received — capture channel context for notifications
      // Fires for every inbound message; populates the ring buffer.
      // -------------------------------------------------------------------
      tryOn(
        api,
        'message_received',
        (
          event: unknown,
          ctx: unknown
        ) => {
          // OpenClaw may put channelId/accountId on event or ctx depending on version.
          const e = event as { from?: string; content?: string; channelId?: string; accountId?: string; conversationId?: string };
          const c = (ctx ?? {}) as { channelId?: string; accountId?: string; conversationId?: string };
          const channelId = c.channelId ?? e.channelId;
          const accountId = c.accountId ?? e.accountId;
          const conversationId = c.conversationId ?? e.conversationId;
          if (!e.from || typeof e.content !== 'string' || !channelId) {
            logger.warn('[plugin] message_received: missing fields, skipping', {
              hasFrom: !!e.from,
              hasContent: typeof e.content === 'string',
              hasChannelId: !!channelId,
            });
            return;
          }
          channelContextStore.onMessageReceived(e.from, e.content, channelId, accountId, conversationId);
          logger.info('[plugin] message_received: stored channel context', { from: e.from, channelId, conversationId });
        },
        'message_received'
      );

      // -------------------------------------------------------------------
      // Hook: before_message_write — bind sessionKey to channel context
      // Fires synchronously before a message is written to the JSONL transcript.
      // We use it to correlate sessionKey ↔ channelInfo via message content.
      // -------------------------------------------------------------------
      tryOn(
        api,
        'before_message_write',
        (
          event: unknown,
          ctx: unknown
        ) => {
          // sessionKey may be on ctx or directly on event depending on OpenClaw version.
          const e = event as { message?: { role?: string; content?: unknown }; sessionKey?: string; role?: string; content?: unknown };
          const c = (ctx ?? {}) as { sessionKey?: string };
          const sessionKey = c.sessionKey ?? e.sessionKey;
          // Handle both {message: {role, content}} and flat {role, content} shapes.
          const role = e.message?.role ?? e.role;
          const content = e.message?.content ?? e.content;
          if (sessionKey && role === 'user') {
            const text = extractMessageText(content);
            if (text) {
              const matched = channelContextStore.onBeforeMessageWrite(sessionKey, text);
              if (matched) {
                logger.info('[plugin] before_message_write: correlated', { sessionKey });
              }
            }
          }
        },
        'before_message_write'
      );

      // -------------------------------------------------------------------
      // Commands: !approve / !deny — intercepted before the LLM
      // -------------------------------------------------------------------
      // Cast needed: our CommandDefinition handler is typed (ctx: CommandContext) while
      // the gateway interface uses (ctx: unknown). Safe — the gateway passes the full context.
      tryRegisterCommand(
        api,
        createApproveCommand() as Parameters<typeof tryRegisterCommand>[1],
        'approve-command'
      );
      tryRegisterCommand(
        api,
        createDenyCommand() as Parameters<typeof tryRegisterCommand>[1],
        'deny-command'
      );

      logger.info('Reins: registration complete');
    } catch (error) {
      logger.error('Failed to initialize Reins plugin', { error });
      throw error;
    }
  },
};
