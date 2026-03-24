export type ActionVerb =
  | 'read'
  | 'write'
  | 'delete'
  | 'move'
  | 'send'
  | 'execute'
  | 'navigate'
  | 'grant'
  | 'revoke'
  | 'purchase'
  | 'modify_account'
  | 'unknown';

export type ActionObject =
  | 'file'
  | 'directory'
  | 'email'
  | 'message'
  | 'user_account'
  | 'admin_role'
  | 'payment_method'
  | 'subscription'
  | 'browser_page'
  | 'network_resource'
  | 'system'
  | 'unknown';

export type ActionScope = 'one' | 'many' | 'all' | 'unknown';

export interface NormalizedAction {
  verb: ActionVerb;
  object: ActionObject;
  scope: ActionScope;
  target?: string;
  quantity?: number;
  destructive: boolean;
  irreversible: boolean;
  confidence: number;
  evidence: string[];
}

function flattenText(value: unknown): string {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(flattenText).join(' ');
  if (typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).map(flattenText).join(' ');
  }
  return '';
}

function inferScope(quantity?: number, text?: string): ActionScope {
  if (quantity !== undefined) {
    if (quantity <= 1) return 'one';
    if (quantity >= 1000) return 'all';
    return 'many';
  }

  const lower = (text || '').toLowerCase();
  if (/\b(all|entire|everything|whole)\b/.test(lower)) return 'all';
  if (/\b(many|multiple|bulk|batch|several)\b/.test(lower)) return 'many';
  if (/\b(one|single|this)\b/.test(lower)) return 'one';
  return 'unknown';
}

function inferDestructive(verb: ActionVerb): boolean {
  return verb === 'delete' || verb === 'revoke' || verb === 'purchase' || verb === 'modify_account';
}

function inferIrreversible(verb: ActionVerb, text: string): boolean {
  return inferDestructive(verb) || /\b(permanent|irreversible|rm -rf|wipe|purge|empty trash)\b/.test(text);
}

function pickVerb(text: string): ActionVerb {
  if (/\b(read|review|summarize|inspect|find|list|search|check|look)\b/.test(text)) return 'read';
  if (/\b(write|edit|update file|overwrite|save)\b/.test(text)) return 'write';
  if (/\b(delete|remove|trash|purge|wipe|drop|empty)\b/.test(text)) return 'delete';
  if (/\b(move|rename|relocate)\b/.test(text)) return 'move';
  if (/\b(send|message|email|reply|forward|post)\b/.test(text)) return 'send';
  if (/\b(run|exec|execute|bash|command|script)\b/.test(text)) return 'execute';
  if (/\b(go to|navigate|open|visit|click)\b/.test(text)) return 'navigate';
  if (/\b(grant|add admin)\b/.test(text)) return 'grant';
  if (/\b(revoke|remove admin|disable sso)\b/.test(text)) return 'revoke';
  if (/\b(buy|purchase|checkout|order)\b/.test(text)) return 'purchase';
  if (/\b(payment|card|bank|billing|subscription)\b/.test(text)) return 'modify_account';
  return 'unknown';
}

function pickObject(text: string): ActionObject {
  if (/\b(email|gmail|mail|inbox|spam|trash|draft)\b/.test(text)) return 'email';
  if (/\b(message|dm|chat|slack|telegram|whatsapp)\b/.test(text)) return 'message';
  if (/\b(file|document|path|txt|json|yaml|md)\b/.test(text)) return 'file';
  if (/\b(folder|directory|repo|workspace)\b/.test(text)) return 'directory';
  if (/\buser|account\b/.test(text)) return 'user_account';
  if (/\badmin|role|permission|sso\b/.test(text)) return 'admin_role';
  if (/\bpayment|card|bank|billing\b/.test(text)) return 'payment_method';
  if (/\bsubscription|plan\b/.test(text)) return 'subscription';
  if (/\burl|website|page|browser|tab\b/.test(text)) return 'browser_page';
  if (/\bapi|webhook|fetch|request|http\b/.test(text)) return 'network_resource';
  if (/\bsystem|disk|root|filesystem\b/.test(text)) return 'system';
  return 'unknown';
}

function pickTarget(text: string): string | undefined {
  const urlMatch = /(https?:\/\/[^\s"'<>]+)/i.exec(text);
  if (urlMatch) return urlMatch[1];

  const pathMatch = /((?:\/|~\/)[\w./-]+)/.exec(text);
  if (pathMatch) return pathMatch[1];

  const mailboxMatch = /\bin:(inbox|spam|trash|sent|drafts)\b/i.exec(text);
  if (mailboxMatch) return mailboxMatch[1].toLowerCase();

  return undefined;
}

function pickQuantity(args: Record<string, unknown>): number | undefined {
  for (const key of ['count', 'total', 'quantity']) {
    const value = args[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }

  for (const value of Object.values(args)) {
    if (Array.isArray(value)) return value.length;
  }

  return undefined;
}

export function normalizeTextAction(text: string): NormalizedAction {
  const lower = text.toLowerCase();
  const verb = pickVerb(lower);
  const object = pickObject(lower);
  const quantityMatch = /\b(\d{1,6})\b/.exec(lower);
  const quantity = quantityMatch ? Number(quantityMatch[1]) : undefined;

  return {
    verb,
    object,
    scope: inferScope(quantity, lower),
    target: pickTarget(lower),
    quantity,
    destructive: inferDestructive(verb),
    irreversible: inferIrreversible(verb, lower),
    confidence: verb === 'unknown' && object === 'unknown' ? 0.3 : 0.7,
    evidence: [`text:${text.slice(0, 120)}`],
  };
}

export function normalizeToolCall(
  toolName: string,
  params: Record<string, unknown>,
  meta?: { moduleName?: string; methodName?: string }
): NormalizedAction {
  const moduleName = (meta?.moduleName || '').toLowerCase();
  const methodName = (meta?.methodName || '').toLowerCase();
  const text = `${toolName} ${moduleName} ${methodName} ${flattenText(params)}`.toLowerCase();
  let verb = pickVerb(text);
  let object = pickObject(text);

  if (moduleName === 'filesystem') {
    object = object === 'unknown' ? 'file' : object;
    if (methodName === 'read') verb = 'read';
    if (methodName === 'write') verb = 'write';
    if (methodName === 'delete' || methodName === 'remove') verb = 'delete';
  } else if (moduleName === 'gmail') {
    object = 'email';
    if (methodName.includes('delete')) verb = 'delete';
    else if (methodName.includes('read') || methodName.includes('list') || methodName.includes('search')) verb = 'read';
  } else if (moduleName === 'shell') {
    verb = 'execute';
    object = 'system';
  } else if (moduleName === 'browser') {
    object = 'browser_page';
    if (methodName === 'navigate') verb = 'navigate';
    else if (methodName === 'click' || methodName === 'type' || methodName === 'evaluate') verb = 'navigate';
  } else if (moduleName === 'gateway' && methodName === 'sendmessage') {
    verb = 'send';
    object = 'message';
  } else if (moduleName === 'network') {
    verb = 'read';
    object = 'network_resource';
  }

  const quantity = pickQuantity(params);

  return {
    verb,
    object,
    scope: inferScope(quantity, text),
    target: pickTarget(text),
    quantity,
    destructive: inferDestructive(verb) || /\brm\s+-rf\b/.test(text),
    irreversible: inferIrreversible(verb, text),
    confidence: 0.85,
    evidence: [`tool:${toolName}`],
  };
}
