export interface TaskState {
  sessionKey: string;
  userGoal: string;
  allowedEffects: Array<'read' | 'write' | 'delete' | 'send' | 'buy' | 'revoke'>;
  forbiddenEffects: Array<'delete' | 'send' | 'buy' | 'revoke'>;
  protectedTargets: string[];
  activeSubgoals: string[];
  lastUserMessage?: string;
  updatedAt: number;
}

function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}

function deriveAllowedEffects(text: string): TaskState['allowedEffects'] {
  const lower = text.toLowerCase();
  const effects: TaskState['allowedEffects'] = [];

  if (/\b(read|review|summarize|inspect|find|list|search|check|look)\b/.test(lower)) effects.push('read');
  if (/\b(write|edit|update|draft)\b/.test(lower)) effects.push('write');
  if (/\b(delete|remove|trash|purge|wipe)\b/.test(lower)) effects.push('delete');
  if (/\b(send|reply|forward|message|email)\b/.test(lower)) effects.push('send');
  if (/\b(buy|purchase|checkout|order)\b/.test(lower)) effects.push('buy');
  if (/\b(revoke|disable sso|remove admin)\b/.test(lower)) effects.push('revoke');

  if (effects.length === 0) effects.push('read');
  return unique(effects);
}

function deriveForbiddenEffects(text: string): TaskState['forbiddenEffects'] {
  const lower = text.toLowerCase();
  const effects: TaskState['forbiddenEffects'] = [];

  if (/\b(do not|don't|dont|only|just)\b/.test(lower)) {
    if (!/\bdelete\b/.test(lower)) effects.push('delete');
    if (!/\bsend\b/.test(lower)) effects.push('send');
    if (!/\bbuy|purchase\b/.test(lower)) effects.push('buy');
    if (!/\brevoke\b/.test(lower)) effects.push('revoke');
  }

  return unique(effects);
}

function deriveProtectedTargets(text: string): string[] {
  const out: string[] = [];
  const mailbox = /\bin:(inbox|spam|trash|sent|drafts)\b/i.exec(text);
  if (mailbox) out.push(mailbox[1].toLowerCase());
  const pathMatch = /((?:\/|~\/)[\w./-]+)/.exec(text);
  if (pathMatch) out.push(pathMatch[1]);
  return out;
}

export class TaskStateStore {
  private readonly states = new Map<string, TaskState>();

  ingestUserMessage(sessionKey: string, text: string): TaskState {
    const next: TaskState = {
      sessionKey,
      userGoal: text,
      allowedEffects: deriveAllowedEffects(text),
      forbiddenEffects: deriveForbiddenEffects(text),
      protectedTargets: deriveProtectedTargets(text),
      activeSubgoals: [],
      lastUserMessage: text,
      updatedAt: Date.now(),
    };
    this.states.set(sessionKey, next);
    return next;
  }

  get(sessionKey: string): TaskState | undefined {
    return this.states.get(sessionKey);
  }
}

export const taskStateStore = new TaskStateStore();
