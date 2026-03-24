import { NormalizedAction } from './ActionNormalizer';

export type TraceEventKind =
  | 'user_message'
  | 'assistant_intent'
  | 'tool_call'
  | 'tool_result';

export interface TraceEvent {
  sessionKey: string;
  runId?: string;
  kind: TraceEventKind;
  timestamp: number;
  rawSummary: string;
  action?: NormalizedAction;
}

const MAX_EVENTS_PER_SESSION = 100;

export class TraceRecorder {
  private readonly events = new Map<string, TraceEvent[]>();
  private readonly dedupeKeys = new Set<string>();

  append(event: TraceEvent): void {
    const dedupeKey = `${event.sessionKey}:${event.kind}:${event.runId || ''}:${event.rawSummary}`;
    if (event.kind === 'assistant_intent' && this.dedupeKeys.has(dedupeKey)) {
      return;
    }

    this.dedupeKeys.add(dedupeKey);
    const existing = this.events.get(event.sessionKey) || [];
    existing.push(event);
    if (existing.length > MAX_EVENTS_PER_SESSION) {
      existing.splice(0, existing.length - MAX_EVENTS_PER_SESSION);
    }
    this.events.set(event.sessionKey, existing);
  }

  getRecent(sessionKey: string, limit: number = 10): TraceEvent[] {
    const existing = this.events.get(sessionKey) || [];
    return existing.slice(-limit);
  }
}

export const traceRecorder = new TraceRecorder();
