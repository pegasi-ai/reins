/**
 * IntentCache
 *
 * Subscribes to the llm_output hook and caches the agent's response text
 * keyed by runId. When before_tool_call fires with the same runId, the tool
 * interceptor can retrieve the agent's stated intent — what it *said* it was
 * about to do — and use it as a richer classification signal than tool params alone.
 *
 * A single LLM turn (one llm_output event) may produce multiple tool calls,
 * all sharing the same runId. We keep entries until they expire rather than
 * consuming on first read.
 */

const TTL_MS = 5 * 60 * 1000; // 5 minutes — well beyond any single agent turn

interface IntentEntry {
  texts: string[];
  ts: number;
}

export class IntentCache {
  private readonly entries = new Map<string, IntentEntry>();

  /**
   * Record the agent's response text for a given runId.
   * Called from the llm_output hook handler.
   */
  record(runId: string, texts: string[]): void {
    if (!runId || texts.length === 0) return;
    this.entries.set(runId, { texts, ts: Date.now() });
    this.evictExpired();
  }

  /**
   * Return the agent's response text for a given runId, or an empty array
   * if no entry exists or it has expired.
   * Called from before_tool_call to enrich classification context.
   */
  getTexts(runId: string): string[] {
    const entry = this.entries.get(runId);
    if (!entry) return [];
    if (Date.now() - entry.ts > TTL_MS) {
      this.entries.delete(runId);
      return [];
    }
    return entry.texts;
  }

  /**
   * Convenience: return all texts joined as a single string.
   */
  getText(runId: string): string {
    return this.getTexts(runId).join(' ');
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) {
      if (now - entry.ts > TTL_MS) this.entries.delete(key);
    }
  }
}

export const intentCache = new IntentCache();
