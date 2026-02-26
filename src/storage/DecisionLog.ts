/**
 * ClawReins DecisionLog
 * Audit trail in JSON Lines format (~/.openclaw/clawreins/decisions.jsonl)
 */

import fs from 'fs-extra';
import path from 'path';
import { CLAWREINS_DATA_DIR, logger } from '../core/Logger';
import { stripControlChars } from '../core/InputSanitizer';

const DECISIONS_FILE = path.join(CLAWREINS_DATA_DIR, 'decisions.jsonl');

export interface DecisionRecord {
  timestamp: string;
  module: string;
  method: string;
  args: unknown[];
  decision: 'ALLOWED' | 'APPROVED' | 'REJECTED' | 'BLOCKED';
  userId?: string;
  decisionTime: number; // milliseconds
  reason?: string;
}

export class DecisionLog {
  /**
   * Append a decision record to the log (JSON Lines format)
   */
  static async append(record: DecisionRecord): Promise<void> {
    try {
      await fs.ensureDir(CLAWREINS_DATA_DIR);

      // Append as JSON Lines (one JSON object per line)
      const line = stripControlChars(JSON.stringify(record)) + '\n';
      await fs.appendFile(DECISIONS_FILE, line, 'utf8');

      logger.debug('Decision logged', { decision: record.decision, module: record.module });
    } catch (error) {
      logger.error('Failed to log decision', { error });
      // Don't throw - logging failures shouldn't break execution
    }
  }

  /**
   * Read all decisions from the log
   */
  static async readAll(): Promise<DecisionRecord[]> {
    try {
      if (!(await fs.pathExists(DECISIONS_FILE))) {
        return [];
      }

      const content = await fs.readFile(DECISIONS_FILE, 'utf8');
      const lines = content.trim().split('\n').filter(Boolean);

      return lines.map((line) => JSON.parse(line));
    } catch (error) {
      logger.error('Failed to read decision log', { error });
      return [];
    }
  }

  /**
   * Read the last N decisions
   */
  static async readLast(n: number): Promise<DecisionRecord[]> {
    const all = await this.readAll();
    return all.slice(-n);
  }

  /**
   * Get the decision log file path
   */
  static getPath(): string {
    return DECISIONS_FILE;
  }
}
