/**
 * Reins DecisionLog
 * Audit trail in JSON Lines format (~/.openclaw/reins/decisions.jsonl)
 */

import fs from 'fs-extra';
import { logger } from '../core/Logger';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';

export interface DecisionRecord {
  timestamp: string;
  module: string;
  method: string;
  args: unknown[];
  decision: 'ALLOWED' | 'APPROVED' | 'REJECTED' | 'BLOCKED';
  userId?: string;
  decisionTime: number; // milliseconds
  reason?: string;
  eventType?:
    | 'destructive_detected'
    | 'approval_requested'
    | 'approval_decision'
    | 'tool_executed'
    | 'tool_blocked';
  tool?: string;
  severity?: 'HIGH' | 'CATASTROPHIC';
  reasons?: string[];
  bulkCount?: number;
  target?: string;
  argsHash?: string;
  summary?: string;
  requireToken?: string;
  approved?: boolean;
  decisionInput?: 'yes' | 'allow' | 'no' | 'confirm';
  confirmation?: string;
}

export class DecisionLog {
  /**
   * Append a decision record to the log (JSON Lines format)
   */
  static async append(record: DecisionRecord): Promise<void> {
    try {
      const decisionsFile = getPreferredDataPath('decisions.jsonl');
      await fs.ensureDir(getReinsDataDir());

      // Append as JSON Lines (one JSON object per line)
      const line = JSON.stringify(record) + '\n';
      await fs.appendFile(decisionsFile, line, 'utf8');

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
      const decisionsFile = getDataPath('decisions.jsonl');
      if (!(await fs.pathExists(decisionsFile))) {
        return [];
      }

      const content = await fs.readFile(decisionsFile, 'utf8');
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
    return getPreferredDataPath('decisions.jsonl');
  }
}
