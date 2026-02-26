/**
 * Irreversibility scoring for tool actions.
 *
 * Higher score = harder to undo + higher blast radius.
 */

import { stripControlChars } from './InputSanitizer';

export type IrreversibilityLevel = 'low' | 'medium' | 'high';

export interface IrreversibilityAssessment {
  score: number;
  level: IrreversibilityLevel;
  reasons: string[];
  summary: string;
}

const BASELINE_SCORES: Record<string, number> = {
  'FileSystem.read': 5,
  'FileSystem.write': 35,
  'FileSystem.edit': 35,
  'FileSystem.delete': 40,
  'Shell.bash': 70,
  'Shell.exec': 70,
  'Network.fetch': 25,
  'Network.request': 50,
  'Network.webhook': 70,
  'Network.download': 20,
  'Gateway.sendMessage': 75,
  'Browser.click': 30,
  'Browser.type': 30,
  'Browser.evaluate': 35,
  'Browser.navigate': 10,
  'Browser.screenshot': 5,
};

const HIGH_IMPACT_PATTERNS: Array<[RegExp, number, string]> = [
  [/payment|charge|wire transfer|bank transfer|checkout|send money|payout|invoice/i, 35, 'Payment/transfer action detected'],
  [/publish|post publicly|tweet|linkedin|send email|mailchimp|blast|newsletter/i, 30, 'Public/email broadcast action detected'],
  [/delete account|close account|terminate|drop table|truncate table/i, 30, 'Account/data destruction action detected'],
  [/rm -rf|del \/[sq]|shred|wipe|format/i, 25, 'Destructive command pattern detected'],
  [/submit|confirm|finalize|place order/i, 20, 'Finalization verb detected'],
  [/production|prod|live environment/i, 15, 'Production environment marker detected'],
];

const RECOVERY_PATTERNS: Array<[RegExp, number, string]> = [
  [/draft|preview|dry run|dry-run|test mode|sandbox/i, -20, 'Recoverable/test mode marker detected'],
  [/undo|rollback|revert/i, -10, 'Rollback/undo marker detected'],
];

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function summarizeParams(params: Record<string, unknown>): string {
  try {
    const raw = stripControlChars(JSON.stringify(params));
    return raw.length > 220 ? `${raw.slice(0, 217)}...` : raw;
  } catch {
    return stripControlChars(String(params));
  }
}

export function scoreIrreversibility(
  moduleName: string,
  methodName: string,
  params: Record<string, unknown>
): IrreversibilityAssessment {
  const key = `${moduleName}.${methodName}`;
  const serialized = (() => {
    try {
      return JSON.stringify(params);
    } catch {
      return String(params);
    }
  })();

  let score = BASELINE_SCORES[key] ?? 30;
  const reasons: string[] = [];

  for (const [pattern, delta, reason] of HIGH_IMPACT_PATTERNS) {
    if (pattern.test(serialized)) {
      score += delta;
      reasons.push(reason);
    }
  }

  for (const [pattern, delta, reason] of RECOVERY_PATTERNS) {
    if (pattern.test(serialized)) {
      score += delta;
      reasons.push(reason);
    }
  }

  score = clamp(score, 0, 100);

  const level: IrreversibilityLevel = score >= 75 ? 'high' : score >= 45 ? 'medium' : 'low';

  const summary = `${moduleName}.${methodName} | irreversibility ${score}/100 | args=${summarizeParams(params)}`;

  return { score, level, reasons, summary };
}
