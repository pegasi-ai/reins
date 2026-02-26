/**
 * Input Sanitizer
 *
 * Defense-in-depth utilities for stripping prompt injection markers,
 * terminal escape codes, and control characters from data that flows
 * through display, logging, error messages, and instruction files.
 *
 * Pure utility module — no state, no external dependencies.
 */

// ---------------------------------------------------------------------------
// ANSI / control character stripping
// ---------------------------------------------------------------------------

/**
 * Remove ANSI escape sequences, null bytes, carriage returns, and other
 * control characters that could be used for terminal injection.
 * Preserves \n (0x0A) and \t (0x09) which are safe for display.
 */
export function stripControlChars(text: string): string {
  // Remove ANSI escape sequences (CSI, OSC, simple ESC+char)
  // eslint-disable-next-line no-control-regex
  const ANSI_RE = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)/g;
  let cleaned = text.replace(ANSI_RE, '');
  // Remove null bytes
  // eslint-disable-next-line no-control-regex
  cleaned = cleaned.replace(/\x00/g, '');
  // Remove carriage returns (terminal overwrite trick)
  cleaned = cleaned.replace(/\r/g, '');
  // Remove remaining C0 control chars except \n (0x0A) and \t (0x09)
  // eslint-disable-next-line no-control-regex
  cleaned = cleaned.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  return cleaned;
}

// ---------------------------------------------------------------------------
// Safe truncation
// ---------------------------------------------------------------------------

/**
 * Truncate text without splitting UTF-8 surrogate pairs.
 */
export function truncateForDisplay(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  let end = maxLen;
  // Avoid splitting a high surrogate
  if (
    end > 0 &&
    text.charCodeAt(end - 1) >= 0xd800 &&
    text.charCodeAt(end - 1) <= 0xdbff
  ) {
    end -= 1;
  }
  return text.slice(0, end) + '...';
}

// ---------------------------------------------------------------------------
// Prompt injection filtering
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS: RegExp[] = [
  /IGNORE\s+(ALL\s+)?PREVIOUS\s+INSTRUCTIONS/gi,
  /YOU\s+ARE\s+NOW\s+/gi,
  /NEW\s+INSTRUCTIONS?\s*:/gi,
  /SYSTEM\s*:\s*/gi,
  /\[SYSTEM\]/gi,
  /<<\s*SYS\s*>>/gi,
  /<\|im_start\|>system/gi,
  /ASSISTANT\s*:\s*/gi,
  /\[INST\]/gi,
  /HUMAN\s*:\s*/gi,
  /###\s*(System|User|Assistant)\s*(Message|Prompt)?\s*:?/gi,
];

/**
 * Replace known prompt-injection markers with [FILTERED].
 * This is defense-in-depth, not a comprehensive defense.
 */
export function sanitizeForPrompt(text: string): string {
  let cleaned = text;
  for (const pattern of INJECTION_PATTERNS) {
    cleaned = cleaned.replace(pattern, '[FILTERED]');
  }
  return cleaned;
}

// ---------------------------------------------------------------------------
// Markdown escaping
// ---------------------------------------------------------------------------

/**
 * Escape markdown characters that could alter instruction parsing.
 */
export function escapeMarkdown(text: string): string {
  return text.replace(/([*`#[\]\\~_>|!])/g, '\\$1');
}

// ---------------------------------------------------------------------------
// Composite: safe tool parameter serialization
// ---------------------------------------------------------------------------

const DEFAULT_MAX_DISPLAY_LEN = 2000;

/**
 * Serialize tool parameters safely for display/logging.
 * Strips control characters and truncates to a safe length.
 */
export function sanitizeToolParams(
  params: unknown,
  maxLen: number = DEFAULT_MAX_DISPLAY_LEN
): string {
  let serialized: string;
  try {
    serialized = JSON.stringify(params, null, 2);
  } catch {
    serialized = String(params);
  }
  serialized = stripControlChars(serialized);
  serialized = truncateForDisplay(serialized, maxLen);
  return serialized;
}
