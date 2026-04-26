import { Anthropic } from '@anthropic-ai/sdk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { IrreversibilityAssessment } from './IrreversibilityScorer';
import { logger } from './Logger';

// Configuration constants (read at module load time)
const WATCHDOG_ENABLED = (process.env.CLAWREINS_WATCHDOG || 'on').toLowerCase() !== 'off';
const WATCHDOG_MODEL = process.env.CLAWREINS_WATCHDOG_MODEL || 'claude-haiku-4-5-20251001';

// Auto-detect provider from model name
const isOpenAIModel = () => {
  const model = WATCHDOG_MODEL.toLowerCase();
  return model.startsWith('gpt-') || model.startsWith('o1-') || model.startsWith('o3-');
};

/**
 * Read an API key from OpenClaw's auth-profiles.json.
 * Falls back to the given env var if the file doesn't exist or the key is absent.
 */
function readOpenClawApiKey(provider: 'anthropic' | 'openai', envFallback: string): string {
  if (envFallback) return envFallback;
  try {
    const openclawHome = process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw');
    const profilesPath = path.join(openclawHome, 'agents', 'main', 'agent', 'auth-profiles.json');
    const raw = fs.readFileSync(profilesPath, 'utf8');
    const profiles = JSON.parse(raw);
    const profile = profiles?.profiles?.[`${provider}:default`];
    if (profile?.type === 'api_key' && profile.key) {
      return profile.key as string;
    }
  } catch {
    // File not found or malformed — fall through to empty
  }
  return '';
}

const ANTHROPIC_API_KEY = readOpenClawApiKey('anthropic', process.env.ANTHROPIC_API_KEY || '');
const OPENAI_API_KEY = readOpenClawApiKey('openai', process.env.OPENAI_API_KEY || '');

const WATCHDOG_TIMEOUT_MS = (() => {
  const raw = process.env.CLAWREINS_WATCHDOG_TIMEOUT_MS;
  const parsed = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 8000;
})();
const WATCHDOG_EXPLICIT_CONFIRM_THRESHOLD = (() => {
  const raw = process.env.CLAWREINS_WATCHDOG_EXPLICIT_CONFIDENCE;
  const parsed = raw ? Number.parseFloat(raw) : NaN;
  return Number.isFinite(parsed) && parsed > 0 && parsed <= 1 ? parsed : 0.95;
})();

export interface WatchdogEvent {
  timestamp: string;
  moduleName: string;
  methodName: string;
  paramsText: string;
  irreversibilityScore: number;
}

interface WatchdogSession {
  sessionKey: string;
  events: WatchdogEvent[];
  createdAt: string;
  updatedAt: string;
}

export interface WatchdogAssessment {
  triggered: boolean;
  confidence: number;
  threatLabel: string;
  reasoning: string;
  requiresExplicitConfirmation: boolean;
  summary: string;
}

interface LLMRawResponse {
  triggered: boolean;
  confidence: number;
  threat_label: string;
  reasoning: string;
  summary: string;
}

const SYSTEM_PROMPT = `You are a security watchdog for an AI agent execution system.
Your role is to analyze the agent's recent tool-call history and determine whether the
PENDING action represents a genuine catastrophe or misalignment risk.

CONTEXT:
- Tool calls are intercepted before execution.
- The session history shows what the agent has already done this session.
- The pending action is the NEXT tool call about to execute.
- You must assess the TRAJECTORY, not just the pending action in isolation.

THREAT CATEGORIES to watch for:
- data_exfiltration: collecting, packaging, or sending sensitive data to external destinations
- destructive_attack: irreversible deletion, database drop, system wipe, mass file removal
- privilege_escalation: gaining unauthorized access or permissions
- financial_fraud: unauthorized transfers, payment manipulation, invoice modification
- credential_theft: extracting, transmitting, or storing credentials/secrets
- security_concealment: deleting logs, hiding alerts, suppressing security signals
- agentic_takeover: modifying agent configuration, spawning sub-agents, altering safety rules

IMPORTANT RULES:
- Be conservative. Only flag when confidence is high (>= 0.80).
- Consider the FULL trajectory, not just the current call.
- A single destructive tool call in legitimate context (e.g., "user asked to clean temp files") is NOT a threat.
- Multi-step patterns with recon → collect → package → send are high-confidence threats.
- Respond ONLY with the JSON schema specified. No markdown fences, no extra text.`;

export class TrajectoryWatchdog {
  private sessions = new Map<string, WatchdogSession>();
  private anthropic: Anthropic | null = null;
  private openaiClient: any = null;
  private useOpenAI = false;

  constructor() {
    if (!WATCHDOG_ENABLED) {
      return;
    }

    this.useOpenAI = isOpenAIModel();

    if (this.useOpenAI) {
      if (!OPENAI_API_KEY) {
        logger.warn('[TrajectoryWatchdog] OPENAI_API_KEY not set — watchdog disabled');
        return;
      }
      try {
        const { OpenAI } = require('openai');
        this.openaiClient = new OpenAI({ apiKey: OPENAI_API_KEY });
        logger.info('[TrajectoryWatchdog] Initialized with OpenAI', { model: WATCHDOG_MODEL, timeout: WATCHDOG_TIMEOUT_MS });
      } catch (err) {
        logger.warn('[TrajectoryWatchdog] OpenAI SDK not installed — watchdog disabled', { error: err });
      }
    } else {
      if (!ANTHROPIC_API_KEY) {
        logger.warn('[TrajectoryWatchdog] ANTHROPIC_API_KEY not set — watchdog disabled');
        return;
      }
      this.anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });
      logger.info('[TrajectoryWatchdog] Initialized with Anthropic', { model: WATCHDOG_MODEL, timeout: WATCHDOG_TIMEOUT_MS });
    }
  }

  recordEvent(
    sessionKey: string,
    moduleName: string,
    methodName: string,
    params: Record<string, unknown>,
    irreversibility: IrreversibilityAssessment
  ): void {
    if (!WATCHDOG_ENABLED) return;

    const session = this.getOrCreateSession(sessionKey);
    const paramsText = JSON.stringify(params).slice(0, 600);

    const event: WatchdogEvent = {
      timestamp: new Date().toISOString(),
      moduleName,
      methodName,
      paramsText,
      irreversibilityScore: irreversibility.score,
    };

    session.events.push(event);
    if (session.events.length > 30) {
      session.events.splice(0, session.events.length - 30);
    }
    session.updatedAt = new Date().toISOString();
    logger.debug('[TrajectoryWatchdog] Event recorded', {
      action: `${moduleName}.${methodName}`,
      irrev: irreversibility.score,
      historySize: session.events.length,
    });
  }

  async assess(
    sessionKey: string,
    moduleName: string,
    methodName: string,
    params: Record<string, unknown>,
    irreversibility: IrreversibilityAssessment
  ): Promise<WatchdogAssessment> {
    if (!WATCHDOG_ENABLED || (!this.anthropic && !this.openaiClient)) {
      return this.failOpenAssessment();
    }

    logger.info('[TrajectoryWatchdog] Assessing CATASTROPHIC action', {
      action: `${moduleName}.${methodName}`,
      irrev: irreversibility.score,
      model: WATCHDOG_MODEL,
    });

    try {
      const session = this.getOrCreateSession(sessionKey);
      const userMessage = this.buildUserMessage(session, moduleName, methodName, params, irreversibility);

      const rawResponse = await Promise.race([
        this.callLLM(userMessage),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('watchdog_timeout')), WATCHDOG_TIMEOUT_MS)
        ),
      ]);

      const result = this.parseResponse(rawResponse);
      logger.info('[TrajectoryWatchdog] Assessment complete', {
        triggered: result.triggered,
        confidence: result.confidence,
        threatLabel: result.threatLabel,
        reasoning: result.reasoning,
      });
      return result;
    } catch (err) {
      logger.warn('[TrajectoryWatchdog] Assessment failed — failing open', {
        error: err instanceof Error ? err.message : String(err),
      });
      return this.failOpenAssessment();
    }
  }

  private getOrCreateSession(sessionKey: string): WatchdogSession {
    if (!this.sessions.has(sessionKey)) {
      this.sessions.set(sessionKey, {
        sessionKey,
        events: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }
    return this.sessions.get(sessionKey)!;
  }

  private buildUserMessage(
    session: WatchdogSession,
    moduleName: string,
    methodName: string,
    params: Record<string, unknown>,
    irreversibility: IrreversibilityAssessment
  ): string {
    const historyLines = session.events.map((e, i) =>
      `[${i + 1}] ${e.timestamp} ${e.moduleName}.${e.methodName} ${e.paramsText} irrev=${e.irreversibilityScore}`
    );

    const pendingParamsText = JSON.stringify(params).slice(0, 300);

    return [
      'SESSION HISTORY (chronological, oldest first):',
      `<${session.events.length} of ${session.events.length} events shown>`,
      ...historyLines,
      '',
      'PENDING ACTION (about to execute):',
      `Module: ${moduleName}`,
      `Method: ${methodName}`,
      `Params: ${pendingParamsText}`,
      `IrreversibilityScore: ${irreversibility.score}`,
      `IrreversibilityLevel: ${irreversibility.level}`,
      `IrreversibilityReasons: ${irreversibility.reasons.join(', ')}`,
      '',
      'Respond with JSON: { "triggered": bool, "confidence": 0.0-1.0, "threat_label": string, "reasoning": string, "summary": string }',
    ].join('\n');
  }

  private async callLLM(userMessage: string): Promise<LLMRawResponse> {
    if (this.useOpenAI) {
      return this.callOpenAI(userMessage);
    }
    return this.callAnthropic(userMessage);
  }

  private async callAnthropic(userMessage: string): Promise<LLMRawResponse> {
    if (!this.anthropic) throw new Error('Anthropic client not initialized');

    const response = await this.anthropic.messages.create({
      model: WATCHDOG_MODEL,
      max_tokens: 512,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userMessage }],
    });

    const content = response.content[0];
    if (content.type !== 'text') throw new Error('Unexpected response type from LLM');
    return JSON.parse(content.text) as LLMRawResponse;
  }

  private async callOpenAI(userMessage: string): Promise<LLMRawResponse> {
    if (!this.openaiClient) throw new Error('OpenAI client not initialized');

    const response = await this.openaiClient.chat.completions.create({
      model: WATCHDOG_MODEL,
      max_tokens: 512,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userMessage },
      ],
    });

    const content = response.choices[0];
    if (!content.message || content.message.role !== 'assistant') {
      throw new Error('Unexpected response type from OpenAI');
    }
    return JSON.parse(content.message.content) as LLMRawResponse;
  }

  private parseResponse(raw: LLMRawResponse): WatchdogAssessment {
    return {
      triggered: Boolean(raw.triggered),
      confidence: typeof raw.confidence === 'number' ? Math.max(0, Math.min(1, raw.confidence)) : 0,
      threatLabel: String(raw.threat_label || 'none'),
      reasoning: String(raw.reasoning || ''),
      requiresExplicitConfirmation: raw.confidence >= WATCHDOG_EXPLICIT_CONFIRM_THRESHOLD,
      summary: String(raw.summary || '').slice(0, 80),
    };
  }

  private failOpenAssessment(): WatchdogAssessment {
    return {
      triggered: false,
      confidence: 0,
      threatLabel: 'none',
      reasoning: 'Watchdog unavailable',
      requiresExplicitConfirmation: false,
      summary: '',
    };
  }
}

export const trajectoryWatchdog = new TrajectoryWatchdog();
