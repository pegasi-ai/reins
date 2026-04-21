/**
 * Reins public API exports.
 */

// Core Components
export { Interceptor } from './core/Interceptor';
export { Arbitrator } from './core/Arbitrator';
export { approvalQueue } from './core/ApprovalQueue';
export { logger, LOG_PATH, REINS_DATA_DIR, CLAWREINS_DATA_DIR } from './core/Logger';

// Storage
export { PolicyStore } from './storage/PolicyStore';
export type { PersistedPolicy } from './storage/PolicyStore';
export { DecisionLog } from './storage/DecisionLog';
export type { DecisionRecord } from './storage/DecisionLog';
export { StatsTracker } from './storage/StatsTracker';
export type { Stats } from './storage/StatsTracker';
export { BrowserSessionStore } from './storage/BrowserSessionStore';
export type { SessionInjectionResult } from './storage/BrowserSessionStore';

// Plugin
export { default as ReinsPlugin } from './plugin/index';
export type { ReinsConfig } from './plugin/index';
export { ReinsManifest } from './plugin/index';
export type { ReinsPluginManifest } from './plugin/index';
export {
  createToolCallHook,
  getToolMapping,
  getProtectedModules,
} from './plugin/tool-interceptor';

export {
  isOpenClawInstalled,
  loadOpenClawConfig,
  saveOpenClawConfig,
  registerPlugin,
  unregisterPlugin,
  isPluginRegistered,
} from './plugin/config-manager';

// Configuration
export { DEFAULT_POLICY } from './config';

// Detection + Risk Scoring
export { detectBrowserChallenge } from './core/BrowserChallengeDetector';
export type { BrowserChallengeSignal } from './core/BrowserChallengeDetector';
export {
  classifyDestructiveAction,
  getBulkThreshold,
  isDestructiveGatingEnabled,
  hashArgs,
} from './core/DestructiveClassifier';
export type { DestructiveClassification, DestructiveSeverity } from './core/DestructiveClassifier';
export { scoreIrreversibility } from './core/IrreversibilityScorer';
export type { IrreversibilityAssessment } from './core/IrreversibilityScorer';
export { MemoryRiskForecaster } from './core/MemoryRiskForecaster';
export type { MemoryRiskAssessment, SimulatedPath } from './core/MemoryRiskForecaster';
export { trustRateLimiter, TrustRateLimiter } from './core/TrustRateLimiter';
export type { EscalationLevel, TrustRateLimiterState } from './core/TrustRateLimiter';
export { syncToolShieldDefaults } from './toolshield/sync';
export type { ToolShieldSyncOptions, ToolShieldSyncResult } from './toolshield/sync';

// Types
export * from './types';
