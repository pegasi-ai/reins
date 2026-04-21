/**
 * Reins PolicyStore
 * Manages persistence of security policies in ~/.openclaw/reins/policy.json
 */

import fs from 'fs-extra';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { SecurityPolicy } from '../types';
import { DEFAULT_POLICY } from '../config';
import { logger } from '../core/Logger';
import { getDataPath, getPreferredDataPath, getReinsDataDir } from '../core/data-dir';

export interface PersistedPolicy extends SecurityPolicy {
  version: string;
  createdAt: string;
  updatedAt: string;
}

export class PolicyStore {
  /**
   * Load the policy from disk, or create default if doesn't exist
   */
  static async load(): Promise<PersistedPolicy> {
    try {
      const policyFile = getDataPath('policy.json');
      await fs.ensureDir(getReinsDataDir());

      if (await fs.pathExists(policyFile)) {
        const data = await fs.readJson(policyFile);
        logger.info('Policy loaded from disk', { path: policyFile });
        return data;
      } else {
        // Create default policy
        logger.info('No existing policy found, creating default');
        const defaultPolicy: PersistedPolicy = {
          ...DEFAULT_POLICY,
          version: '1.0.0',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        await this.save(defaultPolicy);
        return defaultPolicy;
      }
    } catch (error) {
      logger.error('Failed to load policy', { error });
      throw new Error(`Failed to load policy: ${error}`);
    }
  }

  /**
   * Save the policy to disk
   */
  static async save(policy: PersistedPolicy): Promise<void> {
    try {
      const policyFile = getPreferredDataPath('policy.json');
      await fs.ensureDir(getReinsDataDir());
      policy.updatedAt = new Date().toISOString();
      await fs.writeJson(policyFile, policy, { spaces: 2 });
      logger.info('Policy saved to disk', { path: policyFile });
    } catch (error) {
      logger.error('Failed to save policy', { error });
      throw new Error(`Failed to save policy: ${error}`);
    }
  }

  /**
   * Reset policy to defaults
   */
  static async reset(): Promise<void> {
    const defaultPolicy: PersistedPolicy = {
      ...DEFAULT_POLICY,
      version: '1.0.0',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await this.save(defaultPolicy);
    logger.info('Policy reset to defaults');
  }

  /**
   * Load the policy synchronously (for plugin register which must be sync)
   */
  static loadSync(): PersistedPolicy {
    try {
      const policyFile = getDataPath('policy.json');
      const preferredPolicyFile = getPreferredDataPath('policy.json');

      const reinsDataDir = getReinsDataDir();
      if (!existsSync(reinsDataDir)) {
        mkdirSync(reinsDataDir, { recursive: true });
      }

      if (existsSync(policyFile)) {
        const data = JSON.parse(readFileSync(policyFile, 'utf-8'));
        logger.info('Policy loaded from disk (sync)', { path: policyFile });
        return data;
      } else {
        const defaultPolicy: PersistedPolicy = {
          ...DEFAULT_POLICY,
          version: '1.0.0',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        writeFileSync(preferredPolicyFile, JSON.stringify(defaultPolicy, null, 2), 'utf-8');
        logger.info('Created default policy (sync)', { path: preferredPolicyFile });
        return defaultPolicy;
      }
    } catch (error) {
      logger.error('Failed to load policy (sync)', { error });
      throw new Error(`Failed to load policy: ${error}`);
    }
  }

  /**
   * Get the policy file path
   */
  static getPath(): string {
    return getPreferredDataPath('policy.json');
  }
}
