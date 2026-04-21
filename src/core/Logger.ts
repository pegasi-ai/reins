/**
 * Reins logger
 * Production-grade logging with Winston
 */

import winston from 'winston';
import {
  ensurePreferredDataDirSync,
  getPreferredDataPath,
  resolveDataDir,
} from './data-dir';

ensurePreferredDataDirSync();

const LOG_FILE = getPreferredDataPath('reins.log');

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'reins' },
  transports: [
    // Console transport (colorized for development)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length > 0 ? JSON.stringify(meta) : '';
          return `[${timestamp}] ${level}: ${message} ${metaStr}`;
        })
      ),
    }),

    // File transport (structured JSON logs)
    new winston.transports.File({
      filename: LOG_FILE,
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      format: winston.format.json(),
    }),
  ],
});

// Export the log file path for reference
export const LOG_PATH = LOG_FILE;
export const REINS_DATA_DIR = resolveDataDir();
export const CLAWREINS_DATA_DIR = REINS_DATA_DIR;
