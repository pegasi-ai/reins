import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { normalizeToolCall } = require('../dist/core/ActionNormalizer.js');
const { buildTrajectoryFeatures } = require('../dist/core/TrajectoryFeatureBuilder.js');
const { decideNotificationPolicy } = require('../dist/core/NotificationPolicy.js');

test('trajectory features flag destructive drift from read-only task', () => {
  const pendingAction = normalizeToolCall('Gmail.deleteMessages', {
    query: 'in:inbox',
    count: 182,
  }, {
    moduleName: 'Gmail',
    methodName: 'deleteMessages',
  });

  const features = buildTrajectoryFeatures({
    taskState: {
      sessionKey: 't1',
      userGoal: 'Summarize the urgent emails from Acme.',
      allowedEffects: ['read'],
      forbiddenEffects: ['delete', 'send', 'buy', 'revoke'],
      protectedTargets: [],
      activeSubgoals: [],
      updatedAt: Date.now(),
    },
    recentEvents: [],
    pendingAction,
  });

  assert.equal(features.verbDrift, true);
  assert.equal(features.mutationDrift, true);
});

test('notification policy notifies only catastrophic contradicted trajectories', () => {
  const decision = decideNotificationPolicy({
    severity: 'CATASTROPHIC',
    judgment: {
      alignment: 'contradicted',
      confidence: 0.91,
      summary: 'contradicted',
      reasons: ['verb_drift'],
    },
  });

  assert.equal(decision.notifyUser, true);
  assert.equal(decision.requireApproval, true);
});

test('notification policy suppresses aligned catastrophic notification', () => {
  const decision = decideNotificationPolicy({
    severity: 'CATASTROPHIC',
    judgment: {
      alignment: 'aligned',
      confidence: 0.96,
      summary: 'aligned',
      reasons: [],
    },
  });

  assert.equal(decision.notifyUser, false);
  assert.equal(decision.requireApproval, true);
});
