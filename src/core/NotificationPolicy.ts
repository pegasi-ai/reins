import { TrajectoryJudgment } from './TrajectoryJudgeLLM';

export interface NotificationDecision {
  notifyUser: boolean;
  requireApproval: boolean;
  logOnly: boolean;
  reason: string;
}

export function decideNotificationPolicy(input: {
  severity?: 'HIGH' | 'CATASTROPHIC';
  judgment?: TrajectoryJudgment;
}): NotificationDecision {
  if (input.severity !== 'CATASTROPHIC') {
    return {
      notifyUser: false,
      requireApproval: false,
      logOnly: false,
      reason: 'non_catastrophic_action',
    };
  }

  if (input.judgment?.alignment === 'contradicted' && input.judgment.confidence >= 0.85) {
    return {
      notifyUser: true,
      requireApproval: true,
      logOnly: true,
      reason: 'catastrophic_contradicted_trajectory',
    };
  }

  if (input.judgment?.alignment === 'drifting' && input.judgment.confidence >= 0.75) {
    return {
      notifyUser: false,
      requireApproval: true,
      logOnly: true,
      reason: 'catastrophic_drifting_trajectory',
    };
  }

  return {
    notifyUser: false,
    requireApproval: true,
    logOnly: true,
    reason: 'catastrophic_aligned_or_unknown_trajectory',
  };
}
