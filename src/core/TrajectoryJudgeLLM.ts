import { NormalizedAction } from './ActionNormalizer';
import { TaskState } from './TaskStateStore';
import { TraceEvent } from './TraceRecorder';
import { TrajectoryFeatures } from './TrajectoryFeatureBuilder';

export interface TrajectoryJudgment {
  alignment: 'aligned' | 'drifting' | 'contradicted';
  confidence: number;
  summary: string;
  reasons: string[];
}

export interface TrajectoryJudgeInput {
  taskState?: TaskState;
  recentEvents: TraceEvent[];
  pendingAction: NormalizedAction;
  features: TrajectoryFeatures;
  severity: 'HIGH' | 'CATASTROPHIC';
}

function heuristicJudge(input: TrajectoryJudgeInput): TrajectoryJudgment {
  const { taskState, pendingAction, features } = input;
  const reasons = [...features.reasons];

  if (!taskState && pendingAction.destructive) {
    return {
      alignment: 'contradicted',
      confidence: 0.9,
      summary: 'No user task state is available for a catastrophic destructive action.',
      reasons: [...reasons, 'missing_user_task_state'],
    };
  }

  if (features.verbDrift || features.mutationDrift || (features.scopeExpansion === 'severe' && pendingAction.destructive)) {
    return {
      alignment: 'contradicted',
      confidence: 0.92,
      summary: taskState
        ? `Pending ${pendingAction.verb} action contradicts the user goal "${taskState.userGoal}".`
        : `Pending ${pendingAction.verb} action appears contradicted by the recent trajectory.`,
      reasons,
    };
  }

  if (features.targetDrift || features.repeatedWidening || features.scopeExpansion === 'moderate') {
    return {
      alignment: 'drifting',
      confidence: 0.76,
      summary: 'Pending action shows trajectory drift but not a clear contradiction yet.',
      reasons,
    };
  }

  return {
    alignment: 'aligned',
    confidence: 0.88,
    summary: 'Pending catastrophic action remains consistent with the observed task trajectory.',
    reasons,
  };
}

export class TrajectoryJudgeLLM {
  async judge(input: TrajectoryJudgeInput): Promise<TrajectoryJudgment> {
    return heuristicJudge(input);
  }
}

export const trajectoryJudgeLLM = new TrajectoryJudgeLLM();
