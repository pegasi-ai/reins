import { NormalizedAction } from './ActionNormalizer';
import { TaskState } from './TaskStateStore';
import { TraceEvent } from './TraceRecorder';

export interface TrajectoryFeatures {
  verbDrift: boolean;
  mutationDrift: boolean;
  scopeExpansion: 'none' | 'moderate' | 'severe';
  targetDrift: boolean;
  repeatedWidening: boolean;
  protectedTargetTouched: boolean;
  reasons: string[];
}

function actionEffect(verb: NormalizedAction['verb']): 'read' | 'write' | 'delete' | 'send' | 'buy' | 'revoke' | null {
  if (verb === 'read' || verb === 'navigate') return 'read';
  if (verb === 'write' || verb === 'move' || verb === 'modify_account' || verb === 'execute') return 'write';
  if (verb === 'delete') return 'delete';
  if (verb === 'send') return 'send';
  if (verb === 'purchase') return 'buy';
  if (verb === 'revoke' || verb === 'grant') return 'revoke';
  return null;
}

function scopeRank(scope: NormalizedAction['scope']): number {
  if (scope === 'one') return 1;
  if (scope === 'many') return 2;
  if (scope === 'all') return 3;
  return 0;
}

export function buildTrajectoryFeatures(input: {
  taskState?: TaskState;
  recentEvents: TraceEvent[];
  pendingAction: NormalizedAction;
}): TrajectoryFeatures {
  const { taskState, recentEvents, pendingAction } = input;
  const reasons: string[] = [];
  const pendingEffect = actionEffect(pendingAction.verb);
  const priorActions = recentEvents
    .map((event) => event.action)
    .filter((action): action is NormalizedAction => Boolean(action));
  const maxPriorScope = priorActions.reduce((max, action) => Math.max(max, scopeRank(action.scope)), 0);

  const verbDrift = Boolean(
    taskState
    && pendingEffect
    && taskState.allowedEffects.length > 0
    && !taskState.allowedEffects.includes(pendingEffect)
  );
  if (verbDrift) reasons.push(`pending_${pendingEffect}_outside_allowed_effects`);

  const mutationDrift = Boolean(
    pendingAction.destructive
    && taskState
    && (
      taskState.forbiddenEffects.includes('delete')
      || taskState.allowedEffects.every((effect) => effect === 'read')
    )
  );
  if (mutationDrift) reasons.push('destructive_mutation_during_read_only_task');

  const targetDrift = Boolean(
    taskState
    && taskState.protectedTargets.length > 0
    && pendingAction.target
    && !taskState.protectedTargets.includes(pendingAction.target)
  );
  if (targetDrift) reasons.push('target_outside_user_named_scope');

  const protectedTargetTouched = Boolean(
    taskState
    && taskState.protectedTargets.length > 0
    && pendingAction.target
    && taskState.protectedTargets.includes(pendingAction.target)
  );

  const wideningDelta = scopeRank(pendingAction.scope) - maxPriorScope;
  const scopeExpansion =
    wideningDelta >= 2 ? 'severe'
      : wideningDelta === 1 ? 'moderate'
        : 'none';
  if (scopeExpansion !== 'none') reasons.push(`scope_expansion_${scopeExpansion}`);

  const repeatedWidening = priorActions.some(
    (action) => action.object === pendingAction.object && scopeRank(action.scope) < scopeRank(pendingAction.scope)
  );
  if (repeatedWidening) reasons.push('repeated_scope_widening');

  return {
    verbDrift,
    mutationDrift,
    scopeExpansion,
    targetDrift,
    repeatedWidening,
    protectedTargetTouched,
    reasons,
  };
}
