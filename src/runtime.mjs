// runtime.mjs - Phase 4: the minimal governed runtime.
//
// THE CENTRAL CLAIM OF THIS FILE: the executor is unreachable except through the gate.
//
//   * The executor function is stored in a module-private WeakMap keyed by the frozen API object.
//     It is not a property of the returned object, so there is no `runtime.executor` to call and
//     no field for a caller to swap.
//   * execute() requires a grant that this runtime issued. Grants are single-use, expiring,
//     bound to (session, agent, artifact hash, identity hash, action, target), and re-validated
//     against current state at execution time - so a grant issued before a revocation is dead.
//   * Executions are recorded before the result is returned, and evidence cannot be written at all
//     without an execution id, which closes "execute now, justify later".

import { ActionRefused, clone, newId, systemClock } from './core.mjs';

const SEALED = new WeakMap();

function refusal(effect, code, reason, extra) {
  return {
    effect,
    code,
    reason,
    invariant: null,
    obligations: [],
    ruleId: null,
    matched: [],
    ...(extra || {}),
  };
}

export function createGovernedRuntime(options) {
  const executor = options && options.executor;
  if (typeof executor !== 'function') throw new Error('a governed runtime needs an executor function');
  const decide = options.decide;
  if (typeof decide !== 'function') throw new Error('a governed runtime needs a decide(request) function');
  const revalidate = options.revalidate || function () { return { ok: true }; };
  const ledger = options.ledger;
  if (!ledger) throw new Error('a governed runtime needs a ledger');
  const clock = options.clock || systemClock;
  const grantTtlMs = options.grantTtlMs === undefined ? 30000 : options.grantTtlMs;
  const runtimeId = options.runtimeId || newId('runtime');

  const counters = {
    submitted: 0,
    allowed: 0,
    refused: 0,
    executed: 0,
    refusalsByCode: Object.create(null),
  };

  function countRefusal(code) {
    counters.refused += 1;
    counters.refusalsByCode[code] = (counters.refusalsByCode[code] || 0) + 1;
  }

  const api = {
    runtimeId,

    /** Ask the gate. Returns the receipt, and a grant id when - and only when - the effect is ALLOW. */
    submit(request) {
      counters.submitted += 1;
      const decided = decide(request);
      const receipt = decided.receipt;
      ledger.append('decision', {
        agentId: request.agentId,
        sessionId: request.sessionId,
        taskId: request.taskId === undefined ? null : request.taskId,
        action: request.action,
        target: request.target === undefined ? null : request.target,
        resource: request.resource === undefined ? null : request.resource,
        effect: receipt.effect,
        code: receipt.code,
        ruleId: receipt.ruleId,
        matched: receipt.matched,
        invariant: receipt.invariant,
      });
      if (receipt.effect !== 'ALLOW') {
        countRefusal(receipt.code);
        return { receipt, granted: false, grantId: null };
      }
      counters.allowed += 1;
      const context = decided.ctx;
      const expiresAt = new Date(new Date(clock()).getTime() + grantTtlMs).toISOString();
      const grant = ledger.issueGrant({
        sessionId: context.session.sessionId,
        agentId: context.identity.agentId,
        definitionHash: context.session.definitionHash,
        identityHash: context.session.identityHash,
        action: request.action,
        target: request.target === undefined ? null : request.target,
        resource: request.resource === undefined ? null : request.resource,
        decisionCode: receipt.code,
        expiresAt,
        external: request.externalAction === undefined ? null : request.externalAction,
        runtimeId,
      });
      return { receipt, granted: true, grantId: grant.grantId, expiresAt };
    },

    /**
     * Execute the action a grant authorises. This is the only path to the executor.
     * The executor receives the GRANTED action and target, never caller-supplied substitutes.
     */
    async execute(grantId, attempt) {
      const sealed = SEALED.get(api);
      const head = ledger.peekGrant(grantId);
      if (!head) {
        countRefusal('GRANT_UNKNOWN');
        throw new ActionRefused(refusal('DENY', 'GRANT_UNKNOWN', 'no such grant: ' + String(grantId)));
      }
      if (head.runtimeId !== runtimeId) {
        countRefusal('GRANT_WRONG_RUNTIME');
        throw new ActionRefused(refusal('DENY', 'GRANT_WRONG_RUNTIME',
          'grant was issued by runtime ' + String(head.runtimeId) + ', this is ' + runtimeId));
      }
      const requested = attempt || {};
      const gate = sealed.revalidate(head, requested);
      if (!gate.ok) {
        countRefusal(gate.code);
        throw new ActionRefused(refusal(gate.effect || 'DENY', gate.code, gate.reason));
      }
      ledger.consumeGrant(grantId, {
        sessionId: requested.sessionId === undefined ? head.sessionId : requested.sessionId,
        agentId: requested.agentId === undefined ? head.agentId : requested.agentId,
        definitionHash: head.definitionHash,
        action: requested.action === undefined ? head.action : requested.action,
        target: requested.target === undefined ? head.target : requested.target,
      });
      const startedAt = clock();
      let result = null;
      let failure = null;
      try {
        result = await sealed.executor({
          action: head.action,
          target: head.target,
          resource: head.resource,
          args: requested.args === undefined ? null : requested.args,
          grantId: head.grantId,
          // The acting identity comes from the GRANT, never from caller-supplied arguments.
          agentId: head.agentId,
          sessionId: head.sessionId,
          // The external descriptor travels with the grant, so an approved external action actually
          // reaches the external executor. Without it that branch was unreachable and two benchmark
          // incidents asserted on a counter that could never move.
          external: head.external === undefined ? null : head.external,
          taskId: gate.taskId === undefined ? null : gate.taskId,
        });
      } catch (error) {
        failure = error;
      }
      const execution = ledger.recordExecution({
        grantId: head.grantId,
        sessionId: head.sessionId,
        agentId: head.agentId,
        action: head.action,
        target: head.target,
        resource: head.resource,
        taskId: gate.taskId === undefined ? null : gate.taskId,
        actorId: gate.actorId === undefined ? null : gate.actorId,
        external: head.external === undefined ? null : head.external,
        startedAt,
        outcome: failure ? 'error' : 'ok',
        produced: failure ? String(failure && failure.message ? failure.message : failure) : result,
      });
      counters.executed += 1;
      if (failure) {
        failure.executionId = execution.executionId;
        throw failure;
      }
      return { executionId: execution.executionId, result, grantId: head.grantId };
    },

    stats() {
      return clone(counters);
    },

    /** What this runtime exposes. Deliberately has no executor field. */
    describe() {
      return Object.freeze({
        runtimeId,
        exposed: ['runtimeId', 'submit', 'execute', 'stats', 'describe'],
        executorExposed: false,
        grantPolicy: 'single-use, expiring, bound to session+identity+artifact+action+target',
      });
    },
  };

  SEALED.set(api, { executor, revalidate });
  return Object.freeze(api);
}
