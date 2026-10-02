// governance.mjs - Phase 3: the Governance <-> Runtime interface.
//
// This is the seam the whole promotion turns on. The runtime does not re-implement ownership,
// resource locking, resource conflicts or approval-scope semantics: it asks the EXISTING
// governance engine (agent-orchestra-repo/scripts/orchestrator/lib.mjs, invariants I1-I10) and
// maps that engine's refusals to decision codes.
//
// Two properties matter more than the mapping:
//   * FAIL CLOSED. If the governance engine cannot be loaded or throws unexpectedly, the bridge
//     reports unavailable and the policy gate returns BLOCK. There is no path where a missing
//     governor means "allow".
//   * THE DECISION IS THE ENGINE'S. probeClaim runs the engine's own claimTask over a scratch copy
//     of its state, so a resource conflict is refused by the code that owns that rule.

import { Refusal, clone } from './core.mjs';

const DEFAULT_LIB = process.env.GAR_GOVERNANCE_LIB
  || new URL('../../agent-orchestra-repo/scripts/orchestrator/lib.mjs', import.meta.url).href;

export async function tryLoadGovernance(libPath) {
  const path = libPath || DEFAULT_LIB;
  try {
    const lib = await import(path);
    if (typeof lib.createState !== 'function' || typeof lib.claimTask !== 'function') {
      return { available: false, path, lib: null, error: 'governance module does not export createState/claimTask' };
    }
    return { available: true, path, lib, error: null };
  } catch (error) {
    return { available: false, path, lib: null, error: String(error && error.message ? error.message : error) };
  }
}

export function classifyClaimMessage(message) {
  const m = String(message || '');
  if (m.includes('cannot claim: resource already held')) return 'RESOURCE_CONFLICT';
  if (m.includes('is assigned to')) return 'NOT_TASK_OWNER';
  if (m.includes('already held by')) return 'TASK_LOCKED_BY_OTHER';
  if (m.includes('is blocked')) return 'TASK_BLOCKED';
  return 'GOVERNANCE_REFUSED';
}

export function classifyDispatchMessage(message) {
  const m = String(message || '');
  if (m.includes('scope must equal')) return 'APPROVAL_SCOPE_MISMATCH';
  if (m.includes('is not approved')) return 'EXTERNAL_ACTION_UNAPPROVED';
  if (m.includes('is blocked')) return 'TASK_BLOCKED';
  if (m.includes('is gated')) return 'VERIFICATION_GATE_CLOSED';
  if (m.includes('already done')) return 'ALREADY_DONE';
  return 'GOVERNANCE_REFUSED';
}

/**
 * The bridge. Holds the governance engine's own state; the runtime never edits it directly.
 */
export class GovernanceBridge {
  constructor(loaded, roster) {
    this.path = loaded ? loaded.path : null;
    this.error = loaded ? loaded.error : 'not loaded';
    this.lib = loaded && loaded.available ? loaded.lib : null;
    // The roster is how the runtime's agent ids become real governance identities: the engine
    // routes the specify stage to the named owner, and claimTask refuses any other agent.
    this.state = this.lib ? this.lib.createState(roster || undefined) : null;
  }

  get available() {
    return this.lib !== null;
  }

  #require() {
    if (!this.lib) {
      throw new Refusal('GOVERNANCE_UNAVAILABLE', 'governance engine unavailable: ' + String(this.error));
    }
  }

  /** Create the governance-side task record. The governance engine owns task identity and locks. */
  createTask(input) {
    this.#require();
    const result = this.lib.createTask(this.state, input);
    this.state = result.state;
    return clone(result.task);
  }

  /** Real claim: takes the single-writer lock. Resource conflicts are refused by the engine. */
  claim(taskId, agentId) {
    this.#require();
    try {
      const result = this.lib.claimTask(this.state, taskId, agentId);
      this.state = result.state;
      return clone(result.task);
    } catch (error) {
      throw new Refusal(classifyClaimMessage(error.message), String(error.message));
    }
  }

  /**
   * Would the engine allow this agent to hold this task right now? Runs claimTask against a scratch
   * copy so the check is the engine's own rule and the real lock is untouched.
   */
  probeClaim(taskId, agentId) {
    this.#require();
    const scratch = clone(this.state);
    try {
      this.lib.claimTask(scratch, taskId, agentId);
      return { ok: true, code: null, message: null };
    } catch (error) {
      return { ok: false, code: classifyClaimMessage(error.message), message: String(error.message) };
    }
  }

  /**
   * Would the engine allow dispatch of this task? nextDispatch is defined for an unlocked task, so
   * the probe runs over a scratch copy with the lock released; the approval-scope equality rule and
   * the verification gate are then evaluated by the engine itself.
   */
  dispatchCheck(taskId) {
    this.#require();
    const scratch = clone(this.state);
    const task = scratch.tasks[taskId];
    if (!task) return { ok: false, code: 'UNKNOWN_TASK', message: 'no such governance task: ' + taskId };
    task.lock = null;
    try {
      this.lib.nextDispatch(scratch, taskId);
      return { ok: true, code: null, message: null };
    } catch (error) {
      return { ok: false, code: classifyDispatchMessage(error.message), message: String(error.message) };
    }
  }

  /** Which live task holds this resource, if any. Used when a session is bound to no task. */
  resourceHolder(resource) {
    if (!this.lib || !resource) return null;
    const want = String(resource).toLowerCase();
    for (const task of Object.values(this.state.tasks)) {
      if (!task.lock) continue;
      if (task.status === 'done' || task.status === 'blocked') continue;
      const hit = (task.resources || []).find(function (r) { return String(r).toLowerCase() === want; });
      if (hit) return { taskId: task.id, owner: task.lock.owner, resource: hit };
    }
    return null;
  }

  isBlocked(taskId) {
    this.#require();
    const task = this.state.tasks[taskId];
    return Boolean(task && task.status === 'blocked');
  }

  approveExternalAction(taskId, approval) {
    this.#require();
    try {
      const result = this.lib.approveExternalAction(this.state, taskId, approval);
      this.state = result.state;
      return clone(result.task);
    } catch (error) {
      throw new Refusal(classifyDispatchMessage(error.message), String(error.message));
    }
  }

  failVerification(taskId, agent, failure) {
    this.#require();
    try {
      const result = this.lib.failVerification(this.state, taskId, agent, failure);
      this.state = result.state;
      return clone(result.task);
    } catch (error) {
      throw new Refusal(classifyDispatchMessage(error.message), String(error.message));
    }
  }

  /**
   * Drive the governance engine's own retry ceiling until it blocks the task, using the engine's
   * public stage machine. Used by the adversarial suite to prove the runtime honours a governance
   * block issued behind its back.
   */
  blockTask(taskId, note) {
    this.#require();
    const roster = this.state.roster;
    const implementerOf = (task) => this.lib.implementerForType(task.type, roster);
    if (this.state.tasks[taskId].phase === 'specify') {
      let r = this.lib.claimTask(this.state, taskId, implementerOf(this.state.tasks[taskId]));
      this.state = r.state;
      r = this.lib.completeStage(this.state, taskId, implementerOf(this.state.tasks[taskId]), { spec: 'injected spec', acceptance: 'injected acceptance' });
      this.state = r.state;
    }
    for (let guard = 0; guard < 12; guard += 1) {
      const task = this.state.tasks[taskId];
      if (task.status === 'blocked') break;
      if (task.phase === 'implement') {
        let r = this.lib.claimTask(this.state, taskId, implementerOf(task));
        this.state = r.state;
        r = this.lib.completeStage(this.state, taskId, implementerOf(task), {});
        this.state = r.state;
        continue;
      }
      if (task.phase === 'verify') {
        const verifier = task.assignedAgent;
        let r = this.lib.claimTask(this.state, taskId, verifier);
        this.state = r.state;
        r = this.lib.failVerification(this.state, taskId, verifier, {
          criteria: ['injected: adversarial verification failure'],
          findings: note || 'adversarial suite',
        });
        this.state = r.state;
        continue;
      }
      break;
    }
    return clone(this.state.tasks[taskId]);
  }

  /** Simulate the governor going away. Used to prove the runtime fails closed, not open. */
  sever(reason) {
    this.saved = { lib: this.lib, state: this.state };
    this.lib = null;
    this.error = reason || 'severed for testing';
    this.state = null;
  }

  view(taskId) {
    if (!this.lib) return null;
    const task = this.state.tasks[taskId];
    return task ? clone(task) : null;
  }

  get verificationAttempts() {
    if (!this.lib) return 0;
    return Object.values(this.state.tasks).reduce(function (n, t) {
      return n + ((t.verification && t.verification.attempts) || 0);
    }, 0);
  }
}
