// control-plane.mjs - the Governed Agent Control Plane.
//
// Everything a caller can do to the system goes through one of two doors:
//
//   1. cp.submit(request)   -> the gate answers ALLOW / REQUIRE_* / DENY / BLOCK
//   2. cp.execute(grantId)  -> the runtime runs the executor, and only with a valid grant
//
// Control-plane state transitions (evidence, verification, done, release, promote, rollback,
// revoke, approval, handoff) are themselves actions that go through both doors. There is no
// administrative back door that writes state directly.

import { Refusal, clone, hashOf, isAllowed, newId, systemClock } from './core.mjs';
import {
  ArtifactRegistry, DEFAULT_ROLES, createAgent, freezeIdentity, trustPermitsExecution,
} from './identity.mjs';
import { Ledger } from './ledger.mjs';
import { AgentMemory } from './memory.mjs';
import { authorize } from './policy.mjs';
import { createGovernedRuntime } from './runtime.mjs';
import { GovernanceBridge, tryLoadGovernance } from './governance.mjs';

/** The governance roster the runtime's agent ids map onto. Specify owns the task. */
export const DEFAULT_RUNTIME_ROSTER = Object.freeze({
  agents: {
    'agent-impl': { cost: 3, available: true, specialties: [], scores: { specify: 3, implement: 3, verify: 1, evidence: 2, environment: 1, domain: 1 } },
    'agent-verify': { cost: 4, available: true, specialties: ['verify'], scores: { specify: 1, implement: 1, verify: 3, evidence: 3, environment: 1, domain: 2 } },
    'agent-coord': { cost: 2, available: true, specialties: [], scores: { specify: 1, implement: 1, verify: 1, evidence: 1, environment: 1, domain: 3 } },
  },
  routes: { specify: 'agent-impl', evidence: 'agent-impl' },
});

export async function createControlPlane(options) {
  const opts = options || {};
  const clock = opts.clock || systemClock;
  const loaded = opts.governance || (await tryLoadGovernance(opts.governanceLibPath));
  const governance = new GovernanceBridge(loaded, opts.roster || DEFAULT_RUNTIME_ROSTER);
  const registry = new ArtifactRegistry();
  const ledger = new Ledger(clock);
  const memory = new AgentMemory();

  const agents = new Map();
  const sessions = new Map();
  const tasks = new Map();
  const externalCalls = [];

  function requireAgent(agentId) {
    const identity = agents.get(agentId);
    if (!identity) throw new Refusal('AGENT_UNKNOWN', 'unknown agent: ' + String(agentId));
    return identity;
  }

  function requireSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) throw new Refusal('SESSION_UNKNOWN', 'unknown session: ' + String(sessionId));
    return session;
  }

  function requireTask(taskId) {
    const task = tasks.get(taskId);
    if (!task) throw new Refusal('TASK_UNKNOWN', 'unknown task: ' + String(taskId));
    return task;
  }

  // ------------------------------------------------------------------ gate

  function decide(request) {
    const session = request && request.sessionId ? sessions.get(request.sessionId) || null : null;
    const identity = session ? agents.get(session.agentId) || null : null;
    const role = identity ? DEFAULT_ROLES[identity.roleId] || null : null;
    const taskState = request && request.taskId ? tasks.get(request.taskId) || null : null;
    const ctx = {
      request,
      session,
      // The gate needs to resolve OTHER sessions too: an approval names the session it is for, and
      // independence has to be checked where the action is authorised, not only in the wrapper.
      sessions,
      identity,
      role,
      registry,
      ledger,
      memory,
      governance,
      taskState,
      now: clock(),
    };
    const receipt = authorize(ctx);
    if (receipt.code === 'ARTIFACT_TAMPERED' && session) {
      ledger.append('integrity.violation', { artifactId: session.artifactId, agentId: session.agentId, rule: receipt.ruleId });
    }
    return { receipt, ctx };
  }

  /**
   * Re-validated at execution time, not just at submit time. This is what makes a grant issued
   * before a revocation, a handoff or an artifact edit dead on arrival rather than a loophole.
   */
  function revalidate(grant) {
    if (!governance.available) {
      return { ok: false, code: 'GOVERNANCE_UNAVAILABLE', effect: 'BLOCK', reason: 'governance engine unavailable at execution time' };
    }
    const session = sessions.get(grant.sessionId);
    if (!session) return { ok: false, code: 'SESSION_UNKNOWN', effect: 'DENY', reason: 'session no longer exists' };
    if (session.closedAt) return { ok: false, code: 'SESSION_CLOSED', effect: 'DENY', reason: 'session was closed' };
    if (session.supersededBy) {
      return { ok: false, code: 'SESSION_SUPERSEDED', effect: 'DENY', reason: 'session was superseded by ' + session.supersededBy };
    }
    if (session.identityHash !== grant.identityHash) {
      return { ok: false, code: 'IDENTITY_DRIFT', effect: 'BLOCK', reason: 'identity changed after the grant was issued' };
    }
    const identity = agents.get(session.agentId);
    if (!identity || identity.identityFingerprint !== grant.identityHash) {
      return { ok: false, code: 'IDENTITY_DRIFT', effect: 'BLOCK', reason: 'agent identity no longer matches the session snapshot' };
    }
    try {
      registry.assertIntegrity(session.artifactId);
    } catch (error) {
      return { ok: false, code: 'ARTIFACT_TAMPERED', effect: 'BLOCK', reason: 'artifact content no longer matches its definition hash' };
    }
    const current = registry.current(session.artifactId);
    if (current.definitionHash !== grant.definitionHash) {
      return { ok: false, code: 'ARTIFACT_MUTATED', effect: 'BLOCK', reason: 'artifact definition changed after the grant was issued' };
    }
    if (current.trust === 'REVOKED') {
      return { ok: false, code: 'TRUST_REVOKED', effect: 'BLOCK', reason: 'trust was revoked after the grant was issued' };
    }
    if (!trustPermitsExecution(current.trust)) {
      return { ok: false, code: 'TRUST_NOT_ESTABLISHED', effect: 'BLOCK', reason: 'artifact trust is ' + current.trust };
    }
    if (session.taskId && governance.isBlocked(session.taskId)) {
      return { ok: false, code: 'TASK_BLOCKED', effect: 'BLOCK', reason: 'governance blocked the task before this ran' };
    }
    const chain = ledger.verifyChain();
    if (!chain.ok) return { ok: false, code: 'LEDGER_TAMPERED', effect: 'BLOCK', reason: 'ledger chain broken at row ' + chain.brokenAt };
    // The task binding is re-derived from the SESSION at execution time and travels with the
    // execution, so a verification cannot later be pointed at unrelated work.
    return { ok: true, taskId: session.taskId === undefined ? null : session.taskId };
  }

  // -------------------------------------------------------- state actions

  /**
   * The executor. Actions that change control-plane state are implemented here, so they are
   * reachable only through the gate. Anything else is delegated to the tool executor the caller
   * supplied (or simulated).
   */
  async function executor(invocation) {
    const action = invocation.action;
    const target = invocation.target;
    const args = invocation.args || {};
    // The acting agent is taken from the consumed grant, not from the request payload.
    const agentId = invocation.agentId;

    switch (action) {
      case 'produce_evidence': {
        const execution = ledger.executions.get(target);
        if (!execution) throw new Refusal('EVIDENCE_WITHOUT_EXECUTION', 'no execution ' + String(target));
        if (execution.agentId !== agentId) {
          throw new Refusal('EVIDENCE_AUTHOR_MISMATCH',
            'agent ' + agentId + ' cannot file evidence for an execution run by ' + execution.agentId);
        }
        return ledger.recordEvidence({
          executionId: target,
          author: agentId,
          grade: args.grade,
          command: args.command,
          exitCode: args.exitCode,
          revision: args.revision,
          peer: args.peer,
          note: args.note,
          criterion: args.criterion,
          artifactHash: args.artifactHash,
        });
      }
      case 'verify': {
        // The task is read from the VERIFIER'S SESSION, not from args. Taking it from the caller let
        // a verifier nominate any passing verification as an unrelated task's implementation.
        const verifierSession = sessions.get(invocation.sessionId);
        const boundTaskId = verifierSession && verifierSession.taskId ? verifierSession.taskId : null;
        const subjectExecution = ledger.executions.get(args.subjectExecutionId || target);
        if (boundTaskId && (!subjectExecution || subjectExecution.taskId !== boundTaskId)) {
          throw new Refusal('VERIFICATION_OF_FOREIGN_WORK',
            'the verification subject belongs to task ' + String(subjectExecution && subjectExecution.taskId) +
            ', but this session is bound to ' + boundTaskId);
        }
        const record = ledger.recordVerification({
          verifierAgentId: agentId,
          subjectExecutionId: args.subjectExecutionId || target,
          verdict: args.verdict,
          criteria: args.criteria,
          evidenceIds: args.evidenceIds,
          findings: args.findings,
        });
        const taskId = boundTaskId;
        if (taskId && tasks.has(taskId)) {
          const task = tasks.get(taskId);
          if (record.verdict === 'PASS') {
            task.verificationId = record.verificationId;
            task.verificationSubjectAgentId = record.subjectAgentId;
            // What this task's work actually IS. Without binding it, a done claim could cite any
            // passing verification in the ledger, including one about unrelated work.
            task.implementationExecutionId = record.subjectExecutionId;
            task.state = 'verified';
          } else {
            task.verificationId = null;
            task.state = 'in_progress';
          }
          task.updatedAt = clock();
        }
        return record;
      }
      case 'mark_done': {
        const taskId = args.taskId || target;
        const task = requireTask(taskId);
        const verificationId = args.verificationId || task.verificationId;
        // The verification must be of THIS task's work.
        const cited = ledger.verifications.get(verificationId);
        if (!cited) throw new Refusal('DONE_WITH_UNKNOWN_VERIFICATION', 'no verification ' + String(verificationId));
        if (!task.implementationExecutionId || cited.subjectExecutionId !== task.implementationExecutionId) {
          throw new Refusal('DONE_VERIFICATION_NOT_BOUND',
            'the cited verification is of execution ' + cited.subjectExecutionId +
            ', but this task\'s work is ' + String(task.implementationExecutionId));
        }
        const fact = ledger.assertFact({
          key: 'task:' + taskId + ':state',
          value: 'done',
          verificationId,
        });
        task.state = 'done';
        task.doneAt = clock();
        task.updatedAt = clock();
        return { taskId, state: 'done', factKey: fact.key, verificationId: fact.verificationId };
      }
      case 'evaluate': {
        const evaluated = registry.evaluate({
          artifactId: target,
          // The evaluator is the agent the GRANT identifies. Taking `by` from caller params let a
          // caller name somebody else and satisfy the independence rule by assertion.
          by: agentId,
          byRole: args.byRole || null,
          checks: args.checks,
          at: clock(),
        });
        ledger.append('artifact.evaluated', {
          artifactId: target,
          evaluationId: evaluated.evaluation.evaluationId,
          passed: evaluated.evaluation.passed,
          by: evaluated.evaluation.by,
        });
        return evaluated;
      }
      case 'mutate_artifact': {
        const mutated = registry.mutate({ artifactId: target, patch: args.patch, by: agentId, at: clock() });
        ledger.append('artifact.mutated', {
          artifactId: target,
          from: mutated.previous.definitionHash,
          to: mutated.current.definitionHash,
          by: agentId,
        });
        return mutated;
      }
      case 'release':
        return registry.release({ artifactId: target, by: agentId, at: clock() });
      case 'promote':
        return registry.promote({ artifactId: target, by: agentId, approval: args.approval, at: clock() });
      case 'rollback':
        return registry.rollback({ artifactId: target, toVersion: args.toVersion, by: agentId, at: clock() });
      case 'revoke':
        return registry.revoke({ artifactId: target, reason: args.reason, by: agentId, at: clock() });
      case 'approve': {
        const session = requireSession(args.sessionId);
        // Defence in depth behind the grant: the gate rule P18d refuses this before a grant is even
        // issued, and the executor refuses it again.
        if (session.agentId === agentId) {
          throw new Refusal('SELF_APPROVAL', 'agent ' + agentId + ' may not approve its own external action');
        }
        // The governance engine records the approval that unlocks dispatch. If it refuses, the
        // approval does NOT happen: it is not downgraded to a note on a success record. Swallowing
        // that refusal was a WARNING-shaped hole in an ALLOW/DENY system (finding C3).
        if (session.taskId && governance.available) {
          governance.approveExternalAction(session.taskId, { approvedBy: args.approvedBy, scope: args.scope });
        }
        const approval = {
          approvedBy: args.approvedBy,
          approvedByAgent: args.approvedByAgent || null,
          scope: args.scope,
          kind: args.kind === undefined ? null : args.kind,
          sessionId: session.sessionId,
          agentId: session.agentId,
          definitionHash: session.definitionHash,
          approved: true,
          at: clock(),
          expiresAt: args.expiresAt || null,
        };
        session.approval = approval;
        ledger.append('approval', { sessionId: session.sessionId, agentId: session.agentId, ...approval });
        return approval;
      }
      case 'handoff': {
        const from = requireSession(args.sessionId);
        const opened = await openSession({ agentId: args.toAgentId, taskId: from.taskId, own: true, reason: 'handoff' });
        const previous = from.sessionId;
        from.supersededBy = opened.sessionId;
        from.closedAt = clock();
        ledger.append('handoff', { taskId: from.taskId, from: previous, to: opened.sessionId, toAgentId: args.toAgentId, reason: args.reason });
        return { from: previous, to: opened.sessionId };
      }
      case 'claim':
        return governance.claim(args.taskId || target, agentId);
      case 'read':
        return { read: target, note: 'read-only action, nothing to change' };
      default: {
        if (invocation.external && typeof opts.externalExecutor === 'function') {
          const record = { at: clock(), by: agentId, kind: invocation.external.kind, target: invocation.external.target };
          externalCalls.push(record);
          return opts.externalExecutor({ ...record, args: invocation.args });
        }
        if (invocation.external) {
          const record = { at: clock(), by: agentId, kind: invocation.external.kind, target: invocation.external.target };
          externalCalls.push(record);
          return { simulatedExternalAction: record };
        }
        if (typeof opts.executor === 'function') return opts.executor(invocation);
        return { simulated: true, action, target };
      }
    }
  }

  const runtime = createGovernedRuntime({
    executor,
    decide,
    revalidate,
    ledger,
    clock,
    grantTtlMs: opts.grantTtlMs,
    runtimeId: opts.runtimeId,
  });

  // ---------------------------------------------------------------- actions

  async function submit(request) {
    return runtime.submit(request);
  }

  async function execute(grantId, attempt) {
    return runtime.execute(grantId, attempt);
  }

  /** Submit and, when the gate allows, execute in one call. Returns the receipt either way. */
  async function act(request) {
    const submitted = await runtime.submit(request);
    if (!submitted.granted) return { receipt: submitted.receipt, executed: false, result: null };
    const result = await runtime.execute(submitted.grantId, { args: request.params || null });
    return { receipt: submitted.receipt, executed: true, ...result };
  }

  function sessionRequest(sessionId, agentId, action, extra) {
    const session = requireSession(sessionId);
    return {
      sessionId,
      agentId: agentId || session.agentId,
      taskId: session.taskId,
      action,
      ...(extra || {}),
    };
  }

  // ------------------------------------------------------------- artifacts

  function registerArtifact(input) {
    const record = registry.register({ ...input, at: clock() });
    ledger.append('artifact.registered', { artifactId: record.artifactId, definitionHash: record.definitionHash, version: record.version });
    return record;
  }

  async function evaluateArtifact(input) {
    const session = requireSession(input.sessionId);
    const result = await act({
      sessionId: input.sessionId,
      agentId: session.agentId,
      taskId: session.taskId,
      action: 'evaluate',
      target: input.artifactId,
      params: { checks: input.checks, by: input.by || session.agentId, byRole: input.roleId || session.agentId },
    });
    return result;
  }

  /**
   * The root of trust. There is no agent above the first artifact, so a named human principal
   * performs the first evaluation and release. This is the ONLY state change outside the gate; it
   * is recorded as such, it is not reachable through any agent role, and everything after it is
   * gated. Bootstrapping silently through an agent would make the whole trust chain circular.
   */
  function bootstrapTrust(input) {
    const record = registry.evaluate({
      artifactId: input.artifactId,
      by: input.by || 'human-principal',
      byRole: 'human',
      checks: input.checks && input.checks.length ? input.checks : [{ name: 'human-root-review', passed: true }],
      at: clock(),
    });
    ledger.append('trust.bootstrap', {
      artifactId: input.artifactId,
      by: input.by || 'human-principal',
      definitionHash: record.artifact.definitionHash,
    });
    let released = null;
    if (input.release !== false) {
      released = registry.release({ artifactId: input.artifactId, by: input.by || 'human-principal', at: clock() });
      ledger.append('artifact.released', { artifactId: input.artifactId, by: input.by || 'human-principal', bootstrap: true });
    }
    return { evaluation: record.evaluation, artifact: released || record.artifact };
  }

  // ------------------------------------------------------------- lifecycle

  function createAgentFromArtifact(input) {
    const current = registry.current(input.artifactId);
    // The role is a property of the ARTIFACT, not a label the caller asserts. Without this an agent
    // could be built from an implementer artifact and claim the coordinator role.
    if (input.roleId && input.roleId !== current.roleId) {
      throw new Refusal('AGENT_ROLE_MISMATCH',
        'artifact ' + input.artifactId + ' declares role ' + current.roleId + ', not ' + String(input.roleId));
    }
    const identity = createAgent({
      ...input,
      artifactVersion: current.version,
      definitionHash: current.definitionHash,
      at: clock(),
    });
    agents.set(identity.agentId, identity);
    ledger.append('agent.bound', { agentId: identity.agentId, artifactId: identity.artifactId, definitionHash: identity.definitionHash, identityFingerprint: identity.identityFingerprint });
    return clone(identity);
  }

  function createTask(input) {
    const rigor = input.rigor || (input.externalAction ? 'L3' : 'L2');
    const govTask = governance.createTask({
      title: input.title,
      type: input.type || 'build',
      resources: input.resources || [],
      rigor,
      domain: input.domain,
      domainReview: input.domainReview,
      externalAction: input.externalAction,
      externalTarget: input.externalTarget,
      workspace: input.workspace,
      executionMode: 'single',
      security: 'skip',
      independentVerify: 'planned',
    });
    const record = {
      taskId: govTask.id,
      title: input.title,
      rigor,
      resources: [...(govTask.resources || [])],
      externalAction: govTask.externalAction,
      state: 'queued',
      ownerAgentId: govTask.assignedAgent,
      implementationExecutionId: null,
      verificationId: null,
      verificationSubjectAgentId: null,
      createdAt: clock(),
      updatedAt: clock(),
    };
    tasks.set(record.taskId, record);
    return clone(record);
  }

  async function openSession(input) {
    const identity = requireAgent(input.agentId);
    const artifactId = identity.artifactId;
    registry.assertIntegrity(artifactId);
    const current = registry.current(artifactId);
    if (!trustPermitsExecution(current.trust)) {
      throw new Refusal('ARTIFACT_NOT_TRUSTED',
        'artifact ' + artifactId + ' is ' + current.trust + '; evaluate and release it before an agent may run');
    }
    if (identity.definitionHash && identity.definitionHash !== current.definitionHash) {
      throw new Refusal('AGENT_ARTIFACT_STALE',
        'agent ' + input.agentId + ' was built from definition ' + identity.definitionHash + ' but the registry serves ' + current.definitionHash);
    }
    if (input.taskId) {
      requireTask(input.taskId);
      if (input.own !== false) governance.claim(input.taskId, input.agentId);
    }
    const sessionId = newId('session');
    const session = {
      sessionId,
      agentId: input.agentId,
      artifactId,
      artifactVersion: current.version,
      definitionHash: current.definitionHash,
      identityHash: identity.identityFingerprint,
      taskId: input.taskId || null,
      ownsTask: Boolean(input.taskId && input.own !== false),
      openedAt: clock(),
      closedAt: null,
      supersededBy: null,
      approval: null,
      identity: freezeIdentity(identity),
      reason: input.reason || 'open',
    };
    sessions.set(sessionId, session);
    ledger.append('session.opened', {
      sessionId, agentId: session.agentId, taskId: session.taskId, ownsTask: session.ownsTask,
      definitionHash: session.definitionHash, identityHash: session.identityHash, reason: session.reason,
    });
    return clone(session);
  }

  async function closeSession(sessionId, reason) {
    const session = requireSession(sessionId);
    session.closedAt = clock();
    session.closeReason = reason || 'closed';
    ledger.append('session.closed', { sessionId, reason: session.closeReason });
    return clone(session);
  }

  async function handoff(input) {
    const from = requireSession(input.fromSessionId);
    return act(sessionRequest(input.fromSessionId, from.agentId, 'handoff', {
      target: from.taskId,
      params: { sessionId: input.fromSessionId, toAgentId: input.toAgentId, reason: input.reason },
    }));
  }

  /** Approve an external action for a session. The approver must be a different agent. */
  async function approve(input) {
    const approverSession = requireSession(input.sessionId);
    const targetSession = requireSession(input.targetSessionId || input.sessionId);
    // An approval authorises a KIND of operation against a target, not just a target.
    const govTask = targetSession.taskId && governance.available ? governance.view(targetSession.taskId) : null;
    const kind = input.kind || (govTask && govTask.externalAction ? govTask.externalAction.kind : null);
    const approver = agents.get(approverSession.agentId);
    // Independence is decided by the SESSION's agent, not by the `approvedBy` string the caller
    // supplies: otherwise an agent satisfies the approval rule by typing somebody else's name.
    if (approverSession.agentId === targetSession.agentId) {
      throw new Refusal('SELF_APPROVAL', 'an agent may not approve its own external action');
    }
    // `approvedBy` stays a human-facing attribution string (unauthenticated - KNOWN-FINDINGS
    // F-GAR-08). What is now recorded alongside it is the AGENT that actually approved, so the
    // session-independence check above is a fact about sessions rather than a claim in a name.
    const submitted = await runtime.submit({
      sessionId: approverSession.sessionId,
      agentId: approverSession.agentId,
      taskId: targetSession.taskId,
      action: 'approve',
      target: targetSession.taskId,
      params: {
        sessionId: targetSession.sessionId,
        approvedBy: input.approvedBy,
        scope: input.scope,
        kind,
        expiresAt: input.expiresAt || null,
        approverRole: approver ? approver.roleId : null,
      },
    });
    if (!submitted.granted) return { receipt: submitted.receipt, executed: false };
    const result = await runtime.execute(submitted.grantId, {
      args: {
        sessionId: targetSession.sessionId,
        approvedBy: input.approvedBy,
        // The grant identifies who is really approving; the name above is only a label.
        approvedByAgent: approverSession.agentId,
        scope: input.scope,
        kind,
        expiresAt: input.expiresAt || null,
      },
    });
    return { receipt: submitted.receipt, executed: true, approval: result.result };
  }

  // ---------------------------------------------------------------- reads

  function systemFact(key) {
    return ledger.fact(key);
  }

  function taskState(taskId) {
    const task = requireTask(taskId);
    return { taskId: task.taskId, state: task.state, verificationId: task.verificationId };
  }

  function remember(input) {
    return memory.write(input);
  }

  function recall(agentId, key) {
    return memory.read(agentId, key);
  }

  /**
   * I18: governance state and runtime state must not silently diverge. This reports the classes of
   * divergence the prototype can actually check, rather than asserting full state mirroring.
   */
  function audit() {
    const divergences = [];
    const observations = [];
    const chain = ledger.verifyChain();
    if (!chain.ok) divergences.push({ code: 'LEDGER_TAMPERED', row: chain.brokenAt });
    for (const session of sessions.values()) {
      if (session.closedAt || session.supersededBy) continue;
      if (!governance.available) {
        divergences.push({ code: 'GOVERNANCE_UNAVAILABLE', sessionId: session.sessionId });
        break;
      }
      const view = governance.view(session.taskId);
      if (session.taskId && !view) {
        divergences.push({ code: 'GOVERNANCE_TASK_MISSING', sessionId: session.sessionId, taskId: session.taskId });
      }
      if (view && view.status === 'blocked') {
        divergences.push({ code: 'RUNTIME_RUNNING_A_BLOCKED_TASK', sessionId: session.sessionId, taskId: session.taskId });
      }
    }
    for (const task of tasks.values()) {
      if (task.state !== 'done') continue;
      const view = governance.view(task.taskId);
      if (!view) {
        divergences.push({ code: 'DONE_WITHOUT_GOVERNANCE_TASK', taskId: task.taskId });
        continue;
      }
      // DECLARED DUALITY, reported rather than hidden: evidence lives in the runtime ledger, while
      // the governance queue's own evidence array is only written by its stage machine. This
      // prototype does not drive that machine to completion, so the two stores disagree by design.
      // Closing it means advancing the governance stages from the runtime - the next phase, not a
      // silent "consistent: true".
      if ((view.evidence || []).length === 0) {
        observations.push({ code: 'EVIDENCE_STORE_DUALITY', detail: 'runtime ledger holds the evidence; the governance task has no stage-completed evidence' });
      }
      if (view.phase !== 'done' && task.state === 'done') {
        observations.push({ code: 'GOVERNANCE_STAGE_NOT_ADVANCED', detail: 'runtime state is done; governance phase is ' + view.phase });
      }
    }
    return {
      chain,
      divergences,
      observations,
      // Deliberately NOT called "consistent": it covers blocking divergences only. A field named
      // consistent that is true while observations record a real disagreement between the two
      // stores is the kind of over-claim this project exists to remove (finding C4).
      noBlockingDivergences: divergences.length === 0,
      note: 'noBlockingDivergences covers blocking divergences only; observations are the declared seam with the governance queue',
    };
  }

  /**
   * THE DEFAULT SURFACE IS READ-ONLY.
   *
   * This is not a stylistic choice. An independent verification round found that exposing the raw
   * ledger let a caller mint a legitimate grant with `issueGrant` and hand it straight to
   * `runtime.execute`: revalidate() passed every check, the executor ran, and NOT ONE policy
   * decision was recorded (finding C1). The same surface also allowed a forged
   * execution -> evidence -> verification -> fact chain (finding C2, closed in the ledger itself).
   *
   * Minting now lives behind `internals: true`, which the test fixture asks for because its
   * adversarial cases need to simulate an already-compromised process. The surface handed to a
   * runner - the thing an agent can reach - cannot mint anything.
   */
  function readOnlyLedger(l) {
    return Object.freeze({
      verifyChain: () => l.verifyChain(),
      rows: () => clone(l.rows),
      fact: (key) => l.fact(key),
      evidence: () => clone([...l.evidence.values()]),
      verifications: () => clone([...l.verifications.values()]),
      executions: () => clone([...l.executions.values()]),
      grants: () => clone([...l.grants.values()]),
    });
  }
  function readOnlyRegistry(r) {
    return Object.freeze({
      current: (id) => clone(r.current(id)),
      history: (id) => r.history(id),
      versionOf: (id, version) => clone(r.versionOf(id, version)),
    });
  }
  function readOnlyGovernance(g) {
    return Object.freeze({
      get available() { return g.available; },
      get error() { return g.error; },
      get path() { return g.path; },
      view: (taskId) => g.view(taskId),
    });
  }

  const exposeInternals = opts.internals === true;
  /** Present so a runner gets a loud refusal instead of silently missing a method. */
  function operatorOnly(name) {
    return function () {
      throw new Refusal('OPERATOR_SURFACE_REQUIRED',
        name + ' mints identity or trust and is an operator action; it is not on the runner-facing surface');
    };
  }
  const ledgerSurface = exposeInternals ? ledger : readOnlyLedger(ledger);
  const registrySurface = exposeInternals ? registry : readOnlyRegistry(registry);
  const memorySurface = exposeInternals ? memory : Object.freeze({ all: (agentId) => memory.all(agentId) });
  const governanceSurface = exposeInternals ? governance : readOnlyGovernance(governance);

  const api = {
    // wiring
    ledger: ledgerSurface,
    registry: registrySurface,
    memory: memorySurface,
    runtime,
    governance: governanceSurface,
    get governanceAvailable() { return governance.available; },

    // gate
    submit,
    execute,
    act,
    decide: (request) => decide(request).receipt,

    // artifacts and trust
    registerArtifact: exposeInternals ? registerArtifact : operatorOnly('registerArtifact'),
    evaluateArtifact,
    releaseArtifact: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId || null, action: 'release', target: input.artifactId, params: { by: input.by } }),
    promoteArtifact: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId || null, action: 'promote', target: input.artifactId, params: { approval: input.approval, by: input.by } }),
    rollbackArtifact: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId || null, action: 'rollback', target: input.artifactId, params: { toVersion: input.toVersion, by: input.by } }),
    revokeTrust: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId || null, action: 'revoke', target: input.artifactId, params: { reason: input.reason, by: input.by } }),
    mutateArtifact: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId || null, action: 'mutate_artifact', target: input.artifactId, params: { patch: input.patch, by: input.by || input.agentId } }),
    bootstrapTrust: exposeInternals ? bootstrapTrust : operatorOnly('bootstrapTrust'),
    artifact: (artifactId) => clone(registry.current(artifactId)),
    artifactHistory: (artifactId) => registry.history(artifactId),

    // agents, tasks, sessions
    // MINTING IDENTITY AND TRUST IS AN OPERATOR ACTION. Leaving these on the runner-facing object
    // let anyone holding it register a coordinator artifact, bootstrap its trust, mint a matching
    // agent and open a session - a complete bypass of the trust root (security scan, high).
    createAgent: exposeInternals ? createAgentFromArtifact : operatorOnly('createAgent'),
    agent: (agentId) => clone(requireAgent(agentId)),
    createTask,
    task: (taskId) => clone(requireTask(taskId)),
    openSession,
    closeSession,
    handoff,
    session: (sessionId) => clone(requireSession(sessionId)),

    // work
    produceEvidence: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId || null, action: 'produce_evidence', target: input.executionId, params: { ...input.params, executionId: input.executionId, agentId: input.agentId } }),
    verify: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId || null, action: 'verify', target: input.subjectExecutionId, params: { subjectExecutionId: input.subjectExecutionId, subjectAgentId: input.subjectAgentId, verdict: input.verdict, criteria: input.criteria, evidenceIds: input.evidenceIds, findings: input.findings, taskId: input.taskId } }),
    markDone: (input) => act({ sessionId: input.sessionId, agentId: input.agentId, taskId: input.taskId, action: 'mark_done', target: input.taskId, params: { taskId: input.taskId, agentId: input.agentId, verificationId: input.verificationId } }),
    approve,

    // reads
    systemFact,
    taskState,
    remember,
    recall,
    audit,
    externalCalls: () => clone(externalCalls),
    stats: () => ({ runtime: runtime.stats(), ledgerRows: ledger.rows.length }),
    describe: () => ({
      governanceAvailable: governance.available,
      governanceError: governance.error,
      invariants: ['I11', 'I12', 'I13', 'I14', 'I15', 'I16', 'I17'],
      effects: ['ALLOW', 'REQUIRE_VERIFICATION', 'REQUIRE_APPROVAL', 'DENY', 'BLOCK'],
      internalsExposed: exposeInternals,
      operatorSurfaceExposed: exposeInternals,
    }),
  };

  /**
   * Exactly what a runner would be handed: the gate, the gated work actions, reads and session
   * lifecycle - with identity/trust minting replaced by a loud refusal. This is the object the
   * security scan's high finding was about, so it can be tested directly instead of reasoned about.
   */
  /**
   * A session-scoped client: the gate and the work actions, with the session and the acting agent
   * fixed by construction. This is what a runner should hold instead of the control plane itself.
   */
  api.clientFor = function clientFor(sessionId) {
    const current = () => {
      const s = sessions.get(sessionId);
      if (!s) throw new Refusal('SESSION_UNKNOWN', 'no session ' + String(sessionId));
      return s;
    };
    const bound = (fn) => (input) => fn({ ...(input || {}), sessionId, agentId: current().agentId });
    return Object.freeze({
      sessionId,
      session: () => clone(current()),
      submit: (request) => submit({ ...request, sessionId, agentId: current().agentId }),
      execute,
      act: (request) => act({ ...request, sessionId, agentId: current().agentId }),
      produceEvidence: bound(api.produceEvidence),
      verify: bound(api.verify),
      markDone: bound(api.markDone),
      handoff: (input) => handoff({ ...(input || {}), fromSessionId: sessionId }),
      close: (reason) => closeSession(sessionId, reason),
      remember: (input) => remember({ ...input, agentId: current().agentId }),
      recall: (key) => recall(current().agentId, key),
      systemFact,
      taskState,
      audit,
    });
  };

  api.runnerSurface = function runnerSurface() {
    const view = {};
    for (const key of Object.keys(api)) view[key] = api[key];
    // The read-only views are rebuilt here rather than inherited: on a privileged control plane
    // api.ledger is the RAW ledger, and inheriting it would hand the runner exactly the minting
    // surface this view exists to withhold.
    view.ledger = readOnlyLedger(ledger);
    view.registry = readOnlyRegistry(registry);
    view.memory = Object.freeze({ all: (agentId) => memory.all(agentId) });
    view.governance = readOnlyGovernance(governance);
    view.registerArtifact = operatorOnly('registerArtifact');
    view.bootstrapTrust = operatorOnly('bootstrapTrust');
    view.createAgent = operatorOnly('createAgent');
    // Opening a session for an already-minted agent let ONE actor hold a verifier session and a
    // coordinator session at once, which made every "a different agent did it" check cosmetic
    // (security scan, high). Sessions are opened by the host; a runner gets a scoped client.
    view.openSession = operatorOnly('openSession');
    view.closeSession = operatorOnly('closeSession');
    view.describe = () => ({ ...api.describe(), internalsExposed: false, operatorSurfaceExposed: false });
    view.runnerSurface = () => Object.freeze({ ...view });
    return Object.freeze(view);
  };

  return api;
}

export { isAllowed };
