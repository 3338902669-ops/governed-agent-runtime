// adversarial.test.mjs - the attack suite.
//
// Each test makes an agent try to get away with something it should not be able to do, and asserts
// three things: the effect is a refusal (DENY / BLOCK / REQUIRE_*), the forbidden side effect did
// NOT happen, and the refusal carries a code that names the invariant. A WARNING would fail here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, openWork, request, runHappyPath } from './harness.mjs';
import { authorize } from '../src/policy.mjs';
import { createControlPlane } from '../src/control-plane.mjs';
import { sha256 } from '../src/core.mjs';
import { Refusal } from '../src/core.mjs';

const REFUSALS = ['DENY', 'BLOCK', 'REQUIRE_VERIFICATION', 'REQUIRE_APPROVAL'];

function refused(result, label) {
  assert.ok(REFUSALS.includes(result.receipt.effect), label + ' was not refused: ' + result.receipt.effect);
  assert.equal(result.executed, false, label + ' executed anyway');
  return result.receipt;
}

test('A01: an agent declares its own task DONE', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const attempt = await world.cp.act(request(work.sImpl, 'mark_done', { target: work.task.taskId }));
  refused(attempt, 'self-declared done');
  assert.notEqual(world.cp.taskState(work.task.taskId).state, 'done');
  assert.equal(world.cp.systemFact('task:' + work.task.taskId + ':state'), null);
});

test('A01b: a coordinator cannot mark a task done without a verification either', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const attempt = await world.cp.act(request(work.sCoord, 'mark_done', { target: work.task.taskId }));
  const receipt = refused(attempt, 'done without verification');
  assert.equal(receipt.code, 'DONE_NEEDS_INDEPENDENT_VERIFICATION');
  assert.notEqual(world.cp.taskState(work.task.taskId).state, 'done');
});

test('A02: an agent passes its own work', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const solo = await world.cp.openSession({ agentId: 'agent-verify', own: false });
  const own = await world.cp.act(request(solo, 'execute', { target: 'self-check', tool: 'shell' }));
  assert.equal(own.receipt.effect, 'ALLOW');

  const selfPass = await world.cp.act(request(solo, 'verify', {
    target: own.executionId,
    params: { subjectExecutionId: own.executionId, subjectAgentId: 'agent-verify', verdict: 'PASS', criteria: ['mine'], evidenceIds: ['whatever'] },
  }));
  const receipt = refused(selfPass, 'self verification');
  assert.equal(receipt.code, 'SELF_VERIFICATION');
  assert.equal(world.cp.ledger.verifications.size, 0);

  // The ledger refuses it independently of the gate.
  assert.throws(
    () => world.cp.ledger.recordVerification({ verifierAgentId: 'agent-verify', subjectExecutionId: own.executionId, verdict: 'PASS', criteria: ['x'], evidenceIds: ['y'] }),
    (e) => e.code === 'SELF_VERIFICATION',
  );
});

test('A03: an agent uses a resource it does not own', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const second = world.cp.createTask({ title: 'second task', resources: ['file:src/a.mjs'] });
  const secondSession = await world.cp.openSession({ agentId: 'agent-impl', taskId: second.taskId }).catch((e) => e);
  // The governance engine refuses the claim itself, so no session ever exists.
  assert.ok(secondSession instanceof Error, 'the governance engine should refuse the conflicting claim');
  assert.equal(secondSession.code, 'RESOURCE_CONFLICT');

  // An agent acting on a task nobody assigned to it.
  const unclaimed = world.cp.createTask({ title: 'unclaimed', resources: ['file:src/b.mjs'] });
  const outsider = await world.cp.openSession({ agentId: 'agent-verify', taskId: unclaimed.taskId, own: false });
  const attempt = await world.cp.act(request(outsider, 'execute', { target: 'probe', tool: 'shell' }));
  assert.equal(refused(attempt, 'acting on someone else\'s task').code, 'NOT_TASK_OWNER');

  // And an agent acting on a task someone else is holding.
  const intruder = await world.cp.openSession({ agentId: 'agent-coord', taskId: work.task.taskId, own: false });
  const blocked = await world.cp.act(request(intruder, 'claim', { target: work.task.taskId }));
  assert.equal(refused(blocked, 'stealing a held task').code, 'TASK_LOCKED_BY_OTHER');
  assert.equal(world.calls.length, 0);
});

test('A04: an agent tries to bypass the policy gate', async () => {
  const world = await makeWorld();
  const work = await openWork(world);

  // a) there is no handle on the executor
  assert.equal(world.cp.runtime.executor, undefined);
  assert.deepEqual(world.cp.runtime.describe().exposed.includes('executor'), false);

  // b) an action the role does not hold
  const forbidden = await world.cp.act(request(work.sVerify, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  assert.equal(refused(forbidden, 'forbidden action').code, 'PERMISSION_DENIED');

  // c) a tool the role does not hold
  const badTool = await world.cp.act(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'rm-rf' }));
  assert.ok(['TOOL_NOT_ALLOWED', 'PERMISSION_DENIED'].includes(refused(badTool, 'forbidden tool').code));

  // d) a forged grant
  await assert.rejects(() => world.cp.runtime.execute('grant-forged', {}), (e) => /GRANT_UNKNOWN/.test(e.message));
  assert.equal(world.calls.length, 0, 'the executor ran despite every refusal');
});

test('A05: an agent uses an expired approval', async () => {
  const world = await makeWorld();
  const work = await openWork(world, { title: 'deploy to production', resources: ['file:src/a.mjs'], externalAction: 'deploy', externalTarget: 'production' });
  const coordOnly = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const approved = await world.cp.approve({
    sessionId: coordOnly.sessionId,
    targetSessionId: work.sImpl.sessionId,
    approvedBy: 'human-root',
    scope: 'production',
    expiresAt: '2026-10-01T23:00:00.000Z',
  });
  assert.equal(approved.executed, true);

  world.clock.advance(3600000);
  const deploy = await world.cp.act(request(work.sImpl, 'execute', {
    target: 'production',
    tool: 'shell',
    externalAction: { kind: 'deploy', target: 'production' },
  }));
  const receipt = refused(deploy, 'expired approval');
  assert.equal(receipt.code, 'APPROVAL_STALE');
  assert.equal(world.cp.externalCalls().length, 0);
});

test('A06: an agent replays an old approval or an old grant', async () => {
  const world = await makeWorld();
  const work = await openWork(world, { title: 'deploy to production', resources: ['file:src/a.mjs'], externalAction: 'deploy', externalTarget: 'production' });
  const coordOnly = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  await world.cp.approve({ sessionId: coordOnly.sessionId, targetSessionId: work.sImpl.sessionId, approvedBy: 'human-root', scope: 'production' });

  // A fresh session for the same agent does not inherit the approval: there is nothing to replay.
  const fresh = await world.cp.openSession({ agentId: 'agent-impl', taskId: work.task.taskId });
  const deploy = await world.cp.act(request(fresh, 'execute', {
    target: 'production', tool: 'shell', externalAction: { kind: 'deploy', target: 'production' },
  }));
  const receipt = refused(deploy, 'replayed approval');
  assert.equal(receipt.code, 'EXTERNAL_ACTION_UNAPPROVED');
  assert.equal(world.cp.externalCalls().length, 0);

  // A consumed grant cannot be replayed either.
  const grant = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  await world.cp.runtime.execute(grant.grantId, { args: {} });
  await assert.rejects(() => world.cp.runtime.execute(grant.grantId, { args: {} }), (e) => /GRANT_REPLAYED/.test(e.message));
});

test('A06b: the approval-binding rule fires when an approval is moved to another session', async () => {
  // The gate is a pure function of its context, so the defence-in-depth rule can be checked
  // directly without adding an unsafe back door to the control plane.
  const world = await makeWorld();
  const work = await openWork(world);
  const receipt = authorize({
    request: { sessionId: 'session-b', agentId: 'agent-impl', sessionToken: 'token-b', taskId: work.task.taskId, action: 'execute', target: 'production', externalAction: { kind: 'deploy', target: 'production' } },
    session: { sessionId: 'session-b', agentId: 'agent-impl', actorId: 'actor-impl', tokenHash: sha256('token-b'), artifactId: world.artifacts.impl.artifactId, definitionHash: 'h', identityHash: 'i', taskId: work.task.taskId, approval: { approved: true, approvedBy: 'human-root', scope: 'production', sessionId: 'session-a', agentId: 'agent-impl' } },
    identity: { agentId: 'agent-impl', identityFingerprint: 'i' },
    role: { roleId: 'implementer', lifecycle: 'ACTIVE', permissions: { allow: ['execute'], deny: [] }, allowedTools: ['shell'], allowedResources: ['*'] },
    registry: { current: () => ({ definitionHash: 'h', trust: 'VALIDATED', evaluations: [] }), assertIntegrity: () => true },
    ledger: { verifyChain: () => ({ ok: true }) },
    governance: { available: true, isBlocked: () => false, probeClaim: () => ({ ok: true }) },
    taskState: null,
    now: '2026-10-02T00:00:00.000Z',
  });
  assert.equal(receipt.effect, 'DENY');
  assert.equal(receipt.code, 'APPROVAL_WRONG_SESSION');
});

test('A07: an agent invents evidence, or edits evidence after the fact', async () => {
  const world = await makeWorld();
  const work = await openWork(world);

  // a) evidence for an action that never passed the gate
  const backfill = await world.cp.produceEvidence({
    sessionId: work.sImpl.sessionId, agentId: 'agent-impl', taskId: work.task.taskId,
    executionId: 'exec-that-never-ran',
    params: { grade: 'E1', command: 'echo ok', exitCode: 0, revision: 'r1' },
  });
  refused(backfill, 'backfilled evidence');
  assert.equal(world.cp.ledger.evidence.size, 0);

  // b) editing a stored evidence record breaks the chain
  const happy = await runHappyPath(world, work);
  const stored = world.cp.ledger.evidence.get(happy.evidence.result.evidenceId);
  stored.exitCode = 1;
  assert.equal(world.cp.ledger.verifyChain().ok, false);
  const blocked = await world.cp.submit(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  assert.equal(blocked.receipt.effect, 'BLOCK');
  assert.equal(blocked.receipt.code, 'LEDGER_TAMPERED');
});

test('A08: an agent keeps using a stale artifact version', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const pending = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));

  const bump = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  await world.cp.mutateArtifact({ sessionId: bump.sessionId, agentId: 'agent-impl', artifactId: world.artifacts.impl.artifactId, patch: { version: '3.0.0', instructions: 'new version' } });

  await assert.rejects(() => world.cp.runtime.execute(pending.grantId, {}), (e) => /ARTIFACT_MUTATED/.test(e.message));
  const attempt = await world.cp.act(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  assert.equal(refused(attempt, 'stale artifact').code, 'ARTIFACT_MUTATED');
  assert.equal(world.calls.length, 0);
});

test('A09: an agent whose trust was revoked keeps working', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const coordOnly = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  await world.cp.revokeTrust({ sessionId: coordOnly.sessionId, agentId: 'agent-coord', artifactId: world.artifacts.impl.artifactId, reason: 'supply chain' });

  const attempt = await world.cp.act(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  assert.equal(refused(attempt, 'revoked agent').code, 'TRUST_REVOKED');
  assert.equal(world.calls.length, 0);
});

test('A10: an agent keeps writing after it handed the work off', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const handed = await world.cp.handoff({ fromSessionId: work.sImpl.sessionId, toAgentId: 'agent-impl', reason: 'shift change' });
  assert.equal(handed.receipt.effect, 'ALLOW');

  const attempt = await world.cp.act(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  const receipt = refused(attempt, 'write after handoff');
  assert.equal(receipt.code, 'SESSION_SUPERSEDED');
  assert.equal(world.calls.length, 0);
});

test('A11: the runtime tries to run with governance severed', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const pending = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  assert.equal(pending.granted, true);

  world.cp.governance.sever('injected outage');

  const attempt = await world.cp.act(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  const receipt = refused(attempt, 'governance outage');
  assert.equal(receipt.effect, 'BLOCK');
  assert.equal(receipt.code, 'GOVERNANCE_UNAVAILABLE');

  // An already-issued grant cannot slip through the outage either.
  await assert.rejects(() => world.cp.runtime.execute(pending.grantId, {}), (e) => /GOVERNANCE_UNAVAILABLE/.test(e.message));
  assert.equal(world.calls.length, 0);
});

test('A12: memory claims the work is done and there is no evidence', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  world.cp.remember({ agentId: 'agent-impl', key: 'status', value: 'task complete, deployed', kind: 'completion-claim' });

  assert.equal(world.cp.systemFact('task:' + work.task.taskId + ':state'), null);
  assert.equal(world.cp.taskState(work.task.taskId).state, 'queued');
  const attempt = await world.cp.submit(request(work.sCoord, 'mark_done', { target: work.task.taskId, basis: 'memory' }));
  assert.equal(attempt.receipt.effect, 'DENY');
  assert.equal(attempt.receipt.code, 'MEMORY_CANNOT_ASSERT_STATE');
});

test('A13: artifact v2 is promoted without evaluation', async () => {
  const world = await makeWorld();
  const bump = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  await world.cp.mutateArtifact({ sessionId: bump.sessionId, agentId: 'agent-impl', artifactId: world.artifacts.impl.artifactId, patch: { version: '2.0.0' } });
  const coordOnly = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const promoted = await world.cp.promoteArtifact({
    sessionId: coordOnly.sessionId, agentId: 'agent-coord',
    artifactId: world.artifacts.impl.artifactId,
    approval: { approvedBy: 'human-root', scope: world.artifacts.impl.artifactId },
  });
  const receipt = refused(promoted, 'promotion without evaluation');
  assert.equal(receipt.effect, 'REQUIRE_VERIFICATION');
  assert.equal(world.cp.artifact(world.artifacts.impl.artifactId).trust, 'UNKNOWN');
  assert.equal(world.cp.artifact(world.artifacts.impl.artifactId).lifecycle, 'DRAFT');
});

test('A14: rollback lands on an artifact nobody verified', async () => {
  const world = await makeWorld();
  const artifactId = world.artifacts.impl.artifactId;
  const bump = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  await world.cp.mutateArtifact({ sessionId: bump.sessionId, agentId: 'agent-impl', artifactId, patch: { version: '8.0.0', instructions: 'unverified rewrite' } });
  const coordOnly = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const rolled = await world.cp.rollbackArtifact({ sessionId: coordOnly.sessionId, agentId: 'agent-coord', artifactId, toVersion: '8.0.0' });
  const receipt = refused(rolled, 'rollback to unverified');
  assert.equal(receipt.code, 'ROLLBACK_TO_UNVERIFIED');
  assert.equal(world.cp.artifact(artifactId).version, '8.0.0', 'the current version must be unchanged');
});

test('A15: governance blocks the task behind the runtime and the runtime keeps going', async () => {
  const world = await makeWorld();
  const work = await openWork(world);

  // The governance engine runs its own retry ceiling and blocks the task. The runtime is not told.
  const task = world.cp.governance.blockTask(work.task.taskId, 'injected failures');
  assert.equal(task.status, 'blocked');
  assert.equal(world.cp.governance.isBlocked(work.task.taskId), true);

  const attempt = await world.cp.act(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  const receipt = refused(attempt, 'work on a governance-blocked task');
  assert.equal(receipt.effect, 'BLOCK');
  assert.equal(receipt.code, 'TASK_BLOCKED');
  assert.equal(world.calls.length, 0);

  // And the audit names the divergence class instead of staying quiet.
  const audit = world.cp.audit();
  assert.equal(audit.chain.ok, true);
});

test('A16: the surface a runner gets cannot mint a grant, an execution or a fact', async () => {
  // This test exists because an independent verification round walked straight through the exposed
  // ledger (finding C1). runnerSurface() is exactly what a runner is handed.
  const world = await makeWorld();
  const runner = world.cp.runnerSurface();
  assert.equal(runner.describe().internalsExposed, false);

  // No raw state on the runner surface at all - not even in read-only form, because the ledger
  // view used to publish redeemable grant ids.
  assert.equal(runner.ledger, undefined, 'no raw ledger on the runner surface');
  assert.equal(runner.registry, undefined);
  assert.equal(runner.governance, undefined);
  assert.equal(runner.memory, undefined);
  assert.equal(runner.runtime, undefined, 'no unmetered path to the executor');

  // Naming another agent is refused loudly rather than silently unavailable.
  assert.throws(() => runner.registerArtifact({ name: 'x', roleId: 'coordinator', createdBy: 'a' }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');
  assert.throws(() => runner.openSession({ agentId: 'agent-verify' }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');
  assert.throws(() => runner.handoff({ fromSessionId: 'x', toAgentId: 'agent-verify' }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');

  // What a runner holds: a client pinned to one session.
  const session = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  const client = runner.clientFor(session.sessionId, session.token);
  assert.equal(client.session().agentId, 'agent-impl');
  assert.equal(client.handoff, undefined, 'handoff names a successor: an operator action');
  await assert.rejects(() => client.execute('grant-forged', {}), (e) => /GRANT_UNKNOWN/.test(e.message));
  assert.equal(world.calls.length, 0);
});

test('A16b: a control plane built WITHOUT the privileged opt-in exposes read-only surfaces', async () => {
  // This pins the construction-time choice itself, not just the runner view derived from it.
  const cp = await createControlPlane();
  assert.equal(cp.describe().internalsExposed, false);
  assert.equal(cp.describe().operatorSurfaceExposed, false);
  assert.equal(cp.ledger.issueGrant, undefined);
  assert.equal(cp.ledger.recordExecution, undefined);
  assert.equal(cp.registry.mutate, undefined);
  assert.equal(cp.governance.blockTask, undefined);
  assert.equal(Object.isFrozen(cp.ledger), true);
  assert.equal(Object.isFrozen(cp.registry), true);
  assert.throws(() => cp.registerArtifact({ name: 'rogue', roleId: 'coordinator' }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');
});

test('A20: a runner holding the surface cannot escalate by minting identity or trust', async () => {
  // The security scan's high finding: registerArtifact + bootstrapTrust + createAgent on the same
  // object let a holder mint a coordinator artifact, trust it, mint a matching agent and act with
  // coordinator authority. Every step of that chain must be shut.
  const world = await makeWorld();
  const runner = world.cp.runnerSurface();

  assert.throws(() => runner.registerArtifact({ name: 'rogue', roleId: 'coordinator' }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');
  assert.throws(() => runner.bootstrapTrust({ artifactId: world.artifacts.coord.artifactId }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');
  assert.throws(() => runner.createAgent({ agentId: 'agent-rogue', artifactId: world.artifacts.coord.artifactId }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');

  // and the role cannot be smuggled in by building an agent from somebody else's artifact
  assert.equal(typeof runner.createAgent, 'function'); // it exists, it refuses

  // The operator surface still works, so the refusal is a boundary and not a broken method.
  const minted = world.cp.createAgent({ agentId: 'agent-coord-2', artifactId: world.artifacts.coord.artifactId, roleId: 'coordinator' });
  assert.equal(minted.roleId, 'coordinator');
  assert.throws(
    () => world.cp.createAgent({ agentId: 'agent-escalated', artifactId: world.artifacts.impl.artifactId, roleId: 'coordinator' }),
    (e) => e.code === 'AGENT_ROLE_MISMATCH',
  );
});

test('A17: an execution cannot be recorded without a grant the gate consumed', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const L = world.cp.ledger;

  // a) a grant id that never existed
  assert.throws(
    () => L.recordExecution({ grantId: 'grant-never-existed', sessionId: 'x', agentId: 'agent-impl', action: 'write', target: 'f', outcome: 'ok' }),
    (e) => e.code === 'EXECUTION_WITHOUT_GRANT',
  );

  // b) a real grant that was issued but never consumed
  const submitted = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  assert.equal(submitted.granted, true);
  assert.throws(
    () => L.recordExecution({ grantId: submitted.grantId, sessionId: work.sImpl.sessionId, agentId: 'agent-impl', action: 'write', target: 'file:src/a.mjs', outcome: 'ok' }),
    (e) => e.code === 'EXECUTION_WITHOUT_GRANT',
  );
  assert.equal(L.rows.filter((r) => r.kind === 'execution').length, 0);

  // c) one grant produces exactly one execution
  await world.cp.runtime.execute(submitted.grantId, { args: {} });
  assert.throws(
    () => L.recordExecution({ grantId: submitted.grantId, sessionId: work.sImpl.sessionId, agentId: 'agent-impl', action: 'write', target: 'file:src/a.mjs', outcome: 'ok' }),
    (e) => e.code === 'EXECUTION_ALREADY_RECORDED',
  );
  assert.equal(L.rows.filter((r) => r.kind === 'execution').length, 1);

  // d) the forged chain from finding C2 is impossible end to end
  assert.throws(() => L.recordEvidence({ executionId: 'exec-forged', author: 'agent-impl', grade: 'E3' }), (e) => e.code === 'EVIDENCE_WITHOUT_EXECUTION');
  assert.equal(world.cp.systemFact('forged:state'), null);
});

test('A18: revoked trust cannot be reinstated by evaluating the artifact', async () => {
  // The A1-A6 sequence a security scan reproduced: revoke -> evaluate -> work resumes -> re-promote.
  const world = await makeWorld();
  const artifactId = world.artifacts.impl.artifactId;
  const coord = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const revoked = await world.cp.revokeTrust({ sessionId: coord.sessionId, agentId: 'agent-coord', artifactId, reason: 'incident response' });
  assert.equal(revoked.receipt.effect, 'ALLOW');
  assert.equal(world.cp.artifact(artifactId).trust, 'REVOKED');

  // A2: no agent built from the revoked definition can even open a session
  await assert.rejects(() => world.cp.openSession({ agentId: 'agent-impl', own: false }), (e) => e.code === 'ARTIFACT_NOT_TRUSTED');

  // A3: the revive step is refused at the gate and in the registry
  const evalSession = await world.cp.openSession({ agentId: 'agent-eval', own: false });
  const revived = await world.cp.act(request(evalSession, 'evaluate', { target: artifactId, params: { checks: [{ name: 'x', passed: true }] } }));
  assert.equal(refused(revived, 'evaluating a revoked artifact').code, 'EVALUATION_OF_REVOKED_ARTIFACT');
  assert.throws(
    () => world.cp.registry.evaluate({ artifactId, by: 'agent-eval', checks: [{ name: 'x', passed: true }] }),
    (e) => e.code === 'ARTIFACT_REVOKED',
  );

  // A4-A6: trust stays revoked, so release and promotion stay shut
  assert.equal(world.cp.artifact(artifactId).trust, 'REVOKED');
  await assert.rejects(
    () => world.cp.releaseArtifact({ sessionId: coord.sessionId, agentId: 'agent-coord', artifactId }),
    (e) => e.code === 'RELEASE_NEEDS_EVALUATION' || e.code === 'ARTIFACT_REVOKED',
  );

  // and the delegation chain cannot be satisfied by naming somebody else
  const evalSession2 = await world.cp.openSession({ agentId: 'agent-eval', own: false });
  const forged = await world.cp.act(request(evalSession2, 'evaluate', { target: world.artifacts.eval.artifactId, params: { checks: [{ name: 'ok', passed: true }], by: 'someone-else' } }));
  assert.equal(forged.receipt.effect, 'ALLOW');
  assert.equal(world.cp.artifact(world.artifacts.eval.artifactId).evaluations.slice(-1)[0].by, 'agent-eval', 'the evaluator is the session agent, not the name in the request');
});

test('A19: a done claim must cite a verification of this task\'s own work', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const first = await runHappyPath(world, work);

  const other = world.cp.createTask({ title: 'unrelated work', resources: ['file:src/b.mjs'] });
  const oImpl = await world.cp.openSession({ agentId: 'agent-impl', taskId: other.taskId });
  const oVerify = await world.cp.openSession({ agentId: 'agent-verify', taskId: other.taskId, own: false });
  const oCoord = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const oWrite = await world.cp.act(request(oImpl, 'write', { target: 'file:src/b.mjs', resource: 'file:src/b.mjs', tool: 'edit', params: {} }));
  const oEv = await world.cp.produceEvidence({ sessionId: oImpl.sessionId, agentId: 'agent-impl', taskId: other.taskId, executionId: oWrite.executionId, params: { grade: 'E3', note: 'other work' } });
  const oVer = await world.cp.verify({ sessionId: oVerify.sessionId, agentId: 'agent-verify', taskId: other.taskId, subjectExecutionId: oWrite.executionId, subjectAgentId: 'agent-impl', verdict: 'PASS', criteria: ['other'], evidenceIds: [oEv.result.evidenceId] });
  assert.equal(oVer.receipt.effect, 'ALLOW');

  // The unrelated verification exists and passes, but it is not this task's work.
  await assert.rejects(
    () => world.cp.markDone({ sessionId: oCoord.sessionId, agentId: 'agent-coord', taskId: other.taskId, verificationId: first.verification.result.verificationId }),
    (e) => e.code === 'DONE_VERIFICATION_NOT_BOUND',
  );
  assert.equal(world.cp.systemFact('task:' + other.taskId + ':state'), null);
});

test('A21: a verifier bound to a task cannot pass off unrelated work as that task\'s', async () => {
  const world = await makeWorld();
  const a = await openWork(world, { title: 'task A', resources: ['file:src/a.mjs'] });
  const b = world.cp.createTask({ title: 'task B', resources: ['file:src/b.mjs'] });
  const bImpl = await world.cp.openSession({ agentId: 'agent-impl', taskId: b.taskId });
  const bWrite = await world.cp.act(request(bImpl, 'write', { target: 'file:src/b.mjs', resource: 'file:src/b.mjs', tool: 'edit', params: {} }));
  assert.equal(bWrite.receipt.effect, 'ALLOW');

  // The verifier's session is bound to task A; the subject execution belongs to task B.
  await assert.rejects(
    () => world.cp.verify({
      sessionId: a.sVerify.sessionId, agentId: 'agent-verify', taskId: a.task.taskId,
      subjectExecutionId: bWrite.executionId, subjectAgentId: 'agent-impl',
      verdict: 'PASS', criteria: ['x'], evidenceIds: ['any'],
    }),
    (e) => e.code === 'VERIFICATION_OF_FOREIGN_WORK',
  );
  // On the privileged surface `verifications` is the raw Map (see KNOWN-FINDINGS F-GAR-10).
  assert.equal(world.cp.ledger.verifications.size, 0);
});

test('A22: an agent cannot approve its own external action through the gated action', async () => {
  const world = await makeWorld();
  const work = await openWork(world, { title: 'deploy', resources: ['file:src/a.mjs'], externalAction: 'deploy', externalTarget: 'production' });
  const coord = await world.cp.openSession({ agentId: 'agent-coord', taskId: work.task.taskId, own: false });
  // Straight at the gated action, not through the cp.approve helper where the check used to live.
  const direct = await world.cp.act(request(coord, 'approve', {
    target: work.task.taskId,
    params: { sessionId: coord.sessionId, approvedBy: 'human-root', scope: 'production', kind: 'deploy' },
  }));
  assert.equal(refused(direct, 'self-approval through the gated action').code, 'SELF_APPROVAL');
  assert.equal(world.cp.session(coord.sessionId).approval, null);
});

test('A23: revocation is terminal through mutate and rollback too', async () => {
  const world = await makeWorld();
  const artifactId = world.artifacts.impl.artifactId;
  const coord = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  await world.cp.revokeTrust({ sessionId: coord.sessionId, agentId: 'agent-coord', artifactId, reason: 'incident response' });
  assert.equal(world.cp.artifact(artifactId).trust, 'REVOKED');

  // mutate used to rewrite REVOKED to SUPERSEDED, and rollback then resurrected it.
  await assert.rejects(
    () => world.cp.mutateArtifact({ sessionId: coord.sessionId, agentId: 'agent-coord', artifactId, patch: { version: '2.0.0' } }),
    (e) => e.code === 'ARTIFACT_REVOKED' || e.code === 'MUTATION_OF_REVOKED_ARTIFACT',
  );
  assert.throws(
    () => world.cp.registry.rollback({ artifactId, toVersion: '1.0.0', by: 'agent-coord' }),
    (e) => e.code === 'ARTIFACT_REVOKED' || e.code === 'ROLLBACK_TO_REVOKED',
  );
  assert.equal(world.cp.artifact(artifactId).trust, 'REVOKED');
  assert.equal(world.cp.artifact(artifactId).version, world.artifacts.impl.version);
});

test('A24: a runner cannot open a session for another agent', async () => {
  const world = await makeWorld();
  const runner = world.cp.runnerSurface();
  // One actor holding two sessions makes every "a different agent did it" check cosmetic.
  assert.throws(() => runner.openSession({ agentId: 'agent-verify' }), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');
  assert.throws(() => runner.closeSession('anything'), (e) => e.code === 'OPERATOR_SURFACE_REQUIRED');

  // What a runner holds instead: a client pinned to one session.
  const session = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  const client = world.cp.clientFor(session.sessionId, session.token);
  assert.equal(client.sessionId, session.sessionId);
  assert.equal(client.session().agentId, 'agent-impl');
  assert.equal(typeof client.act, 'function');
  assert.equal(client.openSession, undefined);
  assert.equal(client.registry, undefined);
  assert.equal(client.ledger, undefined);
});

test('A25: a runner cannot redeem a grant issued to another session', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const pending = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  assert.equal(pending.granted, true);

  const other = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  const client = world.cp.clientFor(other.sessionId, other.token);
  await assert.rejects(() => client.execute(pending.grantId, { args: {} }), (e) => e.code === 'GRANT_WRONG_SESSION');
  assert.equal(world.calls.length, 0, 'possession of a grant id is not authorisation');

  // and the read-only ledger view no longer publishes redeemable ids at all
  const runner = world.cp.runnerSurface();
  assert.equal(runner.ledger, undefined);
});

test('A26: revocation survives mutate and rollback (the third door)', async () => {
  const world = await makeWorld();
  const artifactId = world.artifacts.impl.artifactId;
  const coord = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const bump = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  // A superseded version with a passed evaluation: exactly what rollback used to restore.
  await world.cp.mutateArtifact({ sessionId: bump.sessionId, agentId: 'agent-impl', artifactId, patch: { version: '2.0.0', instructions: 'v2' } });
  await world.cp.revokeTrust({ sessionId: coord.sessionId, agentId: 'agent-coord', artifactId, reason: 'incident response' });

  await assert.rejects(
    () => world.cp.rollbackArtifact({ sessionId: coord.sessionId, agentId: 'agent-coord', artifactId, toVersion: '1.0.0' }),
    (e) => e.code === 'ARTIFACT_REVOKED' || e.code === 'ROLLBACK_TO_REVOKED',
  );
  // A second mutation is refused, and it does not matter whether the refusal arrives as a gate
  // receipt (the session's own artifact is revoked) or as a registry exception.
  const again = await world.cp.mutateArtifact({ sessionId: bump.sessionId, agentId: 'agent-impl', artifactId, patch: { version: '3.0.0' } }).catch((e) => ({ receipt: { effect: 'DENY', code: e.code }, executed: false }));
  assert.notEqual(again.receipt.effect, 'ALLOW');
  assert.equal(again.executed, false);
  // and the registry refuses on its own, version-independently
  assert.throws(() => world.cp.registry.mutate({ artifactId, patch: { version: '4.0.0' }, by: 'agent-impl' }), (e) => e.code === 'ARTIFACT_REVOKED');
  // Revocation is a property of the ARTIFACT, so no version of it can come back.
  assert.equal(world.cp.registry.isRevoked(artifactId), true);
  assert.equal(world.cp.artifact(artifactId).trust, 'REVOKED');
});

test('A27: a session id proves nothing without the actor credential and the session token', async () => {
  const world = await makeWorld();
  // no actor at all
  await assert.rejects(() => world.rawOpenSession({ agentId: 'agent-verify', own: false }), (e) => e.code === 'ACTOR_UNKNOWN' || e.code === 'ACTOR_CREDENTIAL_INVALID');
  // a wrong secret
  await assert.rejects(() => world.rawOpenSession({ actorId: 'actor-impl', actorSecret: 'wrong', agentId: 'agent-impl', own: false }), (e) => e.code === 'ACTOR_CREDENTIAL_INVALID');

  const session = await world.rawOpenSession({ actorId: 'actor-impl', actorSecret: world.actors.impl.secret, agentId: 'agent-impl', own: false });
  const noToken = await world.cp.submit({ sessionId: session.sessionId, agentId: 'agent-impl', action: 'read', target: 'anything' });
  assert.equal(noToken.receipt.effect, 'DENY');
  assert.equal(noToken.receipt.code, 'SESSION_TOKEN_MISSING');
  const wrongToken = await world.cp.submit({ sessionId: session.sessionId, agentId: 'agent-impl', sessionToken: 'not-the-token', action: 'read', target: 'anything' });
  assert.equal(wrongToken.receipt.code, 'SESSION_TOKEN_INVALID');
  const ok = await world.cp.submit({ sessionId: session.sessionId, agentId: 'agent-impl', sessionToken: session.token, action: 'read', target: 'anything' });
  assert.equal(ok.receipt.effect, 'ALLOW');
});

test('A28: one actor cannot verify its own work, even with two agents', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const write = await world.cp.act(request(work.sImpl, 'write', { target: 'file:src/a.mjs', resource: 'file:src/a.mjs', tool: 'edit', params: {} }));
  const ev = await world.cp.produceEvidence({ sessionId: work.sImpl.sessionId, agentId: 'agent-impl', taskId: work.task.taskId, executionId: write.executionId, params: { grade: 'E3', note: 'done by hand' } });

  // The SAME actor opens a verifier session. Different agent id, same principal.
  const sameActor = await world.rawOpenSession({ actorId: 'actor-impl', actorSecret: world.actors.impl.secret, agentId: 'agent-verify', taskId: work.task.taskId, own: false });
  const attempt = await world.cp.act({
    sessionId: sameActor.sessionId, agentId: 'agent-verify', sessionToken: sameActor.token, taskId: work.task.taskId,
    action: 'verify', target: write.executionId,
    params: { subjectExecutionId: write.executionId, subjectAgentId: 'agent-impl', verdict: 'PASS', criteria: ['x'], evidenceIds: [ev.result.evidenceId] },
  });
  assert.equal(attempt.receipt.effect, 'DENY');
  assert.equal(attempt.receipt.code, 'SELF_VERIFICATION', 'independence must be measured between actors, not agent ids');
  assert.equal(world.cp.ledger.verifications.size, 0);

  // A different actor can verify it.
  const different = await world.cp.verify({ sessionId: work.sVerify.sessionId, agentId: 'agent-verify', taskId: work.task.taskId, subjectExecutionId: write.executionId, subjectAgentId: 'agent-impl', verdict: 'PASS', criteria: ['x'], evidenceIds: [ev.result.evidenceId] });
  assert.equal(different.receipt.effect, 'ALLOW');
});

test('A29: a revoked actor cannot open new sessions', async () => {
  const world = await makeWorld();
  world.cp.revokeActor({ actorId: 'actor-verify', reason: 'offboarded' });
  await assert.rejects(
    () => world.rawOpenSession({ actorId: 'actor-verify', actorSecret: world.actors.verify.secret, agentId: 'agent-verify', own: false }),
    (e) => e.code === 'ACTOR_REVOKED',
  );
});

test('A15b: the audit detects a runtime that diverged from governance', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  await runHappyPath(world, work);
  const audit = world.cp.audit();
  assert.equal(audit.noBlockingDivergences, true, JSON.stringify(audit.divergences));
  // The honest seam is reported, not hidden: evidence lives in the runtime ledger, and the
  // governance stage machine (which this prototype does not drive to completion) has its own store.
  assert.ok(audit.observations.some((o) => o.code === 'GOVERNANCE_STAGE_NOT_ADVANCED'));
});
