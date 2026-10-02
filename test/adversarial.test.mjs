// adversarial.test.mjs - the attack suite.
//
// Each test makes an agent try to get away with something it should not be able to do, and asserts
// three things: the effect is a refusal (DENY / BLOCK / REQUIRE_*), the forbidden side effect did
// NOT happen, and the refusal carries a code that names the invariant. A WARNING would fail here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, openWork, request, runHappyPath } from './harness.mjs';
import { authorize } from '../src/policy.mjs';
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
    request: { sessionId: 'session-b', agentId: 'agent-impl', taskId: work.task.taskId, action: 'execute', target: 'production', externalAction: { kind: 'deploy', target: 'production' } },
    session: { sessionId: 'session-b', agentId: 'agent-impl', artifactId: world.artifacts.impl.artifactId, definitionHash: 'h', identityHash: 'i', taskId: work.task.taskId, approval: { approved: true, approvedBy: 'human-root', scope: 'production', sessionId: 'session-a', agentId: 'agent-impl' } },
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
  // Default surface: internals are NOT attached. This test exists because an independent
  // verification round walked straight through the exposed ledger (finding C1).
  const world = await makeWorld({ internals: false });
  await openWork(world);
  assert.equal(world.cp.describe().internalsExposed, false);

  assert.equal(world.cp.ledger.issueGrant, undefined, 'the public ledger must not mint grants');
  assert.equal(world.cp.ledger.recordExecution, undefined);
  assert.equal(world.cp.ledger.recordEvidence, undefined);
  assert.equal(world.cp.ledger.assertFact, undefined);
  assert.equal(world.cp.ledger.consumeGrant, undefined);
  assert.equal(world.cp.registry.mutate, undefined);
  assert.equal(world.cp.registry.evaluate, undefined);
  assert.equal(world.cp.registry.promote, undefined);
  assert.equal(world.cp.governance.blockTask, undefined);
  assert.equal(world.cp.governance.sever, undefined);
  assert.equal(world.cp.memory.write, undefined);

  // Reading is still possible; minting is not.
  assert.equal(typeof world.cp.ledger.verifyChain, 'function');
  assert.equal(typeof world.cp.registry.current, 'function');

  await assert.rejects(() => world.cp.runtime.execute('grant-forged', {}), (e) => /GRANT_UNKNOWN/.test(e.message));
  assert.equal(world.calls.length, 0);
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
    (e) => e.code === 'EVALUATION_OF_REVOKED_ARTIFACT',
  );

  // A4-A6: trust stays revoked, so release and promotion stay shut
  assert.equal(world.cp.artifact(artifactId).trust, 'REVOKED');
  await assert.rejects(
    () => world.cp.releaseArtifact({ sessionId: coord.sessionId, agentId: 'agent-coord', artifactId }),
    (e) => e.code === 'RELEASE_NEEDS_EVALUATION',
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
