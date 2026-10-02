// invariants.test.mjs - I11..I17, each pinned by an executable check.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, openWork, request, runHappyPath, manualClock } from './harness.mjs';
import { freezeIdentity } from '../src/identity.mjs';
import { Refusal } from '../src/core.mjs';

test('I11: the identity snapshot is immutable for the life of a session', async () => {
  const world = await makeWorld();
  const frozen = freezeIdentity(world.cp.agent('agent-impl'));
  assert.throws(() => { frozen.agentId = 'somebody-else'; }, TypeError);
  assert.throws(() => { frozen.runtime.model = 'tampered'; }, TypeError);
  assert.equal(frozen.agentId, 'agent-impl');
});

test('I11: replacing the agent identity mid-execution blocks every action', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const before = world.cp.agent('agent-impl').identityFingerprint;

  // The operator upgrades the agent by rebuilding it from a new artifact version. Same agentId,
  // different fingerprint: "today's verifier" is mechanically distinguishable from yesterday's.
  const v2 = await world.cp.mutateArtifact({
    sessionId: (await world.cp.openSession({ agentId: 'agent-impl', taskId: null, own: false })).sessionId,
    agentId: 'agent-impl',
    artifactId: world.artifacts.impl.artifactId,
    patch: { version: '2.0.0', instructions: 'act as implementer, v2' },
  });
  assert.equal(v2.receipt.effect, 'ALLOW');
  world.cp.bootstrapTrust({ artifactId: world.artifacts.impl.artifactId, by: 'human-root' });
  const rebuilt = world.cp.createAgent({ agentId: 'agent-impl', artifactId: world.artifacts.impl.artifactId, roleId: 'implementer' });

  assert.notEqual(before, rebuilt.identityFingerprint, 'a version change must change the fingerprint');

  const result = await world.cp.act(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  assert.equal(result.receipt.effect, 'BLOCK');
  assert.equal(result.executed, false);
  // Two independent invariants fire, and the gate reports both rather than stopping at the first.
  assert.ok(result.receipt.matched.includes('P06:IDENTITY_DRIFT'), 'identity drift must be reported');
  assert.ok(result.receipt.matched.includes('P07:ARTIFACT_MUTATED'), 'artifact mutation must be reported');
});

test('I12: the executor is not reachable without a grant from the gate', async () => {
  const world = await makeWorld();
  const runtime = world.cp.runtime;

  assert.equal(runtime.executor, undefined, 'the executor must not be a property of the runtime');
  assert.equal(Object.getOwnPropertyNames(runtime).includes('executor'), false);
  assert.equal(runtime.describe().executorExposed, false);

  await assert.rejects(
    () => runtime.execute('grant-does-not-exist', {}),
    (error) => error.code === 'GRANT_UNKNOWN' || /GRANT_UNKNOWN/.test(error.message),
  );
  assert.equal(world.calls.length, 0, 'the executor ran for a fabricated grant');
});

test('I12: a grant is single-use, expiring and bound to one target', async () => {
  const world = await makeWorld();
  const work = await openWork(world);

  const submitted = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  assert.equal(submitted.receipt.effect, 'ALLOW');
  assert.equal(submitted.granted, true);

  await world.cp.runtime.execute(submitted.grantId, { args: { content: 'x' } });
  await assert.rejects(() => world.cp.runtime.execute(submitted.grantId, {}), (e) => /GRANT_REPLAYED/.test(e.message));

  const second = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  await assert.rejects(
    () => world.cp.runtime.execute(second.grantId, { target: 'file:somewhere-else.mjs' }),
    (e) => /GRANT_WRONG_TARGET/.test(e.message),
  );

  const third = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  world.clock.advance(120000);
  await assert.rejects(() => world.cp.runtime.execute(third.grantId, {}), (e) => /GRANT_EXPIRED/.test(e.message));
});

test('I12: the acting agent comes from the grant, not from the request payload', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const submitted = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  // The payload screams that it is somebody else; the grant is what decides who acts.
  await world.cp.runtime.execute(submitted.grantId, { args: { agentId: 'agent-verify', content: 'forged' } });
  assert.equal(world.calls.length, 1);
  assert.equal(world.calls[0].agentId, 'agent-impl');
  assert.equal(world.calls[0].sessionId, work.sImpl.sessionId);

  // And a mismatched session is refused before the executor is reached at all.
  const second = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  await assert.rejects(
    () => world.cp.runtime.execute(second.grantId, { sessionId: work.sVerify.sessionId }),
    (e) => /GRANT_WRONG_SESSION/.test(e.message),
  );
  assert.equal(world.calls.length, 1);
});

test('I13: memory can claim anything and still establish nothing', async () => {
  const world = await makeWorld();
  const work = await openWork(world);

  world.cp.remember({ agentId: 'agent-impl', key: 'deployment', value: 'I already deployed production', kind: 'completion-claim' });
  assert.equal(world.cp.systemFact('deployment'), null, 'memory must not become a system fact');
  assert.equal(world.cp.recall('agent-impl', 'deployment').authority, 'none');
  assert.equal(world.cp.taskState(work.task.taskId).state, 'queued');

  const forged = await world.cp.submit(request(work.sCoord, 'mark_done', { target: work.task.taskId, basis: 'memory' }));
  assert.equal(forged.receipt.effect, 'DENY');
  assert.equal(forged.receipt.code, 'MEMORY_CANNOT_ASSERT_STATE');
  assert.equal(world.cp.taskState(work.task.taskId).state, 'queued');
});

test('I13: only a passed verification turns work into an authoritative fact', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  await runHappyPath(world, work);
  const fact = world.cp.systemFact('task:' + work.task.taskId + ':state');
  assert.equal(fact.value, 'done');
  assert.equal(fact.verifiedBy, 'agent-verify');
});

test('I14: modifying an artifact invalidates the sessions and grants bound to it', async () => {
  const world = await makeWorld();
  const work = await openWork(world);

  const pending = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  assert.equal(pending.granted, true);

  const bump = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  const mutated = await world.cp.mutateArtifact({
    sessionId: bump.sessionId, agentId: 'agent-impl',
    artifactId: world.artifacts.impl.artifactId,
    patch: { version: '1.1.0', instructions: 'changed' },
  });
  assert.equal(mutated.receipt.effect, 'ALLOW');

  const afterwards = await world.cp.act(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  assert.equal(afterwards.receipt.effect, 'BLOCK');
  assert.equal(afterwards.receipt.code, 'ARTIFACT_MUTATED');

  await assert.rejects(
    () => world.cp.runtime.execute(pending.grantId, {}),
    (e) => /ARTIFACT_MUTATED/.test(e.message),
  );
  assert.equal(world.calls.length, 0);
});

test('I14: editing the stored definition in place is detected and revokes trust', async () => {
  const world = await makeWorld();
  const artifactId = world.artifacts.impl.artifactId;
  const record = world.cp.registry.current(artifactId);
  const original = record.instructions;
  record.instructions = original + ' (quietly edited)';
  assert.throws(() => world.cp.registry.assertIntegrity(artifactId), (e) => e.code === 'ARTIFACT_TAMPERED');
  assert.equal(world.cp.registry.current(artifactId).trust, 'REVOKED');
});

test('I15: promotion of an unevaluated artifact is refused before anything happens', async () => {
  const world = await makeWorld();
  const fresh = world.cp.registerArtifact({ name: 'candidate', roleId: 'implementer', instructions: 'v-next', tools: ['read'], createdBy: 'human-dev' });
  const session = await world.cp.openSession({ agentId: 'agent-coord', own: false });

  const unEvaluated = await world.cp.promoteArtifact({ sessionId: session.sessionId, agentId: 'agent-coord', artifactId: fresh.artifactId, approval: { approvedBy: 'human-root', scope: fresh.artifactId } });
  assert.equal(unEvaluated.receipt.effect, 'REQUIRE_VERIFICATION');
  assert.ok(unEvaluated.receipt.matched.some((m) => m.includes('PROMOTION_NEEDS_INDEPENDENT_EVALUATION')));
  assert.equal(unEvaluated.executed, false);
  assert.equal(world.cp.artifact(fresh.artifactId).lifecycle, 'DRAFT');

  // The author may not evaluate its own artifact: the registry refuses it outright.
  assert.throws(
    () => world.cp.registry.evaluate({ artifactId: fresh.artifactId, by: 'human-dev', checks: [{ name: 'x', passed: true }] }),
    (e) => e.code === 'SELF_EVALUATION',
  );
});

test('I15: an artifact that nobody independent evaluated cannot be promoted', async () => {
  const world = await makeWorld();
  const fresh = world.cp.registerArtifact({ name: 'candidate-2', roleId: 'implementer', instructions: 'v-next', tools: ['read'], createdBy: 'human-dev' });
  const evalSession = await world.cp.openSession({ agentId: 'agent-eval', own: false });
  await world.cp.evaluateArtifact({ sessionId: evalSession.sessionId, agentId: 'agent-eval', artifactId: fresh.artifactId, checks: [{ name: 'suite', passed: true }], by: 'agent-eval' });
  assert.equal(world.cp.artifact(fresh.artifactId).trust, 'VALIDATED');

  const release = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const released = await world.cp.releaseArtifact({ sessionId: release.sessionId, agentId: 'agent-coord', artifactId: fresh.artifactId });
  assert.equal(released.receipt.effect, 'ALLOW');

  const coordSession = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const promoted = await world.cp.promoteArtifact({ sessionId: coordSession.sessionId, agentId: 'agent-coord', artifactId: fresh.artifactId, approval: { approvedBy: 'human-root', scope: fresh.artifactId } });
  assert.equal(promoted.receipt.effect, 'ALLOW');
  assert.equal(world.cp.artifact(fresh.artifactId).trust, 'TRUSTED');
  assert.equal(world.cp.artifact(fresh.artifactId).lifecycle, 'PROMOTED');
});

test('I15: an approval whose scope names something else is refused', async () => {
  const world = await makeWorld();
  const fresh = world.cp.registerArtifact({ name: 'candidate-3', roleId: 'implementer', instructions: 'v', tools: ['read'], createdBy: 'human-dev' });
  const evalSession = await world.cp.openSession({ agentId: 'agent-eval', own: false });
  await world.cp.evaluateArtifact({ sessionId: evalSession.sessionId, agentId: 'agent-eval', artifactId: fresh.artifactId, checks: [{ name: 'suite', passed: true }], by: 'agent-eval' });
  await world.cp.releaseArtifact({ sessionId: (await world.cp.openSession({ agentId: 'agent-coord', own: false })).sessionId, agentId: 'agent-coord', artifactId: fresh.artifactId });
  const coordSession = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const promoted = await world.cp.promoteArtifact({ sessionId: coordSession.sessionId, agentId: 'agent-coord', artifactId: fresh.artifactId, approval: { approvedBy: 'human-root', scope: 'some-other-artifact' } });
  assert.equal(promoted.receipt.effect, 'DENY');
  assert.equal(promoted.receipt.code, 'APPROVAL_SCOPE_MISMATCH');
  assert.equal(promoted.executed, false);
  assert.equal(world.cp.artifact(fresh.artifactId).trust, 'VALIDATED');
});

test('I16: rollback refuses a version that was never verified', async () => {
  const world = await makeWorld();
  const artifactId = world.artifacts.impl.artifactId;
  const bump = await world.cp.openSession({ agentId: 'agent-impl', own: false });
  await world.cp.mutateArtifact({ sessionId: bump.sessionId, agentId: 'agent-impl', artifactId, patch: { version: '9.9.9', instructions: 'never evaluated' } });
  const coordSession = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const rolled = await world.cp.rollbackArtifact({ sessionId: coordSession.sessionId, agentId: 'agent-coord', artifactId, toVersion: '9.9.9' });
  assert.equal(rolled.receipt.effect, 'DENY');
  assert.equal(rolled.receipt.code, 'ROLLBACK_TO_UNVERIFIED');
});

test('I17: revoking trust kills live sessions and unspent grants', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const pending = await world.cp.submit(request(work.sImpl, 'write', { target: 'file:src/a.mjs', tool: 'edit' }));
  assert.equal(pending.granted, true);

  const coordSession = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  const revoked = await world.cp.revokeTrust({ sessionId: coordSession.sessionId, agentId: 'agent-coord', artifactId: world.artifacts.impl.artifactId, reason: 'supply chain concern' });
  assert.equal(revoked.receipt.effect, 'ALLOW');

  const afterwards = await world.cp.act(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  assert.equal(afterwards.receipt.effect, 'BLOCK');
  assert.equal(afterwards.receipt.code, 'TRUST_REVOKED');

  await assert.rejects(() => world.cp.runtime.execute(pending.grantId, {}), (e) => /TRUST_REVOKED/.test(e.message));
  assert.equal(world.calls.length, 0);
});

test('I18: a tampered ledger is detected and blocks the gate', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  await runHappyPath(world, work);
  assert.equal(world.cp.ledger.verifyChain().ok, true);

  const rows = world.cp.ledger.rows;
  rows[3].payload.reason = 'edited after the fact';
  const check = world.cp.ledger.verifyChain();
  assert.equal(check.ok, false);
  assert.equal(check.brokenAt, 3);

  const blocked = await world.cp.submit(request(work.sImpl, 'read', { target: 'file:src/a.mjs' }));
  assert.equal(blocked.receipt.effect, 'BLOCK');
  assert.equal(blocked.receipt.code, 'LEDGER_TAMPERED');
});

test('I18: tampering with a stored evidence record is detected too', async () => {
  const world = await makeWorld();
  const work = await openWork(world);
  const happy = await runHappyPath(world, work);
  const stored = world.cp.ledger.evidence.get(happy.evidence.result.evidenceId);
  stored.exitCode = 0;
  stored.command = 'echo nothing';
  assert.equal(world.cp.ledger.verifyChain().ok, false);
});
