// auditor.test.mjs - the read-only auditor, tested the way the rest of this repository is:
// every claim gets a fault injected, and the auditor must name it.
//
// Faults are injected and then the chain is RECOMPUTED, so the mutated ledger is a record that was
// legitimately written and simply says something wrong. Without that step every mutation would trip
// A1 first and the other six checks would never be exercised.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeWorld, openWork, request, runHappyPath } from '../src/fixture.mjs';
import { auditLedger, CLAIMS, HOLDS, FAILS, UNKNOWN } from '../src/auditor.mjs';
import { canonical, sha256 } from '../src/core.mjs';

const GENESIS = '0'.repeat(64);

/** Rebuild prev/hash so an edited ledger is internally consistent - a bad record, not a broken one. */
function rechain(rows) {
  let previous = GENESIS;
  return rows.map((row, i) => {
    const next = { ...row, seq: i, prev: previous };
    next.hash = sha256(previous + canonical({ seq: next.seq, at: next.at, kind: next.kind, payload: next.payload }));
    previous = next.hash;
    return next;
  });
}

const verdictOf = (report, id) => report.claims.find((c) => c.id === id).verdict;

/** A ledger that exercises every claim: a full governed run plus one approved external action. */
async function richLedger() {
  const world = await makeWorld();
  const work = await openWork(world);
  await runHappyPath(world, work);

  const deploy = await openWork(world, { title: 'deploy', resources: ['file:src/d.mjs'], externalAction: 'deploy', externalTarget: 'production' });
  const approver = await world.cp.openSession({ agentId: 'agent-coord', own: false });
  await world.cp.approve({ sessionId: approver.sessionId, targetSessionId: deploy.sImpl.sessionId, approvedBy: 'human-root', scope: 'production' });
  await world.cp.act(request(deploy.sImpl, 'execute', { target: 'production', tool: 'shell', externalAction: { kind: 'deploy', target: 'production' } }));

  return world.cp.ledger.rows;
}

test('the auditor confirms a real governed run', async () => {
  const report = auditLedger(await richLedger());
  const failing = report.claims.filter((c) => c.verdict !== HOLDS);
  assert.deepEqual(failing.map((c) => c.id + ':' + c.verdict + ':' + c.detail), []);
  assert.equal(report.verdict, HOLDS);
  assert.equal(report.claims.length, CLAIMS.length);
});

test('A1 catches an edited row, and refuses to judge the rest', async () => {
  const rows = await richLedger();
  const edited = rows.map((r, i) => (i === 3 ? { ...r, payload: { ...r.payload, tampered: true } } : r));
  const report = auditLedger(edited);
  assert.equal(verdictOf(report, 'A1'), FAILS);
  for (const claim of CLAIMS.slice(1)) assert.equal(verdictOf(report, claim.id), UNKNOWN, claim.id + ' must be UNKNOWN behind a broken chain');
});

test('A2 catches an execution whose grant was never consumed', async () => {
  const rows = await richLedger();
  const consumed = rows.find((r) => r.kind === 'grant.consumed');
  const report = auditLedger(rechain(rows.filter((r) => r !== consumed)));
  assert.equal(verdictOf(report, 'A2'), FAILS);
  assert.equal(verdictOf(report, 'A1'), HOLDS);
});

test('A3 catches evidence filed by somebody other than the executor', async () => {
  const rows = await richLedger();
  const report = auditLedger(rechain(rows.map((r) => (r.kind === 'evidence' ? { ...r, payload: { ...r.payload, author: 'agent-verify' } } : r))));
  assert.equal(verdictOf(report, 'A3'), FAILS);
});

test('A4 catches one actor verifying its own work', async () => {
  const rows = await richLedger();
  const execution = rows.find((r) => r.kind === 'execution' && r.payload.actorId);
  const report = auditLedger(rechain(rows.map((r) => (
    r.kind === 'verification' && r.payload.subjectExecutionId === execution.payload.executionId
      ? { ...r, payload: { ...r.payload, verifierActorId: execution.payload.actorId } }
      : r
  ))));
  assert.equal(verdictOf(report, 'A4'), FAILS);
});

test('A4 says UNKNOWN, not HOLDS, when the record predates actor attribution', async () => {
  const rows = await richLedger();
  const report = auditLedger(rechain(rows.map((r) => (r.kind === 'verification' ? { ...r, payload: { ...r.payload, verifierActorId: null } } : r))));
  assert.equal(verdictOf(report, 'A4'), UNKNOWN, 'a record that cannot answer the question is not a record that answered it');
});

test('A5 catches a done fact grounded in another task work', async () => {
  const rows = await richLedger();
  const fact = rows.find((r) => r.kind === 'fact' && /^task:.*:state$/.test(String(r.payload.key)));
  const verification = rows.find((r) => r.kind === 'verification' && r.payload.verificationId === fact.payload.verificationId);
  assert.ok(fact && verification, 'the governed run must produce a done fact citing a verification');

  // The verification now points at work that belongs to some other task.
  const report = auditLedger(rechain(rows.map((r) => (
    r.kind === 'execution' && r.payload.executionId === verification.payload.subjectExecutionId
      ? { ...r, payload: { ...r.payload, taskId: 'task-9999' } }
      : r
  ))));
  assert.equal(verdictOf(report, 'A5'), FAILS);
  assert.equal(verdictOf(report, 'A1'), HOLDS);
});

test('A6 catches an external action with no matching approval', async () => {
  const rows = await richLedger();
  const report = auditLedger(rechain(rows.filter((r) => r.kind !== 'approval')));
  assert.equal(verdictOf(report, 'A6'), FAILS);
});

test('A7 catches an execution that ran after its artifact was revoked', async () => {
  const rows = await richLedger();
  const session = rows.find((r) => r.kind === 'session.opened');
  const execution = rows.find((r) => r.kind === 'execution' && r.payload.sessionId === session.payload.sessionId);
  const revocation = { seq: 0, at: execution.at, kind: 'trust.revoked', payload: { artifactId: session.payload.artifactId, reason: 'injected', by: 'agent-coord', at: execution.at }, prev: GENESIS, hash: '' };
  const withRevocation = [...rows.slice(0, execution.seq), revocation, ...rows.slice(execution.seq)];
  const report = auditLedger(rechain(withRevocation));
  assert.equal(verdictOf(report, 'A7'), FAILS);
});

test('the CLI contract: exit 0 when the record holds, 1 when it does not, 2 when it cannot judge', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gar-audit-'));
  const good = join(dir, 'good.json');
  const bad = join(dir, 'bad.json');
  const junk = join(dir, 'junk.json');
  const rows = await richLedger();
  writeFileSync(good, JSON.stringify({ rows }));
  writeFileSync(bad, JSON.stringify({ rows: rows.map((r, i) => (i === 3 ? { ...r, payload: { ...r.payload, tampered: true } } : r)) }));
  writeFileSync(junk, JSON.stringify({ not: 'a ledger' }));

  const run = (file) => spawnSync(process.execPath, ['bin/audit.mjs', file], { cwd: join(import.meta.dirname, '..'), encoding: 'utf8' });
  assert.equal(run(good).status, 0);
  assert.equal(run(bad).status, 1);
  assert.equal(run(junk).status, 2);
});
