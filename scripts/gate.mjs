// gate.mjs - one command that must be able to fail.
//
// A green test suite proves nothing on its own: a suite that cannot fail is a decoration. So this
// gate first runs the real suite, then INJECTS known faults into a copy of the source and requires
// every one of them to be caught. A mutation that survives is reported as a gate failure.

import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const GOVERNANCE_LIB = new URL('../../agent-orchestra-repo/scripts/orchestrator/lib.mjs', import.meta.url).href;
const TEST_FILES = ['test/invariants.test.mjs', 'test/adversarial.test.mjs'];

const MUTATIONS = [
  {
    id: 'policy-allow-all',
    file: 'src/policy.mjs',
    find: '  const winner = worstEffect(fired);',
    replace: '  const winner = null;',
    caughtBy: 'every gate refusal becomes ALLOW',
  },
  {
    id: 'grant-replay',
    file: 'src/ledger.mjs',
    find: "    if (grant.consumedAt) throw new Refusal('GRANT_REPLAYED'",
    replace: "    if (false) throw new Refusal('GRANT_REPLAYED'",
    caughtBy: 'a spent grant can be used twice',
  },
  {
    id: 'self-verification',
    file: 'src/ledger.mjs',
    find: '    if (input.verifierAgentId === subject.agentId) {',
    replace: '    if (false) {',
    caughtBy: 'an agent may verify its own execution',
  },
  {
    id: 'expired-approval',
    file: 'src/policy.mjs',
    find: '      if (approval.expiresAt && new Date(ctx.now).getTime() > new Date(approval.expiresAt).getTime()) {',
    replace: '      if (false) {',
    caughtBy: 'an expired approval still authorises an external action',
  },
  {
    id: 'approval-check-in-wrapper-only',
    file: 'src/policy.mjs',
    find: '      if (target.agentId !== ctx.request.agentId) return null;',
    replace: '      if (true) return null;',
    caughtBy: 'an agent can approve its own external action through the gated action',
  },
  {
    id: 'revocation-door-via-mutate',
    file: 'src/identity.mjs',
    find: "    if (previous.trust === 'REVOKED') {",
    replace: '    if (false) {',
    caughtBy: 'revocation is terminal only on the evaluate path',
  },
  {
    id: 'runner-can-open-sessions',
    file: 'src/control-plane.mjs',
    find: "    view.openSession = operatorOnly('openSession');",
    replace: '    view.openSession = openSession;',
    caughtBy: 'a runner can open a session for any minted agent',
  },
  {
    id: 'runner-surface-inherits-raw',
    file: 'src/control-plane.mjs',
    find: '    view.ledger = readOnlyLedger(ledger);',
    replace: '    view.ledger = ledger;',
    caughtBy: 'the runner-facing view hands back the minting ledger',
  },
  {
    id: 'verification-of-foreign-work',
    file: 'src/control-plane.mjs',
    find: '        if (boundTaskId && (!subjectExecution || subjectExecution.taskId !== boundTaskId)) {',
    replace: '        if (false) {',
    caughtBy: 'a verifier can bind unrelated work to its task',
  },
  {
    id: 'revocation-is-terminal',
    file: 'src/identity.mjs',
    find: "    if (record.trust === 'REVOKED') {",
    replace: '    if (false) {',
    caughtBy: 'a revoked artifact can be revived by evaluating it',
  },
  {
    id: 'forged-execution',
    file: 'src/ledger.mjs',
    find: "    if (!grant) {",
    replace: "    if (false) {",
    caughtBy: 'an execution can be recorded without a grant the gate consumed',
  },
  {
    id: 'public-ledger-minting',
    file: 'src/control-plane.mjs',
    find: '  const ledgerSurface = exposeInternals ? ledger : readOnlyLedger(ledger);',
    replace: '  const ledgerSurface = ledger;',
    caughtBy: 'the default surface can mint grants again',
  },
  {
    id: 'evidence-backfill',
    file: 'src/policy.mjs',
    find: '      const execution = ctx.ledger.executions.get(executionId);',
    replace: '      const execution = ctx.ledger.executions.get(executionId) || { agentId: ctx.request.agentId };',
    caughtBy: 'evidence is accepted for an execution that never happened',
  },
];

function run(command, args, cwd, env) {
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, GAR_GOVERNANCE_LIB: GOVERNANCE_LIB, ...(env || {}) },
    encoding: 'utf8',
  });
  return { status: result.status, stdout: result.stdout || '', stderr: result.stderr || '' };
}

function nodeRun(args, cwd) {
  return run(process.execPath, args, cwd);
}

const rows = [];
let failed = false;

// 1. the clean suite must pass
const clean = nodeRun(['--test', ...TEST_FILES], REPO);
rows.push({ id: 'clean-suite', verdict: clean.status === 0 ? 'PASS' : 'FAIL', detail: clean.status === 0 ? 'the real suite is green' : 'the real suite is not green' });
if (clean.status !== 0) {
  failed = true;
  console.error(clean.stdout);
  console.error(clean.stderr);
}

// 2. the benchmark must prevent every incident
const bench = nodeRun(['bench/benchmark.mjs'], REPO);
let benchOk = false;
try {
  const evidencePath = process.env.GAR_OUT_DIR
    ? join(process.env.GAR_OUT_DIR, 'benchmark.json')
    : join(REPO, 'bench', 'evidence', 'benchmark.json');
  const evidence = JSON.parse(readFileSync(evidencePath, 'utf8'));
  benchOk = bench.status === 0 && evidence.totals.runtime === 0;
  rows.push({
    id: 'benchmark',
    verdict: benchOk ? 'PASS' : 'FAIL',
    detail: evidence.totals.runtime + ' of ' + evidence.totals.incidents + ' incidents landed, positive control ' + String(evidence.positiveControl),
  });
} catch (error) {
  rows.push({ id: 'benchmark', verdict: 'FAIL', detail: 'no evidence produced: ' + String(error.message) });
}
if (!benchOk) failed = true;

// 3. every injected fault must be caught
let mutationIndex = 0;
for (const mutation of MUTATIONS) {
  const dir = mkdtempSync(join(tmpdir(), 'gar-gate-'));
  try {
    cpSync(join(REPO, 'src'), join(dir, 'src'), { recursive: true });
    cpSync(join(REPO, 'test'), join(dir, 'test'), { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'mutant', type: 'module' }));
    const target = join(dir, mutation.file);
    const source = readFileSync(target, 'utf8');
    if (!source.includes(mutation.find)) {
      rows.push({ id: mutation.id, verdict: 'FAIL', detail: 'the mutation no longer applies; update the gate' });
      failed = true;
      continue;
    }
    writeFileSync(target, source.replace(mutation.find, mutation.replace));
    const mutant = nodeRun(['--test', ...TEST_FILES], dir);
    const caught = mutant.status !== 0;
    rows.push({ id: mutation.id, verdict: caught ? 'PASS' : 'FAIL', detail: caught ? 'caught: ' + mutation.caughtBy : 'SURVIVED: ' + mutation.caughtBy });
    if (!caught) failed = true;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  mutationIndex += 1;
}

console.log('');
console.log('| Gate step | Verdict | Detail |');
console.log('|---|---|---|');
for (const row of rows) console.log('| ' + row.id + ' | ' + row.verdict + ' | ' + row.detail + ' |');
console.log('');
console.log(failed ? 'GATE FAILED' : 'GATE PASSED: ' + MUTATIONS.length + ' injected faults, all caught');
process.exitCode = failed ? 1 : 0;
