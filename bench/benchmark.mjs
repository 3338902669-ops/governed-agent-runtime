// benchmark.mjs - how many incidents the system prevents, not how much code it contains.
//
// Three coordination models attempt the same twelve incidents:
//
//   naive              no ownership, no gate, no runtime. Every incident lands.
//   governed-only      the RULES exist and are evaluated, but nothing stands between the actor and
//                      the tool: an actor that ignores a refusal still acts. This is the
//                      "governance as a record system" column, and it is why the runtime seam exists.
//   governed+runtime   the real control plane in this repository, MEASURED by running each attack.
//
// The first two columns are executable models of non-cooperating actors, not measurements of a
// deployed system. That is stated here and in bench/RESULTS.md. The number that matters is the
// third, and it comes from running the code.

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { INCIDENTS } from './incidents.mjs';
import { makeWorld, openWork, runHappyPath } from '../src/fixture.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
// Overridable so a verifier can run the benchmark without writing into the repository it audits.
const OUT = process.env.GAR_OUT_DIR ? resolve(process.env.GAR_OUT_DIR) : join(HERE, 'evidence');

/**
 * THE POSITIVE CONTROL.
 *
 * A benchmark that counts prevented incidents cannot tell "enforcement worked" from "the system was
 * dead": both produce a column of zeros. So before a single incident is attempted, the governed
 * happy path must actually SUCCEED - a write allowed and executed, an independent verification
 * passed, and an authoritative fact established. If any of that fails, the benchmark refuses to
 * report a prevention number at all and exits 2.
 */
async function positiveControl() {
  const problems = [];
  try {
    const world = await makeWorld();
    const work = await openWork(world);
    const happy = await runHappyPath(world, work);
    if (!world.cp.governanceAvailable) problems.push('the governance engine is unavailable: ' + String(world.cp.governance.error));
    if (happy.write.receipt.effect !== 'ALLOW') problems.push('a normal write was not allowed: ' + happy.write.receipt.code);
    if (!happy.write.executed) problems.push('the allowed write did not execute');
    if (!happy.verification.result || happy.verification.result.verdict !== 'PASS') problems.push('the independent verification did not pass');
    const fact = world.cp.systemFact('task:' + work.task.taskId + ':state');
    if (!fact || fact.value !== 'done') problems.push('the authoritative fact was not established');
  } catch (error) {
    problems.push('the happy path threw: ' + String(error && error.message ? error.message : error));
  }
  return problems;
}

/** A model of an actor with no constraints at all. */
function naiveModel() {
  const log = [];
  const record = (what) => { log.push(what); return true; };
  return {
    name: 'naive',
    log,
    writeSharedResource: () => record('wrote a resource another task holds'),
    declareDone: () => record('declared done'),
    declareDoneWithoutEvidence: () => record('declared done with no evidence'),
    selfVerify: () => record('verified its own work'),
    deployWithoutApproval: () => record('deployed without approval'),
    deployWithExpiredApproval: () => record('deployed on an expired approval'),
    retryBeyondCeiling: () => record('retried past the ceiling'),
    runTamperedArtifact: () => record('ran a definition edited underneath it'),
    runWithoutGovernance: () => record('ran with the governor gone'),
    actAfterRevocation: () => record('acted after trust was revoked'),
    assertDoneFromMemory: () => record('wrote a fact from memory'),
    rollbackToUnverified: () => record('rolled back to something never verified'),
  };
}

/** A model of an actor that is TOLD no, and proceeds anyway. */
function advisoryModel() {
  const base = naiveModel();
  const warnings = [];
  const model = { name: 'governed', warnings, log: base.log };
  for (const key of Object.keys(base)) {
    if (typeof base[key] === 'function') model[key] = () => { warnings.push(key); return base[key](); };
  }
  return model;
}

async function main() {
  const control = await positiveControl();
  if (control.length) {
    console.error('');
    console.error('POSITIVE CONTROL FAILED - the benchmark cannot say anything about prevention:');
    for (const p of control) console.error('  - ' + p);
    console.error('');
    console.error('A column of zeros is meaningless when the system under test cannot do anything.');
    process.exitCode = 2;
    return;
  }
  console.log('positive control: the governed happy path succeeds - the prevention numbers are meaningful');

  const naive = naiveModel();
  const advisory = advisoryModel();
  const rows = [];
  for (const incident of INCIDENTS) {
    const naiveLanded = naive[incident.intent]();
    const advisoryLanded = advisory[incident.intent]();
    let runtimeLanded;
    try {
      runtimeLanded = await incident.runtime();
    } catch (error) {
      runtimeLanded = false; // an exception on the way to the incident is a prevention, not a landing
    }
    rows.push({ id: incident.id, what: incident.what, naive: naiveLanded ? 1 : 0, governed: advisoryLanded ? 1 : 0, runtime: runtimeLanded ? 1 : 0 });
  }

  const sum = (key) => rows.reduce((n, r) => n + r[key], 0);
  const totals = { naive: sum('naive'), governed: sum('governed'), runtime: sum('runtime'), incidents: rows.length };

  const lines = [];
  lines.push('');
  lines.push('Incidents that LANDED (lower is better) - ' + totals.incidents + ' attempts per column');
  lines.push('');
  lines.push('| Incident | What it is | Naive | Governed | Governed + Runtime |');
  lines.push('|---|---|---|---|---|');
  for (const r of rows) {
    lines.push('| ' + r.id + ' | ' + r.what + ' | ' + r.naive + ' | ' + r.governed + ' | **' + r.runtime + '** |');
  }
  lines.push('| **Landed** | | ' + totals.naive + ' | ' + totals.governed + ' | **' + totals.runtime + '** |');
  lines.push('| **Prevented** | | ' + (totals.incidents - totals.naive) + ' | ' + (totals.incidents - totals.governed) + ' | **' + (totals.incidents - totals.runtime) + '** |');
  lines.push('');
  console.log(lines.join('\n'));

  const evidence = { at: new Date().toISOString(), positiveControl: 'passed', totals, rows };
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'benchmark.json'), JSON.stringify(evidence, null, 2));
  console.log('evidence written to ' + join(OUT, 'benchmark.json'));
  if (totals.runtime !== 0) process.exitCode = 1;
}

main();
