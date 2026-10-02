// demo.mjs - the whole story in one run: the governed path, then twelve attacks, then the audit.

import { makeWorld, openWork, request, runHappyPath } from '../src/fixture.mjs';
import { INCIDENTS } from '../bench/incidents.mjs';

const line = (s) => console.log(s);

async function governedPath() {
  line('');
  line('1. THE GOVERNED PATH');
  line('   agent-impl owns task-0001 through the governance engine; nobody else may act on it.');
  const world = await makeWorld();
  const work = await openWork(world);
  const happy = await runHappyPath(world, work);

  line('   write              -> ' + happy.write.receipt.effect + '  ' + happy.write.receipt.code);
  line('   produce_evidence   -> ' + happy.evidence.receipt.effect + '  ' + happy.evidence.result.evidenceId + ' (E1)');
  line('   verify             -> ' + happy.verification.receipt.effect + '  ' + happy.verification.result.verdict + ' by ' + happy.verification.result.verifierAgentId);
  line('   mark_done          -> ' + happy.done.receipt.effect + ' by ' + 'agent-coord');
  const fact = world.cp.systemFact('task:' + work.task.taskId + ':state');
  line('   system fact        -> ' + fact.key + ' = ' + fact.value + ' (verified by ' + fact.verifiedBy + ')');
  world.cp.remember({ agentId: 'agent-impl', key: 'deployment', value: 'I already deployed production', kind: 'completion-claim' });
  const note = world.cp.recall('agent-impl', 'deployment');
  line('   memory says        -> "' + note.value + '" (authority: ' + note.authority + ')');
  line('   the fact store is unmoved by it: ' + JSON.stringify(world.cp.systemFact('deployment')));
  return world;
}

async function attacks() {
  line('');
  line('2. THE ATTACKS (an attack that lands is a defect)');
  const rows = [];
  for (const incident of INCIDENTS) {
    let landed = false;
    try {
      landed = await incident.runtime();
    } catch (error) {
      landed = false;
    }
    rows.push({ id: incident.id, what: incident.what, landed });
  }
  for (const row of rows) {
    line('   ' + (row.landed ? 'LANDED ' : 'blocked') + '  ' + row.id.padEnd(24) + row.what);
  }
  const landedCount = rows.filter((r) => r.landed).length;
  line('   ' + (rows.length - landedCount) + '/' + rows.length + ' attacks blocked');
  return landedCount;
}

async function main() {
  const world = await governedPath();
  const landed = await attacks();

  line('');
  line('3. AUDIT');
  const audit = world.cp.audit();
  line('   ledger chain: ' + audit.chain.length + ' rows, intact=' + audit.chain.ok);
  line('   divergences: ' + (audit.divergences.length ? JSON.stringify(audit.divergences) : 'none'));
  line('   observations (declared seam): ' + JSON.stringify(audit.observations.map((o) => o.code)));
  line('');
  line('   gate decisions recorded: ' + world.cp.ledger.rows.filter((r) => r.kind === 'decision').length);
  line('   runtime stats: ' + JSON.stringify(world.cp.runtime.stats()));
  line('');
  line(landed === 0 ? 'RESULT: no attack landed.' : 'RESULT: ' + landed + ' attack(s) landed - this is a failure.');
  if (landed !== 0) process.exitCode = 1;
}

main();
