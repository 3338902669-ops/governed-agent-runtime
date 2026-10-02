// auditor.mjs - READ-ONLY. It answers "can this record be used as evidence?", never "may you do
// this?". That distinction is the whole point.
//
// Six rounds of security scanning (SECURITY-SCAN-LOG.md) found the same class of defect over and
// over: the *authorisation* surface never closed. An auditor makes no authorisation decision, so
// that unclosed surface is not on its path. It reads what already happened and reports whether it
// adds up - and it never blocks anything.
//
// Every check is tri-state. UNKNOWN exists because a record that does not carry the field a claim
// needs cannot be called good: that is how "fixed but never independently re-verified" (F-GAR-09)
// stayed visible instead of quietly passing.

import { canonical, sha256 } from './core.mjs';

const GENESIS = '0'.repeat(64);

export const HOLDS = 'HOLDS';
export const FAILS = 'FAILS';
export const UNKNOWN = 'UNKNOWN';

export const CLAIMS = [
  { id: 'A1', title: 'the ledger chain is intact' },
  { id: 'A2', title: 'every execution consumed a grant the gate issued' },
  { id: 'A3', title: 'every piece of evidence is attached to a real execution, by its author' },
  { id: 'A4', title: 'every verification came from a different actor than the work it checked' },
  { id: 'A5', title: 'a done fact rests on a verification of that task own work' },
  { id: 'A6', title: 'every external action carries a matching, unexpired approval' },
  { id: 'A7', title: 'nothing executed under an artifact after its trust was revoked' },
];

function index(rows) {
  const byKind = new Map();
  rows.forEach((row, position) => {
    const entry = { ...row, position };
    if (!byKind.has(row.kind)) byKind.set(row.kind, []);
    byKind.get(row.kind).push(entry);
  });
  return (kind) => byKind.get(kind) || [];
}

/** Accepts either a bare array of rows or an export object shaped { rows: [...] }. */
export function normalizeLedger(input) {
  if (Array.isArray(input)) return input;
  if (input && Array.isArray(input.rows)) return input.rows;
  return null;
}

export function auditLedger(input) {
  const rows = normalizeLedger(input);
  if (!rows) {
    return { claims: [], verdict: UNKNOWN, error: 'not a ledger export: expected an array of rows or { rows: [...] }' };
  }

  const of = index(rows);
  const executions = of('execution').map((r) => ({ ...r.payload, at: r.at, position: r.position }));
  const evidence = of('evidence').map((r) => ({ ...r.payload, at: r.at, position: r.position }));
  const verifications = of('verification').map((r) => ({ ...r.payload, at: r.at, position: r.position }));
  const facts = of('fact').map((r) => ({ ...r.payload, at: r.at, position: r.position }));
  const issued = of('grant.issued').map((r) => ({ ...r.payload, position: r.position }));
  const consumed = of('grant.consumed').map((r) => ({ ...r.payload, position: r.position }));
  const approvals = of('approval').map((r) => ({ ...r.payload, position: r.position }));
  const revocations = of('trust.revoked').map((r) => ({ ...r.payload, position: r.position }));
  const sessions = of('session.opened').map((r) => ({ ...r.payload, position: r.position }));

  const result = [];
  const record = (id, verdict, detail, evidenceList) => {
    const claim = CLAIMS.find((c) => c.id === id);
    result.push({ id, title: claim ? claim.title : id, verdict, detail, evidence: evidenceList || [] });
  };

  // A1 - the chain. If this fails nothing else can be trusted, so every other claim is UNKNOWN.
  let chainBreak = null;
  let previous = GENESIS;
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    const expected = sha256(previous + canonical({ seq: row.seq, at: row.at, kind: row.kind, payload: row.payload }));
    if (row.prev !== previous || row.hash !== expected) { chainBreak = { position: i, kind: row.kind, expected, found: row.hash }; break; }
    previous = row.hash;
  }
  if (chainBreak) {
    record('A1', FAILS, 'row ' + chainBreak.position + ' (' + chainBreak.kind + ') does not hash to its recorded value', [chainBreak]);
    for (const claim of CLAIMS.slice(1)) {
      record(claim.id, UNKNOWN, 'the chain is broken, so this claim cannot be evaluated', []);
    }
    return finish(result);
  }
  record('A1', HOLDS, rows.length + ' rows, chain intact', [{ head: previous }]);

  // A2 - an execution is the receipt of a gate decision.
  const issuedBy = new Map(issued.map((g) => [g.grantId, g]));
  const consumedBy = new Map(consumed.map((c) => [c.grantId, c]));
  const A2 = executions.filter((e) => {
    const grant = issuedBy.get(e.grantId);
    const use = consumedBy.get(e.grantId);
    return !grant || !use || use.position > e.position;
  });
  record('A2', A2.length ? FAILS : HOLDS,
    A2.length ? A2.length + ' execution(s) without a grant that the gate issued and consumed'
      : executions.length + ' executions, each traceable to a consumed grant',
    A2.map((e) => ({ executionId: e.executionId, grantId: e.grantId })));

  // A3 - evidence is grounded in the execution that produced it.
  const executionById = new Map(executions.map((e) => [e.executionId, e]));
  const A3 = [];
  for (const item of evidence) {
    const execution = executionById.get(item.executionId);
    if (!execution) { A3.push({ evidenceId: item.evidenceId, why: 'no such execution ' + String(item.executionId) }); continue; }
    if (item.author !== execution.agentId) { A3.push({ evidenceId: item.evidenceId, why: 'author ' + item.author + ' did not run the execution' }); continue; }
    if (item.position < execution.position) A3.push({ evidenceId: item.evidenceId, why: 'recorded before the execution it cites' });
  }
  record('A3', A3.length ? FAILS : HOLDS,
    A3.length ? A3.length + ' evidence record(s) not grounded in their execution'
      : evidence.length + ' evidence records, each attached to its author execution',
    A3);

  // A4 - independence between ACTORS, not between agent ids.
  const A4 = [];
  let A4unknown = 0;
  for (const verification of verifications) {
    const execution = executionById.get(verification.subjectExecutionId);
    if (!execution) { A4.push({ verificationId: verification.verificationId, why: 'subject execution does not exist' }); continue; }
    if (verification.verifierAgentId === execution.agentId) { A4.push({ verificationId: verification.verificationId, why: 'the verifier ran the work' }); continue; }
    if (!verification.verifierActorId || !execution.actorId) { A4unknown += 1; continue; }
    if (verification.verifierActorId === execution.actorId) {
      A4.push({ verificationId: verification.verificationId, why: 'actor ' + verification.verifierActorId + ' verified its own work' });
    }
  }
  if (A4.length) record('A4', FAILS, A4.length + ' verification(s) not independent by actor', A4);
  else if (A4unknown) record('A4', UNKNOWN, A4unknown + ' verification(s) predate actor attribution, so independence cannot be re-checked', []);
  else record('A4', HOLDS, verifications.length + ' verifications, each by an actor other than the one that worked', []);

  // A5 - a done fact must rest on a verification of THAT task's own work.
  const verificationById = new Map(verifications.map((v) => [v.verificationId, v]));
  const A5 = [];
  for (const fact of facts) {
    const match = /^task:(.+):state$/.exec(String(fact.key));
    if (!match) continue;
    const taskId = match[1];
    const verification = verificationById.get(fact.verificationId);
    if (!verification) { A5.push({ fact: fact.key, why: 'cites verification ' + String(fact.verificationId) + ' which is not in the ledger' }); continue; }
    const execution = executionById.get(verification.subjectExecutionId);
    if (!execution) { A5.push({ fact: fact.key, why: 'the cited verification has no subject execution' }); continue; }
    if (execution.taskId !== taskId) {
      A5.push({ fact: fact.key, why: 'grounded in an execution belonging to task ' + String(execution.taskId) });
    }
  }
  record('A5', A5.length ? FAILS : HOLDS,
    A5.length ? A5.length + ' done fact(s) not grounded in their own task work' : 'every done fact is grounded in its own task work',
    A5);

  // A6 - an external action needs an approval of the same target AND the same operation.
  const A6 = [];
  for (const execution of executions) {
    const external = execution.external;
    if (!external || !external.target) continue;
    const match = approvals.find((a) => a.sessionId === execution.sessionId
      && String(a.scope) === String(external.target)
      && (a.kind === null || a.kind === undefined || a.kind === external.kind)
      && a.position < execution.position
      && (!a.expiresAt || new Date(execution.at).getTime() <= new Date(a.expiresAt).getTime()));
    if (!match) {
      A6.push({ executionId: execution.executionId, why: 'no approval for ' + external.kind + ' -> ' + external.target + ' before this execution' });
    }
  }
  const externalCount = executions.filter((e) => e.external && e.external.target).length;
  record('A6', A6.length ? FAILS : HOLDS,
    A6.length ? A6.length + ' external action(s) without a matching approval'
      : externalCount + ' external action(s), each covered by an approval of that target and kind',
    A6);

  // A7 - revocation is terminal: nothing runs under the artifact afterwards.
  const sessionById = new Map(sessions.map((s) => [s.sessionId, s]));
  const A7 = [];
  for (const execution of executions) {
    const session = sessionById.get(execution.sessionId);
    if (!session) continue;
    for (const revocation of revocations) {
      if (revocation.artifactId !== session.artifactId) continue;
      if (execution.position > revocation.position) {
        A7.push({ executionId: execution.executionId, artifactId: revocation.artifactId, why: 'ran after trust was revoked at ' + String(revocation.at) });
      }
    }
  }
  record('A7', A7.length ? FAILS : HOLDS,
    A7.length ? A7.length + ' execution(s) after revocation of their artifact' : 'no execution ran after its artifact trust was revoked',
    A7);

  return finish(result);
}

function finish(claims) {
  const counts = { HOLDS: 0, FAILS: 0, UNKNOWN: 0 };
  for (const claim of claims) counts[claim.verdict] += 1;
  return {
    claims,
    counts,
    verdict: counts.FAILS ? FAILS : (counts.UNKNOWN ? UNKNOWN : HOLDS),
  };
}
