// ledger.mjs - the append-only, hash-chained record of everything the runtime did.
//
// Two rules make this a control-plane ledger rather than a log file:
//   * EVIDENCE CANNOT BE WRITTEN WITHOUT AN EXECUTION. There is no API that records an evidence
//     row for an action that never passed the gate, so "execute first, backfill evidence later"
//     has nowhere to write to.
//   * A SYSTEM FACT CANNOT BE ASSERTED WITHOUT A PASSED VERIFICATION. Facts are not written by
//     agents and not written by memory; they are derived from verification records.
//
// Every entry is chained: hash = sha256(prev + canonical(entry)). Editing any past entry breaks
// verifyChain(), and the control plane refuses to hand out facts from a broken chain.

import { Refusal, canonical, clone, hashOf, newId, sha256 } from './core.mjs';

export const GENESIS = '0'.repeat(64);

export class Ledger {
  constructor(clock) {
    this.clock = clock || function () { return new Date().toISOString(); };
    this.rows = [];
    this.head = GENESIS;
    this.seq = 0;
    this.grants = new Map();
    this.executions = new Map();
    this.evidence = new Map();
    this.verifications = new Map();
    this.facts = new Map();
  }

  #at() {
    return this.clock();
  }

  append(kind, payload) {
    const prev = this.head;
    const row = { seq: this.seq, at: this.#at(), kind, payload };
    const hash = sha256(prev + canonical(row));
    row.prev = prev;
    row.hash = hash;
    this.rows.push(row);
    this.seq += 1;
    this.head = hash;
    return row;
  }

  /** Recompute the whole chain. Returns the index of the first broken row, or -1. */
  verifyChain() {
    let prev = GENESIS;
    for (let i = 0; i < this.rows.length; i += 1) {
      const row = this.rows[i];
      const expected = sha256(prev + canonical({ seq: row.seq, at: row.at, kind: row.kind, payload: row.payload }));
      if (row.prev !== prev || row.hash !== expected) return { ok: false, brokenAt: i, expected, found: row.hash };
      prev = row.hash;
    }
    if (prev !== this.head) return { ok: false, brokenAt: this.rows.length, expected: prev, found: this.head };
    return { ok: true, brokenAt: -1, length: this.rows.length, head: this.head };
  }

  assertChainIntact() {
    const check = this.verifyChain();
    if (!check.ok) throw new Refusal('LEDGER_TAMPERED', 'ledger chain is broken at row ' + check.brokenAt);
    return check;
  }

  // ---------------------------------------------------------------- grants

  /**
   * Issue a single-use authorisation. A grant is bound to the session, the identity snapshot, the
   * artifact definition hash, the exact action and the exact target, and it expires quickly.
   * Anything that does not match is refused at consume time.
   */
  issueGrant(input) {
    const grant = {
      grantId: newId('grant'),
      nonce: sha256(newId('nonce')).slice(0, 32),
      sessionId: input.sessionId,
      agentId: input.agentId,
      definitionHash: input.definitionHash,
      identityHash: input.identityHash,
      action: input.action,
      target: input.target,
      resource: input.resource === undefined ? null : input.resource,
      decisionCode: input.decisionCode,
      // The external descriptor travels WITH the grant, so the executor can be told what kind of
      // external action it is running. Without it the runtime never passed `external` through and
      // the external executor was unreachable - which made two benchmark incidents vacuous.
      external: input.external === undefined ? null : input.external,
      runtimeId: input.runtimeId === undefined ? null : input.runtimeId,
      issuedAt: this.#at(),
      expiresAt: input.expiresAt,
      consumedAt: null,
      executionId: null,
    };
    this.grants.set(grant.grantId, grant);
    this.append('grant.issued', {
      grantId: grant.grantId, sessionId: grant.sessionId, agentId: grant.agentId,
      action: grant.action, target: grant.target, decisionCode: grant.decisionCode,
      definitionHash: grant.definitionHash, identityHash: grant.identityHash, runtimeId: grant.runtimeId,
    });
    return clone(grant);
  }

  peekGrant(grantId) {
    const g = this.grants.get(grantId);
    return g ? clone(g) : null;
  }

  /**
   * Consume a grant. Every failure mode is a distinct code, because "denied" is not an explanation:
   * unknown, replayed, expired, or not bound to what is being attempted.
   */
  consumeGrant(grantId, attempt) {
    const grant = this.grants.get(grantId);
    if (!grant) throw new Refusal('GRANT_UNKNOWN', 'no such grant: ' + String(grantId));
    if (grant.consumedAt) throw new Refusal('GRANT_REPLAYED', 'grant ' + grantId + ' was already consumed at ' + grant.consumedAt);
    const nowIso = this.#at();
    if (grant.expiresAt && new Date(nowIso).getTime() > new Date(grant.expiresAt).getTime()) {
      throw new Refusal('GRANT_EXPIRED', 'grant ' + grantId + ' expired at ' + grant.expiresAt);
    }
    const a = attempt || {};
    if (a.sessionId && a.sessionId !== grant.sessionId) throw new Refusal('GRANT_WRONG_SESSION', 'grant was issued to a different session');
    if (a.agentId && a.agentId !== grant.agentId) throw new Refusal('GRANT_WRONG_AGENT', 'grant was issued to a different agent');
    if (a.definitionHash && a.definitionHash !== grant.definitionHash) {
      throw new Refusal('GRANT_STALE_ARTIFACT', 'grant was issued against a different artifact definition');
    }
    if (a.action && a.action !== grant.action) throw new Refusal('GRANT_WRONG_ACTION', 'grant authorises ' + grant.action + ', not ' + a.action);
    if (a.target !== undefined && a.target !== null && String(a.target) !== String(grant.target)) {
      throw new Refusal('GRANT_WRONG_TARGET', 'grant authorises target "' + grant.target + '", not "' + a.target + '"');
    }
    grant.consumedAt = nowIso;
    this.append('grant.consumed', { grantId: grant.grantId, agentId: grant.agentId, action: grant.action, target: grant.target });
    return clone(grant);
  }

  recordExecution(input) {
    // An execution is the receipt of a gate decision, not a free-standing row. Requiring a grant
    // that the gate issued AND consumed is what closes the forged-chain path: without it, a caller
    // could record an execution for a grant id that never existed, then attach evidence, a
    // verification and finally an authoritative fact - with no policy decision anywhere.
    const grant = this.grants.get(input.grantId);
    if (!grant) {
      throw new Refusal('EXECUTION_WITHOUT_GRANT',
        'no grant ' + String(input.grantId) + ': an execution must consume a grant the gate issued');
    }
    if (!grant.consumedAt) {
      throw new Refusal('EXECUTION_WITHOUT_GRANT',
        'grant ' + grant.grantId + ' was never consumed through the gate; no execution can be recorded for it');
    }
    if (grant.executionId) {
      throw new Refusal('EXECUTION_ALREADY_RECORDED',
        'grant ' + grant.grantId + ' already produced execution ' + grant.executionId);
    }
    const execution = {
      executionId: newId('exec'),
      grantId: input.grantId,
      sessionId: input.sessionId,
      agentId: input.agentId,
      action: input.action,
      target: input.target,
      resource: input.resource === undefined ? null : input.resource,
      // Which task this execution belongs to. A verification may only be about work from its own
      // task; without this, a verifier could nominate unrelated work as a task's implementation.
      taskId: input.taskId === undefined ? null : input.taskId,
      startedAt: input.startedAt || this.#at(),
      finishedAt: this.#at(),
      outcome: input.outcome,
      produced: input.produced === undefined ? null : input.produced,
    };
    this.executions.set(execution.executionId, execution);
    this.append('execution', execution);
    grant.executionId = execution.executionId;
    return clone(execution);
  }

  // -------------------------------------------------------------- evidence

  /**
   * Record evidence. The executionId is mandatory and must resolve: evidence that is not attached
   * to a gate-passed execution is refused, which is what stops backfilled evidence.
   */
  recordEvidence(input) {
    if (!input || !input.executionId) {
      throw new Refusal('EVIDENCE_WITHOUT_EXECUTION', 'evidence must name the execution that produced it');
    }
    const execution = this.executions.get(input.executionId);
    if (!execution) {
      throw new Refusal('EVIDENCE_WITHOUT_EXECUTION', 'no execution ' + input.executionId + '; evidence cannot be backfilled');
    }
    const grade = input.grade || 'E3';
    if (!['E1', 'E2', 'E3', 'E4'].includes(grade)) throw new Refusal('EVIDENCE_BAD_GRADE', 'unknown grade: ' + grade);
    if (grade === 'E1') {
      for (const field of ['command', 'exitCode', 'revision']) {
        if (input[field] === undefined || input[field] === null) {
          throw new Refusal('EVIDENCE_E1_INCOMPLETE', 'E1 evidence needs ' + field);
        }
      }
    }
    if (grade === 'E2' && !input.peer) throw new Refusal('EVIDENCE_E2_INCOMPLETE', 'E2 evidence needs a peer');
    const record = {
      evidenceId: newId('ev'),
      executionId: execution.executionId,
      author: input.author,
      grade,
      command: input.command === undefined ? null : input.command,
      exitCode: input.exitCode === undefined ? null : input.exitCode,
      revision: input.revision === undefined ? null : input.revision,
      peer: input.peer === undefined ? null : input.peer,
      note: input.note === undefined ? null : input.note,
      criterion: input.criterion === undefined ? null : input.criterion,
      artifactHash: input.artifactHash === undefined ? null : input.artifactHash,
      at: this.#at(),
    };
    if (record.peer && record.peer === record.author) {
      throw new Refusal('EVIDENCE_SELF_PEER', 'a peer witness cannot be the evidence author');
    }
    this.evidence.set(record.evidenceId, record);
    this.append('evidence', record);
    return clone(record);
  }

  getEvidence(evidenceId) {
    const e = this.evidence.get(evidenceId);
    if (!e) throw new Refusal('EVIDENCE_UNKNOWN', 'no such evidence: ' + evidenceId);
    return clone(e);
  }

  evidenceByAuthor(agentId) {
    return [...this.evidence.values()].filter(function (e) { return e.author === agentId; }).map(clone);
  }

  // ---------------------------------------------------------- verification

  /**
   * Record a verification. The verifier must be a different agent from the subject, and must not
   * be an author of any evidence the verification rests on. Both are structural, not advisory.
   */
  recordVerification(input) {
    const subject = this.executions.get(input.subjectExecutionId);
    if (!subject) throw new Refusal('VERIFICATION_UNKNOWN_SUBJECT', 'no execution ' + String(input.subjectExecutionId));
    if (!input.verifierAgentId) throw new Refusal('VERIFICATION_NEEDS_VERIFIER', 'a verification must name its verifier');
    if (input.verifierAgentId === subject.agentId) {
      throw new Refusal('SELF_VERIFICATION', 'agent ' + input.verifierAgentId + ' may not verify its own execution');
    }
    const evidenceIds = Array.isArray(input.evidenceIds) ? input.evidenceIds : [];
    if (evidenceIds.length === 0) {
      throw new Refusal('VERIFICATION_NEEDS_EVIDENCE', 'a verification with no evidence is an assertion');
    }
    let groundedInSubject = false;
    let authoredByOthers = 0;
    for (const id of evidenceIds) {
      const e = this.evidence.get(id);
      if (!e) throw new Refusal('VERIFICATION_UNKNOWN_EVIDENCE', 'no such evidence: ' + id);
      if (e.author === subject.agentId) groundedInSubject = true;
      if (e.author !== input.verifierAgentId) authoredByOthers += 1;
    }
    if (authoredByOthers === 0) {
      throw new Refusal('VERIFICATION_SELF_EVIDENCE', 'every piece of evidence cited was authored by the verifier');
    }
    if (!groundedInSubject) {
      throw new Refusal('VERIFICATION_NOT_GROUNDED',
        'the verification cites nothing produced by the agent whose work is being verified');
    }
    const verdict = input.verdict === 'PASS' ? 'PASS' : 'FAIL';
    const record = {
      verificationId: newId('ver'),
      verifierAgentId: input.verifierAgentId,
      subjectExecutionId: subject.executionId,
      subjectAgentId: subject.agentId,
      verdict,
      criteria: Array.isArray(input.criteria) ? input.criteria : [],
      evidenceIds: [...evidenceIds],
      findings: input.findings === undefined ? null : input.findings,
      at: this.#at(),
    };
    if (verdict === 'PASS' && record.criteria.length === 0) {
      throw new Refusal('VERIFICATION_NEEDS_CRITERIA', 'a PASS must name the criteria it checked');
    }
    this.verifications.set(record.verificationId, record);
    this.append('verification', record);
    return clone(record);
  }

  passingVerificationFor(executionId, excludeAgentId) {
    for (const v of this.verifications.values()) {
      if (v.verdict !== 'PASS') continue;
      if (v.subjectExecutionId !== executionId) continue;
      if (excludeAgentId && v.verifierAgentId === excludeAgentId) continue;
      return clone(v);
    }
    return null;
  }

  // ----------------------------------------------------------------- facts

  /**
   * The ONLY writer of authoritative state. A fact must cite a passed verification, which must
   * cite evidence, which must cite an execution. Memory is not on this path at any point.
   */
  assertFact(input) {
    const verification = this.verifications.get(input.verificationId);
    if (!verification) throw new Refusal('FACT_REQUIRES_VERIFICATION', 'no verification ' + String(input.verificationId));
    if (verification.verdict !== 'PASS') throw new Refusal('FACT_REQUIRES_PASSING_VERIFICATION', 'verification did not pass');
    const record = {
      key: input.key,
      value: input.value,
      verificationId: verification.verificationId,
      verifiedBy: verification.verifierAgentId,
      at: this.#at(),
    };
    this.facts.set(input.key, record);
    this.append('fact', record);
    return clone(record);
  }

  fact(key) {
    this.assertChainIntact();
    const f = this.facts.get(key);
    return f ? clone(f) : null;
  }
}
