// identity.mjs - Phase 1 + Phase 2 of the promotion: the object model and the agent type system.
//
// Three ideas live here:
//   * a Role is a system object (capabilities, permissions, evidence it must produce and the
//     constraints it can never escape), not a label on a prompt;
//   * an Agent Artifact is a versioned, hashed definition that can be built, evaluated, released,
//     promoted, rolled back and revoked;
//   * an Agent Identity is a frozen binding of (agent, role, artifact version, runtime) whose
//     fingerprint is stable for the life of one execution and changes when any of those change.

import { Refusal, canonical, clone, hashOf, newId, deepFreeze } from './core.mjs';

/** The action vocabulary. A role may do exactly these things and nothing else. */
export const ACTIONS = Object.freeze([
  'read', 'write', 'execute', 'claim', 'handoff', 'recover',
  'verify', 'report', 'produce_evidence',
  'evaluate', 'release', 'promote', 'rollback', 'revoke', 'approve', 'mark_done',
  'mutate_artifact',
]);

/**
 * Role as a system object.
 *
 * The point of putting cannotVerifyOwnImplementation here rather than in each workflow is that
 * verification independence stops being a rule somebody remembers and becomes a property of the
 * type: a verifier is an agent that structurally cannot verify its own work.
 */
export const DEFAULT_ROLES = Object.freeze({
  implementer: {
    roleId: 'implementer',
    capabilities: ['implement', 'write-code', 'run-tests', 'claim-work'],
    permissions: {
      allow: ['read', 'write', 'execute', 'claim', 'handoff', 'produce_evidence', 'report', 'mutate_artifact'],
      deny: ['verify', 'approve', 'promote', 'release', 'evaluate', 'mark_done', 'revoke'],
    },
    requiredEvidence: { L1: ['E3', 'E2', 'E1'], L2: ['E1', 'E2'], L3: ['E1'] },
    requiredCommand: true,
    verificationConstraints: {
      cannotVerifyOwnImplementation: true,
      cannotVerifyOwnEvidence: true,
    },
    allowedTools: ['read', 'edit', 'shell'],
    allowedResources: ['*'],
    lifecycle: 'ACTIVE',
  },
  verifier: {
    roleId: 'verifier',
    capabilities: ['verify', 'adversarial-check', 'evidence-review'],
    permissions: {
      allow: ['read', 'execute', 'verify', 'produce_evidence', 'report'],
      deny: ['write', 'claim', 'approve', 'promote', 'release', 'evaluate', 'mark_done', 'revoke', 'handoff'],
    },
    requiredEvidence: { L1: ['E2', 'E1'], L2: ['E1'], L3: ['E1'] },
    requiredCommand: false,
    verificationConstraints: {
      cannotVerifyOwnImplementation: true,
      cannotVerifyOwnEvidence: true,
      mustBeIndependentOfImplementer: true,
      mustNotAuthorSubjectEvidence: true,
    },
    allowedTools: ['read', 'shell'],
    allowedResources: ['*'],
    lifecycle: 'ACTIVE',
  },
  evaluator: {
    roleId: 'evaluator',
    capabilities: ['evaluate-artifact', 'run-evaluation-suite', 'verify'],
    permissions: {
      allow: ['read', 'execute', 'evaluate', 'verify', 'produce_evidence', 'report'],
      deny: ['write', 'claim', 'approve', 'promote', 'release', 'mark_done', 'revoke'],
    },
    requiredEvidence: { L1: ['E2', 'E1'], L2: ['E1'], L3: ['E1'] },
    requiredCommand: true,
    verificationConstraints: {
      cannotVerifyOwnImplementation: true,
      cannotVerifyOwnEvidence: true,
      cannotEvaluateOwnArtifact: true,
    },
    allowedTools: ['read', 'shell'],
    allowedResources: ['*'],
    lifecycle: 'ACTIVE',
  },
  coordinator: {
    roleId: 'coordinator',
    capabilities: ['coordinate', 'approve-external-action', 'promote-artifact', 'recover-work'],
    permissions: {
      allow: ['read', 'claim', 'handoff', 'recover', 'approve', 'release', 'promote', 'rollback',
        'revoke', 'mark_done', 'report', 'evaluate', 'mutate_artifact'],
      deny: ['write', 'implement', 'verify'],
    },
    requiredEvidence: { L1: ['E3'], L2: ['E3'], L3: ['E3'] },
    requiredCommand: false,
    verificationConstraints: { cannotVerifyOwnImplementation: true },
    allowedTools: ['read'],
    allowedResources: ['*'],
    lifecycle: 'ACTIVE',
  },
});

/** Deny always wins. An unknown action is denied, not ignored. */
export function roleAllows(role, action) {
  if (!role) return false;
  if (!ACTIONS.includes(action)) return false;
  if ((role.permissions.deny || []).includes(action)) return false;
  return (role.permissions.allow || []).includes(action);
}

export function roleAllowsTool(role, tool) {
  if (!role) return false;
  const allowed = role.allowedTools || [];
  if (allowed.includes('*')) return true;
  return allowed.includes(tool);
}

export function roleAllowsResource(role, resource) {
  if (!role) return false;
  const allowed = role.allowedResources || [];
  if (allowed.includes('*')) return true;
  return allowed.some(function (pattern) {
    if (pattern.endsWith('/*')) return String(resource).startsWith(pattern.slice(0, -1));
    return pattern === resource;
  });
}

export const TRUST_STATES = Object.freeze(['UNKNOWN', 'VALIDATED', 'TRUSTED', 'SUPERSEDED', 'REVOKED']);
export const LIFECYCLE_STATES = Object.freeze(['DRAFT', 'VALIDATED', 'RELEASED', 'PROMOTED', 'REVOKED']);

/** Trust states that permit an agent to run at all. Everything else blocks. */
export function trustPermitsExecution(state) {
  return state === 'VALIDATED' || state === 'TRUSTED';
}

/**
 * The agent artifact registry: versions, evaluation, release, promotion, rollback, revocation.
 * There is no setter for trust. The only way a trust state changes is by calling a method here,
 * which is what makes "ARTIFACT MODIFICATION INVALIDATES PREVIOUS TRUST" (I14) checkable.
 */
export class ArtifactRegistry {
  constructor() {
    this.versions = new Map();   // definitionHash -> version record
    this.artifacts = new Map();  // artifactId -> { artifactId, current: definitionHash, history: [] }
    this.events = [];
  }

  #log(type, detail) {
    this.events.push({ type, at: this.events.length, ...detail });
  }

  register(input) {
    if (!input || !input.name) throw new Refusal('ARTIFACT_INVALID', 'an artifact needs a name');
    if (!input.roleId || !DEFAULT_ROLES[input.roleId]) {
      throw new Refusal('ARTIFACT_INVALID', 'unknown role: ' + String(input.roleId));
    }
    // Required, not optional: with a missing author the independence checks silently skipped
    // themselves (`!record.createdBy || ...`), so an unattributed artifact could be evaluated and
    // promoted by anyone (security scan, low).
    if (!input.createdBy) {
      throw new Refusal('ARTIFACT_NEEDS_AUTHOR', 'an artifact must record who wrote it; independence checks depend on it');
    }
    const artifactId = input.artifactId || newId('artifact');
    const definition = {
      artifactId,
      name: input.name,
      version: input.version || '1.0.0',
      roleId: input.roleId,
      instructions: input.instructions || '',
      tools: [...(input.tools || [])].sort(),
      policies: [...(input.policies || [])].sort(),
      memorySchema: input.memorySchema || { writableBy: 'self', authority: 'none' },
    };
    const definitionHash = hashOf(definition);
    if (this.versions.has(definitionHash)) {
      throw new Refusal('ARTIFACT_DUPLICATE', 'this exact definition is already registered');
    }
    const record = {
      ...definition,
      definitionHash,
      contentHash: definitionHash,
      createdBy: input.createdBy || null,
      createdAt: input.at || null,
      trust: 'UNKNOWN',
      lifecycle: 'DRAFT',
      evaluations: [],
      verifications: [],
      releases: [],
      promotions: [],
      revokedAt: null,
      revokedReason: null,
      supersededBy: null,
    };
    this.versions.set(definitionHash, record);
    const entry = this.artifacts.get(artifactId) || { artifactId, current: null, history: [] };
    entry.current = definitionHash;
    entry.history.push(definitionHash);
    this.artifacts.set(artifactId, entry);
    this.#log('registered', { artifactId, definitionHash });
    return clone(record);
  }

  /** Recompute the content hash. A mismatch means the stored definition was edited underneath us. */
  assertIntegrity(artifactId) {
    const record = this.current(artifactId);
    const recomputed = hashOf({
      artifactId: record.artifactId,
      name: record.name,
      version: record.version,
      roleId: record.roleId,
      instructions: record.instructions,
      tools: record.tools,
      policies: record.policies,
      memorySchema: record.memorySchema,
    });
    if (recomputed !== record.definitionHash) {
      record.trust = 'REVOKED';
      record.revokedAt = 'integrity-check';
      record.revokedReason = 'content edited in place: stored hash ' + record.definitionHash + ' != recomputed ' + recomputed;
      this.#log('integrity_violation', { artifactId, expected: record.definitionHash, recomputed });
      throw new Refusal('ARTIFACT_TAMPERED', 'artifact content does not match its definition hash');
    }
    return true;
  }

  current(artifactId) {
    const entry = this.artifacts.get(artifactId);
    if (!entry || !entry.current) throw new Refusal('ARTIFACT_UNKNOWN', 'unknown artifact: ' + artifactId);
    return this.versions.get(entry.current);
  }

  byHash(definitionHash) {
    const r = this.versions.get(definitionHash);
    if (!r) throw new Refusal('ARTIFACT_UNKNOWN', 'unknown definition hash');
    return r;
  }

  versionOf(artifactId, version) {
    const entry = this.artifacts.get(artifactId);
    if (!entry) throw new Refusal('ARTIFACT_UNKNOWN', 'unknown artifact: ' + artifactId);
    for (const h of entry.history) {
      const r = this.versions.get(h);
      if (r.version === version) return r;
    }
    throw new Refusal('ARTIFACT_VERSION_UNKNOWN', 'no such version: ' + version);
  }

  history(artifactId) {
    const entry = this.artifacts.get(artifactId);
    if (!entry) throw new Refusal('ARTIFACT_UNKNOWN', 'unknown artifact: ' + artifactId);
    return entry.history.map((h) => clone(this.versions.get(h)));
  }

  /**
   * Evaluate an artifact. Independence is structural: the evaluator may not be the author of the
   * artifact nor of the instructions it is judging. A failed check leaves trust UNKNOWN and is
   * recorded rather than erased.
   */
  evaluate(input) {
    const record = this.current(input.artifactId);
    const checks = Array.isArray(input.checks) ? input.checks : [];
    // REVOCATION IS TERMINAL. Without this, `evaluate` silently rewrote trust back to VALIDATED,
    // so an agent holding the evaluate role could un-revoke a definition an operator had
    // deliberately killed, resume work under it, and re-promote it. Reproduced end to end
    // (A1-A6) by a security scan; it defeated invariant I17 outright.
    if (record.trust === 'REVOKED') {
      throw new Refusal('EVALUATION_OF_REVOKED_ARTIFACT',
        'artifact ' + input.artifactId + ' trust was revoked (' + String(record.revokedReason) +
        '); an evaluation cannot reinstate it');
    }
    if (record.trust === 'SUPERSEDED') {
      throw new Refusal('EVALUATION_OF_SUPERSEDED_ARTIFACT',
        'artifact ' + input.artifactId + ' was superseded by ' + String(record.supersededBy));
    }
    if (!input.by) throw new Refusal('EVALUATION_NEEDS_EVALUATOR', 'an evaluation must name its evaluator');
    if (input.by === record.createdBy) {
      throw new Refusal('SELF_EVALUATION', 'the author of an artifact may not evaluate it: ' + input.by);
    }
    if (checks.length === 0) {
      throw new Refusal('EVALUATION_NEEDS_CHECKS', 'an evaluation with no checks is an opinion, not an evaluation');
    }
    const failed = checks.filter(function (c) { return c.passed !== true; });
    const evaluation = {
      evaluationId: newId('eval'),
      by: input.by,
      byRole: input.byRole || null,
      definitionHash: record.definitionHash,
      checks: clone(checks),
      passed: failed.length === 0,
      at: input.at || null,
    };
    record.evaluations.push(evaluation);
    if (evaluation.passed) {
      record.trust = 'VALIDATED';
      record.lifecycle = 'VALIDATED';
      this.#log('evaluated', { artifactId: record.artifactId, definitionHash: record.definitionHash, by: input.by });
    } else {
      this.#log('evaluation_failed', { artifactId: record.artifactId, failed: failed.length });
    }
    return { evaluation: clone(evaluation), artifact: clone(record) };
  }

  release(input) {
    const record = this.current(input.artifactId);
    if (!input.by) throw new Refusal('RELEASE_NEEDS_ACTOR', 'a release must name who released it');
    if (!trustPermitsExecution(record.trust)) {
      throw new Refusal('RELEASE_NEEDS_EVALUATION', 'artifact ' + input.artifactId + ' is ' + record.trust + '; evaluate it first');
    }
    record.lifecycle = 'RELEASED';
    record.releases.push({ by: input.by, at: input.at || null, definitionHash: record.definitionHash });
    this.#log('released', { artifactId: record.artifactId, definitionHash: record.definitionHash, by: input.by });
    return clone(record);
  }

  /**
   * Promotion is the lifecycle gate. It needs all three of: a passed evaluation, an independent
   * verification of this exact definition hash, and an approval whose scope names the promotion.
   * Any one of them missing is a refusal with a different code, never a partial promotion.
   */
  promote(input) {
    const record = this.current(input.artifactId);
    if (record.lifecycle === 'REVOKED') throw new Refusal('ARTIFACT_REVOKED', 'a revoked artifact cannot be promoted');
    if (record.lifecycle !== 'RELEASED') {
      throw new Refusal('PROMOTION_NEEDS_RELEASE', 'artifact is ' + record.lifecycle + '; release it before promotion');
    }
    const passingEval = record.evaluations.filter(function (e) { return e.passed === true; });
    if (passingEval.length === 0) {
      throw new Refusal('PROMOTION_NEEDS_EVALUATION', 'artifact ' + input.artifactId + ' has no passed evaluation');
    }
    const independent = record.evaluations.filter(function (e) {
      return e.passed === true && e.by !== record.createdBy;
    });
    if (independent.length === 0) {
      throw new Refusal('PROMOTION_NEEDS_INDEPENDENT_EVALUATION', 'every passed evaluation was written by the author');
    }
    const approval = input.approval;
    if (!approval || !approval.approvedBy || !approval.scope) {
      throw new Refusal('PROMOTION_NEEDS_APPROVAL', 'promotion needs an approval with approvedBy and scope');
    }
    const normalise = function (v) { return String(v === undefined || v === null ? '' : v).trim().toLowerCase(); };
    if (normalise(approval.scope) !== normalise(record.artifactId)) {
      throw new Refusal('APPROVAL_SCOPE_MISMATCH',
        'approval scope "' + approval.scope + '" does not name artifact "' + record.artifactId + '"');
    }
    if (approval.definitionHash && approval.definitionHash !== record.definitionHash) {
      throw new Refusal('APPROVAL_STALE', 'the approval was issued for a different definition hash');
    }
    if (normalise(approval.approvedBy) === normalise(record.createdBy)) {
      throw new Refusal('SELF_APPROVAL', 'the artifact author may not approve its own promotion');
    }
    record.trust = 'TRUSTED';
    record.lifecycle = 'PROMOTED';
    record.promotions.push({
      by: input.by || null,
      approvedBy: approval.approvedBy,
      scope: approval.scope,
      at: input.at || null,
      definitionHash: record.definitionHash,
    });
    this.#log('promoted', { artifactId: record.artifactId, definitionHash: record.definitionHash, approvedBy: approval.approvedBy });
    return clone(record);
  }

  revoke(input) {
    const record = this.current(input.artifactId);
    if (!input.reason) throw new Refusal('REVOCATION_NEEDS_REASON', 'a revocation must state a reason');
    record.trust = 'REVOKED';
    record.lifecycle = 'REVOKED';
    record.revokedAt = input.at || null;
    record.revokedReason = input.reason;
    this.#log('revoked', { artifactId: record.artifactId, reason: input.reason, by: input.by || null });
    return clone(record);
  }

  /**
   * Modify the artifact definition. This creates a NEW version: the previous version is marked
   * superseded and stops being the one sessions are bound to, so every live session and every
   * unused grant that referenced it is dead on arrival (I14).
   */
  mutate(input) {
    const previous = this.current(input.artifactId);
    // Revocation is terminal on every path, not just the evaluate one. `mutate` used to rewrite a
    // REVOKED version to SUPERSEDED, and `rollback` then resurrected it - a second door onto the
    // same invariant (security scan, high).
    if (previous.trust === 'REVOKED') {
      throw new Refusal('MUTATION_OF_REVOKED_ARTIFACT',
        'artifact ' + input.artifactId + ' trust was revoked (' + String(previous.revokedReason) +
        '); a new version cannot be derived from it');
    }
    previous.supersededBy = null; // filled below
    const next = this.register({
      artifactId: input.artifactId,
      name: input.patch && input.patch.name ? input.patch.name : previous.name,
      version: input.patch && input.patch.version ? input.patch.version : nextVersion(previous.version),
      roleId: input.patch && input.patch.roleId ? input.patch.roleId : previous.roleId,
      instructions: input.patch && input.patch.instructions !== undefined ? input.patch.instructions : previous.instructions,
      tools: input.patch && input.patch.tools ? input.patch.tools : previous.tools,
      policies: input.patch && input.patch.policies ? input.patch.policies : previous.policies,
      memorySchema: input.patch && input.patch.memorySchema ? input.patch.memorySchema : previous.memorySchema,
      createdBy: input.by || previous.createdBy,
      at: input.at || null,
    });
    previous.trust = 'SUPERSEDED';
    previous.supersededBy = next.definitionHash;
    this.#log('mutated', { artifactId: input.artifactId, from: previous.definitionHash, to: next.definitionHash });
    return { previous: clone(previous), current: next };
  }

  /**
   * Roll back to a named version. The target must have been VERIFIED before: a version whose trust
   * never reached VALIDATED is refused, so rollback can never be a way to ship something untested.
   */
  rollback(input) {
    const target = this.versionOf(input.artifactId, input.toVersion);
    if (target.trust === 'REVOKED') {
      throw new Refusal('ROLLBACK_TO_REVOKED',
        'version ' + input.toVersion + ' of ' + input.artifactId + ' has revoked trust; rolling back to it would reinstate it');
    }
    const everVerified = target.evaluations.some(function (e) { return e.passed === true; });
    const trustOk = target.trust === 'VALIDATED' || target.trust === 'TRUSTED' || target.trust === 'SUPERSEDED';
    if (!everVerified || !trustOk) {
      throw new Refusal('ROLLBACK_TO_UNVERIFIED',
        'version ' + input.toVersion + ' of ' + input.artifactId + ' was never evaluated; refusing to roll back to it');
    }
    const entry = this.artifacts.get(input.artifactId);
    const currentRecord = this.versions.get(entry.current);
    const restored = clone(target);
    restored.trust = target.trust === 'SUPERSEDED' ? (target.promotions.length ? 'TRUSTED' : 'VALIDATED') : target.trust;
    restored.lifecycle = restored.trust === 'TRUSTED' ? 'PROMOTED' : 'RELEASED';
    restored.rollbackFrom = currentRecord.definitionHash;
    restored.rolledBackAt = input.at || null;
    // The rolled-back definition is re-registered as the current one, keeping its prior trust.
    this.versions.set(restored.definitionHash, restored);
    entry.current = restored.definitionHash;
    if (!entry.history.includes(restored.definitionHash)) entry.history.push(restored.definitionHash);
    this.#log('rolled_back', { artifactId: input.artifactId, toVersion: input.toVersion, by: input.by || null });
    return clone(restored);
  }
}

function nextVersion(version) {
  const parts = String(version).split('.').map(function (n) { return parseInt(n, 10) || 0; });
  while (parts.length < 3) parts.push(0);
  parts[1] += 1;
  parts[2] = 0;
  return parts.join('.');
}

/**
 * An Agent Identity is a snapshot binding. The fingerprint is what a session freezes on open, so
 * "is today's verifier the same agent as yesterday's" has a mechanical answer: compare fingerprints.
 */
export function createAgent(input) {
  if (!input || !input.agentId) throw new Refusal('AGENT_INVALID', 'an agent needs an agentId');
  const role = DEFAULT_ROLES[input.roleId];
  if (!role) throw new Refusal('AGENT_INVALID', 'unknown role: ' + String(input.roleId));
  if (role.lifecycle !== 'ACTIVE') throw new Refusal('ROLE_RETIRED', 'role ' + input.roleId + ' is ' + role.lifecycle);
  if (!input.artifactId) throw new Refusal('AGENT_INVALID', 'an agent must be built from an artifact');
  const runtime = {
    runtimeId: (input.runtime && input.runtime.runtimeId) || 'runtime-local',
    provider: (input.runtime && input.runtime.provider) || 'unspecified',
    model: (input.runtime && input.runtime.model) || 'unspecified',
    isolation: (input.runtime && input.runtime.isolation) || 'process',
  };
  const identity = {
    agentId: input.agentId,
    roleId: role.roleId,
    artifactId: input.artifactId,
    artifactVersion: input.artifactVersion || null,
    definitionHash: input.definitionHash || null,
    runtime,
    capabilities: [...role.capabilities],
    policyId: input.policyId || 'default-policy',
    createdAt: input.at || null,
  };
  identity.identityFingerprint = hashOf({
    agentId: identity.agentId,
    roleId: identity.roleId,
    artifactId: identity.artifactId,
    artifactVersion: identity.artifactVersion,
    definitionHash: identity.definitionHash,
    runtime: identity.runtime,
  });
  return identity;
}

export function freezeIdentity(identity) {
  return deepFreeze(clone(identity));
}
