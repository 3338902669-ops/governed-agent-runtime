// policy.mjs - the gate. Every runtime action is turned into an ActionRequest and answered here.
//
// The answer is one of five effects: ALLOW, REQUIRE_VERIFICATION, REQUIRE_APPROVAL, DENY, BLOCK.
// There is no WARNING and no LOG, because a gate that can only warn is a record, not a control.
//
// Rules are collected rather than short-circuited, then the MOST SEVERE result wins. A rule that
// says ALLOW can never talk the gate out of a rule that says BLOCK, regardless of table order.

import { Refusal, severityOf, worstEffect } from './core.mjs';
import { roleAllows, roleAllowsTool, roleAllowsResource, trustPermitsExecution } from './identity.mjs';

export const STATE_ESTABLISHING_ACTIONS = Object.freeze([
  'mark_done', 'promote', 'release', 'rollback', 'revoke', 'verify', 'assert_fact',
]);

export const MUTATING_ACTIONS = Object.freeze(['write', 'execute', 'claim', 'handoff']);

function decision(effect, code, reason, invariant, obligations) {
  return {
    effect,
    code,
    reason,
    invariant: invariant || null,
    obligations: obligations || [],
  };
}

function approvalOf(ctx) {
  return ctx.session ? ctx.session.approval : null;
}

/**
 * The rule table. Each rule returns null when it does not apply.
 * `invariant` names the invariant the rule enforces, so a refusal can be traced to a principle.
 */
export const RULES = [
  {
    id: 'P01',
    invariant: 'I12',
    code: 'GOVERNANCE_UNAVAILABLE',
    when(ctx) {
      if (ctx.governance && ctx.governance.available) return null;
      return decision('BLOCK', 'GOVERNANCE_UNAVAILABLE',
        'the governance engine is unavailable, so no action can be authorised', 'I12');
    },
  },
  {
    id: 'P02',
    invariant: 'I18',
    code: 'LEDGER_TAMPERED',
    when(ctx) {
      const check = ctx.ledger.verifyChain();
      if (check.ok) return null;
      return decision('BLOCK', 'LEDGER_TAMPERED',
        'the ledger chain is broken at row ' + check.brokenAt + '; state is not trustworthy', 'I18');
    },
  },
  {
    id: 'P03',
    invariant: 'I12',
    code: 'SESSION_UNKNOWN',
    when(ctx) {
      if (ctx.session) return null;
      return decision('DENY', 'SESSION_UNKNOWN', 'no open session for this request', 'I12');
    },
  },
  {
    id: 'P03b',
    invariant: 'I12',
    code: 'AGENT_SESSION_MISMATCH',
    when(ctx) {
      if (!ctx.session || !ctx.request.agentId) return null;
      if (ctx.request.agentId === ctx.session.agentId) return null;
      return decision('DENY', 'AGENT_SESSION_MISMATCH',
        'request claims to be ' + ctx.request.agentId + ' but the session belongs to ' + ctx.session.agentId, 'I12');
    },
  },
  {
    id: 'P04',
    invariant: 'I17',
    code: 'SESSION_SUPERSEDED',
    when(ctx) {
      if (!ctx.session || !ctx.session.supersededBy) return null;
      return decision('DENY', 'SESSION_SUPERSEDED',
        'this session was superseded by ' + ctx.session.supersededBy + ' (handoff); it may not act again', 'I17');
    },
  },
  {
    id: 'P05',
    invariant: 'I17',
    code: 'SESSION_CLOSED',
    when(ctx) {
      if (!ctx.session || !ctx.session.closedAt) return null;
      return decision('DENY', 'SESSION_CLOSED', 'this session was closed at ' + ctx.session.closedAt, 'I17');
    },
  },
  {
    id: 'P06',
    invariant: 'I11',
    code: 'IDENTITY_DRIFT',
    when(ctx) {
      if (!ctx.session || !ctx.identity) return null;
      if (ctx.identity.identityFingerprint === ctx.session.identityHash) return null;
      return decision('BLOCK', 'IDENTITY_DRIFT',
        'the agent identity changed during an execution: session froze ' + ctx.session.identityHash +
        ', the registry now reports ' + ctx.identity.identityFingerprint, 'I11');
    },
  },
  {
    id: 'P07',
    invariant: 'I14',
    code: 'ARTIFACT_MUTATED',
    when(ctx) {
      if (!ctx.session) return null;
      const current = ctx.registry.current(ctx.session.artifactId);
      if (current.definitionHash === ctx.session.definitionHash) return null;
      return decision('BLOCK', 'ARTIFACT_MUTATED',
        'artifact ' + ctx.session.artifactId + ' was modified after this session opened: it is bound to ' +
        ctx.session.definitionHash + ', the registry serves ' + current.definitionHash, 'I14');
    },
  },
  {
    id: 'P07b',
    invariant: 'I14',
    code: 'ARTIFACT_TAMPERED',
    when(ctx) {
      if (!ctx.session) return null;
      try {
        ctx.registry.assertIntegrity(ctx.session.artifactId);
        return null;
      } catch (error) {
        // assertIntegrity recomputes the definition hash; a mismatch means the stored artifact was
        // edited underneath the session. It also revokes the artifact's trust as a side effect, so
        // every other session on it dies too. Anything else is a broken rule, not a tamper, and is
        // left to the gate's own error handling rather than mislabelled.
        if (!error || error.code !== 'ARTIFACT_TAMPERED') throw error;
        return decision('BLOCK', 'ARTIFACT_TAMPERED',
          'artifact ' + ctx.session.artifactId + ' does not match its definition hash: ' + String(error.message), 'I14');
      }
    },
  },
  {
    id: 'P08',
    invariant: 'I17',
    code: 'TRUST_REVOKED',
    when(ctx) {
      if (!ctx.session) return null;
      const current = ctx.registry.current(ctx.session.artifactId);
      if (current.trust === 'REVOKED') {
        return decision('BLOCK', 'TRUST_REVOKED',
          'trust in ' + ctx.session.artifactId + ' was revoked: ' + String(current.revokedReason), 'I17');
      }
      if (current.trust === 'SUPERSEDED') {
        return decision('BLOCK', 'TRUST_SUPERSEDED', 'artifact ' + ctx.session.artifactId + ' was superseded', 'I14');
      }
      if (!trustPermitsExecution(current.trust)) {
        return decision('BLOCK', 'TRUST_NOT_ESTABLISHED',
          'artifact ' + ctx.session.artifactId + ' is ' + current.trust + '; it must be evaluated before use', 'I14');
      }
      return null;
    },
  },
  {
    id: 'P08b',
    invariant: 'I17',
    code: 'EVALUATION_OF_REVOKED_ARTIFACT',
    when(ctx) {
      if (ctx.request.action !== 'evaluate') return null;
      let current;
      try { current = ctx.registry.current(ctx.request.target); } catch (error) { return null; }
      if (current.trust !== 'REVOKED') return null;
      return decision('BLOCK', 'EVALUATION_OF_REVOKED_ARTIFACT',
        'artifact ' + String(ctx.request.target) + ' trust was revoked; an evaluation cannot reinstate it', 'I17');
    },
  },
  {
    id: 'P09',
    invariant: 'I12',
    code: 'ROLE_RETIRED',
    when(ctx) {
      if (!ctx.role) return decision('BLOCK', 'ROLE_UNKNOWN', 'the agent role does not resolve', 'I12');
      if (ctx.role.lifecycle !== 'ACTIVE') {
        return decision('BLOCK', 'ROLE_RETIRED', 'role ' + ctx.role.roleId + ' is ' + ctx.role.lifecycle, 'I12');
      }
      return null;
    },
  },
  {
    id: 'P10',
    invariant: 'I12',
    code: 'PERMISSION_DENIED',
    when(ctx) {
      if (!ctx.role || roleAllows(ctx.role, ctx.request.action)) return null;
      return decision('DENY', 'PERMISSION_DENIED',
        'role ' + ctx.role.roleId + ' may not perform action "' + ctx.request.action + '"', 'I12');
    },
  },
  {
    id: 'P11',
    invariant: 'I12',
    code: 'TOOL_NOT_ALLOWED',
    when(ctx) {
      const tool = ctx.request.tool;
      if (!tool || !ctx.role || roleAllowsTool(ctx.role, tool)) return null;
      return decision('DENY', 'TOOL_NOT_ALLOWED',
        'role ' + ctx.role.roleId + ' may not use tool "' + tool + '"', 'I12');
    },
  },
  {
    id: 'P12',
    invariant: 'I12',
    code: 'RESOURCE_NOT_ALLOWED',
    when(ctx) {
      const resource = ctx.request.resource;
      if (!resource || !ctx.role || roleAllowsResource(ctx.role, resource)) return null;
      return decision('DENY', 'RESOURCE_NOT_ALLOWED',
        'role ' + ctx.role.roleId + ' may not touch resource "' + resource + '"', 'I12');
    },
  },
  {
    id: 'P13',
    invariant: 'I13',
    code: 'MEMORY_CANNOT_ASSERT_STATE',
    when(ctx) {
      const basis = ctx.request.basis;
      if (basis !== 'memory') return null;
      if (!STATE_ESTABLISHING_ACTIONS.includes(ctx.request.action)) return null;
      return decision('DENY', 'MEMORY_CANNOT_ASSERT_STATE',
        'action "' + ctx.request.action + '" cannot rest on agent memory: memory is context, not fact', 'I13');
    },
  },
  {
    id: 'P14',
    invariant: 'I12',
    code: 'EVIDENCE_NEEDS_EXECUTION',
    when(ctx) {
      if (ctx.request.action !== 'produce_evidence') return null;
      const params = ctx.request.params || {};
      const executionId = params.executionId || ctx.request.target;
      if (!executionId) {
        return decision('DENY', 'EVIDENCE_WITHOUT_EXECUTION',
          'evidence must name the execution that produced it; nothing may be backfilled', 'I12');
      }
      const execution = ctx.ledger.executions.get(executionId);
      if (!execution) {
        return decision('DENY', 'EVIDENCE_WITHOUT_EXECUTION',
          'there is no execution ' + String(executionId) + '; evidence cannot be backfilled', 'I12');
      }
      if (execution.agentId !== ctx.request.agentId) {
        return decision('DENY', 'EVIDENCE_AUTHOR_MISMATCH',
          'agent ' + ctx.request.agentId + ' cannot file evidence for an execution run by ' + execution.agentId, 'I12');
      }
      return null;
    },
  },
  {
    id: 'P15',
    invariant: 'I15',
    code: 'SELF_VERIFICATION',
    when(ctx) {
      if (ctx.request.action !== 'verify') return null;
      const subject = ctx.request.params && ctx.request.params.subjectAgentId;
      if (subject && subject !== ctx.request.agentId) return null;
      return decision('DENY', 'SELF_VERIFICATION',
        'agent ' + ctx.request.agentId + ' may not verify its own implementation or execution', 'I15');
    },
  },
  {
    id: 'P16',
    invariant: 'I15',
    code: 'VERIFICATION_NEEDS_EVIDENCE',
    when(ctx) {
      if (ctx.request.action !== 'verify') return null;
      const ids = (ctx.request.params && ctx.request.params.evidenceIds) || [];
      if (ids.length > 0) return null;
      return decision('REQUIRE_VERIFICATION', 'VERIFICATION_NEEDS_EVIDENCE',
        'a verification must cite the evidence it checked', 'I15',
        [{ kind: 'evidence', note: 'attach the evidence ids produced by a gate-passed execution' }]);
    },
  },
  {
    id: 'P17',
    invariant: 'I12',
    code: 'TASK_BLOCKED',
    when(ctx) {
      const boundTask = ctx.session ? ctx.session.taskId : null;
      if (!boundTask || !ctx.governance || !ctx.governance.available) return null;
      if (!ctx.governance.isBlocked(boundTask)) return null;
      return decision('BLOCK', 'TASK_BLOCKED',
        'the governance engine has blocked task ' + boundTask + '; it needs an explicit recovery', 'I12');
    },
  },
  {
    id: 'P18',
    invariant: 'I12',
    code: 'RESOURCE_CONFLICT',
    when(ctx) {
      // The task is taken from the SESSION, never from the request: otherwise an agent could name a
      // task it owns while acting on another task's resources, and the exclusion check would pass.
      const boundTask = ctx.session ? ctx.session.taskId : null;
      if (!boundTask || !ctx.governance || !ctx.governance.available) return null;
      if (!MUTATING_ACTIONS.includes(ctx.request.action) && ctx.request.action !== 'produce_evidence') return null;
      const probe = ctx.governance.probeClaim(boundTask, ctx.request.agentId);
      if (probe.ok) return null;
      return decision(probe.code === 'TASK_BLOCKED' ? 'BLOCK' : 'DENY', probe.code, probe.message, 'I2');
    },
  },
  {
    id: 'P19',
    invariant: 'I12',
    code: 'EXTERNAL_ACTION_UNAPPROVED',
    when(ctx) {
      if (!ctx.request.externalAction) return null;
      const approval = approvalOf(ctx);
      if (approval && approval.approved) return null;
      return decision('REQUIRE_APPROVAL', 'EXTERNAL_ACTION_UNAPPROVED',
        'external action "' + ctx.request.externalAction.kind + '" needs an approval naming "' +
        String(ctx.request.externalAction.target) + '"', 'I12',
        [{ kind: 'approval', scope: ctx.request.externalAction.target, action: ctx.request.externalAction.kind }]);
    },
  },
  {
    id: 'P19b',
    invariant: 'I12',
    code: 'EXTERNAL_TARGET_MISMATCH',
    when(ctx) {
      if (!ctx.request.externalAction) return null;
      const normalise = function (v) { return String(v === undefined || v === null ? '' : v).trim().toLowerCase(); };
      if (normalise(ctx.request.target) === normalise(ctx.request.externalAction.target)) return null;
      return decision('DENY', 'EXTERNAL_TARGET_MISMATCH',
        'the approved target is "' + String(ctx.request.externalAction.target) + '" but the action would run against "' +
        String(ctx.request.target) + '"', 'I12');
    },
  },
  {
    id: 'P20',
    invariant: 'I12',
    code: 'APPROVAL_SCOPE_MISMATCH',
    when(ctx) {
      if (!ctx.request.externalAction) return null;
      const approval = approvalOf(ctx);
      if (!approval || !approval.approved) return null;
      const normalise = function (v) { return String(v === undefined || v === null ? '' : v).trim().toLowerCase(); };
      const scope = normalise(approval.scope);
      const required = normalise(ctx.request.externalAction.target);
      if (scope && required && scope === required) return null;
      return decision('DENY', 'APPROVAL_SCOPE_MISMATCH',
        'the approval scope "' + String(approval.scope) + '" does not equal the action target "' +
        String(ctx.request.externalAction.target) + '"', 'I12');
    },
  },
  {
    id: 'P21',
    invariant: 'I14',
    code: 'APPROVAL_STALE',
    when(ctx) {
      if (!ctx.request.externalAction) return null;
      const approval = approvalOf(ctx);
      if (!approval || !approval.approved) return null;
      if (approval.sessionId && approval.sessionId !== ctx.session.sessionId) {
        return decision('DENY', 'APPROVAL_WRONG_SESSION',
          'the approval was issued to session ' + approval.sessionId + ' and cannot be replayed into ' + ctx.session.sessionId, 'I12');
      }
      if (approval.agentId && approval.agentId !== ctx.request.agentId) {
        return decision('DENY', 'APPROVAL_WRONG_AGENT',
          'the approval was issued to ' + approval.agentId + ' and cannot be replayed by ' + ctx.request.agentId, 'I12');
      }
      if (approval.definitionHash && approval.definitionHash !== ctx.session.definitionHash) {
        return decision('DENY', 'APPROVAL_STALE',
          'the approval was granted for definition ' + approval.definitionHash + ', this session runs ' +
          ctx.session.definitionHash, 'I14');
      }
      if (approval.expiresAt && new Date(ctx.now).getTime() > new Date(approval.expiresAt).getTime()) {
        return decision('DENY', 'APPROVAL_STALE', 'the approval expired at ' + approval.expiresAt, 'I12');
      }
      return null;
    },
  },
  {
    id: 'P22',
    invariant: 'I16',
    code: 'DONE_NEEDS_INDEPENDENT_VERIFICATION',
    when(ctx) {
      if (ctx.request.action !== 'mark_done') return null;
      const taskState = ctx.taskState;
      if (!taskState || !taskState.verificationId) {
        return decision('REQUIRE_VERIFICATION', 'DONE_NEEDS_INDEPENDENT_VERIFICATION',
          'task ' + String(ctx.request.taskId) + ' has no passed independent verification; it cannot be done', 'I16',
          [{ kind: 'verification', subjectExecutionId: taskState ? taskState.implementationExecutionId : null }]);
      }
      if (taskState.verificationSubjectAgentId === ctx.request.agentId) {
        return decision('DENY', 'SELF_VERIFICATION',
          'the verifier is the agent that produced the work', 'I15');
      }
      return null;
    },
  },
  {
    id: 'P23',
    invariant: 'I15',
    code: 'PROMOTION_NEEDS_EVALUATION',
    when(ctx) {
      if (ctx.request.action !== 'promote' && ctx.request.action !== 'release') return null;
      const artifactId = ctx.request.target;
      const current = ctx.registry.current(artifactId);
      const passing = current.evaluations.filter(function (e) { return e.passed === true; });
      const independent = passing.filter(function (e) { return !current.createdBy || e.by !== current.createdBy; });
      if (independent.length > 0) return null;
      return decision('REQUIRE_VERIFICATION', 'PROMOTION_NEEDS_INDEPENDENT_EVALUATION',
        'artifact ' + artifactId + ' has no passed evaluation from someone other than its author', 'I15',
        [{ kind: 'evaluation', artifactId: artifactId }]);
    },
  },
  {
    id: 'P23a',
    invariant: 'I15',
    code: 'PROMOTION_NEEDS_RELEASE',
    when(ctx) {
      if (ctx.request.action !== 'promote') return null;
      const current = ctx.registry.current(ctx.request.target);
      if (current.lifecycle === 'RELEASED') return null;
      return decision('REQUIRE_VERIFICATION', 'PROMOTION_NEEDS_RELEASE',
        'artifact ' + String(ctx.request.target) + ' is ' + current.lifecycle + '; release it before promotion', 'I15',
        [{ kind: 'release', artifactId: ctx.request.target }]);
    },
  },
  {
    id: 'P23b',
    invariant: 'I15',
    code: 'APPROVAL_SCOPE_MISMATCH',
    when(ctx) {
      if (ctx.request.action !== 'promote') return null;
      const approval = ctx.request.params && ctx.request.params.approval;
      if (!approval) return null;
      const normalise = function (v) { return String(v === undefined || v === null ? '' : v).trim().toLowerCase(); };
      if (normalise(approval.scope) === normalise(ctx.request.target)) return null;
      return decision('DENY', 'APPROVAL_SCOPE_MISMATCH',
        'the promotion approval names "' + String(approval.scope) + '", not "' + String(ctx.request.target) + '"', 'I15');
    },
  },
  {
    id: 'P23c',
    invariant: 'I15',
    code: 'SELF_APPROVAL',
    when(ctx) {
      if (ctx.request.action !== 'promote') return null;
      const current = ctx.registry.current(ctx.request.target);
      const approval = ctx.request.params && ctx.request.params.approval;
      if (!approval || !current.createdBy) return null;
      const normalise = function (v) { return String(v === undefined || v === null ? '' : v).trim().toLowerCase(); };
      if (normalise(approval.approvedBy) !== normalise(current.createdBy)) return null;
      return decision('DENY', 'SELF_APPROVAL', 'the artifact author may not approve its own promotion', 'I15');
    },
  },
  {
    id: 'P24',
    invariant: 'I16',
    code: 'ROLLBACK_NEEDS_VERIFIED_TARGET',
    when(ctx) {
      if (ctx.request.action !== 'rollback') return null;
      const params = ctx.request.params || {};
      let target;
      try {
        target = ctx.registry.versionOf(ctx.request.target, params.toVersion);
      } catch (error) {
        return decision('DENY', 'ROLLBACK_TO_UNKNOWN_VERSION', String(error.message), 'I16');
      }
      const verified = target.evaluations.some(function (e) { return e.passed === true; });
      if (verified && (target.trust === 'VALIDATED' || target.trust === 'TRUSTED' || target.trust === 'SUPERSEDED')) {
        return null;
      }
      return decision('DENY', 'ROLLBACK_TO_UNVERIFIED',
        'version ' + String(params.toVersion) + ' of ' + String(ctx.request.target) +
        ' has no passed evaluation in its history', 'I16');
    },
  },
];

/**
 * Run the gate. Returns the receipt: the winning effect plus every rule that fired, so a refusal is
 * explainable and a reviewer can see that nothing was hidden behind a first-match short circuit.
 */
export function authorize(ctx) {
  const fired = [];
  for (const rule of RULES) {
    let out = null;
    try {
      out = rule.when(ctx);
    } catch (error) {
      out = decision('BLOCK', 'POLICY_RULE_ERROR',
        'rule ' + rule.id + ' could not be evaluated: ' + String(error && error.message ? error.message : error), rule.invariant);
    }
    if (out) fired.push({ ruleId: rule.id, ...out });
  }
  const winner = worstEffect(fired);
  if (!winner) {
    return {
      effect: 'ALLOW',
      code: 'ALLOWED',
      reason: 'no rule refused this request',
      invariant: null,
      obligations: [],
      ruleId: null,
      matched: [],
    };
  }
  return { ...winner, matched: fired.map(function (f) { return f.ruleId + ':' + f.code; }) };
}

export function assertAllowed(receipt) {
  if (receipt.effect !== 'ALLOW') {
    throw new Refusal(receipt.code, receipt.reason, { effect: receipt.effect, invariant: receipt.invariant });
  }
  return receipt;
}
