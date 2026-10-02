// core.mjs - canonical serialization, hashing, ids, decisions.
// Zero dependencies. Everything else in this runtime is built on these six exports.

import { createHash, randomUUID } from 'node:crypto';

/**
 * Deterministic serialization: object keys are sorted, undefined-valued keys are dropped,
 * array order is preserved. Two structurally equal values always hash the same.
 */
export function canonical(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'undefined') return 'null';
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return Number.isFinite(value) ? String(value) : 'null';
  if (t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).filter(function (k) { return value[k] !== undefined; }).sort();
    return '{' + keys.map(function (k) { return JSON.stringify(k) + ':' + canonical(value[k]); }).join(',') + '}';
  }
  return JSON.stringify(String(value));
}

export function sha256(text) {
  return createHash('sha256').update(String(text), 'utf8').digest('hex');
}

export function hashOf(value) {
  return sha256(canonical(value));
}

export function newId(prefix) {
  return prefix + '-' + randomUUID().replace(/-/g, '').slice(0, 16);
}

export function clone(value) {
  return structuredClone(value);
}

export function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

/** The five effects a governance decision can have. There is no WARNING and no LOG. */
export const EFFECTS = Object.freeze([
  'ALLOW',
  'REQUIRE_VERIFICATION',
  'REQUIRE_APPROVAL',
  'DENY',
  'BLOCK',
]);

/** Higher wins. A gate that finds any denial must not be talked out of it by an allow. */
export const EFFECT_SEVERITY = Object.freeze({
  ALLOW: 0,
  REQUIRE_VERIFICATION: 1,
  REQUIRE_APPROVAL: 2,
  DENY: 3,
  BLOCK: 4,
});

export function severityOf(effect) {
  const s = EFFECT_SEVERITY[effect];
  return s === undefined ? 4 : s;
}

/** Pick the most severe decision, or ALLOW when there are none. */
export function worstEffect(decisions) {
  let winner = null;
  for (const d of decisions) {
    if (winner === null || severityOf(d.effect) > severityOf(winner.effect)) winner = d;
  }
  return winner;
}

export function isAllowed(effect) {
  return effect === 'ALLOW';
}

/** Thrown by the runtime when it refuses to execute. Carries the receipt, not just a message. */
export class ActionRefused extends Error {
  constructor(receipt) {
    super(receipt.effect + ' ' + receipt.code + ': ' + receipt.reason);
    this.name = 'ActionRefused';
    this.effect = receipt.effect;
    this.code = receipt.code;
    this.receipt = receipt;
  }
}

/** A refusal that carries a machine-readable code. Used by every registry in this runtime. */
export class Refusal extends Error {
  constructor(code, message, detail) {
    super(code + ': ' + message);
    this.name = 'Refusal';
    this.code = code;
    this.detail = detail === undefined ? {} : detail;
  }
}

export function systemClock() {
  return new Date().toISOString();
}

export function fixedClock(startIso, stepMs) {
  const step = stepMs === undefined ? 1000 : stepMs;
  let n = 0;
  return function () {
    const t = new Date(new Date(startIso).getTime() + n * step);
    n += 1;
    return t.toISOString();
  };
}

/** Milliseconds between two ISO timestamps. Positive when b is later. */
export function msBetween(a, b) {
  return new Date(b).getTime() - new Date(a).getTime();
}
