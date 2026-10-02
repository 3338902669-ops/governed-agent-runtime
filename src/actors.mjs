// actors.mjs - THE ACTOR PRIMITIVE.
//
// Four rounds of security scans all pointed at the same root: the runtime had no notion of WHO was
// asking. A session was a bearer token - whoever held the id acted as that agent - and verification
// independence was checked between agent ids, which one actor could mint two of.
//
// An Actor is the principal that must exist before any session does. It is deliberately separate
// from Agent Identity: the agent is the role and the artifact; the actor is the party answerable
// for what was done. Independence is a property of actors, not of labels.

import { Refusal, clone, newId, sha256 } from './core.mjs';

export class ActorRegistry {
  constructor() {
    this.actors = new Map();  // actorId -> { actorId, name, kind, secretHash, revokedAt }
  }

  /** Mint an actor. The secret is returned ONCE and only its hash is kept. */
  create(input) {
    const actorId = (input && input.actorId) || newId('actor');
    if (this.actors.has(actorId)) throw new Refusal('ACTOR_EXISTS', 'actor already exists: ' + actorId);
    const secret = newId('secret') + newId('secret');
    const record = {
      actorId,
      name: (input && input.name) || actorId,
      kind: (input && input.kind) || 'agent-host',
      secretHash: sha256(secret),
      revokedAt: null,
      createdAt: (input && input.at) || null,
    };
    this.actors.set(actorId, record);
    return { actorId, secret, name: record.name, kind: record.kind };
  }

  has(actorId) {
    return this.actors.has(actorId);
  }

  /** Resolve an actor from a credential. Every failure mode has its own code. */
  authenticate(actorId, secret) {
    const record = this.actors.get(actorId);
    if (!record) throw new Refusal('ACTOR_UNKNOWN', 'no such actor: ' + String(actorId));
    if (record.revokedAt) throw new Refusal('ACTOR_REVOKED', 'actor ' + actorId + ' was revoked at ' + record.revokedAt);
    if (!secret || sha256(String(secret)) !== record.secretHash) {
      throw new Refusal('ACTOR_CREDENTIAL_INVALID', 'the actor credential does not match');
    }
    return clone(record);
  }

  revoke(actorId, reason, at) {
    const record = this.actors.get(actorId);
    if (!record) throw new Refusal('ACTOR_UNKNOWN', 'no such actor: ' + actorId);
    record.revokedAt = at || 'revoked';
    record.revokedReason = String(reason || 'unspecified');
    return clone(record);
  }

  view(actorId) {
    const record = this.actors.get(actorId);
    return record ? clone(record) : null;
  }
}
