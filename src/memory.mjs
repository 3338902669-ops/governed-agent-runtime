// memory.mjs - agent memory. Deliberately NOT the ledger, and deliberately not authoritative.
//
// MEMORY IS NOT TRUTH. An agent may remember anything it likes; nothing in this file can change
// system state, and no reader of system state consults it. The separation is the architecture,
// not a convention: memory entries carry authority 'none' and there is no code path from here to
// Ledger.assertFact.
//
//   Memory  -> Agent Context   (soft, self-reported, may be wrong, may be stale)
//   Evidence -> System Fact    (hard, gate-produced, verified)

import { clone, newId } from './core.mjs';

export class AgentMemory {
  constructor() {
    this.entries = [];
  }

  write(input) {
    const entry = {
      noteId: newId('note'),
      agentId: input.agentId,
      key: input.key,
      value: input.value,
      kind: input.kind || 'observation',
      authority: 'none',
      at: input.at || new Date().toISOString(),
    };
    this.entries.push(entry);
    return clone(entry);
  }

  /** Record that the agent believes something is finished. This changes nothing outside this store. */
  claimCompletion(input) {
    return this.write({ ...input, kind: 'completion-claim', key: input.key || 'completion' });
  }

  read(agentId, key) {
    for (let i = this.entries.length - 1; i >= 0; i -= 1) {
      const e = this.entries[i];
      if (e.agentId === agentId && e.key === key) return clone(e);
    }
    return null;
  }

  all(agentId) {
    return this.entries.filter(function (e) { return !agentId || e.agentId === agentId; }).map(clone);
  }
}
