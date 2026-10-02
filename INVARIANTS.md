# Invariants I11-I18

Each row states where the invariant is enforced and the test that fails if the enforcement is removed.
`scripts/gate.mjs` proves the mechanism works by injecting faults into a copy of the source and
requiring every one to be caught.

| ID | Invariant | Status | Enforced by | Pinned by |
|---|---|---|---|---|
| I11 | Agent Identity must be immutable during an execution | ENFORCED | `freezeIdentity`, `session.identityHash`, policy `P06`, `revalidate()` | `I11: the identity snapshot is immutable for the life of a session`; `I11: replacing the agent identity mid-execution blocks every action` |
| I12 | Runtime action requires Governance authorization | ENFORCED | `createGovernedRuntime` (sealed executor + grants), policy `P01-P12, P18`, `Ledger.consumeGrant` | `I12: the executor is not reachable without a grant from the gate`; `I12: a grant is single-use, expiring and bound to one target`; `I12: the acting agent comes from the grant`; attacks A04, A11 |
| I12a | A grant may only be issued by the gate, and the surface a runner gets must not mint one | ENFORCED | `readOnlyLedger`/`readOnlyRegistry`/`readOnlyGovernance`, `internals` opt-in, policy — | attack A16; gate mutation `public-ledger-minting`; found by independent verification (finding C1) |
| I12c | An execution must consume a grant the gate issued, exactly once | ENFORCED | `Ledger.recordExecution` (`EXECUTION_WITHOUT_GRANT`, `EXECUTION_ALREADY_RECORDED`) | attack A17; gate mutation `forged-execution`; found by independent verification (finding C2) |
| I12b | The runtime must fail closed when the governor is unavailable | ENFORCED | policy `P01`, `revalidate()`, `GovernanceBridge.#require` | attack A11; gate mutation `policy-allow-all` |
| I13 | Memory cannot directly establish authoritative system state | ENFORCED | `memory.mjs` (`authority: none`), policy `P13`, `Ledger.assertFact` | `I13: memory can claim anything and still establish nothing`; `I13: only a passed verification turns work into an authoritative fact`; attack A12 |
| I14 | Artifact modification invalidates previous trust | ENFORCED | `ArtifactRegistry.mutate`, `assertIntegrity`, policy `P07`, `P07b`, `P21`, `revalidate()` | `I14: modifying an artifact invalidates the sessions and grants bound to it`; `I14: editing the stored definition in place is detected and revokes trust`; attacks A08, and the benchmark's `artifact-tampering` incident |
| I15 | Promotion requires independent evaluation | ENFORCED | `ArtifactRegistry.evaluate/promote`, policy `P15, P23, P23a-c`, `Ledger.recordVerification` grounding rules | `I15: promotion of an unevaluated artifact is refused before anything happens`; `I15: an artifact that nobody independent evaluated cannot be promoted`; `I15: an approval whose scope names something else is refused`; attacks A02, A13 |
| I16 | Rollback must restore a previously verified artifact | ENFORCED | `ArtifactRegistry.rollback`, policy `P24` | `I16: rollback refuses a version that was never verified`; attack A14 |
| I17 | Revoked trust cannot be bypassed by stale sessions | ENFORCED | `ArtifactRegistry.revoke`, policy `P04, P05, P08`, `revalidate()` | `I17: revoking trust kills live sessions and unspent grants`; attacks A09, A10 |
| I18 | Governance state and runtime state cannot silently diverge | ENFORCED (detection) | `Ledger.verifyChain`, policy `P02`, `controlPlane.audit()` | `I18: a tampered ledger is detected and blocks the gate`; `I18: tampering with a stored evidence record is detected too`; attacks A15, A15b |

Imported from the layer below and relied on here: I1 (one owner per task), I2 (one writer per
resource), I3 (no implementer verifies its own L2/L3 work), I5 (a failed verification blocks
downstream), I6 (three failed rounds block the task), I9 (an external action needs a matching
approval). The runtime does not re-implement these; `src/governance.mjs` asks the Agent Orchestra
engine and maps its refusals to decision codes.

## What is deliberately not claimed

- **I18 is detection, not synchronisation.** `audit()` reports blocking divergences separately from
  declared storage duality. It does not claim the two stores mirror each other.
- **I12 is enforced in-process.** The grant protocol is a structural constraint on code that goes
  through this runtime. It is not a security boundary against code that does not.
- **The evidence checks are structural.** The gate refuses E1 evidence that is missing a command, an
  exit code or a revision. It does not verify that the command ran - the same honest boundary Agent
  Orchestra records as its finding F-012.
