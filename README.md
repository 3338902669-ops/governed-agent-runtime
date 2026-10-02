# Governed Agent Runtime

**A runtime where an agent cannot act unless governance says so - and cannot declare its own success either.**

This is the layer that sits under [Agent Orchestra](../agent-orchestra-repo). Agent Orchestra answers
*"how do several agents finish a task correctly?"* (I1-I10: task, resource, ownership, handoff,
verification, evidence, approval, recovery). This repository answers the next question:

> **An agent from creation to exit: how does it stay governable the whole time?**

The answer here is one seam and one rule.

**The seam.** Every action an agent wants to take becomes an ActionRequest. The request goes to a
policy gate. The gate answers with exactly one of five effects - `ALLOW`, `REQUIRE_VERIFICATION`,
`REQUIRE_APPROVAL`, `DENY`, `BLOCK` - and only `ALLOW` produces a grant. The executor is reachable
through that grant and nowhere else.

**The rule.** Execution rights and completion rights are separate. An agent may do work; no agent may
declare that the work is good.

```
Agent -> Action Request -> Governance -> Policy -> ALLOW / DENY / BLOCK / REQUIRE_* -> Runtime
                                                                                      |
                                                      Execution -> Evidence -> Independent Verification
                                                                                      |
                                                                              State Transition (fact)
```

## Run it

Node 18+, zero dependencies.

```bash
node bin/demo.mjs          # the governed path, twelve attacks, and the audit
node --test "test/*.test.mjs"   # 38 checks: 16 invariant tests, 22 attack tests
node bench/benchmark.mjs   # naive vs governed vs governed+runtime (positive control first)
node scripts/gate.mjs      # the suite, the benchmark, and eight injected faults that must be caught
```

## Measured, not asserted

`node bench/benchmark.mjs` attempts twelve incidents against three coordination models. Only the
third column is the real system, and only its number is measured by running code:

| Incident | Naive | Governed (rules only) | Governed + Runtime |
|---|---|---|---|
| resource collision | landed | landed | **prevented** |
| self-declared done | landed | landed | **prevented** |
| done with no evidence | landed | landed | **prevented** |
| self-verification | landed | landed | **prevented** |
| external action, no approval | landed | landed | **prevented** |
| external action, expired approval | landed | landed | **prevented** |
| retry past the ceiling | landed | landed | **prevented** |
| artifact edited underneath a session | landed | landed | **prevented** |
| runtime runs with no grant | landed | landed | **prevented** |
| action after trust revocation | landed | landed | **prevented** |
| memory becomes system state | landed | landed | **prevented** |
| rollback to an unverified version | landed | landed | **prevented** |
| **Landed** | 12/12 | 12/12 | **0/12** |

Before any incident runs, the benchmark executes the **positive control**: the governed happy path
must actually succeed (write allowed *and executed*, verification passed, fact established). If it
does not, the benchmark refuses to print a prevention number at all and exits 2 - because "everything
was blocked" and "enforcement worked" produce the same column of zeros. That control exists because
an independent verification round raised exactly that objection.

The middle column is the point of the whole exercise: **rules that are only evaluated are rules an
actor can ignore.** The first two columns are executable models of non-cooperating actors, not
measurements of a deployed system - see [bench/RESULTS.md](bench/RESULTS.md) for the methodology and
its limits.

## The object model

```
Agent Artifact                      Agent Identity                 Role
  artifactId, name, version           agentId                        capabilities
  roleId, instructions                roleId, artifactId             permissions {allow, deny}
  tools, policies, memorySchema       artifactVersion                requiredEvidence (L1/L2/L3)
  definitionHash (content hash)       definitionHash                 verificationConstraints
  trust:      UNKNOWN -> VALIDATED    runtime {runtimeId, ...}       allowedTools
              -> TRUSTED -> REVOKED   identityFingerprint            allowedResources
  lifecycle:  DRAFT -> VALIDATED      trust (derived)                lifecycle
              -> RELEASED             lifecycle (derived)
              -> PROMOTED
```

Two questions the identity layer answers mechanically rather than by convention:

- *"Is today's verifier the same agent as yesterday's?"* -> compare `identityFingerprint`. It covers
  agent id, role, artifact version, definition hash and runtime. A version bump changes it.
- *"If the verifier goes v1 -> v2, does governance know?"* -> the session freezes the fingerprint on
  open, and every later action is re-checked against it. A changed identity is a `BLOCK`.

A **Role** is a system object, not a label. `verifier.verificationConstraints.cannotVerifyOwnImplementation`
is `true`, so "a verifier cannot verify its own work" is a property of the type rather than a sentence
repeated in every workflow.

## Memory is not truth

```
Memory   -> Agent Context   (soft, self-reported, may be stale, authority: "none")
Evidence -> System Fact     (hard, produced by a gate-passed execution, verified, chained)
```

An agent may remember anything it likes. `ledger.assertFact` is the only writer of authoritative
state, and it requires a PASSED verification, which requires evidence, which requires an execution
that went through the gate. There is no code path from `memory.mjs` to a fact.

## The five effects

| Effect | Means | Example |
|---|---|---|
| `ALLOW` | a grant is issued, bound to session + identity + artifact hash + action + target | a normal write inside your own task |
| `REQUIRE_VERIFICATION` | the action is right but the state is not there yet | marking a task done without a passing verification |
| `REQUIRE_APPROVAL` | a human decision is missing | deploying to production |
| `DENY` | this actor may never do this | self-verification, a replayed grant, an expired approval |
| `BLOCK` | the world itself is unsafe | ledger tampering, revoked trust, artifact mutation, governance unavailable |

There is no `WARNING` and no `LOG`. A gate that can only warn is a record, not a control.

## What independent verification found

The implementer is not the verifier. Two independent rounds (天枢 / headless `rivet` worker) were run
against this repository, and both **failed to complete** - but their static reading found four
defects that the 34-test suite, the benchmark and the gate had all passed over. The full log is in
[VERIFICATION.md](VERIFICATION.md). The two that mattered:

- **C1 - the gate could be walked around.** `createControlPlane` attached the raw ledger to its
  public API, and `Ledger.issueGrant` is a public method. Minting a grant by hand and handing it to
  `runtime.execute` passed every check in `revalidate()`: **the executor ran with zero policy
  decisions recorded.** Reproduced, then fixed: the default surface is now read-only and minting
  lives behind an explicit `internals: true` that only the test fixture asks for.
- **C2 - an execution could be forged.** `recordExecution` ignored a missing grant, so an entire
  execution -> evidence -> verification -> **authoritative fact** chain could be written without
  touching the gate. Reproduced (`{"key":"forged:state","value":"done"}`), then fixed in the ledger
  itself, so it holds even for a caller holding the privileged surface.

**A test suite tests the API you intended; an adversary tests the API you shipped.**

## Where governance actually stops the runtime

Three mechanisms, and each one has a test that removes it and fails:

1. **The executor is not exposed, and neither is the minting.** The executor lives in a
   module-private `WeakMap` keyed by the frozen API object (`runtime.executor` is `undefined`), and
   the default control-plane surface is read-only: no `issueGrant`, no `recordExecution`, no
   `assertFact`, no registry mutators. `internals: true` attaches them, and only the test fixture
   asks for it - because its adversarial cases simulate an already-compromised process.
2. **Grants are single-use, expiring, and bound.** `execute()` requires a grant this runtime issued,
   for this session, this identity, this artifact hash, this action and this target. Replay, expiry
   and substitution each have their own refusal code.
3. **Grants are re-validated at execution time.** A grant issued before a revocation, a handoff, an
   artifact edit or a governance block is dead on arrival, not a loophole. And the acting identity
   comes from the grant, never from the request payload.

Evidence cannot be backfilled: `recordEvidence` requires an execution id that resolves, and the
policy gate refuses evidence for an execution that does not exist - so "run first, justify later" has
nowhere to write.

## Invariants I11-I18

Full table with enforcement points and the test that pins each one: [INVARIANTS.md](INVARIANTS.md).
In short: I11-I17 are enforced with tests; I18 is enforced as *detection* (the audit names divergence
classes) with full state mirroring left as a declared seam.

## Honest limits

This is a prototype, and the boundaries are written down rather than implied - see
[KNOWN-FINDINGS.md](KNOWN-FINDINGS.md). The four that matter most:

- **It is an in-process discipline, not a security boundary.** Sessions, grants and the ledger live in
  memory. An agent that can run arbitrary code in the same process is not contained by this. Signed
  state or an external authorisation service is the fix, and it is not here.
- **Evidence lives in the runtime ledger, not in the governance queue.** The governance stage machine
  is not driven to completion by this prototype, so the two stores disagree by design. `audit()`
  reports it as an observation instead of claiming consistency.
- **Cross-agent handoff cannot be expressed yet.** The governance engine has no reassign API, so a
  handoff here is a same-agent epoch bump that supersedes the old session. Reassignment is a gap in
  the layer below, not a missing feature here.
- **The root of trust is outside the gate.** `bootstrapTrust` lets a named human principal perform
  the first evaluation and release, because there is no agent above the first artifact. It is
  recorded as such and no agent role can reach it.

## Layout

```
src/core.mjs           canonical serialization, hashing, ids, the five effects
src/identity.mjs       roles, agent artifacts, trust and lifecycle registry, agent identity
src/ledger.mjs         hash-chained ledger, single-use grants, evidence, verification, facts
src/memory.mjs         agent memory - deliberately not authoritative, and not on the fact path
src/policy.mjs         the gate: the rule table and the decision receipt
src/governance.mjs     the seam to Agent Orchestra (fail-closed if it is unavailable)
src/runtime.mjs        the sealed executor and the grant protocol
src/control-plane.mjs  wiring: every state change is a gated action
src/fixture.mjs        the world the tests and the benchmark build
test/invariants.test.mjs   I11-I18
test/adversarial.test.mjs  the fifteen attacks
bench/                 incidents, the three-model benchmark, evidence
bin/demo.mjs           the run-through
scripts/gate.mjs       the suite, the benchmark, and the injected faults
```
