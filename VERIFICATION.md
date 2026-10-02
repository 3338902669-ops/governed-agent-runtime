# Independent verification log

Who verified what, what it cost, and what changed as a result. The implementer (DSH) is not the
verifier; the verifier (天枢 / tianshu, headless `rivet` worker) does not write to the source tree.

| Round | Verifier | Outcome | What it changed |
|---|---|---|---|
| 1 | 天枢 job `pwsh-24` | **FAILED to complete** (turn budget + sandbox junction). 4 baseline commands never ran; V1-V10 all UNVERIFIED; no `verdict.json` produced. | Raised static finding **F1**: a benchmark of *prevented* incidents cannot distinguish "enforcement worked" from "the system was dead". |
| 2 | 天枢 job `pwsh-57` | **FAILED to complete** (turn budget again; 1 of 4 baselines ran). No artifacts produced. | Raised static findings **C1-C4**, all in the source it read. |
| 3 | 天枢 (split cards) | see below | - |

## What the verifier's findings were worth

None of these were found by the 49-test suite, the benchmark, or the gate - all of which were green.
They were found by reading the code for the *reachable* surface rather than the *intended* one.

### F1 - a prevention count with no positive control  → FIXED

A benchmark that only counts incidents that landed reports 0 when the system is dead, exactly as it
reports 0 when the system works. **Fix:** `bench/benchmark.mjs` now runs the governed happy path
first and requires it to succeed (write allowed *and executed*, verification passed, fact
established); otherwise it prints why and exits 2 without a prevention number.

### C1 - the gate could be walked around through the exposed ledger  → FIXED (this was the real one)

`createControlPlane` attached the raw `ledger` to its public API, and `Ledger.issueGrant` is a
public method. Minting a grant by hand and handing it to `runtime.execute` passed every check in
`revalidate()`, so **the executor ran with zero policy decisions recorded**. The central claim -
"the executor is reachable through the gate and nowhere else" - was false as implemented.

Reproduced before the fix:

```
cp.ledger.issueGrant is a function: true
C1 CONFIRMED - executor ran, executionId= exec-a76899c9f1a543b6  executorCalls= 1
   policy decisions recorded: 0
```

**Fix:** the default surface is read-only (`readOnlyLedger` / `readOnlyRegistry` /
`readOnlyGovernance`). Minting is only attached when an embedder explicitly asks for
`internals: true`, which the test fixture does in order to simulate an already-compromised process.
Pinned by test **A16** and gate mutation **public-ledger-minting**.

### C2 - an execution could be forged with a grant id that never existed  → FIXED

`Ledger.recordExecution` looked the grant up and carried on when it was missing, so a caller could
record an execution, attach evidence, pass a verification and write an **authoritative fact** -
without touching the gate at all.

Reproduced before the fix: `C2 CONFIRMED - authoritative fact: {"key":"forged:state","value":"done",...}`

**Fix:** `recordExecution` now requires a grant that the gate issued **and consumed**, and refuses a
second execution for the same grant (`EXECUTION_WITHOUT_GRANT`, `EXECUTION_ALREADY_RECORDED`). This
is enforced in the ledger itself, so it holds even for a caller holding the privileged surface.
Pinned by test **A17** and gate mutation **forged-execution**.

### C3 - a refused approval was downgraded to a note  → FIXED

`approve` caught the governance engine's refusal and stored it as `approval.governanceNote` while
still recording the approval as a success. That is a WARNING inside an ALLOW/DENY system.

**Fix:** the governor is consulted first and its refusal propagates; no approval is recorded.
Verified: the refusal now surfaces as `GOVERNANCE_REFUSED` with `session.approval === null`, and a
legitimate approval on a task that does carry an external action still succeeds.

### C4 - `audit().consistent` was true while a real disagreement existed  → FIXED (renamed)

The field only covered blocking divergences, yet it was named `consistent`. A runtime could be
`done` while the governance queue still sat in `specify`, and the audit still said `consistent: true`.

**Fix:** renamed to `noBlockingDivergences`. Observations stay separate and are still reported.

## The lesson that generalises

## Round 4 - the security scan (codex-security + DeepSeek, a different channel)

A second, independent channel was run over the same tree: `node scripts/secscan.cjs --root
governed-agent-runtime --name governed-agent-runtime --model deepseek-flash`. The relay/luna channel
preflighted as unavailable (the local router forwards to an endpoint that rejects `gpt-5.6-luna`), so
the documented DeepSeek-direct fallback was used.

`--evaluate` on the sealed artifacts: **8 findings, 0 critical, 0 high, 6 medium, 2 low** - PASS at the
high threshold. But an addendum finding was produced *after* the manifest was sealed, so it is not in
that count, and it was **high**:

> **Revoked artifact trust can be silently reinstated and re-promoted through the gated `evaluate`
> action.** `ArtifactRegistry.evaluate` wrote `trust = VALIDATED` for any passing check without
> consulting the current trust, and the revocation rule only inspected the acting session's own
> artifact.

**Reproduced with the scanner's own POC** (`poc-a-revocation.mjs`), before the fix:

```
A1 revoke effect: ALLOW | trust now: REVOKED
A2 impl action after revoke: BLOCK TRUST_REVOKED | executed: false
A3 evaluate revoked artifact: ALLOW ALLOWED | trust now: VALIDATED | lifecycle: VALIDATED   <-- the bypass
A4 impl action after re-evaluation: ALLOW ALLOWED | executed: true                          <-- work resumed
A5 release revived artifact: ALLOW ALLOWED
A6 promote revived artifact: ALLOW ALLOWED | trust: TRUSTED
```

**After the fix**, the same POC:

```
A1 revoke effect: ALLOW | trust now: REVOKED
A2 impl action after revoke: BLOCK TRUST_REVOKED | executed: false
A3 evaluate revoked artifact: BLOCK EVALUATION_OF_REVOKED_ARTIFACT | trust now: REVOKED | lifecycle: REVOKED
A4 impl action after re-evaluation: BLOCK TRUST_REVOKED | executed: false
A5 -> the exploit chain dies: RELEASE_NEEDS_EVALUATION (a revoked artifact cannot be released)
```

Revocation is now terminal: `evaluate` refuses a REVOKED or SUPERSEDED artifact, and policy rule
`P08b` refuses it at the gate. Pinned by test **A18** and gate mutation **revocation-is-terminal**.
Un-revocation is deliberately not supported in this prototype.

### The six medium findings, all in one family: caller-supplied identity and scope

| # | Finding | Fix |
|---|---|---|
| M1 | An agent can grant its own external-action approval and satisfy the approval rule | approval independence is now decided by the *approving session's* agent, and the approving agent is recorded (`approvedByAgent`) alongside the free-text `approvedBy` label |
| M2 | Artifact evaluation and promotion independence is decided by caller-supplied name strings | the evaluator/releaser/promoter/roller-back/revoker is the agent the **grant** identifies, never `params.by` |
| M3 | External-action approval scope is not bound to the operation the executor runs | policy `P19b`: the request target must equal the approved target, or `EXTERNAL_TARGET_MISMATCH` |
| M4 | Runtime resource exclusion is enforced against a caller-supplied task id | policy `P17`/`P18` take the task from the **session**, not the request |
| M5 | Agent role is caller-asserted and never checked against the artifact definition | `createAgent` refuses a role that disagrees with the artifact's declared role (`AGENT_ROLE_MISMATCH`) |
| M6 | A task can be marked done citing a verification not bound to its work | a PASS binds `task.implementationExecutionId`; `mark_done` refuses any other verification (`DONE_VERIFICATION_NOT_BOUND`) |

Pinned by tests **A19** and the updated **A05/A06/A16/A17**.

### What this round does NOT establish

The security fixes (the high finding and M1-M6) have been confirmed **only by the implementer**, by
re-running the scanner's own POC and the suite. They have **not** been through an independent
verification round - the 天枢 rounds that succeeded ran against the tree as it stood before them. A
fresh scan was started against the hardened tree and its result is not in this document yet.
Recording that gap is the point: "fixed" and "independently confirmed fixed" are different claims.

**A test suite tests the API you intended; an adversary tests the API you shipped.**

The 49 tests passed, the benchmark reported 12/12 prevented and the gate caught 16 injected faults -
none of which touched the two-line path from `cp.ledger.issueGrant` to `cp.runtime.execute`. Two
rounds of an independent reader who was told "do not trust the implementer's numbers" found it in
minutes of reading. That is the whole argument for separating execution rights from completion
rights, applied to this repository itself.
