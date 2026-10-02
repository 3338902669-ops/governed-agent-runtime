# Independent verification log

Who verified what, what it cost, and what changed as a result. The implementer (DSH) is not the
verifier; the verifier (天枢 / tianshu, headless `rivet` worker) does not write to the source tree.

| Round | Verifier | Outcome | What it changed |
|---|---|---|---|
| 1 | 天枢 job `pwsh-24` | **FAILED to complete** (turn budget + sandbox junction). 4 baseline commands never ran; V1-V10 all UNVERIFIED; no `verdict.json` produced. | Raised static finding **F1**: a benchmark of *prevented* incidents cannot distinguish "enforcement worked" from "the system was dead". |
| 2 | 天枢 job `pwsh-57` | **FAILED to complete** (turn budget again; 1 of 4 baselines ran). No artifacts produced. | Raised static findings **C1-C4**, all in the source it read. |
| 3 | 天枢 (split cards) | see below | - |

## What the verifier's findings were worth

None of these were found by the 34-test suite, the benchmark, or the gate - all of which were green.
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

**A test suite tests the API you intended; an adversary tests the API you shipped.**

The 34 tests passed, the benchmark reported 12/12 prevented and the gate caught 7 injected faults -
none of which touched the two-line path from `cp.ledger.issueGrant` to `cp.runtime.execute`. Two
rounds of an independent reader who was told "do not trust the implementer's numbers" found it in
minutes of reading. That is the whole argument for separating execution rights from completion
rights, applied to this repository itself.
