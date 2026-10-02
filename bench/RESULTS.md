# Benchmark: how many incidents the system prevents

Reproduce with `node bench/benchmark.mjs`. The machine-readable record is
`bench/evidence/benchmark.json`.

| Incident | Naive | Governed (rules only) | Governed + Runtime |
|---|---|---|---|
| resource collision | 1 | 1 | **0** |
| self-declared done | 1 | 1 | **0** |
| done with no evidence | 1 | 1 | **0** |
| self-verification | 1 | 1 | **0** |
| external action, no approval | 1 | 1 | **0** |
| external action, expired approval | 1 | 1 | **0** |
| retry past the ceiling | 1 | 1 | **0** |
| artifact edited underneath a session | 1 | 1 | **0** |
| runtime runs with no grant | 1 | 1 | **0** |
| action after trust revocation | 1 | 1 | **0** |
| memory becomes system state | 1 | 1 | **0** |
| rollback to an unverified version | 1 | 1 | **0** |
| **Landed** | 12/12 | 12/12 | **0/12** |
| **Prevented** | 0/12 | 0/12 | **12/12** |

## The positive control

A benchmark that counts prevented incidents cannot tell **"enforcement worked"** from **"the system
was dead"** - both produce a column of zeros. So before any incident runs, the benchmark executes the
governed happy path and requires it to SUCCEED: a write allowed *and executed*, an independent
verification passed, and an authoritative fact established.

If that control fails, the benchmark prints why and **exits 2 without reporting a prevention number**.

```
$ GAR_GOVERNANCE_LIB=file:///nonexistent/lib.mjs node bench/benchmark.mjs
POSITIVE CONTROL FAILED - the benchmark cannot say anything about prevention:
  - the happy path threw: GOVERNANCE_UNAVAILABLE: governance engine unavailable
A column of zeros is meaningless when the system under test cannot do anything.   [exit 2]
```

This control was added after an independent verification round raised exactly this objection (its
finding F1). It is the difference between a number and a measurement.

## Methodology

- **Twelve incidents**, one per failure mode in the promotion brief. Each is a scripted attempt, not
  a model call, so the benchmark is deterministic and reproducible.
- **The third column is measured.** Every incident runs against the real control plane in this
  repository and lands (1) or does not (0). An exception on the way to the incident counts as a
  prevention, not a landing, which is the conservative direction for the claim.
- **The first two columns are models, and they say so.** `naiveModel` is an actor with no
  constraints; `advisoryModel` is the same actor with an advisory gate in front of it that it
  ignores. They are executable, not measurements of a deployed system, and they land every incident
  by construction. The reason to print them is that "we have rules for that" and "the rules have
  teeth" produce identical documents and different numbers.
- **The gate enforces the result.** `scripts/gate.mjs` fails if the third column is not zero, and
  fails if the positive control did not pass. Sixteen injected faults must all be caught, including two
  that pin the defects an independent verification round found (C1: the default surface must not mint
  grants; C2: an execution must consume a grant the gate issued).
- **The benchmark writes outside the repository on request.** Set `GAR_OUT_DIR` to keep
  `benchmark.json` out of the tree under audit, so a verifier can run it without modifying it.

## What this does not measure

- Model quality. There are no LLMs in this benchmark on purpose; it measures the coordination layer.
- The cost of the gate. Every action carries a decision, a ledger row and a grant; the prototype does
  not measure throughput.
- Adversaries outside the process. The threat model is a non-cooperating *agent*, not arbitrary code
  execution in the same process.
