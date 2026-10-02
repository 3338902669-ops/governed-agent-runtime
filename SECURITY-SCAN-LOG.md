# Security scan log — six rounds, zero passes

This is the honest record of what happened when this prototype was put in front of an adversarial
channel. It is published because it is the most useful thing in the repository: the code shows what
was intended, this shows what was actually reachable.

**Method.** `node scripts/secscan.cjs --root <repo> --model deepseek-flash` (codex-security over the
DeepSeek Responses API). Verdicts are read from the sealed artifacts with `--evaluate`, never from a
process exit code alone. A scan that reports **"Scan target changed during execution"** is discarded:
it measured a moving tree.

| # | Revision | Coverage | Findings | Verdict |
|---|---|---|---|---|
| 1 | before the first fix round | partial | 6 medium, 2 low **+ 1 high addendum** | not passed (the addendum is outside the seal) |
| 2 | mid-fix | - | - | **discarded** — the tree was edited while it ran |
| 3 | `193a65d` | complete | **3 high**, 2 medium, 1 low | not passed |
| 4 | `6bf9461` | complete | **1 high**, 2 medium, 1 low | not passed |
| 5 | `66374a8` | - | - | **cancelled** — the tree was edited while it ran |
| 6 | `9b98073` | complete | **1 high**, 3 medium, 1 low | not passed |

Six rounds. Zero passes. Meanwhile the project's own suite was green every time (49 tests) and the
mutation gate caught all 16 injected faults. **A test suite tests the API you intended; an adversary
tests the API you shipped.**

## The shape of the failure

Every round closed the reported hole and exposed a sibling of it:

| Round | HIGH reported | What the previous round had closed |
|---|---|---|
| 1 | revoked trust reinstated through `evaluate` | - |
| 3 | a session could be opened for any minted agent | identity minting |
| 4 | `handoff` still called `openSession` internally | session opening |
| 6 | approval independence decided between agent ids, not actors | verification independence (actor-level) |

The root is the same every time: **the runtime had no notion of who was asking.** A session was a
bearer token, and "a different agent did it" was a check between labels rather than between
principals. Round 7 of the work (revision `9b98073`) added the actor primitive — sessions require an
authenticated actor plus a token, executions record the actor, and verification independence is
measured between actors. Round 6 above shows it still was not closed, because **approval**
independence was left at the agent-id level.

## Round 1

**Sealed set:** 6 medium, 2 low. **Addendum, produced after the manifest was sealed:** 1 high —
*"Revoked artifact trust can be silently reinstated and re-promoted through the gated `evaluate`
action."* Reproduced with the scanner's own proof of concept: `revoke` → `evaluate` → trust
`VALIDATED` → work resumes → `release` → `promote` → `TRUSTED`. Fixed by making revocation
artifact-scoped and terminal; the same proof of concept now fails at every step.

The six medium findings were all one family — **caller-supplied identity and scope**: an agent could
approve its own external action, artifact evaluation independence was decided by a name string, the
approval scope was not bound to the operation, resource exclusion used a caller-supplied task id,
the agent role was never checked against the artifact, and lifecycle actions took the actor from
caller parameters.

## Round 3 — `193a65d` (3 high)

- **A runner could open a session for any minted agent.** The policy gate derives identity, role and
  permissions from the session, so one actor could hold a verifier session and a coordinator
  session at once and every "a different agent did it" check became cosmetic.
- **Approval independence lived only in the `cp.approve` helper.** Submitting the gated `approve`
  action directly walked around it — validation outside the enforcement point, which is the exact
  anti-pattern this gate exists to prevent.
- **Revocation was terminal on the `evaluate` path but erasable through `mutate` then `rollback`:**
  `mutate` rewrote a `REVOKED` version to `SUPERSEDED`, and `rollback` restored it.

## Round 4 — `6bf9461` (1 high)

- **`handoff` was still on the runner surface, and its executor called the operator-only
  `openSession` with a caller-chosen `toAgentId`.** The previous round closed `openSession` and
  missed its internal caller.
- Medium: revocation had a third door via a superseded version; the read-only ledger published
  redeemable grant ids and `execute` authorised by possession alone.

## Round 6 — `9b98073` (1 high)

- **Approval independence is decided between agent ids, not actors.** One actor holding both the
  requesting session and any coordinator session approves its own deploy.
- Medium: `revokeActor` leaves live sessions and unspent grants usable; any agent with
  `mutate_artifact` can replace another agent's artifact definition; a task-bound session can write a
  resource another live task holds.
- Low: the runner client's `close` and `execute` bypass the session token — it is enforced only
  inside the policy gate.

## Why this is published rather than fixed

Not because it is unfixable, but because the *shape* repeats: each round is a path patch, and the
next sibling appears. Closing it properly needs a threat model and a single identity/authority model
rather than more rules. See `KNOWN-FINDINGS.md` and `VERIFICATION.md`.

Raw scan reports (including proofs of concept) are kept outside the repository; the summaries above
are reproduced from them.
