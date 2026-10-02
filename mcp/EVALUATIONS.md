# MCP adapter evaluations

Five questions a client should be able to answer through this server alone. Each lists the tool
call and what a correct answer looks like. They are the "can a model actually use this" check, as
opposed to "does the handler work", which the protocol suite covers.

| # | Question | Tool call | Correct answer |
|---|---|---|---|
| 1 | What does the auditor check? | `list_audit_claims` | Seven claims A1-A7; a client should be able to say what each asserts without reading the source |
| 2 | Is this ledger admissible? | `audit_ledger` with the export | `verdict: HOLDS` only when all seven hold; the answer must report the counts, not just a boolean |
| 3 | Which claim failed, and why? | `audit_ledger` on a ledger with a known fault | The failing claim id plus its `detail` (e.g. "A4 ... actor X verified its own work"), not a generic failure |
| 4 | The record says the work is done and the audit says UNKNOWN on A4. Is that a pass? | `audit_ledger` | **No.** UNKNOWN means the record does not carry the field the claim needs. A client that reports UNKNOWN as a pass has failed this evaluation. |
| 5 | Can I use this server to approve a deploy? | `tools/list` | **No.** There is no such tool, and both tools are annotated `readOnlyHint: true`. The correct answer names the absence rather than improvising one. |

## What question 4 is really testing

The whole repository turns on one distinction: **"I could not check" is not "it is fine"**. A model
that collapses UNKNOWN into a pass has reproduced, at the client, the exact failure this project
exists to remove - so it is worth testing explicitly rather than assuming.

## Not covered

Questions requiring live runtime state (the server reads an export, it does not attach to a running
instance), and anything that would need write access - by design.
