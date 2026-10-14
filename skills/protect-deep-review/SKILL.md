---
name: protect-deep-review
description: File-by-file manual secure code review and "anti-amateur" quality review — authorization/IDOR, input validation, business logic, error handling, secrets, crypto, logging, plus professional code-quality signals — recorded as evidence-backed findings (confirmed / needs validation / rejected) against a coverage ledger. Use after automated scanning, or whenever asked to review code for security or professionalism.
---

# Deep review

Scanners find patterns; reviewers find **missing** things (a route with no auth check, a price taken from the client,
validation that exists on the frontend only). This is where most serious bugs are found. A finding counts only when it
names a real trust boundary that is crossed and shows the evidence.

## Method
1. **Plan coverage.** From `.protectors/recon.json`, write `.protectors/coverage.json`: one unit per
   *surface × boundary × attack class* (see `references/evidence-contract.md`). Everything you will not review is a unit
   too, marked `out_of_scope`, `blocked` or `deferred` with a note. Never let silence imply "reviewed".
2. **Review unit by unit**, high-risk surfaces first. For each file, apply `references/review-checklist.md` for its role
   (route/controller, auth, data access, UI, config, IPC, infra). Trace user input from source to sink across files.
   Mark the unit `covered` with the paths you read, or `candidate` with the findings it produced.
3. **Triage the scanner.** Every critical/high scanner and dependency finding is read in context and becomes `confirmed`,
   `needs_validation` or `rejected` in `review.json`, with the reason.
4. **Prove it.** For each candidate, write the boundary (attacker, input, control, crossed, affected) and the trace.
   Reproduce critical/high candidates with a local test or harness against the project's own code, using dummy data,
   before calling them confirmed. Keep the test: after the fix it becomes the regression test.
   If the deciding fact is outside the repository, record `needs_validation` with the blocker and a safe plan.
5. **Verify independently.** For critical/high confirmed findings, have a fresh reviewer (sub-agent with
   `agents/finding-verifier.md`, or a separate pass of your own that re-reads only the cited lines) confirm the trace and the
   evidence before the finding is reported.
6. **Professionalism.** Apply `references/anti-amateur.md` across the codebase; these are hardening items, not
   vulnerabilities, unless they cross a boundary.
7. Run `node <kit>/skills/protect-verify/scripts/review-check.mjs .` until it passes. It writes `REVIEW_STATUS.md`.

## Must-answer questions (write answers in THREAT_MODEL.md)
- Which endpoints/handlers/IPC channels/message listeners exist, and which ones enforce authentication? Authorization (ownership/role)? List any that don't.
- Where does every piece of user input enter, and where is it validated (server-side, schema-based)?
- Where are secrets loaded from? Is anything sensitive shipped to the client bundle (`NEXT_PUBLIC_*`, `VITE_*`, `BuildConfig`, extension code)?
- What happens on error — what does the user see, what is logged?
- What third parties receive data? Does the app render or convert untrusted documents (HTML→PDF, PDF viewers, Office files, images)?
- Could a normal user do something only an admin should (role checks), or act on another user's object (IDOR)? Another tenant's?
- Are money/quantity/price/role values ever trusted from the client?
- If there are LLM features: can user or retrieved content change the model's instructions, and can model output reach a tool, a query or the DOM without validation?

## References
- `references/evidence-contract.md` — review.json / coverage.json format, severity anchors, safe reproduction, anti-patterns.
- `references/review-checklist.md` — per-role checklist (ASVS-aligned).
- `references/anti-amateur.md` — professionalism checklist and the fixes.
