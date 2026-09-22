---
name: protect-deep-review
description: File-by-file manual secure code review and "anti-amateur" quality review — authorization/IDOR, input validation, business logic, error handling, secrets, crypto, logging, plus professional code-quality signals. Use after automated scanning, or whenever asked to review code for security or professionalism.
---

# Deep review

Scanners find patterns; reviewers find **missing** things (a route with no auth check, a price taken from the client, validation that exists on the frontend only). This is where most serious bugs are found.

## Method
1. Load `.protectors/recon.json`. Build the review list: all source + config files, excluding generated, vendored, lockfiles and assets. Order: high-risk first, then entry points, then the rest.
2. For each file, apply `references/review-checklist.md` for its role (route/controller, auth, data access, UI, config, IPC, infra). Trace user input from source to sink across files.
3. Apply `references/anti-amateur.md` across the codebase.
4. Record each issue in `.protectors/REVIEW.md`:
   `| ID | Severity | File:line | Category | Issue | Evidence | Fix |`
5. Track coverage at the top of REVIEW.md: `Reviewed N / M files`. Target 100 % of non-generated source.

## Must-answer questions (write answers in THREAT_MODEL.md)
- Which endpoints/handlers/IPC channels/message listeners exist, and which ones enforce authentication? Authorization (ownership/role)? List any that don't.
- Where does every piece of user input enter, and where is it validated (server-side, schema-based)?
- Where are secrets loaded from? Is anything sensitive shipped to the client bundle (`NEXT_PUBLIC_*`, `VITE_*`, `BuildConfig`, extension code)?
- What happens on error — what does the user see, what is logged?
- What third parties receive data?
- Could a normal user do something only an admin should (role checks), or act on another user's object (IDOR)?
- Are money/quantity/price/role values ever trusted from the client?

## References
- `references/review-checklist.md` — per-role checklist (ASVS-aligned).
- `references/anti-amateur.md` — professionalism checklist and the fixes.
