---
name: protect-verify
description: Verify security fixes and hardening actually work and didn't break the project — re-scan, build/lint/typecheck/tests, security tests, runtime header/auth checks — then produce the final SECURITY_REPORT. Use after implementing defenses or before declaring a project secure.
---

# Verify & report

## 1. Re-scan
```bash
node <kit>/skills/protect-scan/scripts/scan.mjs . --out .protectors --fail-on high
```
Compare with the first scan (keep the original as `.protectors/findings.before.json` — copy it before Phase 4). Report score before → after.

## 2. Project gates
Run the project's own scripts (from package.json / Makefile / pyproject / gradle): install with the lockfile, lint, typecheck, unit tests, build. All must pass. If a pre-existing failure exists, prove it pre-dates your changes (run it on the original state via `git stash`) and report it separately.

## 3. Security tests (add them — they're part of the deliverable)
- Validation: invalid payload → 400; unknown fields rejected.
- AuthN: every non-public route without credentials → 401.
- AuthZ: user A cannot access user B's resource → 403/404.
- Rate limiting: burst on auth route → 429.
- Guards: `safeResolve('../etc/passwd')` throws; `assertSafeUrl('http://169.254.169.254')` throws; `safeRedirectTarget('//evil.com')` falls back.
- Headers: response includes CSP/HSTS/nosniff/Referrer-Policy (supertest / TestClient / curl against a local server).
Use the project's existing test framework and conventions.

## 4. Runtime check (when the project can run locally)
Start it, then:
```bash
curl -sI http://localhost:<port>/ | grep -iE 'content-security|strict-transport|x-content-type|referrer-policy|permissions-policy|x-powered-by'
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:<port>/api/<protected-route>   # expect 401
```
Only against the user's local/preview environment — never production or third-party hosts unless the user explicitly asks.

## 5. Loop
Fix → re-verify, up to 5 iterations. Anything still failing goes into the report with the reason and a concrete next step.

## 6. SECURITY_REPORT.md
Fill `references/report-template.md` → `.protectors/SECURITY_REPORT.md`. Be factual: every claim has a file path, command output, or test name as evidence. Never include secret values.
