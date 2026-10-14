# Evidence contract: review.json and coverage.json

Manual findings are recorded as data, checked by `protect-verify/scripts/review-check.mjs`, and only then reported.
The point is to separate **what was proven** from **what is suspected**, and to say honestly **what was not reviewed**.

## coverage.json — what was reviewed
Units are *surface × boundary × attack class*. Build them from recon: every entry point (route group, IPC channel,
message listener, CLI command, ioctl, OTA handler, webhook…) crossed with the boundaries it touches and the attack
classes that apply.

```json
{
  "units": [
    { "id": "api/orders:authz", "surface": "REST /api/orders/*", "boundary": "user → other users' orders", "attack_class": "authorization / IDOR",
      "status": "covered", "reviewed_paths": ["src/routes/orders.ts", "src/services/orders.ts"], "findings": ["idor.orders-get"] },
    { "id": "api/upload:files", "surface": "POST /api/upload", "boundary": "internet → filesystem", "attack_class": "file upload / path traversal",
      "status": "covered", "reviewed_paths": ["src/routes/upload.ts"], "findings": [] },
    { "id": "infra/cdn:headers", "surface": "CDN / reverse proxy", "boundary": "browser → app", "attack_class": "security headers",
      "status": "blocked", "note": "Proxy config is not in this repository." }
  ]
}
```
Statuses: `planned`, `in_progress`, `covered`, `candidate` (produced a finding), `blocked`, `deferred`, `out_of_scope`,
`not_applicable`. Anything not `covered`/`candidate` needs a `note`. A review with open units is **partial** and must
say so.

Typical attack classes: authentication, session, authorization/IDOR, input validation, injection (SQL/NoSQL/command/
template), XSS/HTML sinks, SSRF, file handling/path traversal, deserialization, crypto & secrets, business logic
(price, quantity, state machine), rate limiting & resource exhaustion, multi-tenant isolation, logging & privacy,
supply chain & CI, platform hardening (Electron, extension, mobile, firmware, driver), document rendering, LLM features.

## review.json — what was found
```json
{
  "findings": [
    {
      "fingerprint": "idor.orders-get", "verdict": "confirmed", "unit": "api/orders:authz",
      "title": "Any signed-in user can read any order by id",
      "boundary": { "attacker": "authenticated customer", "input": "GET /api/orders/:id with another customer's id",
                    "control": "order ownership check", "crossed": "customer → other customers' orders", "affected": "order PII and addresses" },
      "trace": [
        { "kind": "entrypoint", "file": "src/routes/orders.ts", "line": 18, "note": "router.get('/:id') with requireAuth only" },
        { "kind": "sink", "file": "src/services/orders.ts", "line": 42, "note": "findById(id) without owner filter" }
      ],
      "root_cause": "The service queries by id alone; ownership is never compared with the session user.",
      "evidence": [ { "type": "test", "command": "npm test -- orders.idor.test.ts", "file": "test/orders.idor.test.ts", "line": 1,
                      "result": "user B received user A's order (200) before the fix; 404 after" } ],
      "severity": "high", "severity_rationale": "Fully defeats ownership for every order; exposes other customers' addresses.",
      "fix": { "invariant": "An order is readable only by its owner or an admin.", "change": "Filter findById by ownerId = session.userId in OrdersService.get",
               "regression_test": "test/orders.idor.test.ts" },
      "status": "fixed"
    },
    {
      "fingerprint": "headers.csp-at-edge", "verdict": "needs_validation", "unit": "infra/cdn:headers",
      "title": "No CSP is set by the app; it may be set by the CDN",
      "boundary": { "attacker": "script injected via any XSS", "input": "malicious markup", "control": "Content-Security-Policy",
                    "crossed": "untrusted script → user session", "affected": "all signed-in users" },
      "trace": [ { "kind": "entrypoint", "file": "src/server.ts", "line": 10, "note": "no CSP middleware" } ],
      "blocker": "CDN response-header configuration is not in the repository.",
      "validation_plan": "Owner checks the production response headers in the CDN console or with their browser devtools."
    },
    { "fingerprint": "sqli.reports-raw", "verdict": "rejected", "unit": "api/orders:authz", "title": "Scanner: SQL concatenation in reports.ts",
      "reason": "The concatenated value is a constant column name from a fixed allow-list (reports.ts:12–20); no user input reaches it." }
  ]
}
```

## Rules the checker enforces
- **confirmed**: all five boundary fields; a trace with an entrypoint and a sink (every file:line must exist); root cause;
  severity with rationale; fix invariant and change; evidence. Evidence must include a `test` or `harness` run with its
  command, **or** a `reproduction_waiver` explaining why running code adds nothing (a committed credential, a manifest
  flag, a disabled compiler mitigation). `fixed` requires a regression test; `accepted_risk` requires an owner and reason.
- **needs_validation**: boundary + trace + the missing fact (`blocker`) + a safe `validation_plan`. **No severity.**
- **rejected**: a reason. Rejected candidates stay in the file so later runs do not re-report them.

## Severity anchors (confirmed only)
- **critical**: unauthenticated code execution, full data-store access, or takeover of arbitrary accounts; a live
  production secret committed.
- **high**: an explicit control fully defeated with real consequences: auth bypass, cross-tenant read/write, stored XSS
  affecting other users, authenticated RCE, SSRF to cloud metadata.
- **medium**: a real boundary violation with limited blast radius or uncommon preconditions.
- **low**: non-secret internals disclosed, or an effect needing sustained effort for little gain.
- **info**: confirmed but minimal impact.
If you cannot state the concrete damage, the severity is lower than it feels.

## Reproduce safely
Tests and harnesses run **locally against the project's own code**, with dummy users, dummy data and dummy secrets: a unit
test, an integration test against a local server, a small fixture. Never against production, shared environments or
third-party services. Stop at the minimum effect that proves the boundary is crossed (a wrong 200, another dummy user's
record). If the deciding fact lives outside the repository (proxy, cloud console, identity provider), the finding is
`needs_validation`, not confirmed.

## Anti-patterns
1. A checklist deviation reported as a vulnerability (missing best practice with no reachable boundary violation goes in
   hardening recommendations, not findings).
2. Guessing deployment, proxy or provider behaviour that is not in the repository.
3. Treating a user's power over their own data as a cross-boundary result.
4. Claiming a stronger effect than was observed.
5. Severity on a `needs_validation` item.
6. Writing the report before the checker passes, or letting the prose and the JSON disagree.
