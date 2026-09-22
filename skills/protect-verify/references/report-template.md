# Security Report — <project name>

_The Protectors · <date> · commit <sha>_

## 1. Executive summary
- **What this project is:** <type(s), stack, purpose, users, sensitive data handled>
- **Security score:** <before>/100 (grade <X>) → **<after>/100 (grade <Y>)**
- **Findings:** <n> critical, <n> high, <n> medium, <n> low found · <n> fixed · <n> remaining
- **Review coverage:** <reviewed>/<total> source files read manually
- **Top risk remaining:** <one sentence>

## 2. Actions for you (cannot be done safely by an AI)
| Priority | Action | Why | How |
|---|---|---|---|
| 🔴 Now | Rotate <secret type> found in `<file>` | Exposed in git history | Provider console → revoke & re-issue; update secret manager |
| 🔴 Now | Purge secret from git history | Still retrievable from old commits | `git filter-repo ...` then force-push (coordinate with team) |
| 🟠 Soon | Enable GitHub secret scanning + push protection | Prevent recurrence | Settings → Code security |
| 🟠 Soon | Enable WAF managed rules | Edge protection | <provider-specific steps> |

## 3. Threat model (summary)
Assets · entry points · trust boundaries · top threats (STRIDE). Full version: `.protectors/THREAT_MODEL.md`.

## 4. Findings (prioritised)
| ID | Sev | Status | Location | Issue (CWE / OWASP) | Fix / Evidence |
|---|---|---|---|---|---|
| P-001 | Critical | ✅ Fixed | `src/db/users.ts:42` | SQL injection (CWE-89, A03) | Parameterised query; test `users.sqli.test.ts` |
| P-002 | High | ⚠️ Open | `…` | … | Needs product decision: … |

## 5. Defense system implemented
| Layer | Control | Files |
|---|---|---|
| Edge | … | … |
| Browser | CSP (nonce), HSTS, … | `middleware.ts` |
| Identity / Access | … | … |
| Input / Output | … | … |
| Abuse | Rate limiting (global 300/15 min, auth 10/15 min) | … |
| Secrets | Validated env config, .env.example | `src/config/env.ts` |
| Observability | Request ids, redacted logging, problem+json errors | … |
| Supply chain | Dependabot, security CI (SARIF), lockfile | `.github/…` |
| Platform | … | … |

## 6. Professional-quality improvements
Anti-amateur items fixed (with files) and recommended refactors not applied (with reasons).

## 7. Verification evidence
- Scanner: before/after counts
- Build/lint/typecheck/tests: commands and results
- Security tests added: list
- Runtime checks: header/auth command outputs (local only)

## 8. Next steps (roadmap)
1. …
2. …

_Static and manual review cannot prove the absence of vulnerabilities. For high-risk systems (payments, health, finance), follow with an independent penetration test._
