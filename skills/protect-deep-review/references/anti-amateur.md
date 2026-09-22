# Anti-amateur checklist

Signals that make a project look unprofessional to a reviewer, an acquirer or an enterprise security team. Fix the ones that are safe to fix automatically; list the rest in the report.

| # | Amateur signal | Professional standard | Auto-fix? |
|---|---|---|---|
| 1 | Secrets, API keys, passwords in code or committed `.env` | Env/secret manager, `.env.example`, startup validation (zod / pydantic-settings) | ✅ move to env + template; ⚠️ rotation is the user's action |
| 2 | No input validation, or validation only on the frontend | Schema validation at every trust boundary (zod, pydantic, Joi, class-validator, Bean Validation) | ✅ |
| 3 | `try { … } catch (e) {}` / bare `except: pass` | Handle, log with context, rethrow or return typed error | ✅ |
| 4 | `console.log`/`print` debugging left everywhere | Structured logger with levels & redaction | ✅ for obvious debug lines |
| 5 | Stack traces / raw DB errors returned to users | Central error handler, correlation ids | ✅ |
| 6 | Magic strings/numbers, copy-pasted blocks | Named constants, shared helpers | ⚠️ only where trivial |
| 7 | God files (1000+ lines mixing routing, SQL and HTML) | Layered structure: routes → services → data access | ❌ recommend with a target structure |
| 8 | Commented-out code blocks, TODO graveyards | Delete (git remembers); track work in issues | ✅ remove dead commented code |
| 9 | No lockfile / `*` / `latest` versions | Lockfile committed, CI uses frozen installs | ✅ |
| 10 | No README / LICENSE / SECURITY.md / CONTRIBUTING | All present and accurate | ✅ SECURITY.md; README section additions |
| 11 | No `.gitignore` or it misses `.env`, keys, build output | Comprehensive `.gitignore` | ✅ |
| 12 | No linting/formatting, inconsistent style | ESLint/Biome/Ruff/etc. + formatter + `.editorconfig` | ✅ config (don't reformat the whole codebase unasked) |
| 13 | TypeScript `any` everywhere / `strict: false` | `strict: true`, typed boundaries | ⚠️ enable if it compiles; else report |
| 14 | No tests, especially for auth/payments | Tests for security-critical logic at minimum | ✅ add tests for the security layers you add |
| 15 | No CI | CI: lint, typecheck, test, build, security scan (SARIF), dependency review | ✅ |
| 16 | HTTP URLs, disabled TLS verification | HTTPS only, verification on | ✅ |
| 17 | Mixed naming conventions, misspelled identifiers in public APIs | Consistent conventions per language | ❌ report |
| 18 | Hard-coded environment specifics (localhost URLs, file paths) | Config per environment | ✅ |
| 19 | Using deprecated/unsafe APIs (MV2, `createCipher`, `yaml.load`, `md5` passwords) | Current APIs | ✅ |
| 20 | Debug flags / dev servers in production config | Env-driven, secure defaults | ✅ |
| 21 | No rate limiting or abuse controls on public forms | Rate limits + bot protection (Turnstile/hCaptcha) on sensitive forms | ✅ rate limit; ⚠️ captcha keys are user's |
| 22 | Default credentials (admin/admin), sample users in seeds shipped to prod | Seeds only in dev; forced password setup | ✅ |
| 23 | Everything in one folder / no separation of client and server secrets | Clear `src/` layout, server-only modules marked (`server-only`) | ⚠️ |
| 24 | No versioning/changelog for libraries & extensions | SemVer + CHANGELOG | ✅ add CHANGELOG stub |
