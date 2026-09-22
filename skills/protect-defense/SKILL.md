---
name: protect-defense
description: Design and implement a tailored cybersecurity defense system for a project based on its type — websites (CSP/headers/WAF), APIs (authn/z, validation, rate limiting), mobile apps (secure storage, pinning, obfuscation), desktop apps (Electron/Tauri hardening), browser extensions (MV3 least privilege, messaging validation), CLIs/libraries (supply chain), cloud/IaC, firmware/IoT (secure boot, signed OTA, debug lockdown), and drivers/kernel code (IOCTL validation, device ACLs) — with production-ready templates.
---

# Defense implementation

## 1. Pick playbooks
Always `references/common.md`, plus one per detected type:
`website.md` · `api.md` · `mobile.md` · `desktop.md` · `browser-extension.md` · `cli-library.md` · `cloud-infra.md` · `firmware.md` · `driver.md`

Each playbook has: threat model summary → **mandatory controls** → recommended controls → framework-specific snippets → verification steps.

## 2. Defense-in-depth layers (map each to concrete code/config)
| Layer | Goal | Typical implementation |
|---|---|---|
| Edge | Filter attacks before app code | WAF managed rules (Cloudflare / AWS WAF / Azure Front Door / ModSecurity CRS), bot mgmt, DDoS, TLS 1.2+ |
| Transport | Confidentiality/integrity | HTTPS only, HSTS preload, certificate pinning (mobile, optional) |
| Browser | Contain XSS/clickjacking | CSP with nonces, frame-ancestors, COOP/CORP, Permissions-Policy, Trusted Types |
| Identity | Right user | Proven auth provider / library, MFA, secure sessions/JWT |
| Access | Right permissions | Deny-by-default authz middleware, object ownership checks, RLS |
| Input | Only valid data | Schema validation at every boundary, size limits, sanitisation for rich text |
| Output | Safe rendering | Context encoding, parameterised queries, no shell |
| Abuse | Resist automation | Rate limiting, lockout/backoff, captcha on sensitive forms, idempotency |
| Secrets | Nothing exposed | Env/secret manager, startup validation, rotation, no client exposure |
| Data | Minimise & protect | Encryption at rest, field-level for sensitive data, retention |
| Observability | Detect & respond | Structured logs with redaction, security events, alerts, error tracking |
| Supply chain | Trusted dependencies | Lockfiles, Dependabot, dependency review, SBOM, pinned CI actions, signed releases |
| Platform | OS/runtime hardening | Electron sandbox, Android network config/R8, iOS ATS/Keychain, non-root containers |
| Device / boot | Trusted firmware & kernel | Secure boot, signed OTA + anti-rollback, flash encryption, debug-port lockdown, signed drivers/modules, least-privilege device ACLs |

## 3. Templates (adapt to the project — never paste blindly)
| Template | For |
|---|---|
| `templates/node/security-middleware.ts` | Express/Node APIs — helmet headers, CORS allow-list, rate limits, body limits, request ids, safe error handler |
| `templates/node/validate.ts` | zod request validation middleware |
| `templates/node/env.ts` | Typed, validated environment config (fail fast) |
| `templates/node/guards.ts` | SSRF-safe fetch, path-traversal-safe file resolve, safe redirect, HTML sanitise, constant-time compare |
| `templates/nextjs/middleware.ts` | Next.js nonce-based CSP + security headers |
| `templates/python/fastapi_security.py` | FastAPI headers, CORS, rate limit, error handler, settings |
| `templates/python/django_security_settings.py` | Django production security settings |
| `templates/python/guards.py` | SSRF / path / redirect guards for Python |
| `templates/electron/main.secure.ts`, `templates/electron/preload.ts` | Hardened Electron window + narrow IPC bridge |
| `templates/browser-extension/manifest.json`, `templates/browser-extension/messaging.ts` | Least-privilege MV3 manifest + validated messaging |
| `templates/mobile/network_security_config.xml` | Android TLS policy + optional pinning |
| `templates/firmware/hardening-flags.cmake` | GCC/Clang hardening flags for firmware & native code (+ host fuzzing setup) |
| `templates/firmware/sdkconfig.production` | ESP-IDF production security config (secure boot, flash/NVS encryption, anti-rollback, JTAG/console off) |
| `templates/drivers/linux_ioctl_safe.c` | Hardened Linux misc-device ioctl (capability check, single fetch, zeroed output, locking) |
| `templates/drivers/windows_kmdf_ioctl_safe.c` | Hardened KMDF IOCTLs (METHOD_BUFFERED, SDDL ACL, size-enforced buffers, ExAllocatePool2) |
| `templates/infra/Dockerfile.node` | Hardened multi-stage container |
| `templates/infra/nginx-security.conf` | Reverse-proxy headers, TLS, rate limiting (+ ModSecurity CRS hook) |
| `templates/repo/security-ci.yml` | CI: Protectors scan (SARIF), CodeQL, dependency review, secret scan, OSV |
| `templates/repo/dependabot.yml` | Automated dependency updates |
| `templates/repo/SECURITY.md` | Vulnerability disclosure policy |
| `templates/repo/.env.example` | Env template convention |
| `templates/repo/gitignore-security.txt` | Secret-safe .gitignore block |

## 4. Rules
- Match the project's language, framework version, module system, formatting and folder conventions.
- Every new layer is wired in (registered middleware, imported config) — not just a file dropped in the repo.
- Every new layer has at least one test, or a verification command recorded in the report.
- Don't break existing behaviour: restrictive policies (CSP, CORS) start from what the app actually uses — inventory script/style/connect/img sources first. If unsure, ship CSP as `Content-Security-Policy-Report-Only` and say so.
