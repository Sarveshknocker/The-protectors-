# Secure code review checklist (OWASP ASVS 4/5-aligned)

## Routes / controllers / handlers / API resolvers
- [ ] Authentication enforced by default (global middleware / deny-by-default), public routes explicitly listed
- [ ] Authorization per object: the resource's owner/tenant is checked against the session user (no IDOR)
- [ ] Role/permission checks on the server, never only by hiding UI
- [ ] Input validated with a schema (type, length, range, format, enum) — body, query, params, headers, cookies, files
- [ ] Unknown fields rejected / stripped (mass assignment: `role`, `isAdmin`, `price`, `userId` never bound from input)
- [ ] Output encoded for context (HTML, attribute, URL, JS, SQL, shell, LDAP)
- [ ] State-changing requests protected against CSRF (cookie auth) and use POST/PUT/PATCH/DELETE, not GET
- [ ] Rate limits on login, signup, password reset, OTP, search, expensive and public endpoints
- [ ] Pagination/limits on list endpoints (no unbounded queries)
- [ ] GraphQL: depth/complexity limits, introspection off in prod, per-field authz
- [ ] Webhooks: signature verified (HMAC, constant-time compare), replay window enforced
- [ ] File uploads: size/type allow-list, magic-byte check, random names, stored outside web root / private bucket, served with `Content-Disposition`

## Authentication & session
- [ ] Passwords: argon2id (or bcrypt cost ≥ 12); breached-password check; min length 8–12, no composition rules
- [ ] Login errors don't reveal whether the account exists; timing-safe comparisons
- [ ] MFA available for privileged users; recovery flows as strong as login
- [ ] Session cookies: `HttpOnly; Secure; SameSite=Lax|Strict; Path=/`, `__Host-` prefix; rotated on login/privilege change; server-side invalidation on logout
- [ ] JWT: verified with explicit algorithm allow-list, `aud`, `iss`, `exp`; short-lived access tokens; refresh tokens rotated & revocable; never stored in localStorage for web
- [ ] OAuth/OIDC: PKCE, `state` and `nonce` validated, exact redirect URI match
- [ ] Password reset tokens: single-use, ≥ 128-bit random, expire ≤ 1 h, hashed at rest

## Data access
- [ ] Parameterised queries / ORM everywhere; raw queries reviewed individually
- [ ] Least-privilege DB user; no superuser app connections
- [ ] Multi-tenant: tenant filter enforced centrally (RLS / scoped repository), not per query by hand
- [ ] Sensitive fields encrypted at rest where required (PII, tokens); secrets never stored in plaintext
- [ ] Supabase: RLS enabled on every table with policies; service-role key never in client. Firebase: rules deny by default

## Frontend / UI
- [ ] No secrets in client bundles or public env vars
- [ ] No raw HTML sinks with untrusted data; sanitise with DOMPurify if unavoidable
- [ ] CSP deployed (nonce-based), plus frame-ancestors, and no inline event handlers
- [ ] Tokens not in localStorage; third-party scripts minimised, loaded with SRI where static
- [ ] `target="_blank"` links use `rel="noopener noreferrer"`

## Crypto & secrets
- [ ] Only standard libraries (no home-made crypto); AES-GCM / ChaCha20-Poly1305; RSA ≥ 2048 / Ed25519
- [ ] CSPRNG for all tokens/ids that matter
- [ ] Secrets from env/secret manager, validated at startup; no defaults in code
- [ ] Keys rotated; separate keys per environment

## Errors, logging, monitoring
- [ ] Central error handler; generic messages to clients with correlation id; no stack traces in prod
- [ ] Structured logs with redaction (passwords, tokens, cookies, auth headers, PII)
- [ ] Security events logged: login success/failure, permission denied, password/MFA changes, admin actions
- [ ] No `catch {}` swallowing errors silently in security paths

## Config & deployment
- [ ] Debug off by default, env-driven; separate dev/prod configs
- [ ] Security headers (see website playbook); HTTPS enforced + HSTS
- [ ] CORS allow-list; no credentials with wildcard
- [ ] Containers non-root, minimal base, pinned; secrets not baked into images
- [ ] Health endpoints don't leak versions/config

## IPC / messaging (desktop, extensions, mobile, workers)
- [ ] Every message handler validates the sender and message schema
- [ ] Privileged operations are explicit, narrow functions — no generic "run command"/"read any file" channels
- [ ] Deep links / intents / custom protocols validate all parameters

## Business logic
- [ ] Prices, totals, discounts, quantities computed server-side
- [ ] Idempotency keys for payments/orders; race conditions handled (transactions, unique constraints)
- [ ] Limits on resource creation (spam/abuse), enumeration-resistant ids (UUIDv4/ULID) for public references
