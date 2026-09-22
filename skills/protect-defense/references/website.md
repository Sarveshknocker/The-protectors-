# Website / web app playbook

## Threats
XSS, CSRF, clickjacking, open redirect, secrets leaked in bundles, third-party script compromise, session theft, credential stuffing on login forms, SSRF via server-side features (image proxies, link previews), dependency vulnerabilities.

## Mandatory controls
1. **Security headers** (all responses):
   | Header | Value |
   |---|---|
   | Content-Security-Policy | `default-src 'self'; script-src 'self' 'nonce-{N}' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' <api/analytics origins>; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests` |
   | Strict-Transport-Security | `max-age=63072000; includeSubDomains; preload` (only once HTTPS is everywhere) |
   | X-Content-Type-Options | `nosniff` |
   | Referrer-Policy | `strict-origin-when-cross-origin` |
   | Permissions-Policy | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()` (enable only what's used) |
   | Cross-Origin-Opener-Policy | `same-origin` |
   | Cross-Origin-Resource-Policy | `same-site` |
   | X-Frame-Options | `DENY` (legacy; CSP frame-ancestors is authoritative) |
   Remove `X-Powered-By` / `Server` version banners.
   - Next.js → `templates/nextjs/middleware.ts` (nonce CSP) + `poweredByHeader: false`.
   - Express → `templates/node/security-middleware.ts`.
   - Static hosting → `_headers` (Netlify/Cloudflare Pages), `vercel.json` headers, `staticwebapp.config.json`, or `templates/infra/nginx-security.conf`.
2. **No secrets in the client**: audit `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `PUBLIC_*`, and anything imported into client components. Mark server modules with `import 'server-only'` (Next.js).
3. **XSS**: remove raw HTML sinks or sanitise with DOMPurify; for Markdown use a sanitising renderer.
4. **Forms**: server-side schema validation (zod/valibot) on every Server Action / API route; CSRF protection for cookie sessions (Next.js Server Actions check Origin by default — keep `serverActions.allowedOrigins` tight); rate limit + Turnstile/hCaptcha on login, signup, contact, password reset.
5. **Auth**: use a proven library/provider (Auth.js, Clerk, Supabase Auth, Lucia-style patterns, Django auth); secure cookie flags; no tokens in localStorage.
6. **Third-party scripts**: minimise; load via the framework's script component; SRI for static CDN assets; consent-gate analytics.
7. **Links**: `rel="noopener noreferrer"` on external `target="_blank"`; validate redirect targets.

## Edge / WAF
- **Cloudflare**: enable Managed Rules (Cloudflare + OWASP Core Ruleset, paranoia 1–2), Bot Fight Mode, rate-limit rule for `/api/*` and auth paths, "Always Use HTTPS", minimum TLS 1.2, HSTS.
- **AWS WAF** (CloudFront/ALB): `AWSManagedRulesCommonRuleSet`, `KnownBadInputsRuleSet`, `SQLiRuleSet`, `AmazonIpReputationList`, rate-based rule (e.g. 1000 req/5 min/IP; lower for auth paths).
- **Vercel**: Firewall custom rules + Attack Challenge Mode; `vercel.json` headers.
- **Self-hosted**: nginx + ModSecurity v3 + OWASP CRS (`templates/infra/nginx-security.conf`).

## Verification
- `curl -sI https://<local-or-preview>/ | grep -iE 'content-security|strict-transport|x-content|referrer|permissions|cross-origin'`
- Browser console: no CSP violations on key pages (or report-only first).
- Mozilla Observatory / securityheaders.com style grade A (on a preview URL the user owns).
