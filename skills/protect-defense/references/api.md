# API / backend playbook

## Threats (OWASP API Top 10 2023)
Broken object-level authz (IDOR), broken authentication, broken object property level authz (mass assignment / excessive data exposure), unrestricted resource consumption, broken function-level authz, sensitive business flows abuse, SSRF, misconfiguration, improper inventory (old/debug endpoints), unsafe consumption of third-party APIs.

## Mandatory controls
1. **Deny-by-default auth middleware**: every route requires auth unless on an explicit public list.
2. **Authorization**: central policy helpers (`can(user, action, resource)`), object ownership / tenant checks in the service layer. Add tests: user A cannot read/update user B's resource.
3. **Validation**: schema per route for body/query/params (zod `templates/node/validate.ts`, pydantic models, class-validator DTOs, Bean Validation `@Valid`). Reject unknown fields. Response DTOs — never return ORM entities directly (password hashes, internal flags).
4. **Tokens**:
   - Prefer opaque server sessions or short-lived JWT (≤ 15 min) + rotating refresh tokens (httpOnly cookie for web).
   - Verify JWT with `algorithms: ['RS256'|'EdDSA'|'HS256']` explicitly, check `iss`, `aud`, `exp`, `nbf`; keys from JWKS with caching; clock skew ≤ 60 s.
   - OAuth2/OIDC: Authorization Code + PKCE; scopes mapped to permissions; client credentials only for machine-to-machine.
   - API keys for integrations: hashed at rest (SHA-256 of a 32-byte random key), prefix for identification, scoped, revocable, last-used tracking.
5. **Rate limiting & quotas**: global per-IP + stricter per-route (auth, OTP, search, exports) + per-user/API-key quotas; body size limits (e.g. 100 kb JSON); pagination caps; request timeouts. Use a shared store (Redis) when horizontally scaled.
6. **CORS**: exact origin allow-list from config; credentials only with explicit origins.
7. **Errors**: RFC 9457 problem+json responses with generic detail and a correlation id; log the real error.
8. **SSRF**: outbound requests to user-influenced URLs go through `safeFetch` (`templates/node/guards.ts` / `templates/python/guards.py`).
9. **Webhooks**: verify HMAC signatures with constant-time compare and timestamp tolerance.
10. **Security headers for APIs**: `Cache-Control: no-store` on authenticated responses, `X-Content-Type-Options: nosniff`, CSP `default-src 'none'; frame-ancestors 'none'`.
11. **Inventory**: remove/disable debug, test and legacy endpoints; OpenAPI spec kept in sync; admin endpoints behind separate auth + network restriction.

## Framework snippets
- **Express/Fastify/Nest**: `templates/node/security-middleware.ts` (Fastify: `@fastify/helmet`, `@fastify/rate-limit`, `@fastify/cors`; Nest: `helmet()`, `ThrottlerModule`, global `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`).
- **FastAPI**: `templates/python/fastapi_security.py`.
- **Django/DRF**: `templates/python/django_security_settings.py`; DRF `DEFAULT_PERMISSION_CLASSES = [IsAuthenticated]`, `DEFAULT_THROTTLE_CLASSES`.
- **Flask**: `flask-talisman` (headers/CSP), `flask-limiter`, `flask-wtf` CSRF, `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE`.
- **Spring Boot**: Spring Security `SecurityFilterChain` with `authorizeHttpRequests(a -> a.requestMatchers(PUBLIC).permitAll().anyRequest().authenticated())`, `headers(h -> h.contentSecurityPolicy(...))`, method security `@PreAuthorize`, Bucket4j rate limiting.
- **ASP.NET Core**: `[Authorize]` global filter / `FallbackPolicy = RequireAuthenticatedUser`, `AddRateLimiter`, `UseHsts`, `UseHttpsRedirection`, antiforgery, `ProblemDetails`.
- **Laravel**: `auth:sanctum` middleware groups, `RateLimiter::for`, Form Requests validation, `$fillable` only, `APP_DEBUG=false`.
- **Go**: `chi` middleware (`httprate`, timeouts), `go-playground/validator`, `unrolled/secure`.

## BaaS (Supabase / Firebase)
- Supabase: RLS **enabled on every table** with explicit policies (`auth.uid() = user_id`), service-role key server-only, storage bucket policies, disable anonymous sign-ins unless needed.
- Firebase: Firestore/Storage rules deny by default (`allow read, write: if false;`) then grant per path with `request.auth.uid == resource.data.owner`; App Check enabled; admin SDK only on server.

## Verification
- Unauthenticated request to every non-public route → 401.
- Cross-user access tests → 403/404.
- Oversized body → 413; burst of requests → 429.
- Invalid payload → 400 with no stack trace.
