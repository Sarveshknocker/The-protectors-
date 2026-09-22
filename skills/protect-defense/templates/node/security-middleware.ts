// Security middleware stack for Express (Node 18+).
// deps: npm i helmet express-rate-limit cors
// Usage:
//   const app = express();
//   applySecurity(app, { allowedOrigins: env.CORS_ORIGINS });
//   app.use('/api/auth', authLimiter);          // stricter limit on auth routes
//   ...routes...
//   app.use(notFoundHandler);
//   app.use(errorHandler);                       // must be registered last
import { randomUUID } from 'node:crypto';
import type { Express, NextFunction, Request, Response } from 'express';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

export interface SecurityOptions {
  allowedOrigins: string[];
  /** JSON/urlencoded body limit. Keep small; raise per-route for uploads. */
  bodyLimit?: string;
  /** Set when behind exactly N proxies (load balancer, CDN) so req.ip is the client IP. */
  trustProxy?: number | false;
}

declare module 'express-serve-static-core' {
  interface Request { id: string }
}

export function applySecurity(app: Express, opts: SecurityOptions) {
  app.disable('x-powered-by');
  if (opts.trustProxy) app.set('trust proxy', opts.trustProxy);

  // Correlation id for logs and error responses.
  app.use((req, res, next) => {
    const incoming = req.get('x-request-id');
    req.id = incoming && /^[\w-]{8,64}$/.test(incoming) ? incoming : randomUUID();
    res.setHeader('X-Request-Id', req.id);
    next();
  });

  // Secure headers. For HTML-serving apps, tailor the CSP to real sources (inventory them first).
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'object-src': ["'none'"],
          'frame-ancestors': ["'none'"],
          'base-uri': ["'self'"],
          'form-action': ["'self'"],
          'upgrade-insecure-requests': [],
        },
      },
      crossOriginEmbedderPolicy: false, // enable only if you need cross-origin isolation
      strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    }),
  );
  app.use((_req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    next();
  });

  // CORS: exact allow-list. Requests without Origin (server-to-server, curl) are allowed through CORS but still need auth.
  const allowed = new Set(opts.allowedOrigins);
  app.use(
    cors({
      origin(origin, cb) {
        if (!origin || allowed.has(origin)) return cb(null, true);
        return cb(null, false);
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
      maxAge: 600,
    }),
  );

  // Body limits (defends against memory exhaustion).
  const limit = opts.bodyLimit ?? '100kb';
  app.use(express.json({ limit }));
  app.use(express.urlencoded({ extended: false, limit }));

  // Global rate limit (per IP). Use a shared store (rate-limit-redis) when running multiple instances.
  app.use(globalLimiter);
}

export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

/** Stricter limiter for login, signup, password reset, OTP. */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { type: 'about:blank', title: 'Too many attempts', status: 429 },
});

/** Authenticated responses must not be cached by shared caches. */
export function noStore(_req: Request, res: Response, next: NextFunction) {
  res.setHeader('Cache-Control', 'no-store');
  next();
}

export class HttpError extends Error {
  constructor(public status: number, public title: string, public detail?: string) { super(title); }
}

export function notFoundHandler(_req: Request, _res: Response, next: NextFunction) {
  next(new HttpError(404, 'Not Found'));
}

// RFC 9457 problem+json. Never leaks stack traces or internal messages for 5xx.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
  const isHttp = err instanceof HttpError;
  const status = isHttp ? err.status : (err as { status?: number })?.status && (err as { status: number }).status < 500 ? (err as { status: number }).status : 500;
  if (status >= 500) {
    // Replace with the project's logger (pino/winston) — keep the request id for correlation.
    console.error(JSON.stringify({ level: 'error', requestId: req.id, msg: (err as Error)?.message, stack: (err as Error)?.stack }));
  }
  res.status(status).type('application/problem+json').json({
    type: 'about:blank',
    title: isHttp ? err.title : status >= 500 ? 'Internal Server Error' : 'Bad Request',
    status,
    ...(isHttp && err.detail && status < 500 ? { detail: err.detail } : {}),
    requestId: req.id,
  });
}
