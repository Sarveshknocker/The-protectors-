// Next.js (app router) — nonce-based CSP + security headers on every HTML response.
// Place at the project root (or src/). Next.js 16+: name the file `proxy.ts` and rename the export to `proxy`
// (`middleware` is the name up to Next.js 15). Next.js automatically applies the nonce to its own scripts
// when it reads the CSP from the request header. Read it in server components with:
//   const nonce = (await headers()).get('x-nonce') ?? undefined;  → pass to <Script nonce={nonce}>
// Also set in next.config: poweredByHeader: false
import { NextResponse, type NextRequest } from 'next/server';

// Add real third-party origins your app uses (analytics, APIs, image CDNs). Inventory before tightening.
const CONNECT_SRC = ["'self'"];
const IMG_SRC = ["'self'", 'data:', 'blob:'];

export function middleware(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const isDev = process.env.NODE_ENV === 'development';

  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ''}`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src ${IMG_SRC.join(' ')}`,
    `font-src 'self' data:`,
    `connect-src ${CONNECT_SRC.join(' ')}${isDev ? ' ws:' : ''}`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    ...(isDev ? [] : ['upgrade-insecure-requests']),
  ].join('; ');

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  response.headers.set('X-Frame-Options', 'DENY');
  return response;
}

export const config = {
  matcher: [
    // All paths except static assets and prefetches.
    { source: '/((?!api|_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)', missing: [{ type: 'header', key: 'next-router-prefetch' }, { type: 'header', key: 'purpose', value: 'prefetch' }] },
  ],
};
