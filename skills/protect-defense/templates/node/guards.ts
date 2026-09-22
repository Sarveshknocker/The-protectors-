// Reusable security guards for Node/TypeScript. Zero runtime deps except DOMPurify for sanitizeHtml.
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import path from 'node:path';
import { timingSafeEqual, createHmac } from 'node:crypto';

// ---------------------------------------------------------------------------
// SSRF: fetch only public http(s) hosts from an allow-list (or any public host if allowList is empty).
// ---------------------------------------------------------------------------
function isPrivateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v6 = ip.toLowerCase();
  // IPv4-mapped IPv6, in dotted (::ffff:127.0.0.1) or hex (::ffff:7f00:1, as the WHATWG URL parser normalises it) form.
  const mapped = /^(?:0{0,4}:){0,5}:?ffff:(.+)$/.exec(v6)?.[1];
  if (mapped) {
    if (isIP(mapped) === 4) return isPrivateAddress(mapped);
    const hex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(mapped);
    if (hex) {
      const hi = parseInt(hex[1], 16), lo = parseInt(hex[2], 16);
      return isPrivateAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return true; // unparseable mapped form: treat as unsafe
  }
  return v6 === '::1' || v6 === '::' || v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80') || v6.startsWith('ff');
}

export async function assertSafeUrl(raw: string, allowList: string[] = []): Promise<URL> {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('Invalid URL'); }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('Scheme not allowed');
  if (url.username || url.password) throw new Error('Credentials in URL not allowed');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (allowList.length && !allowList.some((h) => host === h || host.endsWith('.' + h))) throw new Error('Host not allowed');
  const addrs = isIP(host) ? [{ address: host }] : await lookup(host, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateAddress(a.address))) throw new Error('Destination not allowed');
  return url;
}

/** fetch() wrapper for user-influenced URLs: validates, disables redirects, enforces a timeout and size cap.
 *  Note: DNS can change between check and connect (rebinding). For high-risk cases, route egress through a proxy that enforces the same rules. */
export async function safeFetch(raw: string, init: RequestInit & { allowList?: string[]; timeoutMs?: number; maxBytes?: number } = {}) {
  const { allowList = [], timeoutMs = 5000, maxBytes = 5 * 1024 * 1024, ...rest } = init;
  const url = await assertSafeUrl(raw, allowList);
  const res = await fetch(url, { ...rest, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  if (res.status >= 300 && res.status < 400) throw new Error('Redirects not allowed');
  const len = Number(res.headers.get('content-length') ?? 0);
  if (len > maxBytes) throw new Error('Response too large');
  return res;
}

// ---------------------------------------------------------------------------
// Path traversal: resolve a user-supplied relative path inside a fixed base directory.
// ---------------------------------------------------------------------------
export function safeResolve(baseDir: string, userPath: string): string {
  if (userPath.includes('\0')) throw new Error('Invalid path');
  const base = path.resolve(baseDir);
  const target = path.resolve(base, userPath);
  if (target !== base && !target.startsWith(base + path.sep)) throw new Error('Path escapes base directory');
  return target;
}

// ---------------------------------------------------------------------------
// Open redirect: only allow same-site relative paths (or allow-listed absolute origins).
// ---------------------------------------------------------------------------
export function safeRedirectTarget(target: unknown, fallback = '/', allowedOrigins: string[] = []): string {
  if (typeof target !== 'string' || target.length > 2048) return fallback;
  if (target.startsWith('/') && !target.startsWith('//') && !target.startsWith('/\\')) return target;
  try {
    const u = new URL(target);
    return allowedOrigins.includes(u.origin) ? u.toString() : fallback;
  } catch { return fallback; }
}

// ---------------------------------------------------------------------------
// Constant-time comparisons & webhook signatures.
// ---------------------------------------------------------------------------
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** Verify `sha256=<hex>` style HMAC webhook signatures with a replay window. */
export function verifyWebhook(rawBody: string | Buffer, signature: string, secret: string, timestamp?: number, toleranceSec = 300): boolean {
  if (timestamp !== undefined && Math.abs(Date.now() / 1000 - timestamp) > toleranceSec) return false;
  const payload = timestamp !== undefined ? `${timestamp}.${rawBody.toString()}` : rawBody;
  const expected = 'sha256=' + createHmac('sha256', secret).update(payload).digest('hex');
  return safeEqual(expected, signature);
}

// ---------------------------------------------------------------------------
// HTML sanitising for user rich text (server: isomorphic-dompurify; browser: dompurify).
// ---------------------------------------------------------------------------
// import DOMPurify from 'isomorphic-dompurify';
// export const sanitizeHtml = (dirty: string) =>
//   DOMPurify.sanitize(dirty, { USE_PROFILES: { html: true }, FORBID_TAGS: ['style', 'form'], FORBID_ATTR: ['style'] });
