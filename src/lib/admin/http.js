// Admin HTTP helpers (admin design §8.1, §10.3, §16): client-IP
// derivation, domain-separated source hashing, same-origin checks,
// bounded JSON body reading, and the admin response header set.
import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';

export function isProduction() {
  return process.env.NODE_ENV === 'production';
}

// The repository's existing convention (see the public scan routes):
// first x-forwarded-for entry, else x-real-ip, else the literal
// bucket 'local'. A present-but-invalid value becomes 'unknown'.
// The raw IP is used only transiently — to derive a hash and to
// evaluate limits — and is never stored, logged, or returned.
export function clientIp(request) {
  const raw =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    null;
  if (raw == null || raw === '') return 'local';
  return isIP(raw) ? raw : 'unknown';
}

export function normalizeIp(ip) {
  return String(ip || '').trim().toLowerCase();
}

// admin source hash = HMAC-SHA256(VISITOR_HASH_SECRET,
//   "admin-source:v1:" + normalizedIp)   (design §8.1)
export function adminSourceHash(secret, ip) {
  return createHmac('sha256', secret).update(`admin-source:v1:${normalizeIp(ip)}`).digest('hex');
}

export function requestOrigin(request) {
  try {
    return new URL(request.url).origin;
  } catch {
    return null;
  }
}

// Same-origin evaluation shared by login (strict check, no session
// yet) and authenticated POSTs (defense in depth beside the CSRF
// token):
//  - an Origin header, when present, must equal the request origin;
//  - in production a state-changing admin POST with no Origin is
//    rejected outright;
//  - a Referer header, when present, must have the same origin too.
export function checkSameOrigin(request, { requireOrigin = isProduction() } = {}) {
  const origin = requestOrigin(request);
  if (!origin) return false;
  const originHeader = request.headers.get('origin');
  if (originHeader != null) {
    if (originHeader !== origin) return false;
  } else if (requireOrigin) {
    return false;
  }
  const referer = request.headers.get('referer');
  if (referer != null && referer !== '') {
    try {
      if (new URL(referer).origin !== origin) return false;
    } catch {
      return false;
    }
  }
  return true;
}

export class BodyError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'BodyError';
    this.status = status;
  }
}

// Bounded JSON body reader. Rejects non-JSON content types, bodies
// over maxBytes (checked on the raw text before parsing), and
// malformed JSON — each with a generic, detail-free BodyError.
export async function readJsonBody(request, maxBytes) {
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new BodyError(415, 'Request body must be JSON.');
  }
  let text;
  try {
    text = await request.text();
  } catch {
    throw new BodyError(400, 'Request body must be JSON.');
  }
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new BodyError(413, 'Request body is too large.');
  }
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new BodyError(400, 'Request body must be a JSON object.');
    }
    return value;
  } catch (err) {
    if (err instanceof BodyError) throw err;
    throw new BodyError(400, 'Request body must be JSON.');
  }
}

// The admin header set (design §16.1). next.config.mjs applies the
// same set at the platform layer; route handlers additionally pin
// Cache-Control on their own responses so no-store does not depend
// solely on config matching.
export const ADMIN_RESPONSE_HEADERS = [
  ['Cache-Control', 'no-store, max-age=0'],
  [
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  ],
  ['X-Frame-Options', 'DENY'],
  ['X-Content-Type-Options', 'nosniff'],
  ['Referrer-Policy', 'no-referrer'],
  ['X-Robots-Tag', 'noindex, nofollow, noarchive'],
  ['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'],
  ['Cross-Origin-Opener-Policy', 'same-origin'],
  ['Cross-Origin-Resource-Policy', 'same-origin'],
  ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'],
];

export function adminHeaders(extra = {}) {
  const headers = {};
  for (const [k, v] of ADMIN_RESPONSE_HEADERS) headers[k] = v;
  return { ...headers, ...extra };
}

export function adminJson(body, status = 200, extraHeaders = {}) {
  return Response.json(body, { status, headers: adminHeaders(extraHeaders) });
}
