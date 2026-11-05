import { NextResponse } from 'next/server';

// Per-request CSP nonce for the /admin pages (see next.config.mjs
// for why): Next.js reads the nonce out of the Content-Security-
// Policy value carried in the REQUEST headers and stamps it onto
// the inline scripts it generates, so hydration works while
// script-src stays strict (no 'unsafe-inline', no 'unsafe-eval').
// All other directives mirror the admin policy that used to be
// served statically from next.config.
export function middleware(request) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data:",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join('; ');

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);
  return response;
}

export const config = {
  matcher: ['/admin/:path*'],
};
