/** @type {import('next').NextConfig} */

// Admin surface headers (admin design §16.1): no-store, a strict CSP
// with frame-ancestors 'none', DENY framing, nosniff, no-referrer,
// noindex/noarchive, and HSTS. Applied to /admin pages and
// /api/admin/* APIs; route handlers additionally pin Cache-Control
// on their own responses so no-store does not depend solely on this
// config matching.
//
// CSP split (2026-11-05): the static script-src 'self' CSP below is
// kept for /api/admin/* only. On /admin PAGES it silently killed all
// client interactivity: Next.js App Router streams its hydration
// payload in inline scripts, which script-src 'self' blocks, so
// every admin form rendered but never hydrated (the login form fell
// back to a native GET submit and no one could sign in through the
// UI). Admin pages now get their CSP from middleware.js instead:
// same directives, but script-src carries a per-request nonce that
// Next stamps onto its inline scripts. No 'unsafe-inline' anywhere.
const ADMIN_HEADERS = [
  { key: 'Cache-Control', value: 'no-store, max-age=0' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'X-Robots-Tag', value: 'noindex, nofollow, noarchive' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
];

const ADMIN_API_HEADERS = [
  ...ADMIN_HEADERS,
  {
    key: 'Content-Security-Policy',
    value:
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  },
];

const nextConfig = {
  // Reports and scan pages must never be indexed (spec: Data rules).
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [{ key: 'X-Robots-Tag', value: 'noindex, nofollow' }],
      },
      { source: '/admin/:path*', headers: ADMIN_HEADERS },
      { source: '/api/admin/:path*', headers: ADMIN_API_HEADERS },
    ];
  },
};

export default nextConfig;
